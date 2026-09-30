"""S3：设备属性漂移分级（L0 / L1 / L2 / L3）。

为什么要有这一层
────────────────
证书身份（S1）把身份锚从「IP + 主机名」换成了 `node_id + 证书公钥`。好处是换 IP、
换机房、过 NAT 都不会掉线；代价是**我们再也不能用 IP 判断"这还是不是那台机器"**。
于是需要单独一套「属性漂移」检测：身份不变的前提下，属性变了要能分级处置。

分级定义（用户 2026-09-18 确认）
──────────────────────────────
  L0  无变化。
  L1  环境漂移：IP / 主机名变了，硬件分量没变。
      → **自动接受**：更新库里的 IP 与计算机名，写一条审计。DHCP 换址不该让机器掉线。
  L2  硬件漂移：machine-id / 主板序列号 / 主网卡 MAC 中有变化（但不是全部都变）。
      → **只告警，不阻断**：继续正常上报，写审计 + 一条待确认告警。
      理由（评估文档 §3.3）：克隆 / sysprep 不彻底的镜像 machine-id 会重复，
      自动降权必然误伤 —— 换主板、重装系统都会命中，一降权就是真掉线。
  L3  身份冲突：可比的硬件分量**全部**都变（等于换了一台物理机却拿着同一张证书）。
      → **告警 + 保留旧指纹**：不阻断上报（避免误伤），但**不更新**库里的指纹，
        保留旧值当证据，并打一条 critical 告警逼管理员去看。

几点刻意的取舍
──────────────
* **空值当"未采集"跳过比对**。虚拟机 / 容器常常读不到主板序列号，要是把空值也
  算进"变化"，这些机器会永远在报漂移。
* **L2 更新指纹、L3 不更新**。更新了下次就比不出变化 → L2 天然只告警一次；
  L3 刻意不更新，让证据留在库里，靠"已有未确认的同级告警"去重，避免每 5 秒一条。
* **首次登记一律 L0**。老版本 Agent 只上报总哈希、没有分项，库里 `fingerprint_parts`
  为空 → 按首次登记处理，恰好完成迁移，不会在升级那天集体误报。
"""
from __future__ import annotations

import json
from typing import Optional

ENV_PARTS = ("host",)
HW_PARTS = ("mid", "board", "mac")

L0, L1, L2, L3 = "L0", "L1", "L2", "L3"

_PART_LABEL = {
    "host": "主机名",
    "mid": "machine-id / MachineGuid",
    "board": "主板序列号",
    "mac": "主网卡 MAC",
}


def parse_parts(raw) -> dict:
    """库里存的 `fingerprint_parts` 是 JSON 字符串；容忍空值 / 脏数据。"""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    try:
        v = json.loads(raw)
        return dict(v) if isinstance(v, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _norm(v) -> str:
    return str(v or "").strip()


def classify(prev: dict, cur: dict, prev_ip: str = "", cur_ip: str = "") -> dict:
    """比对两次上报的属性，给出漂移等级。

    `prev` 为空（首次登记 / 老 Agent 升级上来的第一次）一律返回 L0。
    只比对**两边都非空**的分量 —— 采不到的那一项不参与判断。
    """
    prev = parse_parts(prev)
    cur = parse_parts(cur)
    if not prev or not cur:
        return {"level": L0, "changed": [], "detail": "首次登记，无历史指纹可比"}

    env_changed, hw_changed, hw_compared = [], [], []
    for k in ENV_PARTS:
        p, c = _norm(prev.get(k)), _norm(cur.get(k))
        if p and c and p != c:
            env_changed.append(k)
    for k in HW_PARTS:
        p, c = _norm(prev.get(k)), _norm(cur.get(k))
        if not p or not c:
            continue
        hw_compared.append(k)
        if p != c:
            hw_changed.append(k)

    ip_changed = bool(prev_ip and cur_ip and prev_ip != cur_ip)
    if ip_changed and "host" not in env_changed:
        env_changed.append("ip")

    if not hw_changed:
        if env_changed:
            return {
                "level": L1,
                "changed": env_changed,
                "detail": "环境属性变化：" + "、".join(_PART_LABEL.get(k, k) for k in env_changed),
            }
        return {"level": L0, "changed": [], "detail": "无变化"}

    if hw_compared and len(hw_changed) >= len(hw_compared) and len(hw_compared) >= 2:
        return {
            "level": L3,
            "changed": hw_changed,
            "detail": "全部硬件标识都变了（疑似换机 / 证书被复制到另一台机器）："
                      + "、".join(_PART_LABEL.get(k, k) for k in hw_changed),
        }

    return {
        "level": L2,
        "changed": hw_changed + env_changed,
        "detail": "硬件标识部分变化：" + "、".join(_PART_LABEL.get(k, k) for k in hw_changed),
    }


def apply_drift(db, server, agent_key, cur_parts: dict, cur_ip: str = "",
                prev_ip: Optional[str] = None) -> Optional[dict]:
    """把 `classify()` 的结果落到库里。返回分级结果（L0 也返回，调用方可忽略）。

 `prev_ip` 要传**更新前**的 IP：心跳里 L1 的 IP 更新发生在调用本函数之前，
    等这里再读 `server.ip_address` 就已经是新值了，比不出变化。

    本函数负责：更新计算机名（L1）、更新分项指纹（L0/L1/L2）、写审计与告警（L1/L2/L3）。
    """
    from models import Alert
    from services.audit_logger import log_operation

    prev_parts = parse_parts(getattr(agent_key, "fingerprint_parts", ""))
    if prev_ip is None:
        prev_ip = getattr(server, "ip_address", "")
    prev_ip = _norm(prev_ip)
    res = classify(prev_parts, cur_parts, prev_ip, cur_ip)
    level = res["level"]

    if level == L0:
        if cur_parts and cur_parts != prev_parts:
            agent_key.fingerprint_parts = json.dumps(cur_parts, ensure_ascii=False)
            if not prev_parts:
                res["detail"] = "登记基线指纹"
        return res

    server_name = getattr(server, "name", "") or f"server#{getattr(server, 'id', '?')}"
    changed = [_PART_LABEL.get(k, k) for k in res["changed"]]

    if level == L1:
        host_now = _norm(cur_parts.get("host"))
        if host_now:
            try:
                cfg = getattr(server, "extra_config", None) or {}
                if _norm(cfg.get("computer_name")) != host_now:
                    cfg["computer_name"] = host_now
                    server.extra_config = cfg
            except Exception:  # noqa: BLE001
                pass
        agent_key.fingerprint_parts = json.dumps(cur_parts, ensure_ascii=False)
        res["detail"] = f"{res['detail']}：{prev_ip or '(空)'} → {cur_ip or '(空)'}"
        log_operation(
            db,
            category="identity",
            action="drift_l1",
            level="info",
            message=f"主机 {server_name} 环境属性变化，已自动接受：{res['detail']}",
            target_type="server",
            target_id=str(getattr(server, "id", "")),
            details={"level": L1, "changed": changed, "ip_before": prev_ip, "ip_after": cur_ip},
        )
        return res

    if level == L2:
        agent_key.fingerprint_parts = json.dumps(cur_parts, ensure_ascii=False)
        db.add(Alert(
            server_id=server.id,
            level="warning",
            title=f"设备硬件标识变化（L2）：{server_name}",
            message=(
                f"{res['detail']}。设备身份（node_id + 证书）未变，已继续正常监控；"
                f"若这是更换主板 / 重装系统 / 虚拟机克隆，可忽略并确认本条告警。"
            ),
            metric_type="identity",
        ))
        log_operation(
            db,
            category="identity",
            action="drift_l2",
            level="warning",
            # L2 = 「检测到了变化、但已继续正常监控」，检测动作本身是成功的。
            status="success",
            message=f"主机 {server_name} 硬件标识变化（L2，未阻断）：{res['detail']}",
            target_type="server",
            target_id=str(server.id),
            details={"level": L2, "changed": changed},
        )
        return res

    # 刻意**不更新** fingerprint_parts：全变说明手里这张证书可能已经被搬到另一台
    # 机器上，旧指纹是唯一的证据，不能覆盖掉。管理员「确认告警」= 认可这次换机，
    # 那时才以当前硬件重新登记基线（否则会一直卡在冲突态）。
    existing = (
        db.query(Alert)
        .filter(
            Alert.server_id == server.id,
            Alert.metric_type == "identity",
            Alert.level == "critical",
        )
        .order_by(Alert.id.desc())
        .first()
    )
    if existing is not None and existing.acknowledged == 1:
        agent_key.fingerprint_parts = json.dumps(cur_parts, ensure_ascii=False)
        log_operation(
            db,
            category="identity",
            action="drift_l3_accept",
            level="info",
            message=f"主机 {server_name} 的 L3 身份冲突已由管理员确认，以当前硬件重新登记基线",
            target_type="server",
            target_id=str(server.id),
            details={"level": L3, "changed": changed},
        )
        res["detail"] += "（管理员已确认，重新登记基线）"
        return res
    if existing is not None:
        res["detail"] += "（已有未确认的 L3 告警，本次不再重复告警）"
        return res

    db.add(Alert(
        server_id=server.id,
        level="critical",
        title=f"设备身份冲突（L3）：{server_name}",
        message=(
            f"{res['detail']}。这台机器拿着原来的 node_id 和证书，但硬件标识全变了 —— "
            f"可能是整机更换，也可能是配置目录被复制到了另一台机器。"
            f"已保留旧指纹不覆盖，请人工核对；确认无误后点「确认告警」，"
            f"之后会以当前硬件重新登记基线。"
        ),
        metric_type="identity",
    ))
    log_operation(
        db,
        category="identity",
        action="drift_l3",
        level="error",
        status="failed",
        message=f"主机 {server_name} 设备身份冲突（L3）：{res['detail']}",
        target_type="server",
        target_id=str(server.id),
        details={"level": L3, "changed": changed},
    )
    return res
