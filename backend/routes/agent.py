"""Agent route — receives encrypted metrics from remote agents."""
import hmac, os
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import Server, MetricSnapshot, MonitoredService, AgentKey
from sqlalchemy.orm.attributes import flag_modified

logger = logging.getLogger("backend")


def _maybe_issue_api_cert(db: Session, agent_key: "AgentKey", server: Server, data: dict) -> dict:
    """P1-1（9998 通道 TLS）：payload 带 api_csr 时给 Agent 的本地 API 签服务器证书。

    信任级别与 register 时下发的 HMAC token 一致（注册零审核，api 证书同样零审核；
    防伪靠 CSR 私钥持有证明 + 服务端调用侧的 CA 链校验）。已有证书时只允许
    **同一把公钥**续期且到期前 30 天才重签。失败只记日志，绝不影响注册/入户主流程。
    """
    api_csr = str(data.get("api_csr") or "").strip()
    if not api_csr:
        return {}
    try:
        from services import tls as tls_util
        from services import agent_identity as aid
        from cryptography import x509 as _x
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        node_id = (agent_key.node_id or "").strip()
        if not node_id:
            node_id = str(data.get("node_id") or "").strip()
            if not node_id.startswith("vnode-"):
                return {}
            agent_key.node_id = node_id
        new_csr = _x.load_pem_x509_csr(api_csr.encode("utf-8"))
        new_pub = new_csr.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if agent_key.api_cert:
            cur_pub = aid.cert_public_key(agent_key.api_cert)
            if cur_pub is not None and (
                    cur_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != new_pub):
                logger.warning(
                    f"api 证书公钥已更换 server_id={server.id}，拒绝重签（防顶替）")
                return {}
            if cur_pub is not None and not tls_util.cert_issued_by_current_ca(agent_key.api_cert):
                # 🚨 2026-09-28：`cert_needs_renew()` 只看日期。服务端**重装 / 重建 CA**
                # 之后，库里这份证书虽然没到期，却已经不是当前 CA 签的了。原样发回去，
                # Agent 的 9998 会永久挂在 CA 链校验失败上；而 Agent 侧因为证书未到期，
                # 永远不上送 api_csr —— 两边都"觉得没问题"，通道就此永久断掉。
                # 现场症状：资源管理器/远程桌面全报「无法连接到 Agent {ip}:9998」。
                logger.info(
                    f"库内 api 证书已不归当前 CA（服务端 CA 变更过），"
                    f"为 server_id={server.id} 重签")
            elif (cur_pub is not None
                    and not tls_util.cert_needs_renew(agent_key.api_cert_not_after)):
                # 1.1.39：Agent 带 api_csr 前来 = 本地没有这份证书（needs_api_cert
                # 才会带）。此前返回空导致 1.1.53 Agent 反复申请、服务端反复
                # 空手打发，9998 永远停在自签证书上。这里直接**重发库里的
                # 那份**（同公钥、未到期、不重签无 churn），Agent 落盘后
                # 10 秒内热切换 TLS listener。
                _na = agent_key.api_cert_not_after
                logger.info(
                    f"重发现有 api 证书给 server_id={server.id}"
                    f"（Agent 本地缺失，同公钥未到期不重签）")
                return {"api_cert": agent_key.api_cert,
                        "api_cert_not_after": _na.isoformat() if _na else ""}
        signed = tls_util.sign_agent_server_cert(api_csr, node_id, server.ip_address or "")
        agent_key.api_cert = signed["cert_pem"]
        agent_key.api_cert_not_after = signed["not_after"]
        db.commit()
        logger.info(
            f"已为 server_id={server.id} 签发 Agent API 服务器证书，"
            f"有效期至 {signed['not_after'].isoformat()}")
        return {"api_cert": signed["cert_pem"],
                "api_cert_not_after": signed["not_after"].isoformat()}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"签发 Agent API 证书失败 server_id={server.id}: {e}")
        return {}


def _is_apipa(ip: str) -> bool:
    """Return True for APIPA/link-local addresses (169.254.0.0/16)."""
    return (ip or "").startswith("169.254.")


def _is_valid_agent_ip(ip: str) -> bool:
    """Return True for a non-loopback, non-link-local, non-zero IPv4 address."""
    if not ip or ip in ("0.0.0.0", "127.0.0.1", "unknown"):
        return False
    if ip.startswith("127.") or _is_apipa(ip):
        return False
    return True


# ── 待审核队列防护（S0，2026-09-18） ─────────────────────────────────────
# `/register` 是**零鉴权**接口（Agent 专用，设计如此），也就是说它是一个
# 「任何人都能写」的表面。在给它接上客户端证书（S1）之前，先补三道闸门：
#   ① 同一来源 IP 的滑动窗口限速 —— 拦住脚本批量刷注册
#   ② 全局队列上限 + 同一 IP 名下条目上限 —— 防止管理员被垃圾条目淹没
#   ③ TTL 清理 —— 无人处理的条目不能无限期躺在库里
# 这里改成自动加后缀 + 标记撞车，由注册管理页给出「名称重复」警告。
_PENDING_TOTAL_LIMIT = 200
_PENDING_PER_IP_LIMIT = 3
_PENDING_TTL_HOURS = 72
_REGISTER_WINDOW_SEC = 60
_REGISTER_MAX_PER_WINDOW = 5
_REGISTER_HITS: dict = {}


def _register_too_frequent(source_ip: str) -> bool:
    """同一来源 IP 的注册频率限速（进程内滑动窗口）。"""
    import time

    now = time.time()
    key = source_ip or "unknown"
    hits = [t for t in _REGISTER_HITS.get(key, []) if now - t < _REGISTER_WINDOW_SEC]
    if len(hits) >= _REGISTER_MAX_PER_WINDOW:
        _REGISTER_HITS[key] = hits
        return True
    hits.append(now)
    _REGISTER_HITS[key] = hits
    # 防止被伪造源 IP 的洪泛把内存撑爆：定期丢掉已经冷却的条目
    if len(_REGISTER_HITS) > 2000:
        for k in list(_REGISTER_HITS):
            recent = [t for t in _REGISTER_HITS[k] if now - t < _REGISTER_WINDOW_SEC]
            if recent:
                _REGISTER_HITS[k] = recent
            else:
                _REGISTER_HITS.pop(k, None)
    return False


def _pending_ip_count(db: Session, ip: str) -> int:
    """同一来源 IP 名下已有多少条待审核条目。"""
    if not ip:
        return 0
    return (
        db.query(Server)
        .filter(
            Server.protocol == "agent",
            Server.status == "registered",
            Server.ip_address == ip,
        )
        .count()
    )


def _delete_pending_server(db: Session, server: Server) -> None:
    """删除一条待审核条目，连带清掉它的 AgentKey 与分组成员行（避免孤儿行）。"""
    try:
        key = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
        if key:
            db.delete(key)
    except Exception:  # noqa: BLE001
        pass
    try:
        from models import HostGroupMember

        for row in db.query(HostGroupMember).filter(
            HostGroupMember.server_id == server.id
        ).all():
            db.delete(row)
    except Exception:  # noqa: BLE001
        pass
    db.delete(server)


def _cleanup_pending(db: Session) -> dict:
    """TTL 清理 + 全局上限淘汰。返回 {"expired": n, "evicted": n}。"""
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=_PENDING_TTL_HOURS)
        stale = (
            db.query(Server)
            .filter(
                Server.protocol == "agent",
                Server.status == "registered",
                Server.created_at < cutoff,
            )
            .all()
        )
        expired = len(stale)
        for s in stale:
            _delete_pending_server(db, s)
        if expired:
            db.flush()
            logger.warning(
                f"待审核队列：清除 {expired} 条超过 {_PENDING_TTL_HOURS} 小时未处理的注册请求"
            )

        rows = (
            db.query(Server)
            .filter(Server.protocol == "agent", Server.status == "registered")
            .order_by(Server.created_at.asc())
            .all()
        )
        excess = len(rows) - _PENDING_TOTAL_LIMIT
        evicted = 0
        if excess > 0:
            for s in rows[:excess]:
                _delete_pending_server(db, s)
            db.flush()
            evicted = excess
            logger.warning(
                f"待审核队列已满（上限 {_PENDING_TOTAL_LIMIT}），淘汰最旧的 {evicted} 条"
            )
        return {"expired": expired, "evicted": evicted}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"待审核队列清理失败：{e}")
        return {"expired": 0, "evicted": 0}


def _unique_server_name(db: Session, hostname: str) -> "tuple[str, Optional[int]]":
    """避开 `Server.name` 的唯一约束。

    Server.name 是 unique —— 同名但来自另一台机器（不同源 IP）时，
    现有 step2/step3 都匹配不到，直接 INSERT 会抛 IntegrityError(500)。
    这里改成追加序号后缀，并把撞车的那条记录 id 返回，
    由注册管理页显示「名称与已存在主机重复」警告（对应安全方案第五节第 3 点）。
    """
    exists = db.query(Server).filter(Server.name == hostname).first()
    if not exists:
        return hostname, None
    for i in range(2, 100):
        candidate = f"{hostname}-{i}"
        if not db.query(Server).filter(Server.name == candidate).first():
            return candidate, exists.id
    return f"{hostname}-{int(datetime.now(timezone.utc).timestamp())}", exists.id


def _best_agent_ip(report_ip: str, client_host: str) -> str:
    """Choose the most reliable IP for an agent.

    Prefer the agent's self-reported IP unless it is APIPA/invalid.
    In that case fall back to the HTTP request's client IP.
    """
    if _is_valid_agent_ip(report_ip):
        return report_ip
    if _is_valid_agent_ip(client_host):
        return client_host
    return report_ip or client_host or "0.0.0.0"


def _store_cpu_model(server: Server, incoming: str) -> None:
    """把 Agent 上报的 CPU 型号写入 extra_config（调用方负责 commit）。

    老版本 Agent 在 Windows 上只会给出 CPUID 代号
    （"Intel64 Family 6 Model 165 Stepping 3, GenuineIntel"），这种值不允许
    覆盖已经拿到的品牌型号 —— 否则「主机信息」页顺带修正好的型号，
    会在下一次心跳里被劣化回去。
    """
    try:
        from services import cpu_model as cpu_util
    except Exception:  # noqa: BLE001
        return
    value = cpu_util.clean(incoming)
    if not value:
        return
    if not isinstance(server.extra_config, dict):
        server.extra_config = {}
    current = server.extra_config.get("cpu_model") or ""
    if value == current:
        return
    if cpu_util.is_cpuid_code(value) and current and not cpu_util.is_cpuid_code(current):
        return
    server.extra_config["cpu_model"] = value
    flag_modified(server, "extra_config")


_AGENT_DIR = str(Path(__file__).resolve().parent.parent.parent / "agent")
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)
try:
    from collector_v2 import (
        _is_system_proc,
        _is_service_proc,
        _is_core_system_proc,
        _is_system_service_proc,
        _is_third_party_service_proc,
        _operation_level,
        _operation_level_from_legacy,
    )
except Exception:
    def _is_system_proc(name: str) -> bool:
        return False

    def _is_service_proc(name: str) -> bool:
        return False

    def _is_core_system_proc(name: str) -> bool:
        return False

    def _is_system_service_proc(name: str) -> bool:
        return False

    def _is_third_party_service_proc(name: str) -> bool:
        return False

    def _operation_level(category: str) -> str:
        return {
            "core_system": "view_only",
            "system_service": "terminate_with_confirm",
            "third_party_service": "terminate_with_confirm",
            "user_process": "full",
        }.get(category, "full")

    def _operation_level_from_legacy(category: str, is_system: bool) -> str:
        if is_system or category == "system":
            return "view_only"
        if category == "service":
            return "terminate_with_confirm"
        return "full"


def _server_classify(name: str, category: str | None = None, is_system: bool | None = None,
                     detailed_category: str | None = None, operation_level: str | None = None) -> dict:
    """Return classification fields with a server-side fallback heuristic.

    The returned dict contains legacy ``category`` / ``is_system`` plus the
    four-level ``detailed_category`` and ``operation_level``.
    """
    n = (name or "").lower().replace(".exe", "").strip()

    if detailed_category:
        dc = detailed_category
    elif category:
        if is_system or category == "system" or _is_core_system_proc(name):
            dc = "core_system" if _is_core_system_proc(name) else "system_service"
        elif category == "service" or _is_third_party_service_proc(name):
            dc = "third_party_service"
        else:
            dc = "user_process"
    else:
        if not n or n in {"system", "registry", "idle", "system idle process"}:
            dc = "core_system"
        elif _is_core_system_proc(name):
            dc = "core_system"
        elif _is_system_service_proc(name):
            dc = "system_service"
        elif _is_system_proc(name) or is_system:
            dc = "system_service"
        elif _is_third_party_service_proc(name) or _is_service_proc(name):
            dc = "third_party_service"
        else:
            dc = "user_process"

    legacy_category = "system" if dc in {"core_system", "system_service"} else ("service" if dc == "third_party_service" else "user")
    is_sys = legacy_category == "system"
    op_level = operation_level or _operation_level(dc)

    return {
        "category": legacy_category,
        "is_system": is_sys,
        "detailed_category": dc,
        "operation_level": op_level,
    }

router = APIRouter()


def _verify_auth_ex(server_id: int, token: str, db: Session) -> "tuple[Server | None, str]":
    """HMAC-SHA256 token 校验，并返回对上的是哪一把密钥。

    返回 `(Server, 密钥代)`，密钥代为 `"current"` / `"prev"` / `"expired"` / `""`。
    `"prev"` 表示这把 token 是**轮换前**的旧货 —— 调用方应当顺手把新 token
    下发给 Agent，让它自己换过来（见心跳接口）。

    ⚠ 遗留路径（安全演进 S1 之前的实现）。`AgentKey.secret_key` 是对称密钥，
    服务端和 Agent 都能算出同一个 token —— 一旦这台机器上任意进程读到配置里的
    token，就能冒充该主机。新版本 Agent 由 `_authenticate()` 切到客户端证书路线；
    这里只在本机 Agent 还没迁移时兜底，并打告警。

    🚨 2026-09-23 开源加固 ⑤：原来是 `expected[:32] == token[:32]` 的**截断比较**
       （只比前 32 个 hex 字符），碰撞面被人为放大了一倍。改成全量比对 ——
       Agent 侧发的本来就是完整的 64 位，不影响任何现有部署。
    """
    from services.agent_auth import match_agent_token
    agent_key = db.query(AgentKey).filter(AgentKey.server_id == server_id).first()
    if not agent_key:
        return None, ""
    which = match_agent_token(agent_key, server_id, token)
    if which in ("current", "prev"):
        return db.query(Server).filter(Server.id == server_id).first(), which
    return None, which


def _verify_auth(server_id: int, token: str, db: Session) -> Server | None:
    """只要对得上（当前或轮换宽限期内）就算通过。需要区分密钥代时用 `_verify_auth_ex`。"""
    return _verify_auth_ex(server_id, token, db)[0]


def _authenticate(request: Request, db: Session,
                  allow_pending: bool = False) -> "tuple[Server | None, str]":
    """统一认证入口（方案 A，1.1.51：**单路径，无回落**）。

    设备身份 = `node_id` + **服务端库里登记的公钥**。每个请求都必须用对应的私钥
    对规范串签名（含时间戳 + nonce），服务端拿登记的公钥验。

    🚨 改之前这里有两套凭据（客户端证书 / 静态 token）并且**互相回落**，一共 15
    个分支。回落的边界情况穷举不完 —— 光「服务端换机器部署」这一个场景就连着长出
    两条 401（未知 node_id、IP mismatch），界面表现都是「注册成功几秒后又变回
    未注册」，而根因完全不同、排查只能靠猜。现在只有一条路，没有回落。

    为什么可以不要证书：见 `docs/认证体系简化评估.md`。要点：
      · 自签 CA 场景下「CA 签过」等价于「服务端库里记一行公钥」，证书**不多提供**
        任何信任；
      · 真正防冒充的「私钥不出本机」这一点，两种方案完全一样；
      · 反过来，被砍掉的静态 token 才是**真后门** —— 它是配置文件里的一把静态串，
        本机任意进程读到就能冒充这台主机上报，且吊销机制拦不住。

    ⚠ `token` 并没有消失，它降级成了**仅服务端回调本机 9998 用的下行凭据**
    （Agent 侧叫 callback key）。它**不再**能用于上行认证 —— 上行的唯一凭据是签名。

    为什么签名挂在应用层而不是做 mTLS：见 `services/agent_identity.py` 顶部注释。
    一句话：uvicorn 不把对端证书暴露给 FastAPI，而 8001 还要同时服务浏览器。

    `allow_pending=True`（只有心跳用）：允许**尚未加入管理**的设备用
    `AgentKey.pending_pub_key`（入户时暂存的公钥）通过校验，返回
    `(server, "pubkey-pending")`。

    为什么需要这条：`last_seen` 是"在线"的唯一依据，而它只在心跳里更新。以前
    未准入设备连心跳都签不了名 → 一直显示离线，管理员以为机器没连上。现在
    **在线 = 网络连通**（心跳通就行），**准入 = 能不能上报数据**（仍然是 pub_key
    这一道闸）—— 两件事分开。
    ⚠ 暂存公钥同样要**验签**，不是免认证：没有它，任何人拿一个 node_id 就能把
    主机刷成在线。所以这里不是"放开一条免鉴权通道"，只是换了把钥匙去验。

    返回 `(Server, 认证方式)`，失败一律 `(None, 原因)`。
    """
    try:
        from services import agent_identity as aid
    except Exception as e:  # noqa: BLE001
        logger.error(f"身份模块不可用，无法认证任何 Agent：{e}")
        return None, "身份模块不可用（服务端身份组件加载失败）"

    node_id = (request.headers.get(aid.NODE_HEADER) or "").strip()
    sig = (request.headers.get(aid.SIG_HEADER) or "").strip()
    if not node_id or not sig:
        return None, "缺少设备签名（须带 X-VS-Node / X-VS-Sig）"

    key = db.query(AgentKey).filter(AgentKey.node_id == node_id).first()
    if not key:
        return None, "该设备尚未入户（服务端没有这个 node_id），请在 Agent 上重新入户"
    if key.revoked:
        return None, "该设备已被吊销"

    # 拿哪把公钥验签：已准入的用 pub_key；未准入的（仅心跳）用暂存的 pending_pub_key。
    _auth_key = (key.pub_key or "").strip()
    _auth_mode = "pubkey"
    if not _auth_key:
        if not allow_pending:
            return None, "该设备尚未登记公钥（等待管理员在「注册管理」批准）"
        _auth_key = (key.pending_pub_key or "").strip()
        _auth_mode = "pubkey-pending"
        if not _auth_key:
            return None, "该设备尚未登记公钥（等待管理员在「注册管理」批准）"

    ts_raw = request.headers.get(aid.TS_HEADER) or ""
    try:
        ts = int(ts_raw)
    except (TypeError, ValueError):
        return None, "X-VS-Ts 不是整数"
    import time as _t

    if abs(_t.time() - ts) > aid.SIGN_SKEW_SEC:
        return None, "时间戳超出允许偏差（检查两端时钟）"

    nonce = request.headers.get(aid.NONCE_HEADER) or ""
    # 开源加固 ⑦：nonce 落库，跨后端重启仍然防重放
    nonce_err = aid.check_nonce(node_id, nonce, db=db)
    if nonce_err:
        return None, nonce_err

    pub = aid.load_public_key(_auth_key)
    if pub is None:
        return None, "服务端登记的公钥无法解析"
    msg = aid.canonical_string(request.method, request.url.path, node_id, ts_raw, nonce)
    if not aid.verify_signature(pub, sig, msg):
        return None, "签名校验失败（本机私钥与服务端登记的公钥不匹配）"

    server = db.query(Server).filter(Server.id == key.server_id).first()
    if not server:
        return None, "设备对应的主机记录已不存在"

    key.last_signature_at = datetime.now(timezone.utc)
    return server, _auth_mode

def _record_agent_online(server: Server, now: datetime, db: Session = None) -> None:
    """Agent 联系到服务端时更新上下线时间。

    🚨 2026-09-28 用户提的缺陷：**未加入管理的主机「上线时间」永远是第一次安装
    上线那一刻**，断线再连上也不变。

    根因是 `online_time` 原来挂在"状态迁移"上：只有 `offline/unknown/warning/
    critical` → 在管 那一步才写。而未加入管理的主机状态**恒为 `registered`**
    （collector 每轮都会把它从 offline 回滚回 registered，防止落进"受管"集合），
    它永远走不到那条分支，于是只剩「为空时补一次」—— 也就是安装那一次。

    判据改成"这次联系之前是不是离线"，与状态字段彻底解耦：
      用统一的在线判定（`services/device_status.py` 的「采集周期 × 2.5」）
      去看**旧的** `last_seen`。
        · 过期（或从来没连过）→ 这次算重新上线，写 `online_time`；
        · 还新鲜 → 主机一直在线，不动 —— 否则 5 秒一次的心跳会把「上线时间」
          刷成「最后一次心跳时间」，那就不是"上线"了。

    由此带来的两处（正确）行为变化：
      · 已纳管的主机也一样：掉线再连上同样刷新，不再依赖 collector 先把它
        置成 offline；
      · `warning` / `critical`（在线但有告警）不再刷新上线时间 —— 它没有掉线，
        刷新反而把"最近一次上线"写成告警持续的那一刻。

    ⚠ 调用点必须在**写 `last_seen` 之前**：这里要比的是"上一次联系"的时间，
    写完就比不出来了（heartbeat 里正是先调本函数、后写 `last_seen`）。
    """
    # 状态恢复：`join_time` 非空 = 曾被纳入管理，否则保持 registered。
    if server.status in ("offline", "unknown", "warning", "critical"):
        server.status = "monitored" if server.join_time is not None else "registered"

    try:
        from services import device_status as _ds
        _was_offline = not _ds.is_online(server, _ds.load_config(db), now)
    except Exception:  # noqa: BLE001  判不出来就退回"只补一次"的旧行为
        _was_offline = False

    if _was_offline or server.online_time is None:
        server.online_time = now
    server.offline_time = None


@router.get("/ping")
def agent_ping():
    """Simple health check — does nothing but confirms the server is reachable."""
    return {"status": "ok", "message": "VigilServe API is ready"}


@router.get("/ca")
def agent_ca():
    """把本服务端的本地 CA 证书发给 Agent（**免鉴权**，Agent 入户前的信任引导）。

    🚨 为什么必须免鉴权，以及为什么不冲突于 `/api/tls/ca.crt` 的管理员限制：

    每台 VigilServe 服务端都在**首次启动时自己生成一把本地 CA**（`services/tls.py`），
    所以任何"预先打进 Agent 安装包"的 CA 只对打包那台机器有效。换个服务端部署，
    Agent 拿内置 CA 去校验新服务端的证书必然 `CERTIFICATE_VERIFY_FAILED`，界面上
    就是「证书未被信任（缺少本地 CA）」—— 而这时它还没有任何凭据，任何需要登录的
    接口它都调不动，于是永远卡死。这就是本接口存在的唯一理由。

    CA 证书是**公钥**，不含私钥，发出去不泄露密钥；真正的防护在于 Agent 侧：
    拿到 CA 后必须把 SHA-256 指纹显示给操作员核对（TOFU），确认后才落盘信任。
    因此这里额外回传指纹，让两端能对着念。
    `/api/tls/ca.crt` 保持管理员限定 —— 那个口是给"人工导入浏览器"用的。
    """
    from services import tls as tls_svc
    if not tls_svc.CA_CERT.exists():
        raise HTTPException(status_code=404,
                            detail="本地 CA 尚未生成（服务端未启用 HTTPS）")
    info = tls_svc.describe()
    return {
        "ca_pem": tls_svc.CA_CERT.read_text(encoding="utf-8"),
        "fingerprint": info.get("ca_fingerprint", ""),
        "not_after": info.get("ca_not_after", ""),
        "server_sans": info.get("sans", []),
    }


@router.post("/scan")
def agent_scan(request: Request, server_id: int, db: Session = Depends(get_db)):
    """Trigger scan — uses psutil on backend host. Works for any server (admin-only)."""
    import psutil, socket
    from routes.auth import require_admin_full

    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    authed, _why = _authenticate(request, db)
    if not (authed and authed.id == server_id):
        # 管理员分支：2026-09-22 安全审计 P0-4。
        # 旧写法只判断 Authorization 头「非空」（`if not auth: raise 401`）→ 任意值即可通过，
        # 且上面 import 的 require_admin 从头到尾没被调用过。现在改为真正校验管理员身份。
        require_admin_full(request.headers.get("authorization"), db)

    SYSTEM_PROCS = {
        'svchost.exe', 'csrss.exe', 'lsass.exe', 'smss.exe', 'wininit.exe',
        'winlogon.exe', 'dwm.exe', 'explorer.exe', 'taskhostw.exe', 'RuntimeBroker.exe',
        'WmiPrvSE.exe', 'System', 'Registry', 'Idle', 'sihost.exe', 'fontdrvhost.exe',
        'WerFault.exe', 'Wermgr.exe', 'taskmgr.exe', 'powershell.exe', 'cmd.exe',
        'conhost.exe', 'dllhost.exe', 'spoolsv.exe', 'services.exe',
        'wuauclt.exe', 'SearchUI.exe', 'StartMenuExperienceHost.exe', 'ShellExperienceHost.exe',
        'LockApp.exe', 'LogonUI.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
        'python.exe', 'python3.exe', 'node.exe', 'java.exe',
    }

    KNOWN_SERVICES = {
        'iis': ('IIS Web Server', 80, 443, 'InetMgr.exe'),
        'sql_server': ('SQL Server', 1433, None, 'sqlservr.exe'),
        'mysql': ('MySQL', 3306, None, 'mysqld.exe'),
        'apache': ('Apache HTTP', 80, 443, 'httpd.exe'),
        'nginx': ('Nginx', 80, 443, 'nginx.exe'),
        'tomcat': ('Tomcat', 8080, 8443, 'tomcat*.exe'),
        'redis': ('Redis', 6379, None, 'redis-server.exe'),
        'postgresql': ('PostgreSQL', 5432, None, 'postgres.exe'),
        'docker': ('Docker', 2375, 2376, 'dockerd.exe'),
        'mongodb': ('MongoDB', 27017, None, 'mongod.exe'),
        'mq': ('RabbitMQ', 5672, 15672, 'rabbitmq-server.exe'),
        'kafka': ('Kafka', 9092, None, 'kafka.exe'),
        'redis_windows': ('Redis (Windows)', 6379, None, 'redis-server.exe'),
    }

    def is_system_proc(name):
        if not name:
            return True
        n = name.lower()
        if n in {p.lower() for p in SYSTEM_PROCS}:
            return True
        if n.startswith('ms') and n.endswith('.exe'):
            return True
        return False

    listening = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr:
            port = conn.laddr.port
            listening.append({
                'port': port,
                'protocol': 'tcp',
                'address': conn.laddr.ip,
            })
    for conn in psutil.net_connections(kind='inet'):
        if conn.type == socket.SOCK_DGRAM and conn.laddr:
            listening.append({
                'port': conn.laddr.port,
                'protocol': 'udp',
                'address': conn.laddr.ip,
            })

    services_found = []
    seen_procs = set()
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            name = proc.info['name']
            if not name or name in seen_procs:
                continue
            if is_system_proc(name):
                continue
            seen_procs.add(name)

            matched = None
            for key, (display, port1, port2, proc_pattern) in KNOWN_SERVICES.items():
                if name.lower() == proc_pattern.lower() or name.lower() == proc_pattern.replace('.exe', '').lower():
                    matched = (key, display, port1, port2, name)
                    break

            if matched:
                key, display, port1, port2, proc_name = matched
                for port in [port1, port2]:
                    if port and any(l['port'] == port for l in listening):
                        services_found.append({
                            'id': f'scan-{key}-{port}',
                            'name': f'{display} ({port})',
                            'port': port,
                            'process_name': proc_name,
                            'check_type': 'tcp',
                            'matched': True,
                        })
                        break
            else:
                services_found.append({
                    'id': f'scan-proc-{proc.info["pid"]}',
                    'name': f'{name} (进程)',
                    'port': 0,
                    'process_name': name,
                    'check_type': 'process',
                    'matched': False,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return {
        'listening_ports': listening,
        'services': services_found,
    }


@router.post("/register")
def agent_register(request: Request, data: dict, db: Session = Depends(get_db)):
    """Register a new agent and return server_id + auth token.

    If the agent already knows its server_id + token (e.g. after rename),
    prefer that exact record to avoid duplicate server entries.

    Payload: {hostname, ip_address, username, os_type, cpu_cores, total_memory_gb,
              disk_partitions, cpu_model, business_system, server_id, token}
    """
    hostname = data.get("hostname", "unknown")
    client_host = request.client.host if request.client else ""
    ip = _best_agent_ip(data.get("ip_address", ""), client_host)

    if not hostname or len(hostname) < 3 or hostname.lower() == "test":
        raise HTTPException(status_code=400, detail="Invalid hostname")

    server = None

    #    注释说是防「拷贝安装配置劫持别的主机」。这条在 **L1（DHCP 换 IP）场景下
    #    会直接误伤** —— 一台已纳管的主机换了 IP 就认不回来，掉到第 2/3 步按新 IP
    #    匹配，匹配不上就在待审核队列里多出一条副本（评估文档 §3.3 点名要改）。
    #
    #    现在身份锚是 node_id + 登记的公钥，**IP 只是联络地址**：
    #      · 带 node_id 且已登记公钥未吊销 → 直接认领，不看 IP；
    #      · 遗留 HMAC 路径 → token 本身就是持有证明，IP 只作为兜底判据，
    #        再放宽一步「IP 不同但主机名相同」也认，让换 IP 的老机能自己接回来。
    #
    #    ⚠ 2026-09-28：判据原来是 `_k.client_cert`。方案 A（1.1.51）砍掉客户端
    #    证书之后 `client_cert` **再无写入点**，这一支恒假 —— 已纳管的主机换 IP
    #    认不回来，掉到下面按 IP 匹配，匹配不上就变成待审核队列里的重复条目。
    #    「已登记身份」在方案 A 下的等价判据是 `pub_key` 非空。
    _claimed_by_identity = False
    _node_id = str(data.get("node_id") or "").strip()
    if _node_id.startswith("vnode-"):
        _k = db.query(AgentKey).filter(AgentKey.node_id == _node_id).first()
        if _k is not None and (_k.pub_key or "").strip() and not _k.revoked:
            _s = db.query(Server).filter(Server.id == _k.server_id).first()
            if _s is not None:
                server = _s
                _claimed_by_identity = True
                if _s.ip_address and _s.ip_address != ip:
                    logger.info(
                        f"L1 环境漂移：主机 {_s.name} 按设备身份认领，IP "
                        f"{_s.ip_address} -> {ip}（已更新）"
                    )
                    _s.ip_address = ip

    known_server_id = data.get("server_id")
    known_token = data.get("token")
    if server is None and known_server_id and known_token:
        try:
            verified = _verify_auth(int(known_server_id), known_token, db)
            if verified:
                _same_host = bool(hostname) and (
                    verified.name == hostname
                    or (verified.extra_config or {}).get("computer_name") == hostname
                )
                if (verified.ip_address == ip or _same_host
                        or _is_apipa(verified.ip_address)
                        or not _is_valid_agent_ip(verified.ip_address)):
                    server = verified
        except Exception:
            pass

    if not server:
        server = db.query(Server).filter(
            Server.name == hostname,
            Server.ip_address == ip,
        ).first()

    if not server:
        candidates = (
            db.query(Server)
            .filter(Server.ip_address == ip, Server.protocol == "agent")
            .all()
        )
        if candidates:
            server = max(
                candidates,
                key=lambda s: (
                    s.last_seen.timestamp() if s.last_seen else 0,
                    1 if s.status in ("monitored", "online", "warning", "critical") else 0,
                ),
            )

    # ── S0：走到这里说明上面三步都没匹配到，即将新建一条待审核条目。
    # 这是零鉴权接口唯一的写入点，过一遍队列防护。
    name_conflict_with = None
    if not server:
        if _register_too_frequent(client_host or ip):
            raise HTTPException(status_code=429, detail="注册过于频繁，请稍后再试")
        _cleanup_pending(db)
        if _pending_ip_count(db, ip) >= _PENDING_PER_IP_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f"该来源 IP 的待审核条目已达上限（{_PENDING_PER_IP_LIMIT} 条），请先处理已有条目",
            )
        hostname, name_conflict_with = _unique_server_name(db, hostname)

    if server:
        # ⚠ S3：按**设备身份**（node_id）认领到位时**不做**这次清理 ——
        # 清理的判据是 IP，而 IP 是可以共用的（NAT / 出口同一个公网地址 / 同一
        # 台机器上跑两个 Agent）。身份已经确定的情况下再按 IP 删同址记录，
        # 等于把别人的主机记录删掉（评估文档 §3.5：改这套时必须显式关掉自动清理）。
        if not _claimed_by_identity:
            duplicates = (
                db.query(Server)
                .filter(
                    Server.ip_address == ip,
                    Server.protocol == "agent",
                    Server.id != server.id,
                )
                .all()
            )
            for dup in duplicates:
                db.delete(dup)
        now = datetime.now(timezone.utc)
        _record_agent_online(server, now, db)
        if data.get("os_type"):
            server.os_type = data["os_type"]
        if data.get("cpu_cores"):
            server.cpu_cores = data["cpu_cores"]
        if data.get("total_memory_gb"):
            server.total_memory_gb = data["total_memory_gb"]
        if data.get("disk_partitions"):
            server.disk_partitions = data["disk_partitions"]
            server.total_disk_gb = round(sum(p["total_gb"] for p in data["disk_partitions"]), 1)
        if data.get("cpu_model"):
            _store_cpu_model(server, data["cpu_model"])
        if data.get("hostname") or data.get("os_version"):
            if not server.extra_config:
                server.extra_config = {}
            if data.get("hostname") and not server.extra_config.get("computer_name"):
                server.extra_config["computer_name"] = data["hostname"]
            if data.get("os_version") and not server.extra_config.get("os_version"):
                server.extra_config["os_version"] = data["os_version"]
            flag_modified(server, "extra_config")

        if data.get("api_port"):
            try:
                server.agent_port = int(data["api_port"])
            except (ValueError, TypeError):
                pass
        else:
            server.agent_port = 9998

        if data.get("install_path"):
            server.install_path = str(data["install_path"])[:300]

        # MeshCentral 设备 ID（远程桌面直连用）。空串不上报时保持原值，避免
        # Agent 未装 MeshAgent 时把已有 ID 抹掉。
        if data.get("mesh_node_id"):
            server.mesh_node_id = str(data["mesh_node_id"])[:64]

    else:
        now = datetime.now(timezone.utc)
        extra_cfg = {}
        if data.get("cpu_model"):
            extra_cfg["cpu_model"] = data["cpu_model"]
        if data.get("hostname"):
            extra_cfg["computer_name"] = data["hostname"]
        if data.get("os_version"):
            extra_cfg["os_version"] = data["os_version"]
        if name_conflict_with:
            # 主机名与已有记录撞车（不同来源）。名字已经加了后缀，这里留下标记，
            # 让注册管理页能显示「⚠ 名称与已存在主机重复」而不是悄悄另起一条。
            extra_cfg["name_conflict_with"] = name_conflict_with
        server = Server(
            name=hostname,
            ip_address=ip,
            protocol="agent",
            network_env="内网",
            status="registered",
            os_type=data.get("os_type", ""),
            cpu_cores=data.get("cpu_cores", 0),
            total_memory_gb=data.get("total_memory_gb", 0.0),
            total_disk_gb=round(sum(p.get("total_gb", 0) for p in data.get("disk_partitions", [])), 1),
            disk_partitions=data.get("disk_partitions", []),
            business_system=data.get("business_system", ""),
            extra_config=extra_cfg,
            agent_port=int(data["api_port"]) if data.get("api_port") else 9998,
            install_path=str(data.get("install_path", ""))[:300],
            mesh_node_id=str(data.get("mesh_node_id", ""))[:64],
        )
        db.add(server)
        db.flush()

    agent_key = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
    # 这个 node_id 没被别的设备占用时才能登记到本条记录上（避免两台机器抢同一身份）。
    #
    # 🚨 S3：以前这里**只建 secret_key、不写 node_id**，于是走 /register 入户的
    #    机器在库里永远没有设备身份。它本地一旦有客户端证书（从另一台服务端带
    #    来的、或更早版本领的），心跳就会带上签名头，而服务端按 node_id 查不到
    #    记录 → 「未知 node_id」→ 掉线死循环（见 _authenticate() 里的注释）。
    #    登记的只是联络信息，不发证，所以不会给零鉴权的 /register 开口子。
    _node_free = _node_id.startswith("vnode-") and db.query(AgentKey).filter(
        AgentKey.node_id == _node_id).first() is None
    if not agent_key:
        secret = os.urandom(16).hex()
        agent_key = AgentKey(server_id=server.id, secret_key=secret)
        if _node_free:
            agent_key.node_id = _node_id
        db.add(agent_key)
    elif not agent_key.node_id and _node_free:
        # 存量条目（本版本之前建的）node_id 是空的，趁这次补登记
        agent_key.node_id = _node_id

    db.commit()
    token = hmac.new(agent_key.secret_key.encode(), str(server.id).encode(), "sha256").hexdigest()

    # P1-1：Agent 带 api_csr 来就顺手把 9998 的服务器证书也签了（与 token 同级信任）
    api_cert_out = _maybe_issue_api_cert(db, agent_key, server, data)

    # 1.1.52：让 Agent 配置面板能区分「已注册、尚未加入管理」与「已加入管理」。
    # 以前只回 server_id，面板一律显示"注册成功"，操作员会以为接入已经完成，
    # 于是卡在"服务端一直看不到这台机器"上 —— 实际还差服务端「加入管理」一步。
    _managed = bool(agent_key.pub_key) and not agent_key.revoked

    # 2026-09-23 开源加固 ④：更新包验签密钥，与 token **故意分开**下发
    # （详见 services/agent_auth.compute_update_key 的说明）
    from services.agent_auth import compute_update_key
    return {
        "server_id": server.id,
        "token": token,
        "update_key": compute_update_key(agent_key.secret_key, server.id),
        "managed": _managed,
        "identity_state": agent_key.identity_state,
        "status": "registered",
        "name_conflict": bool(name_conflict_with),
        **api_cert_out,
    }


@router.post("/enroll")
def agent_enroll(request: Request, data: dict, db: Session = Depends(get_db)):
    """设备入户：登记身份 → （人工批准后）登记公钥 → 之后一律用私钥签名通信。

    1.1.51 方案 A：身份 = `node_id` + **服务端库里登记的公钥**，不再签发 X.509
    客户端证书（为什么可以不要证书见 `docs/认证体系简化评估.md`）。

    这是新 Agent 的**唯一入口**，旧的 `/register` 保留给还没升级的机器。

    状态机（记在 `AgentKey.identity_state`）：
        none ──▶ pending ──▶ authorized
                   │            │
                   └── revoked ◀┘
      - pending    ：已递交 node_id + 公钥，等管理员在「注册管理」点「加入管理」
                     并核对配对码。**这期间 pub_key 不登记**，只把公钥暂存到
                     `pending_pub_key` —— 于是它**只能过心跳**（服务端要据此显示
                     "在线"），上报数据 / 下发配置仍然会被拒。未批准的设备本来
                     就不该能往库里写数据；但"它连着服务端"是事实，不该被吞掉。
      - authorized ：公钥已登记，之后所有 /push /heartbeat /config 用私钥签名即可。
      - 已授权的设备再送一把**新公钥**来 → 拒绝，必须先吊销重新入户
        （换密钥 = 身份漂移，不能悄悄放行，否则偷到 node_id 的人就能换锁）

    ⚠ 这个接口和 `/register` 一样是**零鉴权**的（否则新机器永远进不来），
    所以它继承了 S0 那套队列防护：来源 IP 限速、队列上限、TTL 清理、同名检测。
    """
    try:
        from services import agent_identity as aid
        from services import tls as tls_util
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"身份模块不可用：{e}")

    hostname = (data.get("hostname") or "unknown").strip()
    client_host = request.client.host if request.client else ""
    ip = _best_agent_ip(data.get("ip_address", ""), client_host)
    node_id = str(data.get("node_id") or "").strip()
    # 方案 A：直接收**公钥 PEM**（不是 CSR）。私钥永远不出本机，公钥登记在服务端，
    # 之后每次请求用它验签。兼容：老 Agent 发 `csr` 来的话也能取出同一把公钥。
    pub_pem = str(data.get("pub_key_pem") or "").strip()
    _legacy_csr = str(data.get("csr") or "").strip()
    if not pub_pem and _legacy_csr:
        try:
            from cryptography import x509 as _x
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat)

            pub_pem = _x.load_pem_x509_csr(_legacy_csr.encode("utf-8")).public_key(
            ).public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        except Exception:  # noqa: BLE001  解析不了就当没带，下面会给出明确原因
            pub_pem = ""
    mfp = str(data.get("machine_fingerprint") or "").strip()

    if not node_id or not node_id.startswith("vnode-") or len(node_id) > 64:
        raise HTTPException(status_code=400, detail="缺少合法的 node_id")
    if not hostname or len(hostname) < 3 or hostname.lower() == "test":
        raise HTTPException(status_code=400, detail="Invalid hostname")

    server = None
    agent_key = db.query(AgentKey).filter(AgentKey.node_id == node_id).first()
    if agent_key:
        server = db.query(Server).filter(Server.id == agent_key.server_id).first()
        if not server:
            db.delete(agent_key)
            db.flush()
            agent_key = None

    name_conflict_with = None
    if server is None:
        # ── 兼容升级：Agent 手里还有旧的 server_id + 遗留 token，直接认主，
        #    不必再走一次 IP / 主机名匹配（那正是我们想摆脱的东西）。
        known_server_id = data.get("server_id")
        known_token = data.get("token")
        if known_server_id and known_token:
            try:
                server = _verify_auth(int(known_server_id), known_token, db)
            except Exception:  # noqa: BLE001
                server = None
            if server:
                agent_key = db.query(AgentKey).filter(
                    AgentKey.server_id == server.id).first()

        #    用机器指纹把还在队列里那条旧记录接住，避免队列里堆同一台机的副本。
        if server is None and mfp:
            reuse = (
                db.query(AgentKey, Server)
                .join(Server, Server.id == AgentKey.server_id)
                .filter(
                    AgentKey.machine_fingerprint == mfp,
                    AgentKey.node_id != node_id,
                    Server.protocol == "agent",
                    Server.status == "registered",
                )
                .order_by(Server.created_at.asc())
                .first()
            )
            if reuse:
                old_key, old_server = reuse
                server = old_server
                agent_key = old_key
                logger.warning(
                    f"检测到同一台机器（指纹 {mfp[:12]}…）重装后重新入户："
                    f"接管待审核记录 server_id={server.id}，旧 node_id={old_key.node_id} → {node_id}"
                )
                old_key.node_id = node_id
                old_key.revoked = 0
                old_key.revoked_at = None
                old_key.revoked_reason = ""

        if server is None:
            # ── 全新条目：走 S0 队列防护（这一支才是零鉴权写入点）
            if _register_too_frequent(client_host or ip):
                raise HTTPException(status_code=429, detail="注册过于频繁，请稍后再试")
            _cleanup_pending(db)
            if _pending_ip_count(db, ip) >= _PENDING_PER_IP_LIMIT:
                raise HTTPException(
                    status_code=429,
                    detail=f"该来源 IP 的待审核条目已达上限（{_PENDING_PER_IP_LIMIT} 条），请先处理已有条目",
                )
            hostname, name_conflict_with = _unique_server_name(db, hostname)
            now = datetime.now(timezone.utc)
            extra_cfg = {"computer_name": data.get("hostname") or hostname}
            if data.get("cpu_model"):
                extra_cfg["cpu_model"] = data["cpu_model"]
            if data.get("os_version"):
                extra_cfg["os_version"] = data["os_version"]
            if name_conflict_with:
                extra_cfg["name_conflict_with"] = name_conflict_with
            server = Server(
                name=hostname,
                ip_address=ip,
                protocol="agent",
                network_env="内网",
                status="registered",
                os_type=data.get("os_type", ""),
                cpu_cores=data.get("cpu_cores", 0),
                total_memory_gb=data.get("total_memory_gb", 0.0),
                total_disk_gb=round(sum(p.get("total_gb", 0) for p in data.get("disk_partitions", [])), 1),
                disk_partitions=data.get("disk_partitions", []),
                business_system=data.get("business_system", ""),
                extra_config=extra_cfg,
                agent_port=int(data["api_port"]) if data.get("api_port") else 9998,
                install_path=str(data.get("install_path", ""))[:300],
                mesh_node_id=str(data.get("mesh_node_id", ""))[:64],
            )
            db.add(server)
            db.flush()

            # 批量部署场景不想一台台点「加入管理」。开了之后新入户的设备直接置为
            # 已纳管，下一个周期就能拿到证书。
            # ⚠ 只对**全新**条目生效：被吊销过的机器不能靠这个开关自己回来，
            #   那等于给了一条绕过吊销的后门。
            # ⚠ 默认 0。置 1 意味着任何能连到本服务端的机器都能领到证书。
            _auto = False
            try:
                from models import GlobalConfig

                _row = db.query(GlobalConfig).filter(
                    GlobalConfig.key == "auto_approve").first()
                _auto = str((_row.value if _row else "0") or "0").strip() == "1"
            except Exception as _e:  # noqa: BLE001
                logger.warning(f"读取 auto_approve 配置失败，按关闭处理：{_e}")

            if _auto:
                _now = datetime.now(timezone.utc)
                server.status = "monitored"
                server.join_time = _now
                # 🚨 `online_time` 刻意**不写**（口径同 routes/servers.py::
                #    _apply_status_change）。它被纳管是"管理员准入"这个人工动作，
                #    不代表主机此刻已经上线；上线时刻由 _record_agent_online
                #    在真正收到心跳时写入（本次 enroll 之后的心跳就会填上）。
                db.flush()
                logger.warning(
                    f"[auto_approve] 新设备免审批直接纳管：name={hostname} ip={ip} "
                    f"node_id={node_id} 来源={client_host}"
                )
                try:
                    from services.audit_logger import log_operation

                    log_operation(
                        db,
                        category="identity",
                        action="auto_approve",
                        level="warning",
                        # 注意：warning 是「这事值得你知道」，不是「操作失败了」——
                        # 设备确实已免审批纳管成功，所以 status 是 success。
                        status="success",
                        message=f"auto_approve 已开启：设备 {hostname}（{ip}）免人工审批直接纳管",
                        target_type="server",
                        target_id=str(server.id),
                        details={"node_id": node_id, "source": client_host},
                    )
                except Exception:  # noqa: BLE001
                    pass
            else:
                logger.info(
                    f"新设备入户待审核：name={hostname} ip={ip} node_id={node_id} "
                    f"来源={client_host}（等待管理员在「注册管理」批准）"
                )

    if agent_key is None:
        agent_key = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
    if agent_key is None:
        agent_key = AgentKey(server_id=server.id, secret_key=os.urandom(16).hex())
        db.add(agent_key)
        db.flush()

    if not agent_key.node_id:
        agent_key.node_id = node_id
    if mfp and agent_key.machine_fingerprint != mfp:
        agent_key.machine_fingerprint = mfp
    if not agent_key.pairing_code:
        agent_key.pairing_code = aid.new_pairing_code()
    if agent_key.identity_state in ("", "none"):
        agent_key.identity_state = "pending"

    # 心跳那条路径覆盖不了「还没批准、还没心跳」的窗口，这里补一次。
    # 两边共用同一份基线，先到的那次把基线写进去，后到的自然比出 L0。
    _parts = data.get("fingerprint_parts")
    if isinstance(_parts, dict) and _parts:
        try:
            from services import drift as _drift

            _res = _drift.apply_drift(db, server, agent_key, _parts, cur_ip=ip,
                                      prev_ip=server.ip_address or "")
            if _res and _res.get("level") != "L0":
                logger.info(
                    f"属性漂移 {_res['level']}（入户）：server_id={server.id} "
                    f"{server.name} —— {_res['detail']}"
                )
        except Exception as _e:  # noqa: BLE001  漂移检测失败不能挡住入户
            logger.warning(f"入户漂移分级失败 server_id={server.id}：{_e}")

    # 已有主机：同步硬件 / 端口 / 安装路径（与 /register 保持一致的行为）
    if data.get("os_type"):
        server.os_type = data["os_type"]
    if data.get("cpu_cores"):
        server.cpu_cores = data["cpu_cores"]
    if data.get("total_memory_gb"):
        server.total_memory_gb = data["total_memory_gb"]
    if data.get("disk_partitions"):
        server.disk_partitions = data["disk_partitions"]
        server.total_disk_gb = round(sum(p["total_gb"] for p in data["disk_partitions"]), 1)
    if data.get("cpu_model"):
        _store_cpu_model(server, data["cpu_model"])
    if data.get("api_port"):
        try:
            server.agent_port = int(data["api_port"])
        except (ValueError, TypeError):
            pass
    if data.get("install_path"):
        server.install_path = str(data["install_path"])[:300]
    if data.get("mesh_node_id"):
        server.mesh_node_id = str(data["mesh_node_id"])[:64]
    if data.get("hostname") or data.get("os_version"):
        if not server.extra_config:
            server.extra_config = {}
        if data.get("hostname") and not server.extra_config.get("computer_name"):
            server.extra_config["computer_name"] = data["hostname"]
        if data.get("os_version") and not server.extra_config.get("os_version"):
            server.extra_config["os_version"] = data["os_version"]
        flag_modified(server, "extra_config")

    now = datetime.now(timezone.utc)
    _record_agent_online(server, now, db)

    approved = server.join_time is not None
    if approved and agent_key.identity_state in ("none", "pending"):
        # 方案 A：批准即授权。真正让设备能通信的是下面登记 pub_key 那一步，
        # 这里只是把状态提前标出来，好让注册管理页能显示"已批准、待首次入户登记"。
        agent_key.identity_state = "approved"

    # ── 登记公钥（方案 A：身份就这一把公钥，不再签发证书）────────────
    # 以前这里要解 CSR、调 CA 签一张 90 天的客户端证书、还要判「是不是同一把公钥
    # 在续期」「剩余有效期够不够」。现在只做一件事：把这把公钥记下来。
    #
    # 为什么换公钥仍要走吊销重来（下面那条判断没删）：
    #   偷到 node_id 的人只要送一把**自己的**公钥来，就能把真机挤下线。所以一旦
    #   登记过，只接受同一把公钥重复登记（重装 / 重新入户时是正常的），换锁必须
    #   管理员先吊销。这条是身份体系的地基，与用不用证书无关。
    issue_error = ""
    _registered_now = False
    if not pub_pem:
        issue_error = "缺少公钥（pub_key_pem）"
    elif agent_key.revoked:
        issue_error = "该设备已被吊销，不允许登记"
    else:
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, load_pem_public_key)

            new_pub = load_pem_public_key(pub_pem.encode("utf-8"))
            spki = new_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        except Exception as e:  # noqa: BLE001
            issue_error = f"公钥无法解析：{str(e)[:120]}"
            spki = None

        if not issue_error:
            if agent_key.pub_key and agent_key.key_fingerprint != aid.pubkey_fingerprint(spki):
                issue_error = "公钥已更换，需先吊销该设备后重新入户"
            elif not approved:
                # 还没批准 → pub_key 先**不**登记。登记了就等于承认它的身份，
                # 而「上报数据」的闸门正是 pub_key。
                # 但公钥要**暂存**一份（pending_pub_key）：未准入设备的心跳需要
                # 它来验签，否则 `last_seen` 永远是空、主机一直显示离线 ——
                # 在线是"网络连通"的事实，不该被"是否已加入管理"拖住。
                agent_key.pending_pub_key = new_pub.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
                issue_error = "主机尚未加入管理，请管理员在「主机管理」中加入管理并核对配对码"
            else:
                agent_key.pub_key = new_pub.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
                agent_key.pending_pub_key = ""
                agent_key.key_fingerprint = aid.pubkey_fingerprint(spki)
                agent_key.identity_state = "authorized"
                agent_key.auth_mode = "pubkey"
                agent_key.revoked = 0
                agent_key.revoked_at = None
                agent_key.revoked_reason = ""
                _registered_now = True
                logger.info(
                    f"已为 server_id={server.id} node_id={node_id} 登记设备公钥"
                    f"（指纹 {agent_key.key_fingerprint[:16]}…）"
                )

    db.commit()
    token = hmac.new(agent_key.secret_key.encode(), str(server.id).encode(), "sha256").hexdigest()

    # P1-1：Agent 9998 的服务器证书（传输层，与设备身份是两件事 —— 它让服务端
    # 回调时能走真正的 TLS，而不是"信任何证书"）。失败不影响入户流程。
    api_cert_out = _maybe_issue_api_cert(db, agent_key, server, data)

    # 🚨 配对码要不要回给 Agent，看的是**这台设备登记过公钥没有**，而不是这次
    #    有没有登记。按「本次没登记就给」写，已经准入的机器每次入户都会收到
    #    配对码，Agent 面板于是长期停在"本机配对码"上，看着像一直没批准。
    #    再排除一种情形：**被吊销**。吊销时 `pub_key` 是刻意保留的（审计要留痕，
    #    且吊销靠 `revoked` 标记生效），若只看 pub_key，设备吊销后重新入户时
    #    配对码照样不回，管理员就没法核对"重来的这台"是不是同一台机器。
    _authorized = bool(agent_key.pub_key) and not agent_key.revoked

    from services.agent_auth import compute_update_key
    return {
        "server_id": server.id,
        # ⚠ 这个 token **只用于服务端回调本机 9998**（下行）；上行认证一律用私钥
        # 签名，token 不能当身份用（方案 A，见 _authenticate 的说明）。
        "token": token,
        # 2026-09-23 开源加固 ④：更新包验签密钥（与 token 分离，见 agent_auth 的说明）
        "update_key": compute_update_key(agent_key.secret_key, server.id),
        "node_id": agent_key.node_id,
        # 🚨 `enrolled` 是**本次有没有登记成功**，不是"这台设备有没有授权过"。
        #    两者混为一谈会有实际后果：换公钥被拒时，设备本来已授权 → 按后者写会
        #    回 enrolled=True，Agent 于是以为自己通过了，其实服务端刚刚拒绝了它。
        #    设备是否已授权看 `identity_state` / 有没有 pairing_code。
        "enrolled": _registered_now,
        "identity_state": agent_key.identity_state,
        # 登记过公钥就永远不再往网络上回配对码 —— 它只在人工比对那一次有用
        "pairing_code": agent_key.pairing_code if not _authorized else "",
        "issue_error": issue_error,
        "status": server.status,
        "name_conflict": bool(name_conflict_with),
        **api_cert_out,
    }


@router.post("/push")
def agent_push(request: Request, data: dict, db: Session = Depends(get_db)):
    """Receive metrics from agent."""
    import time
    start_ts = time.time()
    client_host = request.client.host if request.client else "unknown"

    server, auth_info = _authenticate(request, db)
    if not server:
        # 把原因说出来：排障时"Invalid credentials"四个字分不清是证书过期、
        # 时钟偏差还是有人冒用。这里不涉及凭据本身，泄露风险可忽略。
        raise HTTPException(status_code=401, detail=f"认证失败：{auth_info}")
    server_id = server.id
    # 每 60 秒 × 每台主机都会来一次，用 debug：开着它排查接入问题时再调级别
    logger.debug(f"[Push] request from {client_host} for server_id={server_id} auth={auth_info}")


    now = datetime.now(timezone.utc)
    _record_agent_online(server, now, db)
    # stays accurate even when the agent only pushes metrics.
    server.last_seen = now
    if data.get("api_port"):
        try:
            server.agent_port = int(data["api_port"])
        except (ValueError, TypeError):
            pass

    if "metrics" in data:
        m = data["metrics"]
        ts = datetime.fromisoformat(m.get("timestamp", datetime.now(timezone.utc).isoformat()))
        snapshot = MetricSnapshot(
            server_id=server.id,
            timestamp=ts,
            cpu_percent=m.get("cpu_percent", 0),
            memory_percent=m.get("memory_percent", 0),
            memory_used_gb=m.get("memory_used_gb"),
            disk_percent=m.get("disk_percent", 0),
            disk_used_gb=m.get("disk_used_gb"),
            network_in_mbps=m.get("network_in_mbps", 0),
            network_out_mbps=m.get("network_out_mbps", 0),
            disk_io_read_mbps=m.get("disk_io_read_mbps", 0),
            disk_io_write_mbps=m.get("disk_io_write_mbps", 0),
            tcp_connections=m.get("tcp_connections", 0),
        )
        db.add(snapshot)

        if m.get("total_memory_gb"):
            server.total_memory_gb = m["total_memory_gb"]
        if m.get("cpu_cores"):
            server.cpu_cores = m["cpu_cores"]

    stored = server.extra_config or {}
    if not isinstance(stored, dict):
        stored = {}

    service_filter = stored.get("service_filter") or {}

    def _history_key(sm_or_rp: dict) -> str:
        """Stable key for matching a process across agent pushes."""
        pid = int(sm_or_rp.get("pid") or 0)
        name = (sm_or_rp.get("image_name") or sm_or_rp.get("process_name") or sm_or_rp.get("name") or "").lower().replace(".exe", "")
        return f"{pid}_{name}"

    def _build_history_point(sm: dict) -> dict:
        """Extract a single metric sample for sparkline history."""
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "cpu_percent": round(float(sm.get("cpu_percent", 0) or 0), 1),
            "memory_percent": round(float(sm.get("memory_percent", 0) or 0), 2),
            "disk_read_mbps": round(float(sm.get("disk_read_mbps", 0) or 0), 3),
            "disk_write_mbps": round(float(sm.get("disk_write_mbps", 0) or 0), 3),
            "disk_mbps": round(float(sm.get("disk_mbps", 0) or 0), 3),
            "network_in_mbps": round(float(sm.get("network_in_mbps", 0) or 0), 3),
            "network_out_mbps": round(float(sm.get("network_out_mbps", 0) or 0), 3),
            "network_mbps": round(float(sm.get("network_mbps", 0) or 0), 3),
        }

    existing_pending = stored.get("pending_services") or []
    existing_history: dict[str, list[dict]] = {}
    if isinstance(existing_pending, list):
        for ep in existing_pending:
            key = _history_key(ep)
            hist = ep.get("history")
            if isinstance(hist, list) and hist:
                existing_history[key] = hist

    if "service_metrics" in data:
        pending = []
        for sm in data["service_metrics"]:
            proc_name = (sm.get("name") or sm.get("image_name") or sm.get("process_name") or "").lower().replace(".exe", "")
            if proc_name in ("system idle process", "idle", "system", "registry"):
                continue
            image_name = sm.get("image_name") or sm.get("process_name") or sm.get("name") or "unknown"
            cls = _server_classify(
                image_name,
                sm.get("category"),
                sm.get("is_system"),
                sm.get("detailed_category"),
                sm.get("operation_level"),
            )
            key = _history_key(sm)
            hist = existing_history.get(key) or []
            hist.append(_build_history_point(sm))
            hist = hist[-30:]
            pending.append({
                "id": f"svc_{sm.get('pid', 0)}_{sm.get('name', 'unknown')}",
                "name": sm.get("name") or image_name,
                "display_name": sm.get("name") or image_name,
                "image_name": image_name,
                "process_name": sm.get("process_name") or image_name,
                "port": sm.get("port", 0),
                "pid": sm.get("pid", 0),
                "ppid": sm.get("ppid", 0),
                "path": sm.get("path", ""),
                "description": "",
                "status": sm.get("status") or sm.get("alive_status") or "unknown",
                "alive_status": sm.get("alive_status") or sm.get("status") or "unknown",
                "cpu_percent": sm.get("cpu_percent", 0),
                "memory_percent": sm.get("memory_percent", 0),
                "memory_used_mb": sm.get("memory_used_mb", 0),
                "disk_mbps": sm.get("disk_mbps", 0),
                "disk_read_mbps": sm.get("disk_read_mbps", 0),
                "disk_write_mbps": sm.get("disk_write_mbps", 0),
                "network_mbps": sm.get("network_mbps", 0),
                "network_in_mbps": sm.get("network_in_mbps", 0),
                "network_out_mbps": sm.get("network_out_mbps", 0),
                "alert_status": sm.get("alert_status", "normal"),
                "category": cls["category"],
                "is_system": cls["is_system"],
                "detailed_category": cls["detailed_category"],
                "operation_level": cls["operation_level"],
                "check_type": "process",
                "start_time": sm.get("start_time", ""),
                "cmdline": sm.get("cmdline", ""),
                "username": sm.get("username", ""),
                "has_visible_window": bool(sm.get("has_visible_window", False)),
                "app_instance_id": sm.get("app_instance_id", image_name),
                "history": hist,
            })
        stored["pending_services"] = pending
        stored["agent_version"] = data.get("agent_version", "")
        server.extra_config = stored
        flag_modified(server, "extra_config")
        _store_cpu_model(server, data.get("cpu_model", ""))
        logger.debug(f"[Push] Stored {len(pending)} pending services from service_metrics for server {server.id}")
    elif "services" in data:
        pending = []
        for svc in data["services"]:
            pending.append({
                "id": f"pending_{svc.get('name', 'svc')}_{svc.get('port', 0)}",
                "name": svc.get("display_name", svc.get("name", "unknown")),
                "port": svc.get("port", 0),
                "process_name": svc.get("process_name", svc.get("display_name", "")),
                "pid": svc.get("pid"),
                "path": svc.get("path", ""),
                "description": svc.get("description", ""),
                "status": svc.get("status", "unknown"),
                "check_type": svc.get("check_type", "tcp" if svc.get("port") else "process"),
            })
        stored["pending_services"] = pending
        stored["agent_version"] = data.get("agent_version", "")
        server.extra_config = stored
        flag_modified(server, "extra_config")
        _store_cpu_model(server, data.get("cpu_model", ""))
        logger.debug(f"[Push] Stored {len(pending)} pending services for server {server.id}")

    if "dangerous_ports" in data:
        stored = server.extra_config or {}
        if not isinstance(stored, dict):
            stored = {}
        dports = []
        for dp in data["dangerous_ports"]:
            dports.append({
                "id": f"dport_{dp.get('port')}",
                "name": dp.get("display_name", dp.get("name", "")),
                "port": dp.get("port", 0),
                "process_name": dp.get("process_name", ""),
                "pid": dp.get("pid"),
                "description": dp.get("description", ""),
                "status": dp.get("status", "open"),
                "check_type": "dangerous_port",
            })
        stored["dangerous_ports"] = dports
        server.extra_config = stored
        flag_modified(server, "extra_config")
        logger.debug(f"[Push] Stored {len(dports)} dangerous ports for server {server.id}")

    if "raw_processes" in data:
        stored = server.extra_config or {}
        if not isinstance(stored, dict):
            stored = {}
        raw = data["raw_processes"]
        if isinstance(raw, list):
            stored["raw_processes"] = raw
            stored["raw_processes_count"] = len(raw)
            stored["raw_processes_updated_at"] = datetime.now(timezone.utc).isoformat()

            # an agent upgrade. Metrics default to 0 because raw_processes only
            # carries identity/status, not live counters.
            # Skip any PID already present in pending_services (service_metrics
            # carries live metrics and takes precedence).
            existing_ids = {p.get("id") for p in stored.get("pending_services", []) if p.get("id")}
            existing_pids = {int(p.get("pid") or 0) for p in stored.get("pending_services", []) if p.get("pid")}
            for rp in raw:
                name = rp.get("name") or rp.get("image_name") or "unknown"
                pid = int(rp.get("pid") or 0)
                item_id = f"raw_{pid}_{name}"
                if item_id in existing_ids or pid in existing_pids:
                    continue
                existing_ids.add(item_id)
                existing_pids.add(pid)
                cls = _server_classify(
                    name,
                    rp.get("category"),
                    rp.get("is_system"),
                    rp.get("detailed_category"),
                    rp.get("operation_level"),
                )
                stored.setdefault("pending_services", []).append({
                    "id": item_id,
                    "name": name.replace(".exe", ""),
                    "display_name": name.replace(".exe", ""),
                    "image_name": name,
                    "process_name": rp.get("process_name") or name,
                    "port": int(rp.get("port") or 0),
                    "pid": pid,
                    "ppid": int(rp.get("ppid") or 0),
                    "path": rp.get("path", ""),
                    "description": "",
                    "status": rp.get("status") or "running",
                    "alive_status": rp.get("status") or "running",
                    "cpu_percent": 0,
                    "memory_percent": 0,
                    "memory_used_mb": 0,
                    "disk_mbps": 0,
                    "disk_read_mbps": 0,
                    "disk_write_mbps": 0,
                    "network_mbps": 0,
                    "network_in_mbps": 0,
                    "network_out_mbps": 0,
                    "alert_status": "normal",
                    "category": cls["category"],
                    "is_system": cls["is_system"],
                    "detailed_category": cls["detailed_category"],
                    "operation_level": cls["operation_level"],
                    "check_type": "process",
                    "start_time": rp.get("start_time", ""),
                    "cmdline": rp.get("cmdline", ""),
                    "username": rp.get("username", ""),
                    "history": [],
                })
            server.extra_config = stored
            flag_modified(server, "extra_config")
            logger.debug(f"[Push] Stored {len(raw)} raw processes for server {server.id}")

    # svchost.exe must NOT be used to mark every service with that process name
    # as running; port-based services are checked by port first.
    running_ports = set()
    running_procs = set()
    if "services" in data:
        for svc in data["services"]:
            if svc.get("port"):
                running_ports.add(str(svc["port"]))
            proc = svc.get("process_name", "") or svc.get("name", "")
            if proc:
                running_procs.add(proc.lower())
    if "dangerous_ports" in data:
        for dp in data["dangerous_ports"]:
            if dp.get("port"):
                running_ports.add(str(dp["port"]))
            proc = dp.get("process_name", "")
            if proc:
                running_procs.add(proc.lower())

    monitored = db.query(MonitoredService).filter(
        MonitoredService.server_id == server.id
    ).all()

    service_metric_map: dict[int, dict] = {}
    if "service_metrics" in data:
        for sm in data["service_metrics"]:
            sid = sm.get("service_id")
            if sid:
                service_metric_map[int(sid)] = sm

    def _service_metric_match(msvc: MonitoredService) -> dict | None:
        """Find the service_metric entry matching a MonitoredService record."""
        sm = service_metric_map.get(msvc.id)
        if sm:
            return sm
        msvc_names = {
            (msvc.name or "").lower().replace(".exe", ""),
            (msvc.image_name or "").lower().replace(".exe", ""),
            (msvc.process_name or "").lower().replace(".exe", ""),
        }
        for cand in data.get("service_metrics", []):
            cand_names = {
                cand.get("name", "").lower().replace(".exe", ""),
                cand.get("image_name", "").lower().replace(".exe", ""),
                cand.get("process_name", "").lower().replace(".exe", ""),
            }
            if msvc_names & cand_names:
                return cand
        return None

    for msvc in monitored:
        port = msvc.port or 0
        if port > 0:
            # Port-based service: exact port must be listening
            msvc.status = "running" if str(port) in running_ports else "stopped"
        else:
            proc_name = (msvc.process_name or msvc.name or "").lower()
            msvc.status = "running" if proc_name in running_procs else "stopped"

        sm = _service_metric_match(msvc)
        if sm:
            msvc.cpu_percent = sm.get("cpu_percent", 0)
            msvc.memory_percent = sm.get("memory_percent", 0)
            msvc.disk_mbps = sm.get("disk_mbps", 0)
            msvc.disk_read_mbps = sm.get("disk_read_mbps", 0)
            msvc.disk_write_mbps = sm.get("disk_write_mbps", 0)
            msvc.network_mbps = sm.get("network_mbps", 0)
            msvc.network_in_mbps = sm.get("network_in_mbps", 0)
            msvc.network_out_mbps = sm.get("network_out_mbps", 0)
            msvc.pid = int(sm.get("pid") or 0)
            msvc.ppid = int(sm.get("ppid") or 0)
            msvc.path = sm.get("path", "")
            msvc.start_time = sm.get("start_time", "") or ""
            msvc.cmdline = sm.get("cmdline", "") or ""
            msvc.username = sm.get("username", "") or ""
            if sm.get("alive_status"):
                msvc.alive_status = sm["alive_status"]
            if sm.get("status"):
                msvc.running_status = sm["status"]
                msvc.status = sm["status"]
            if msvc.running_status == "stopped" or msvc.alive_status == "stopped":
                msvc.alert_status = "critical"
            elif msvc.alive_status == "unknown":
                msvc.alert_status = "warning"
            else:
                msvc.alert_status = "normal"

        msvc.last_checked = datetime.now(timezone.utc)

    if "service_metrics" in data:
        existing_by_name = {}
        for msvc in monitored:
            key = (msvc.name or "").lower().replace(".exe", "")
            existing_by_name[key] = msvc
        for sm in data["service_metrics"]:
            key_name = (sm.get("name") or sm.get("image_name") or sm.get("process_name") or "").lower().replace(".exe", "")
            svc = existing_by_name.get(key_name)
            if svc:
                svc.pid = int(sm.get("pid") or 0)
                svc.ppid = int(sm.get("ppid") or 0)
                svc.cpu_percent = sm.get("cpu_percent", 0)
                svc.memory_percent = sm.get("memory_percent", 0)
                svc.disk_mbps = sm.get("disk_mbps", 0)
                svc.disk_read_mbps = sm.get("disk_read_mbps", 0)
                svc.disk_write_mbps = sm.get("disk_write_mbps", 0)
                svc.network_mbps = sm.get("network_mbps", 0)
                svc.network_in_mbps = sm.get("network_in_mbps", 0)
                svc.network_out_mbps = sm.get("network_out_mbps", 0)
                svc.path = sm.get("path", "")
                svc.start_time = sm.get("start_time", "") or ""
                svc.cmdline = sm.get("cmdline", "") or ""
                svc.username = sm.get("username", "") or ""
                svc.alive_status = sm.get("alive_status") or sm.get("status") or "running"
                svc.running_status = sm.get("status") or sm.get("alive_status") or "running"
                svc.status = sm.get("status") or sm.get("alive_status") or "running"
                svc.alert_status = sm.get("alert_status", "normal")
                svc.last_checked = datetime.now(timezone.utc)

    if data.get("disk_partitions"):
        server.disk_partitions = data["disk_partitions"]
        server.total_disk_gb = round(sum(p.get("total_gb", 0) for p in data["disk_partitions"]), 1)

    if data.get("os_type"):
        server.os_type = data["os_type"]

    if data.get("cpu_model"):
        _store_cpu_model(server, data["cpu_model"])

    if data.get("hostname") or data.get("os_version"):
        if not server.extra_config:
            server.extra_config = {}
        if data.get("hostname"):
            server.extra_config["computer_name"] = data["hostname"]
        if data.get("os_version"):
            server.extra_config["os_version"] = data["os_version"]
        flag_modified(server, "extra_config")

    if "terminate_results" in data and server.extra_config:
        done_ids = {r.get("id") for r in data["terminate_results"] if r.get("id")}
        pending = server.extra_config.get("pending_terminate") or []
        if isinstance(pending, list):
            pending = [p for p in pending if p.get("id") not in done_ids]
            server.extra_config["pending_terminate"] = pending
            flag_modified(server, "extra_config")
        reported_at = datetime.now(timezone.utc).isoformat()
        history = server.extra_config.get("last_terminate_results") or []
        if not isinstance(history, list):
            history = []
        for r in data["terminate_results"]:
            history.append({**r, "reported_at": reported_at})
        server.extra_config["last_terminate_results"] = history[-100:]
        flag_modified(server, "extra_config")

    if server.extra_config and server.extra_config.get("trigger_collect_at"):
        server.extra_config["trigger_collect_at"] = None
        flag_modified(server, "extra_config")

    db.commit()
    elapsed = round(time.time() - start_ts, 3)
    svc_count = len(data.get("service_metrics", []))
    logger.debug(f"[Push] server={server.id} services={svc_count} duration={elapsed}s")
    return {"status": "ok", "server_id": server.id}


@router.post("/heartbeat")
def agent_heartbeat(request: Request, data: dict, db: Session = Depends(get_db)):
    """Agent keepalive — returns 200 if authenticated.

    ⚠ 这是**唯一**允许未准入设备通过的接口（`allow_pending=True`）：`last_seen`
    只在这里更新，而它就是"在线"的唯一依据。未准入 ≠ 没连上，两者不能混为一谈。
    """
    server, auth_mode = _authenticate(request, db, allow_pending=True)
    if not server:
        raise HTTPException(status_code=401, detail=f"认证失败：{auth_mode}")
    # 未准入 = 还没加入管理。只有准入的设备才发凭据、上报数据、参与完整性比对。
    _authorized = auth_mode == "pubkey"

    client_host = request.client.host if request.client else ""
    agent_ip = _best_agent_ip(data.get("ip_address", ""), client_host)
    prev_ip = server.ip_address or ""
    if agent_ip and server.ip_address and server.ip_address != agent_ip:
        # 🚨 换了 IP **一律只更新、不拒绝** —— IP 只是联络地址，不是身份
        # （NAT / DHCP 换址 / 多网卡选中另一个 / 搬机房 / 上云都会变）。
        # 这条日志将来就是 L1 漂移的证据。
        #
        # 改之前这里对**非证书**通道是硬拒 401「IP mismatch」，理由是防「拷贝安装
        # 配置指向别的主机」。但它其实挡不住：`ip_address` 是 Agent 在 payload 里
        # 自己填的字段，真要冒充照填就行 —— 一笔**防不住攻击者、只误伤正常机器**
        # 的账。而误伤是硬的：心跳 401 → Agent 清空本地注册 → 重新注册 → 再 401，
        # 界面上就是「注册成功几秒后又变回未注册」，服务端一直离线。
        #
        # 真正的防冒充不靠 IP，靠身份本身：证书通道用私钥签名（私钥不出本机，
        # 抄走配置文件也没用），以及「已发证设备不许退回静态 token」（加固 ⑤）。
        # 这两条都没动。
        # ⚠ 服务端回调本机 9998 用的也是 `server.ip_address`，不更新的话回调会打
        #   到旧地址上 —— 所以这里必须写回。
        logger.info(
            f"来源 IP 变化但设备身份未变：server_id={server.id} "
            f"{server.ip_address} -> {agent_ip}（已更新，认证方式={auth_mode}）"
        )
        server.ip_address = agent_ip

    if data.get("api_port"):
        try:
            server.agent_port = int(data["api_port"])
        except (ValueError, TypeError):
            pass

    if data.get("install_path"):
        server.install_path = str(data["install_path"])[:300]

    # 启动之后才装好，注册时还没 ID。only overwrite with a non-empty value.
    if data.get("mesh_node_id"):
        server.mesh_node_id = str(data["mesh_node_id"])[:64]

    # 心跳是唯一 5 秒一次都走的通道，换 IP / 换主板只能靠它发现。
    # 老版本 Agent 不带 fingerprint_parts，这里直接跳过 —— 等它升级后第一次
    # 上报会自动登记基线，不会误报。
    # ⚠ 只对**已准入**的设备做：未准入的机器还没被承认，给它记基线、发漂移告警
    #   只是噪音，取不到任何安全收益。
    _parts = data.get("fingerprint_parts")
    if _authorized and isinstance(_parts, dict) and _parts:
        try:
            from services import drift as _drift

            _key = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
            if _key is not None:
                _res = _drift.apply_drift(db, server, _key, _parts,
                                          cur_ip=agent_ip, prev_ip=prev_ip)
                if _res and _res.get("level") != "L0":
                    logger.info(
                        f"属性漂移 {_res['level']}：server_id={server.id} "
                        f"{server.name} —— {_res['detail']}"
                    )
        except Exception as _e:  # noqa: BLE001  漂移检测失败绝不能影响存活上报
            logger.warning(f"漂移分级失败 server_id={server.id}：{_e}")

    # ── 开源加固 ⑥：Agent 代码完整性比对（对标 MeshCentral agentTampering）──
    # 开源之后最现实的威胁不是"读代码"，而是有人改几行再重新打包，伪装成官方
    # Agent 接进来 —— 界面上和正常机器一模一样，版本号也还是那个号。
    # 这里让它自报代码指纹，跟基线比；对不上就记审计 + 打标，管理员能在日志里看到。
    try:
        _digest = str(data.get("self_digest") or "").strip()
        _ver = str(data.get("agent_version") or "").strip()
        _hb_key2 = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
        if _authorized and _digest and _hb_key2 is not None:
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
            if not _hb_key2.self_digest:
                # 首次：登记基线（不做任何判断 —— 没法证明第一台就是干净的）
                _hb_key2.self_digest = _digest
                _hb_key2.self_digest_version = _ver
                _hb_key2.self_digest_at = now_naive
                logger.info(f"server_id={server.id} 已登记 Agent 完整性基线 "
                            f"（{data.get('self_digest_files', '?')} 个文件，模式 "
                            f"{data.get('self_digest_mode', '?')}）")
            elif _ver and _ver != (_hb_key2.self_digest_version or ""):
                # 版本变了 —— 合法升级，顺手把基线挪到新版本上，避免每次升级都误报
                _hb_key2.self_digest = _digest
                _hb_key2.self_digest_version = _ver
                _hb_key2.self_digest_at = now_naive
                _hb_key2.tamper_at = None
                _hb_key2.tamper_detail = ""
                logger.info(f"server_id={server.id} Agent 升级到 {_ver}，完整性基线已更新")
            elif _digest != _hb_key2.self_digest:
                # 版本没变、指纹却变了 —— 有人在没走升级流程的情况下换了代码
                _hb_key2.tamper_at = now_naive
                _hb_key2.tamper_detail = (
                    f"版本 {_ver or '(未知)'} 的 Agent 代码指纹与基线不符"
                )
                logger.warning(
                    f"🚨 server_id={server.id} {server.name} 疑似被改造："
                    f"基线 {_hb_key2.self_digest[:16]}… 实测 {_digest[:16]}…"
                )
                from services.audit_logger import log_operation
                log_operation(
                    db, category="security", action="agent_tamper_suspected",
                    level="warning", status="failed",
                    target_type="server", target_id=str(server.id),
                    message=f"主机 {server.name} 的 Agent 代码指纹与基线不符，疑似被改造",
                    details={"server_name": server.name,
                             "baseline": _hb_key2.self_digest, "reported": _digest,
                             "version": _ver,
                             "files": data.get("self_digest_files"),
                             "mode": data.get("self_digest_mode")},
                )
    except Exception as _e:  # noqa: BLE001  完整性自检绝不能影响存活上报
        logger.warning(f"完整性比对失败 server_id={server.id}：{_e}")

    now = datetime.now(timezone.utc)
    _record_agent_online(server, now, db)
    server.last_seen = now
    db.commit()

    # 1.1.38：心跳领证双通道 —— 1.1.51 存量主机客户端证书仍有效，
    # ensure_certificate 不再触发 enroll，api_csr 永不上送，Agent 9998 只能
    # 跑自签证书，服务端 CA 校验拒绝一切回调（推送升级 / 资源管理器 / 远程桌面）。
    # 心跳是唯一每 5 秒必到的通道，在这里补签即可，Agent 侧响应落盘后自动热切换。
    api_cert_out = {}
    _hb_key = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
    # ⚠ 只有**已准入**的设备才发凭据：未准入的能心跳（只为显示在线），
    #   但不该拿到 9998 的服务器证书、也不该领 update_key / 新 token。
    if _hb_key is not None and _authorized:
        if str(data.get("api_csr") or "").strip():
            api_cert_out = _maybe_issue_api_cert(db, _hb_key, server, data)
        # 2026-09-23 开源加固 ④：存量 Agent 是在旧版本注册上来的，手里只有 token、
        # 没有 update_key，而"推送升级"恰好是它们拿到新包的唯一途径 —— 不补发就永远
        # 升不了级。只在 Agent 显式要一次时下发（它拿到后会落盘，之后不再请求）。
        if data.get("need_update_key"):
            from services.agent_auth import compute_update_key
            api_cert_out["update_key"] = compute_update_key(_hb_key.secret_key, server.id)

        # 开源加固 ⑤：这台还在用**轮换前**的旧 token → 把新 token 交给它。
        # 只在宽限期内发生一次：Agent 收下并落盘后，下一次心跳就带着新 token 来了。
        # 没有这一步，管理员一点轮换，所有跑在外的 Agent 就集体失联。
        from services.agent_auth import match_agent_token, compute_agent_token
        if match_agent_token(_hb_key, server.id,
                             request.headers.get("X-Auth-Token", "")) == "prev":
            api_cert_out["token"] = compute_agent_token(_hb_key.secret_key, server.id)
            logger.info(f"server_id={server.id} 已领取轮换后的新 token")
    # `authorized=True`（公钥已登记）时 Agent 才会上报数据。未准入的机器心跳能通、
    # 界面显示在线，但 /push 会被拒 —— Agent 靠这个字段提前知道"现在不该推"，
    # 免得每 60 秒在日志里刷一条无意义的"推送失败"、托盘图标还变红。
    return {"status": "ok", "ip_address": server.ip_address,
            "authorized": _authorized, **api_cert_out}


@router.post("/uninstall-report")
def agent_uninstall_report(request: Request, data: dict, db: Session = Depends(get_db)):
    """Agent 卸载上报 —— 让服务端**当场**知道这台机器上的 Agent 已经没了。

    Agent 卸载时会问一句「是否删除本机配置」，两种答案对应的结局完全不同，
    服务端必须分开处理（用户 2026-09-28 提的三条场景）：

      ┌ 场景 1：已注册、**未加入管理**，卸载且删配置
      │   → 置离线。「加入管理」按钮置灰（前端规则：未纳管且离线时禁用）。
      ├ 场景 2：已注册、已加入管理并在线，卸载**不删**配置
      │   → 保持纳管，只置离线。重装后心跳一到，状态自动回到 monitored。
      └ 场景 3：已注册、已加入管理并在线，卸载**且删**配置
          → 移出管理 + 置离线，「加入管理」按钮置灰。重装后是**一台新设备**
            （node_id 和私钥都随配置一起没了），要重新注册再由管理员加入管理。

    为什么必须有这条上报（而不是等心跳超时）：
      在线判定依赖 `last_seen`，而它只在心跳里更新。Agent 没了之后要等
      「采集周期 × 2.5」才判离线，这期间主机列表上它还是绿的，管理员点
      「加入管理」/ 打开详情页看到的都是假象。卸载是**确定事件**，不该靠
      超时去猜。

    为什么 `allow_pending=True`：场景 1 的主机尚未加入管理，库里只有
    `pending_pub_key`，没有 `pub_key`。不给它放行，最需要这条上报的那一类
    主机反而报不上来。⚠ 放行的是"用暂存公钥验签"，不是免鉴权 —— 与心跳
    同一道闸，没有私钥照样 401，不会因为多了这个接口就多出一条口子。

    为什么删配置要连设备身份一起清：私钥和 node_id 都存在 CONFIG_DIR 里
    （`agent/identity.py` 顶部写了路径），配置一删它们就**永久消失**了，
    重装出来的是另一个 node_id。服务端这边要是留着旧的 node_id 和 pub_key：
      · `/enroll` 里 `if not agent_key.node_id` 不成立 → 新 node_id 永远
        登不上（1.1.49 修的就是这个死循环：注册成功几秒后又变回未注册）；
      · 旧的 `pub_key` 还挂着 → 界面显示"已加入管理"，而实际没有任何一台
        机器握着对应的私钥。
    """
    server, auth_mode = _authenticate(request, db, allow_pending=True)
    if not server:
        raise HTTPException(status_code=401, detail=f"认证失败：{auth_mode}")

    purge = bool(data.get("purge_config"))
    now = datetime.now(timezone.utc)
    was_managed = server.join_time is not None

    server.last_seen = None
    server.offline_time = now
    if was_managed:
        server.status = "offline"
    else:
        # 🚨 未加入管理的主机**不能**置 offline：
        #   · `services/collector.py` 每轮都会把 join_time 为空且状态是
        #     offline/online 的记录回滚成 registered（否则它会落进"受管状态"
        #     集合，管理员既删不掉也看不懂），置了也是白置，还会每轮刷日志；
        #   · 前端 `managedStatuses` 把 offline 算作受管 —— 界面会自己打架。
        #     它本来就是 registered，靠 last_seen 为空判离线即可。
        server.status = "registered"

    _k = db.query(AgentKey).filter(AgentKey.server_id == server.id).first()
    if purge and _k is not None:
        _k.node_id = ""
        _k.pub_key = ""
        _k.pending_pub_key = ""
        _k.key_fingerprint = ""
        _k.identity_state = "none"
        _k.auth_mode = "none"
        # ⚠ 下面这些**刻意保留**：
        #   · `secret_key` —— 9998 下行凭据与 update_key 都由它派生，重装后
        #     服务端还要回调这台机器，换了等于自断通路；
        #   · `pairing_code` —— 管理员重新准入时就是拿它跟 Agent 面板上的码
        #     对，换掉会让"核对配对码"这一步失去意义；
        #   · `self_digest` / `fingerprint_parts` —— 同一台物理机的基线与漂移
        #     记录，跟 Agent 装没装无关。
        # 移出管理：`join_time` 一空，状态回到 registered，主机列表里就不再是
        # 受管条目，「加入管理」按钮按前端新规则置灰。
        if was_managed:
            server.join_time = None
            server.status = "registered"

    db.commit()

    try:
        from services.audit_logger import log_operation
        log_operation(
            db, category="server", action="agent_uninstalled",
            level="warning" if purge else "info", status="success",
            target_type="server", target_id=str(server.id),
            message=(f"主机 {server.name} 的 Agent 已卸载"
                     f"（{'已清除本机配置，已移出管理' if purge else '保留配置'}）"),
            details={"server_name": server.name, "purge_config": purge,
                     "was_managed": was_managed, "auth_mode": auth_mode},
        )
    except Exception as _e:  # noqa: BLE001  记日志失败不能影响卸载上报
        logger.warning(f"卸载上报写审计失败 server_id={server.id}：{_e}")

    logger.info(
        f"Agent 卸载上报：server_id={server.id} {server.name} "
        f"purge={purge}（原{'已纳管' if was_managed else '未纳管'}，认证={auth_mode}）"
    )
    return {"status": "ok", "managed": False if purge else was_managed}


@router.post("/config")
def agent_get_config(request: Request, db: Session = Depends(get_db)):
    """Agent pulls its configuration from server."""
    server, _auth_mode = _authenticate(request, db)
    if not server:
        raise HTTPException(status_code=401, detail=f"认证失败：{_auth_mode}")
    server_id = server.id

    from routes.config import get_config_dict
    full_config = get_config_dict(db)
    monitored = db.query(MonitoredService).filter(
        MonitoredService.server_id == server_id
    ).all()
    monitored_services = [
        {
            "id": m.id,
            "name": m.name,
            "image_name": m.image_name or m.process_name or "",
            "process_name": m.process_name or "",
            "port": m.port or 0,
        }
        for m in monitored
    ]
    now = datetime.now(timezone.utc)
    _record_agent_online(server, now, db)
    server.last_seen = now
    db.commit()

    stored = server.extra_config or {}
    if not isinstance(stored, dict):
        stored = {}

    pending_terminate = stored.get("pending_terminate") or []
    if not isinstance(pending_terminate, list):
        pending_terminate = []
    service_blacklist = stored.get("service_blacklist") or []
    if not isinstance(service_blacklist, list):
        service_blacklist = []
    service_whitelist = stored.get("service_whitelist") or []
    if not isinstance(service_whitelist, list):
        service_whitelist = []

    return {
        "collect_interval": int(full_config.get("agent_collect_interval", {}).get("value", 60)),
        "cpu_threshold_warning": int(full_config.get("cpu_threshold_warning", {}).get("value", 80)),
        "cpu_threshold_critical": int(full_config.get("cpu_threshold_critical", {}).get("value", 95)),
        "memory_threshold_warning": int(full_config.get("memory_threshold_warning", {}).get("value", 85)),
        "memory_threshold_critical": int(full_config.get("memory_threshold_critical", {}).get("value", 95)),
        "disk_threshold_warning": int(full_config.get("disk_threshold_warning", {}).get("value", 85)),
        "disk_threshold_critical": int(full_config.get("disk_threshold_critical", {}).get("value", 95)),
        "monitored_services": monitored_services,
        "trigger_collect_at": stored.get("trigger_collect_at"),
        "pending_terminate": pending_terminate,
        "service_blacklist": service_blacklist,
        "service_whitelist": service_whitelist,
        "debug_push_processes": bool(stored.get("debug_push_processes")),
        "remote_desktop_active": rdp_session_active(server_id),
    }


def rdp_session_active(server_id: int) -> bool:
    """远程桌面会话是否活跃（观看端注册表，同进程内存态）。"""
    try:
        from services.rdp import session_active
        return session_active(server_id)
    except Exception:  # noqa: BLE001
        return False
