"""远程桌面路由（C 方案，自研 Guacamole 协议 hub）。

  * WS   /api/rdp/tunnel/{server_id}  —— 浏览器观看端（guacamole-common-js）
  * WS   /api/rdp/agent/{server_id}   —— VigilServe Agent 推流 / 接收控制指令
  * GET  /api/rdp/status/{server_id}  —— 连接前预检（Agent 是否可推流、当前用户是否有权限）
  * GET  /api/rdp/session/{server_id} —— 会话概览（谁在连、RTT、当前采集参数）
  * POST /api/rdp/settings/{server_id} —— 调整采集参数（fps / 画质 / 最大宽度）

安全策略（阶段 3，集中在 services/rdp 的常量里，勿散落各处）：
  * 观看端必须登录，默认仅管理员可接入（REQUIRE_ADMIN）
  * 单主机并发观看端上限、单用户并发会话上限
  * 单会话总时长上限 + 观看端无响应超时，由 watchdog 协程强制断开
  * 会话开始 / 结束 / 拒绝 都写 operation_logs（category=remote_desktop）
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time

from fastapi import APIRouter, Body, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from database import SessionLocal
from models import Server
from routes.agent import _verify_auth
from routes.auth import get_current_user_full, has_perm, can_manage_server
from services import rdp as rdp_hub
from services.audit_logger import log_operation
from services.rdp import guac

logger = logging.getLogger("backend.rdp")

router = APIRouter(prefix="/api/rdp", tags=["rdp"])

AUDIT_CATEGORY = "remote_desktop"


# ---------------------------------------------------------------- 审计

def _audit(message: str, *, action: str, server_id: int, user: dict | None = None,
           client_ip: str = "", level: str = "info", status: str = "success",
           details: dict | None = None) -> None:
    """写一条远程桌面审计日志（失败不能影响会话本身）。"""
    user = user or {}
    db = SessionLocal()
    try:
        log_operation(
            db,
            message=message,
            category=AUDIT_CATEGORY,
            action=action,
            level=level,
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            ip_address=client_ip,
            status=status,
            target_type="server",
            target_id=str(server_id),
            details=details or {},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[rdp:{server_id}] audit write failed: {exc!r}")
    finally:
        db.close()


def _current_user(authorization: str | None) -> dict:
    if not authorization:
        return {}
    db = SessionLocal()
    try:
        return get_current_user_full(authorization, db)
    finally:
        db.close()



def _notify_agent_rdp(server_ip: str, agent_port: int | None, server_id: int,
                      active: bool, agent_proto: str = "agent") -> None:
    """首个观看者接入/最后一个离开时直连 Agent 开/停推流（秒级首帧）。

    后台线程执行，绝不阻塞 WebSocket 事件循环；Agent 的 5 秒配置轮询保留
    作为兜底（直发失败或丢包时由轮询纠正）。
    """
    if agent_proto != "agent" or not server_ip:
        return
    endpoint = "/rdp/start" if active else "/rdp/stop"

    def _run():
        try:
            import requests as _req
            s = _req.Session()
            s.trust_env = False
            url = f"https://{server_ip}:{agent_port or 9998}{endpoint}"
            from services.agent_auth import agent_headers, agent_ca_verify
            s.verify = agent_ca_verify()  # P1-1：CA 校验 Agent 服务器证书
            r = s.post(url, timeout=5, headers=agent_headers(server_id=server_id))
            logger.info(f"[rdp:{server_id}] agent notify {endpoint} -> {r.status_code}")
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"[rdp:{server_id}] agent notify {endpoint} failed: {exc!r}")

    threading.Thread(target=_run, daemon=True).start()


async def _watchdog(server_id: int, gv: rdp_hub.GuacViewer) -> None:
    """超时巡检：无响应 / 超总时长都强制断开。"""
    try:
        while True:
            await asyncio.sleep(rdp_hub.IDLE_CHECK_INTERVAL)
            if time.time() - gv.last_seen > rdp_hub.VIEWER_IDLE_SECONDS:
                gv.disconnect_reason = f"观看端 {rdp_hub.VIEWER_IDLE_SECONDS} 秒无响应"
            elif gv.elapsed() > rdp_hub.SESSION_MAX_SECONDS:
                gv.disconnect_reason = "会话超过最大时长"
            else:
                continue
            logger.info(f"[rdp:{server_id}] watchdog 断开：{gv.disconnect_reason}")
            try:
                await gv.ws.close(code=4000)
            except Exception:  # noqa: BLE001
                pass
            return
    except asyncio.CancelledError:
        raise


@router.websocket("/tunnel/{server_id}")
async def ws_tunnel(ws: WebSocket, server_id: int):
    """浏览器 <-> hub。

    安全加固阶段 3：JWT 走 WebSocket 子协议（不再出现在 URL / 访问日志里）。
    guacamole-common.js 会固定发 `"guacamole"` 子协议，我们额外发一个
    `vigitoken.<jwt>`；query 参数仅作旧版兼容保留。
    """
    db = SessionLocal()
    try:
        from services.ws_auth import token_from_ws as _tk
        token = _tk(ws)
        user = get_current_user_full(f"Bearer {token}", db) if token else {}
        if not user or not user.get("user_id"):
            await ws.close(code=4401)
            return
        server = db.query(Server).filter(Server.id == server_id).first()
        if not server:
            await ws.close(code=4404)
            return
        if not has_perm(db, user, "host", "rdp", "edit", "connect"):
            _audit("远程桌面：角色无连接权限", action="denied", server_id=server_id, user=user,
                   client_ip=(ws.client.host if ws.client else "") or "",
                   level="warning", status="failed")
            await ws.close(code=4003)
            return
        if not can_manage_server(db, user, server_id):
            _audit("远程桌面：主机不在角色管理范围内", action="denied", server_id=server_id, user=user,
                   client_ip=(ws.client.host if ws.client else "") or "",
                   level="warning", status="failed")
            await ws.close(code=4003)
            return
        ok, reason = rdp_hub.admission_check(server_id, user)
        if not ok:
            _audit(reason, action="denied", server_id=server_id, user=user,
                   client_ip=(ws.client.host if ws.client else "") or "",
                   level="warning", status="failed")
            await ws.close(code=4003)
            return
        # 供直连 Agent 的开/停流通知使用（db 会话即将关闭，先取出来）
        server_ip = server.ip_address
        agent_port = server.agent_port
        agent_proto = server.protocol
    finally:
        db.close()

    # 子协议必须回 "guacamole"，否则客户端连不上
    await ws.accept(subprotocol="guacamole")
    client_ip = (ws.client.host if ws.client else "") or ""
    gv = rdp_hub.GuacViewer(server_id, ws, user, client_ip)
    rdp_hub.viewer_connected(server_id, gv)
    if len(rdp_hub.viewers.get(server_id, ())) == 1:
        # 首个观看者：直连 Agent 立即开流，不等 5 秒轮询（秒级首帧）
        _notify_agent_rdp(server_ip, agent_port, server_id, True, agent_proto)
    logger.info(f"[rdp:{server_id}] viewer connected user={user.get('username')} "
                f"ip={client_ip} viewers={len(rdp_hub.viewers.get(server_id, ()))}")
    _audit(f"{user.get('username', '')} 开始远程桌面会话", action="session_start",
           server_id=server_id, user=user, client_ip=client_ip)

    # 刷新一次被控机 CapsLock 状态：字母大小写要靠它（Agent 侧应答 keystate）
    asyncio.create_task(rdp_hub.query_keystate(server_id))

    sender = asyncio.create_task(gv.send_loop())
    watchdog = asyncio.create_task(_watchdog(server_id, gv))
    parser = guac.InstructionParser()
    try:
        while True:
            text = await ws.receive_text()
            for args in parser.feed(text):
                try:
                    await gv.handle(args)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(f"[rdp:{server_id}] handle {args[0]!r} failed: {exc!r}")
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.info(f"[rdp:{server_id}] tunnel error: {exc!r}")
    finally:
        sender.cancel()
        watchdog.cancel()
        rdp_hub.viewer_disconnected(server_id, gv)
        if not rdp_hub.viewers.get(server_id):
            _notify_agent_rdp(server_ip, agent_port, server_id, False, agent_proto)
        _audit(
            f"{gv.username or '?'} 结束远程桌面会话（{gv.disconnect_reason or '主动断开'}）",
            action="session_end", server_id=server_id, user=user, client_ip=client_ip,
            details={"frames": gv.sent_frames, "duration_sec": round(gv.elapsed()),
                     "rtt_ms": gv.rtt_ms},
        )
        logger.info(f"[rdp:{server_id}] viewer disconnected frames={gv.sent_frames} "
                    f"rtt={gv.rtt_ms}ms duration={round(gv.elapsed())}s")



@router.websocket("/agent/{server_id}")
async def ws_agent(ws: WebSocket, server_id: int):
    """VigilServe Agent <-> hub。鉴权方式与心跳一致：HMAC token。

    安全加固阶段 3：Agent 1.1.40 起用子协议传 token（不进 URL/日志）。
    """
    db = SessionLocal()
    try:
        from services.ws_auth import token_from_ws as _tk
        token = _tk(ws)
        server = _verify_auth(server_id, token, db)
        if not server:
            await ws.close(code=4401)
            return
    finally:
        db.close()

    # 同一主机只允许一个推流连接：旧的先关掉，否则旧 ws 会一直占着句柄和带宽
    old = rdp_hub.agents.get(server_id)
    if old is not None:
        try:
            await old.close(code=4001)
        except Exception:  # noqa: BLE001
            pass
        rdp_hub.agents.pop(server_id, None)

    await ws.accept()
    rdp_hub.agents[server_id] = ws
    logger.info(f"[rdp:{server_id}] agent stream connected")

    settings = rdp_hub.agent_settings.get(server_id)
    if settings:
        try:
            await ws.send_text(json.dumps({"type": "settings", **settings}))
        except Exception:  # noqa: BLE001
            pass

    try:
        while True:
            msg = await ws.receive()
            data = msg.get("bytes")
            if data is None:
                text = msg.get("text")
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except Exception:  # noqa: BLE001
                    logger.debug(f"[rdp:{server_id}] bad agent json: {text[:120]!r}")
                    continue
                kind = payload.get("type")
                if kind == "clipboard_push":
                    await rdp_hub.broadcast_clipboard(server_id, str(payload.get("text", "")))
                elif kind == "keystate":
                    # Agent 注入 CapsLock 后（以及会话开始/被查询时）回报的真实状态，
                    # 供字母大小写的 Shift 决策使用（见 services/rdp/keysym.shift_needed）。
                    # `char` = 该 Agent 支持 keychar（含输入法判定）的字符注入通道，
                    # 缺省视为不支持 -> 服务端自动退回老的 keyvk。
                    rdp_hub.set_caps_state(server_id, bool(payload.get("caps")),
                                           char_inject=payload.get("char"),
                                           ime=payload.get("ime"))
                else:
                    logger.debug(f"[rdp:{server_id}] from agent: {text[:200]}")
                continue
            rdp_hub.stats["frames"] += 1
            rdp_hub.stats["bytes"] += len(data)
            rdp_hub.last_frame[server_id] = data
            width, height = guac.jpeg_size(data) or (0, 0)
            for gv in list(rdp_hub.viewers.get(server_id, ())):
                gv.offer(width, height, data)
    except WebSocketDisconnect:
        pass
    except RuntimeError as exc:
        # 属于正常收尾（例如被新的同主机推流连接顶掉），不要打成 traceback。
        logger.debug(f"[rdp:{server_id}] agent stream stopped: {exc!r}")
    finally:
        if rdp_hub.agents.get(server_id) is ws:
            rdp_hub.agents.pop(server_id, None)
        logger.info(f"[rdp:{server_id}] agent stream disconnected")



@router.get("/status/{server_id}")
async def rdp_status(server_id: int, authorization: str | None = Header(None)):
    """观看端连接前的预检：Agent 是否在线可推流、当前用户是否被允许接入。"""
    user = _current_user(authorization)
    if not user:
        return {"ok": False, "reason": "unauthenticated", "allowed": False}
    db = SessionLocal()
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        if not server:
            return {"ok": False, "reason": "server_not_found", "allowed": False}
        is_agent = server.protocol == "agent"
        online = server.status in ("monitored", "online")
    finally:
        db.close()
    allowed, reason = rdp_hub.admission_check(server_id, user)
    return {
        "ok": bool(is_agent and online and server_id in rdp_hub.agents and allowed),
        "allowed": allowed,
        "reason": reason or "",
        "protocol_agent": bool(is_agent),
        "streaming": server_id in rdp_hub.agents,
    }


@router.get("/session/{server_id}")
async def rdp_session(server_id: int, authorization: str | None = Header(None)):
    """会话概览：排障与状态条用（谁在连、帧数、RTT、当前采集参数）。

    第二轮复查 R-3：以前只验"已登录"，任意账号传别人的 `server_id` 就能看到
    那台主机上**谁正在远程**、帧数与 RTT。现在补主机归属校验。
    沿用本文件既有的「返回体带 error 字段」风格，不改成抛 HTTPException，
    免得前端状态条的处理逻辑跟着改。
    """
    user = _current_user(authorization)
    if not user:
        return {"error": "unauthenticated"}
    db = SessionLocal()
    try:
        if not can_manage_server(db, user, server_id):
            return {"error": "该主机不在当前角色的管理范围内"}
    finally:
        db.close()
    return rdp_hub.session_info(server_id)


@router.post("/settings/{server_id}")
async def rdp_apply_settings(server_id: int, body: dict = Body(default={}),
                             authorization: str | None = Header(None)):
    """调整采集参数（管理员）。可传 {preset} 或 {fps, quality, max_width}。"""
    user = _current_user(authorization)
    if not user:
        return {"error": "unauthenticated"}
    # 第二轮复查 R-8：两处改掉 ——
    #   ① 以前返回 **200 + {"error": ...}**，语义是错的（权限不足就该是 403）。
    #      保留 error 字段，前端读 body 的写法不受影响；只看 res.ok 的地方反而更准。
    #   ② 以前判定挂在 `rdp_hub.REQUIRE_ADMIN` 这个"谁能连远程桌面"的开关上 ——
    #      谁把它置 False，任何登录用户就都能改采集参数了。改参数与"允许谁连接"
    #      是两件事，这里独立判定，不再看那个开关。
    #   （权限点注册表里 host/rdp 只有 connect，没有"改参数"这一项，故仍按管理员判定；
    #    真的要开放给某个角色时，应先去 services/rbac.py 补一个 op。）
    if not (bool(user.get("is_admin")) or user.get("role") == "admin"):
        return JSONResponse(
            status_code=403,
            content={"error": "无权限：仅管理员可调整远程桌面参数"},
        )
    preset = body.get("preset")
    values = body
    if isinstance(preset, str) and preset in rdp_hub.QUALITY_PRESETS:
        values = rdp_hub.QUALITY_PRESETS[preset]
    cur = rdp_hub.apply_settings(server_id, values)
    _audit(f"{user.get('username', '')} 调整远程桌面采集参数", action="settings",
           server_id=server_id, user=user, details=dict(cur, preset=preset or ""))
    return {"ok": True, "settings": cur}
