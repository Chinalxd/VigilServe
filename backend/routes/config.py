"""Global configuration API."""
import json, os, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database import get_db
from models import GlobalConfig
from services.audit_logger import log_operation
from routes.auth import require_admin_full, require_login

router = APIRouter(prefix="/api/config", tags=["config"])

EMAIL_CFG_FILE = os.path.join(os.path.dirname(__file__), '..', 'email_config.json')

DEFAULTS = {
    "collect_interval": {"value": "60", "desc": "服务端指标采集间隔（秒）"},
    "agent_collect_interval": {"value": "60", "desc": "Agent 客户端推送间隔（秒）"},
    "service_check_interval": {"value": "60", "desc": "服务端口/进程检测间隔（秒）"},
    # 方案 B：网络设备（SNMP）采集间隔。交换机不必像服务器那样 60 秒刷一次，
    # 5 分钟足够看端口流量趋势，还能大幅减少对设备的轮询压力。
    # 在线判定 = 本值 × 2.5，改了它离线判定的宽限时间也跟着变（见 services/device_status.py）。
    "snmp_collect_interval": {"value": "300", "desc": "网络设备 SNMP 采集间隔（秒）"},
    "chart_refresh_interval": {"value": "60", "desc": "图表数据刷新间隔（秒）"},
    "alert_check_interval": {"value": "60", "desc": "告警评估间隔（秒）"},
    "frontend_poll_interval": {"value": "10", "desc": "前端轮询间隔（秒）"},
    "data_retention_days": {"value": "90", "desc": "数据保存期限（天）"},
    "alert_log_retention_days": {"value": "30", "desc": "告警日志保留天数（天）"},
    "operation_log_retention_days": {"value": "30", "desc": "操作日志保留天数（天）"},
    "cpu_threshold_warning": {"value": "80", "desc": "CPU 使用率告警阈值（%）"},
    "cpu_threshold_critical": {"value": "95", "desc": "CPU 使用率严重告警阈值（%）"},
    "memory_threshold_warning": {"value": "85", "desc": "内存告警阈值（%）"},
    "memory_threshold_critical": {"value": "95", "desc": "内存严重告警阈值（%）"},
    "disk_threshold_warning": {"value": "85", "desc": "磁盘告警阈值（%）"},
    "disk_threshold_critical": {"value": "95", "desc": "磁盘严重告警阈值（%）"},
    # 2026-09-23：MeshCentral 集成整体下线，以下三个键已移除，
    # meshcentral_url / meshcentral_keyfile / meshcentral_cli_path
    # 库里若还留着旧行不影响运行（只是不再被读取），不清库是为了避免动用户的配置数据。
    # 设备身份（安全演进 S4）
    # 默认 0：新设备入户必须管理员核对配对码后点「加入管理」。
    # 置 1 = 放开人工准入（批量部署场景），代价是**任何能连上服务端的机器都能拿到证书**，
    # 只在受控内网里临时开，用完记得关回去。
    "auto_approve": {"value": "0", "desc": "新设备入户自动批准（0=需人工核对配对码；1=直接发证，仅限受控内网）"},
    # 失联主机的证书自动回收（评估文档 §4.3）：0 = 不回收。
    "cert_reclaim_days": {"value": "90", "desc": "主机失联超过该天数自动吊销其设备证书（0=关闭自动回收）"},
    # S5：SSH 主机密钥首连策略。tofu=首次连接记录指纹并放行（写提示告警请复核）；
    # strict=没有预置指纹就拒绝连接，需管理员先在主机详情「网络」页签确认。
    "ssh_host_key_policy": {"value": "tofu", "desc": "SSH 主机密钥首连策略：tofu（首次信任并提示复核）/ strict（无预置指纹即拒绝）"},
}


def seed_config(db: Session):
    _migrate_month_to_day(db, "data_retention_months", "data_retention_days")
    _migrate_month_to_day(db, "alert_log_retention_months", "alert_log_retention_days")
    _migrate_month_to_day(db, "operation_log_retention_months", "operation_log_retention_days")
    db.commit()

    for key, info in DEFAULTS.items():
        if not db.query(GlobalConfig).filter(GlobalConfig.key == key).first():
            db.add(GlobalConfig(key=key, value=info["value"], description=info["desc"]))
    db.commit()


def _migrate_month_to_day(db: Session, old_key: str, new_key: str):
    old = db.query(GlobalConfig).filter(GlobalConfig.key == old_key).first()
    new = db.query(GlobalConfig).filter(GlobalConfig.key == new_key).first()
    if old and not new:
        try:
            months = int(old.value)
        except (ValueError, TypeError):
            months = 3
        db.add(GlobalConfig(key=new_key, value=str(months * 30), description=DEFAULTS.get(new_key, {}).get("desc", "")))
    if old:
        db.delete(old)


def get_config_dict(db: Session) -> dict:
    items = db.query(GlobalConfig).all()
    result = {}
    legacy_keys = {
        "data_retention_months",
        "alert_log_retention_months",
        "operation_log_retention_months",
    }
    for item in items:
        if item.key in legacy_keys:
            continue
        result[item.key] = {"value": item.value, "description": item.description}
    for key, info in DEFAULTS.items():
        if key not in result:
            result[key] = {"value": info["value"], "description": info["desc"]}
    return result


@router.get("/")
def get_config(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    # 系统参数（采集/轮询间隔、告警阈值等）：登录即可读，不含凭据。
    # 前端 App.jsx / Settings.jsx 用它取前端轮询间隔，非管理员同样需要。
    require_login(authorization, db)
    seed_config(db)
    return get_config_dict(db)



DEFAULT_EMAIL_CFG = {
    "smtp_host": "",
    "smtp_port": "465",
    "encryption": "ssl",
    "smtp_user": "",
    "smtp_pass": "",
    "from_addr": "",
}


def _read_email_cfg():
    try:
        if os.path.exists(EMAIL_CFG_FILE):
            with open(EMAIL_CFG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return DEFAULT_EMAIL_CFG.copy()


def _write_email_cfg(data: dict):
    os.makedirs(os.path.dirname(EMAIL_CFG_FILE), exist_ok=True)
    with open(EMAIL_CFG_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


@router.get("/email")
def get_email_config(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    require_admin_full(authorization, db)
    from models import User
    cfg = _read_email_cfg()
    users = db.query(User).filter(User.email != "", User.email.isnot(None)).all()
    cfg["to_addrs"] = ", ".join(sorted(set(u.email for u in users if u.email.strip())))
    return cfg


@router.put("/email")
def update_email_config(data: dict, authorization: Optional[str] = Header(None),
                        db: Session = Depends(get_db)):
    require_admin_full(authorization, db)
    cfg = _read_email_cfg()
    for key in DEFAULT_EMAIL_CFG:
        if key in data:
            cfg[key] = str(data[key])
    _write_email_cfg(cfg)
    return {"message": "Email config saved"}


@router.post("/email/test")
def send_test_email(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """Send a test alert email using current SMTP config."""
    # 会拿服务器 SMTP 凭据真发信（可被滥用成发信机），仅管理员
    require_admin_full(authorization, db)
    from models import User
    cfg = _read_email_cfg()
    host = cfg.get("smtp_host", "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="SMTP 服务器未配置")
    port = int(cfg.get("smtp_port", "465") or "465")
    enc = cfg.get("encryption", "ssl")
    user = cfg.get("smtp_user", "")
    pwd = cfg.get("smtp_pass", "")
    from_addr = cfg.get("from_addr", "")
    if not from_addr:
        raise HTTPException(status_code=400, detail="发件人地址未配置")

    users = db.query(User).filter(User.email != "", User.email.isnot(None)).all()
    to_addrs = [u.email.strip() for u in users if u.email.strip()]
    if not to_addrs:
        raise HTTPException(status_code=400, detail="没有配置收件人邮箱（请在用户管理中填写用户邮箱）")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = f"[模拟测试] VigilServe 告警测试邮件 - {now}"
    body = f"""<html><body>
<h2 style="color:#d9534f;">⚠ 模拟告警测试</h2>
<p>这是一封由 VigilServe 系统自动发送的模拟测试邮件。</p>
<p><b>发送时间：</b>{now}</p>
<p><b>发送来源：</b>邮件配置测试功能</p>
<hr/>
<p style="color:#6c757d;font-size:12px;">如果收到此邮件，说明 SMTP 邮件配置正确无误。生产告警将在触发时自动发送到相同收件人。</p>
</body></html>"""
    msg.attach(MIMEText(body, "html", "utf-8"))

    try:
        if enc == "ssl":
            srv = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            srv = smtplib.SMTP(host, port, timeout=15)
            if enc == "tls":
                srv.starttls()
        if user and pwd:
            srv.login(user, pwd)
        srv.sendmail(from_addr, to_addrs, msg.as_string())
        srv.quit()
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=400, detail="SMTP 认证失败，请检查用户名/密码")
    except smtplib.SMTPConnectError:
        raise HTTPException(status_code=400, detail=f"无法连接 SMTP 服务器 {host}:{port}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"发送失败: {str(e)}")

    return {"message": f"测试邮件已发送到 {len(to_addrs)} 个收件人"}    


@router.put("/{key}")
def update_config(key: str, value: dict, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = require_admin_full(authorization, db)
    item = db.query(GlobalConfig).filter(GlobalConfig.key == key).first()
    if not item:
        raise HTTPException(status_code=404, detail="Config key not found")
    old = item.value
    item.value = str(value.get("value", item.value))
    db.commit()
    log_operation(
        db,
        category="config",
        action="update",
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        target_type="config",
        target_id=key,
        message=f"更新配置项 {key}: {old} → {item.value}",
        details={"old": old, "new": item.value},
    )
    return {"message": f"Config {key} updated"}


@router.put("/")
def batch_update_config(data: dict, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = require_admin_full(authorization, db)
    changed = []
    for key, value in data.items():
        item = db.query(GlobalConfig).filter(GlobalConfig.key == key).first()
        if item:
            old = item.value
            item.value = str(value)
            if old != str(value):
                changed.append(f"{key}: {old} → {value}")
    db.commit()
    if changed:
        log_operation(
            db,
            category="config",
            action="batch_update",
            username=user.get("username", ""),
            user_id=user.get("user_id"),
            target_type="config",
            message=f"更新 {len(changed)} 项系统配置",
            details={"changes": changed, "source": "settings"},
        )
    return get_config_dict(db)