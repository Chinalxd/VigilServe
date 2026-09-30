"""Database setup and session management."""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "monitor.db")
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    echo=False,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate():
    """Lightweight migrations for SQLite."""
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA synchronous=NORMAL"))
        cols = [row[1] for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()]
        if "preferences" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN preferences TEXT DEFAULT '{}'"))
            conn.commit()
        if "full_name" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(100) DEFAULT ''"))
            conn.commit()
        if "must_reset_password" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN must_reset_password INTEGER DEFAULT 0"))
            conn.commit()
        if "role_id" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN role_id INTEGER"))
            conn.commit()
        # 安全策略：账户有效期 / 首次登录时间 / 最近改密时间
        if "valid_until" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN valid_until DATETIME"))
            conn.commit()
        if "last_login_at" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN last_login_at DATETIME"))
            conn.commit()
        if "password_changed_at" not in cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN password_changed_at DATETIME"))
            conn.commit()

        srv_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(servers)")).fetchall()]
        if "agent_port" not in srv_cols:
            conn.execute(text("ALTER TABLE servers ADD COLUMN agent_port INTEGER DEFAULT 9998"))
            conn.commit()
        if "install_path" not in srv_cols:
            conn.execute(text("ALTER TABLE servers ADD COLUMN install_path VARCHAR(300) DEFAULT ''"))
            conn.commit()
        if "mesh_node_id" not in srv_cols:
            conn.execute(text("ALTER TABLE servers ADD COLUMN mesh_node_id VARCHAR(64) DEFAULT ''"))
            conn.commit()

        snmp_cols = {
            "snmp_enabled": "INTEGER DEFAULT 0",
            "snmp_version": "VARCHAR(8) DEFAULT '3'",
            "snmp_port": "INTEGER DEFAULT 161",
            "snmp_username": "VARCHAR(100) DEFAULT ''",
            "snmp_security_level": "VARCHAR(16) DEFAULT 'authPriv'",
            "snmp_context": "VARCHAR(100) DEFAULT ''",
            "snmp_auth_proto": "VARCHAR(16) DEFAULT 'SHA'",
            "snmp_priv_proto": "VARCHAR(16) DEFAULT 'AES'",
            "snmp_auth_password": "VARCHAR(500) DEFAULT ''",
            "snmp_priv_password": "VARCHAR(500) DEFAULT ''",
        }
        for col, ddl in snmp_cols.items():
            if col not in srv_cols:
                conn.execute(text(f"ALTER TABLE servers ADD COLUMN {col} {ddl}"))
        conn.commit()

        device_cols = {
            "device_kind": "VARCHAR(20) DEFAULT 'host'",
            "device_vendor": "VARCHAR(50) DEFAULT ''",
            "device_model": "VARCHAR(100) DEFAULT ''",
            "device_category": "VARCHAR(30) DEFAULT ''",
            "collect_interval_sec": "INTEGER DEFAULT 0",
        }
        for col, ddl in device_cols.items():
            if col not in srv_cols:
                conn.execute(text(f"ALTER TABLE servers ADD COLUMN {col} {ddl}"))
        # 老库里 protocol 可能是 NULL（早期 default 没生效），顺手补成 host 该有的默认
        conn.execute(text("UPDATE servers SET device_kind='host' WHERE device_kind IS NULL OR device_kind=''"))
        conn.commit()

        # 方案 B：网络设备的命令行（CLI）凭据 —— 「WEB终端」登录设备敲命令用
        cli_cols = {
            "cli_protocol": "VARCHAR(10) DEFAULT 'ssh'",
            "cli_port": "INTEGER DEFAULT 22",
            "cli_username": "VARCHAR(100) DEFAULT ''",
            "cli_password": "VARCHAR(500) DEFAULT ''",
            "cli_enable_password": "VARCHAR(500) DEFAULT ''",
        }
        for col, ddl in cli_cols.items():
            if col not in srv_cols:
                conn.execute(text(f"ALTER TABLE servers ADD COLUMN {col} {ddl}"))
        conn.commit()

        # 方案 B：网络设备的 WEB 管理入口 —— 「WEB管理」页签代理到设备自带的管理界面
        web_cols = {
            "web_protocol": "VARCHAR(5) DEFAULT 'https'",
            "web_port": "INTEGER DEFAULT 443",
            # 2026-09-21：WEB 管理账号口令自动填充（存账号口令，打开开关后
            # 自动填进设备登录页；登录按钮仍由人点）
            "web_auto_login": "INTEGER DEFAULT 0",
            "web_username": "VARCHAR(100) DEFAULT ''",
            "web_password": "VARCHAR(500) DEFAULT ''",
        }
        for col, ddl in web_cols.items():
            if col not in srv_cols:
                conn.execute(text(f"ALTER TABLE servers ADD COLUMN {col} {ddl}"))
        conn.commit()

        metric_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(metric_snapshots)")).fetchall()]
        new_metric_cols = {
            "disk_io_read_mbps": "REAL DEFAULT 0.0",
            "disk_io_write_mbps": "REAL DEFAULT 0.0",
            "tcp_connections": "INTEGER DEFAULT 0",
        }
        for col, ddl in new_metric_cols.items():
            if col not in metric_cols:
                conn.execute(text(f"ALTER TABLE metric_snapshots ADD COLUMN {col} {ddl}"))
        conn.commit()

        # 客户端证书身份（安全演进 S1）：agent_keys 扩展列
        key_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(agent_keys)")).fetchall()]
        new_key_cols = {
            "node_id": "VARCHAR(64) DEFAULT ''",
            "pub_key": "TEXT DEFAULT ''",
            # 2026-09-28：未准入设备的公钥暂存（让它能通过心跳的签名校验，
            # 从而"在线"不再依赖是否已加入管理）。详见 models.AgentKey。
            "pending_pub_key": "TEXT DEFAULT ''",
            "key_fingerprint": "VARCHAR(96) DEFAULT ''",
            "client_cert": "TEXT DEFAULT ''",
            "cert_serial": "VARCHAR(40) DEFAULT ''",
            "cert_not_before": "DATETIME",
            "cert_not_after": "DATETIME",
            "cert_issued_at": "DATETIME",
            "cert_renew_count": "INTEGER DEFAULT 0",
            "identity_state": "VARCHAR(20) DEFAULT 'none'",
            "pairing_code": "VARCHAR(16) DEFAULT ''",
            "machine_fingerprint": "VARCHAR(96) DEFAULT ''",
            "revoked": "INTEGER DEFAULT 0",
            "revoked_at": "DATETIME",
            "revoked_reason": "VARCHAR(200) DEFAULT ''",
            "auth_mode": "VARCHAR(16) DEFAULT 'hmac'",
            "last_signature_at": "DATETIME",
            "fingerprint_parts": "TEXT DEFAULT ''",
            # P1-1（9998 通道 TLS）：Agent 本地 API 的服务器证书
            "api_cert": "TEXT DEFAULT ''",
            "api_cert_not_after": "DATETIME",
            # 2026-09-23 开源加固 ⑤：静态 token 可轮换。
            #   轮换时旧密钥挪到 secret_key_prev，在 secret_key_prev_until 之前
            #   仍然被接受 —— 给已经跑在外的 Agent 一个"来拿新 token"的窗口；
            #   窗口一过，泄露出去的旧 token 自动失效（不再是永久后门）。
            "secret_key_prev": "VARCHAR(64) DEFAULT ''",
            "secret_key_prev_until": "DATETIME",
            # 开源加固 ⑥：Agent 完整性自检（对标 MeshCentral agentTampering）
            "self_digest": "VARCHAR(64) DEFAULT ''",
            "self_digest_version": "VARCHAR(20) DEFAULT ''",
            "self_digest_at": "DATETIME",
            "tamper_at": "DATETIME",
            "tamper_detail": "VARCHAR(300) DEFAULT ''",
        }
        for col, ddl in new_key_cols.items():
            if col not in key_cols:
                conn.execute(text(f"ALTER TABLE agent_keys ADD COLUMN {col} {ddl}"))
        conn.commit()

        svc_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(monitored_services)")).fetchall()]
        new_svc_cols = {
            "disk_read_mbps": "REAL DEFAULT 0.0",
            "disk_write_mbps": "REAL DEFAULT 0.0",
            "network_in_mbps": "REAL DEFAULT 0.0",
            "network_out_mbps": "REAL DEFAULT 0.0",
            "ppid": "INTEGER DEFAULT 0",
            "start_time": "VARCHAR(30) DEFAULT ''",
            "cmdline": "TEXT DEFAULT ''",
            "username": "VARCHAR(100) DEFAULT ''",
        }
        for col, ddl in new_svc_cols.items():
            if col not in svc_cols:
                conn.execute(text(f"ALTER TABLE monitored_services ADD COLUMN {col} {ddl}"))
        conn.commit()

        # 单端口速率列（2026-09-21）：端口表原来只有累计字节，看着像"流量"其实是
        # 开机以来的总量。速率要拿上一轮的累计值差分，基线存在 extra_config 里。
        ni_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(network_interfaces)")).fetchall()]
        new_ni_cols = {
            # 🚨 用 REAL 且**不给 DEFAULT**：没有基线时必须是 NULL，不能是 0。
            # 给 0 的话前端分不清"这口没流量"和"还没算出速率"，会摆一个假的 0 Mbps。
            "in_rate_mbps": "REAL",
            "out_rate_mbps": "REAL",
        }
        for col, ddl in new_ni_cols.items():
            if col not in ni_cols:
                conn.execute(text(f"ALTER TABLE network_interfaces ADD COLUMN {col} {ddl}"))
        conn.commit()


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate()
