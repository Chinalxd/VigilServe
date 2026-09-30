"""Data models for servers, metrics, services, and alerts."""
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base


class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    ip_address = Column(String(50), nullable=False)
    os_type = Column(String(30), default="")
    network_env = Column(String(30), nullable=False)
    business_system = Column(String(100), default="")
    protocol = Column(String(20), default="SSH")
    connection_port = Column(Integer, default=22)
    # network = 装不上 Agent 的网络设备（交换机 / 路由器 / 防火墙 / 存储），
    #           由服务端持 SNMP 凭据主动采集，不需要被管设备配合装东西。
    # 两者共用 servers 表，靠这个字段区分；仪表盘 / 告警 / 分组 / 审计全部复用。
    device_kind = Column(String(20), default="host")
    # 设备资产信息：新增设备时由 SNMP 自动识别（services/device_profile.py），可人工改
    device_vendor = Column(String(50), default="")
    device_model = Column(String(100), default="")      # S5720-28X-SI ...
    device_category = Column(String(30), default="")
    collect_interval_sec = Column(Integer, default=0)
    username = Column(String(100), default="")
    # 静态加密存储（services/secret_store.py 的 Fernet）。库里只有密文，
    # 老的明文数据在"下次保存"时自动升级。读明文一律走 `password_plain`。
    password = Column(String(500), default="")
    status = Column(String(20), default="unknown")
    cpu_cores = Column(Integer, default=0)
    total_memory_gb = Column(Float, default=0.0)
    total_disk_gb = Column(Float, default=0.0)
    disk_partitions = Column(JSON, default=list)
    description = Column(Text, default="")
    sort_order = Column(Integer, default=0)
    extra_config = Column(JSON, default=dict)
    agent_port = Column(Integer, default=9998)
    install_path = Column(String(300), default="")
    mesh_node_id = Column(String(64), default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    join_time = Column(DateTime, nullable=True)
    online_time = Column(DateTime, nullable=True)
    offline_time = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # ── S5：SNMPv3 采集（网络设备：交换机 / 路由器 / 防火墙）──────────────
    # Agent 装不上去的设备（交换机、交换机堆叠、纯网络设备）走这条路：
    # 服务端持凭据主动 SNMP 去问，不需要在被管设备上装任何东西。
    snmp_enabled = Column(Integer, default=0)
    snmp_version = Column(String(8), default="3")
    snmp_port = Column(Integer, default=161)
    snmp_username = Column(String(100), default="")
    snmp_security_level = Column(String(16), default="authPriv")
    # SNMPv3 上下文名（多数设备留空即可；Cisco 的 vlan-<id> / VRF 上下文要靠它区分）
    snmp_context = Column(String(100), default="")
    # 鉴权 / 加密协议名，见 services/snmp_collector.py 的协议表
    snmp_auth_proto = Column(String(16), default="SHA")
    snmp_priv_proto = Column(String(16), default="AES")
    # 库里同样只存 Fernet 密文（与 password 一致），读明文走下面两个属性
    snmp_auth_password = Column(String(500), default="")
    snmp_priv_password = Column(String(500), default="")

    # ── 方案 B：网络设备的命令行（CLI）凭据 ─────────────────────────────
    # SNMP 只能读指标，改不了配置。「WEB终端」要登录设备敲命令，得有 SSH/Telnet
    # 凭据。刻意**不复用** `protocol` / `connection_port` / `username` / `password`：
    # 那四个字段已经被主机侧（SSH/WinRM/Telnet 检测、collector 的 protocol 判断）
    # 占住了，而网络设备的 protocol 固定是 'snmp'（collector 靠它跳过主机采集循环）。
    cli_protocol = Column(String(10), default="ssh")
    cli_port = Column(Integer, default=22)
    cli_username = Column(String(100), default="")
    cli_password = Column(String(500), default="")
    cli_enable_password = Column(String(500), default="")

    # 交换机 / 路由器 / 防火墙 / 存储基本都自带 Web 管理界面。详情页的「WEB管理」
    # 页签由**服务端反向代理**过去 —— 直接嵌 https://设备IP 会被浏览器拦
    # （自签名证书 + X-Frame-Options + HTTPS 页面不允许嵌 HTTP）。
    # 地址固定用 snmp 采集时填的那个管理 IP，这里只存协议和端口。
    web_protocol = Column(String(5), default="https")
    web_port = Column(Integer, default=443)

    # ── 方案 B：WEB 管理的账号口令自动填充（2026-09-21 加，09-22 改为只填不提交）──
    # 「WEB管理」页签代理过去的是设备自带的登录页。管理员在编辑弹窗里存下账号口令并
    # 打开开关后，代理只在**设备返回登录页**时（= 这台设备当前没有我们的会话）把
    # 账号与口令**填进设备自己的登录页**，**但不代替点登录** —— 登录仍由人按，
    # 这样就不存在消耗设备失败次数、把账号锁死的可能（详见
    # services/web_auto_login.py）。有会话时设备根本不会返回登录页，天然不会重复填。
    web_auto_login = Column(Integer, default=0)
    web_username = Column(String(100), default="")
    web_password = Column(String(500), default="")

    metrics = relationship("MetricSnapshot", back_populates="server", cascade="all, delete-orphan")

    @property
    def password_plain(self) -> str:
        """解密后的主机登录口令（唯一允许拿到明文的入口）。

        👉 API 一律**不要**用这个属性往外吐——`routes/servers.py` 现在对所有人
        （含管理员）只返回掩码。只有真正要连主机的地方（WinRM/SSH）才读它。
        """
        from services.secret_store import decrypt_secret
        return decrypt_secret(self.password or "")

    @property
    def snmp_auth_password_plain(self) -> str:
        """SNMPv3 鉴权口令明文（唯一解密入口，不要往 API 吐）。"""
        from services.secret_store import decrypt_secret
        return decrypt_secret(self.snmp_auth_password or "")

    @property
    def snmp_priv_password_plain(self) -> str:
        """SNMPv3 加密口令明文（唯一解密入口，不要往 API 吐）。"""
        from services.secret_store import decrypt_secret
        return decrypt_secret(self.snmp_priv_password or "")

    @property
    def cli_password_plain(self) -> str:
        """网络设备 CLI 登录口令明文（唯一解密入口，不要往 API 吐）。"""
        from services.secret_store import decrypt_secret
        return decrypt_secret(self.cli_password or "")

    @property
    def web_password_plain(self) -> str:
        """网络设备 WEB 管理登录口令明文（唯一解密入口，不要往 API 吐）。

        只有 `routes/network_web.py` 做自动填充时读它 —— 读出来是塞进登录页的
        注入脚本里填进输入框（**不代替提交**），不落盘、不进日志。
        """
        from services.secret_store import decrypt_secret
        return decrypt_secret(self.web_password or "")

    @property
    def cli_enable_password_plain(self) -> str:
        """网络设备 CLI 特权口令明文（唯一解密入口，不要往 API 吐）。"""
        from services.secret_store import decrypt_secret
        return decrypt_secret(self.cli_enable_password or "")

    services = relationship("MonitoredService", back_populates="server", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="server", cascade="all, delete-orphan")


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    cpu_percent = Column(Float, default=0)
    memory_percent = Column(Float, default=0)
    memory_used_gb = Column(Float, default=0)
    disk_percent = Column(Float, default=0)
    disk_used_gb = Column(Float, default=0)
    network_in_mbps = Column(Float, default=0)
    network_out_mbps = Column(Float, default=0)
    disk_io_read_mbps = Column(Float, default=0)
    disk_io_write_mbps = Column(Float, default=0)
    tcp_connections = Column(Integer, default=0)

    server = relationship("Server", back_populates="metrics")

    __table_args__ = (
        Index('ix_metric_snapshots_server_id_timestamp', 'server_id', 'timestamp'),
    )


class MonitoredService(Base):
    __tablename__ = "monitored_services"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    image_name = Column(String(100), default="")
    path = Column(String(300), default="")
    port = Column(Integer, default=0)
    process_name = Column(String(100), default="")  # 保留兼容
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    disk_percent = Column(Float, default=0.0)
    disk_mbps = Column(Float, default=0.0)  # 磁盘写入速度（MB/s），兼容旧字段
    disk_read_mbps = Column(Float, default=0.0)
    disk_write_mbps = Column(Float, default=0.0)
    network_mbps = Column(Float, default=0.0)  # 网络总传输数据量（Mbps），兼容旧字段
    network_in_mbps = Column(Float, default=0.0)
    network_out_mbps = Column(Float, default=0.0)
    alive_status = Column(String(20), default="unknown")
    alert_status = Column(String(20), default="normal")
    running_status = Column(String(20), default="unknown")
    pid = Column(Integer, default=0)
    ppid = Column(Integer, default=0)
    start_time = Column(String(30), default="")
    cmdline = Column(Text, default="")
    username = Column(String(100), default="")
    status = Column(String(20), default="unknown")  # 兼容旧字段，与 running_status 同步
    last_checked = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    description = Column(String(200), default="")
    has_visible_window = Column(Integer, default=0)
    app_instance_id = Column(String(300), default="")

    server = relationship("Server", back_populates="services")

    __table_args__ = (
        Index('ix_monitored_services_server_id_name', 'server_id', 'name'),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)
    # NOTE: no index=True here — the explicit Index('ix_alerts_timestamp', ...)
    # in __table_args__ already defines it; a duplicate name makes create_all
    # fail with "index ix_alerts_timestamp already exists" on a FRESH
    # database (first startup on a new machine).
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    level = Column(String(20), nullable=False)
    title = Column(String(200), nullable=False)
    message = Column(Text, default="")
    acknowledged = Column(Integer, default=0)
    metric_type = Column(String(30), default="")

    server = relationship("Server", back_populates="alerts")

    __table_args__ = (
        Index('ix_alerts_server_id_acknowledged', 'server_id', 'acknowledged'),
        Index('ix_alerts_timestamp', 'timestamp'),
    )


class OperationLog(Base):
    __tablename__ = "operation_logs"

    id = Column(Integer, primary_key=True, index=True)
    # NOTE: no index=True — see Alert.timestamp above; duplicate index names
    # break create_all on a fresh database.
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    level = Column(String(20), default="info")
    category = Column(String(40), default="system")
    action = Column(String(100), default="")
    username = Column(String(50), default="")
    user_id = Column(Integer, nullable=True)
    ip_address = Column(String(50), default="")
    status = Column(String(20), default="success")
    target_type = Column(String(40), default="")
    target_id = Column(String(50), default="")
    message = Column(Text, default="")
    details = Column(JSON, default=dict)

    __table_args__ = (
        Index('ix_operation_logs_timestamp', 'timestamp'),
        Index('ix_operation_logs_category', 'category'),
        Index('ix_operation_logs_username', 'username'),
    )


class AgentKey(Base):
    """每台 Agent 一行的身份记录。

    历史包袱：`secret_key` 是对称 HMAC 密钥。引入证书身份（安全演进 S1）之后，
    它**只剩一个用途** —— 服务端回调 Agent 9998 时算的那个 `X-Auth-Token`
    （`services/agent_auth.py`）。Agent → 服务端方向不再用它，详见下面注释。

    ⚠ 本表所有新增列一律不写 `index=True` —— 与 `__table_args__` 里的显式
    Index 同名会让全新库 `create_all` 抛 "index already exists"（踩过一次）。
    """
    __tablename__ = "agent_keys"
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), unique=True, nullable=False)
    secret_key = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ── 客户端证书身份（安全演进 S1）──────────────────────────────────
    # 身份锚是 node_id + 证书公钥，**不再是 IP / 主机名**。IP 变了照样认，
    # 换了 CDN / NAT / 重装系统 IP 不同也能自己接回来。
    node_id = Column(String(64), default="")
    pub_key = Column(Text, default="")
    # 2026-09-28：**未准入**设备送来的公钥先暂存在这里。
    # 为什么需要它：`_authenticate()` 拿「pub_key 有没有登记」当"是否已准入"的判据，
    # 于是未准入的设备签不了名、心跳一律 401，`last_seen` 永远是空 —— 管理员在
    # 主机列表里看到的是"离线"，而它其实一直连着服务端。
    # 暂存之后，未准入设备可以**完成心跳这一条**签名校验（在线状态与准入解耦），
    # 但 pub_key 不登记，指标上报 / 配置下发仍然照旧拒绝。
    pending_pub_key = Column(Text, default="")
    key_fingerprint = Column(String(96), default="")
    client_cert = Column(Text, default="")              # 服务端签出的客户端证书 PEM
    cert_serial = Column(String(40), default="")        # 证书序列号（十六进制，吊销清单用）
    cert_not_before = Column(DateTime, nullable=True)
    cert_not_after = Column(DateTime, nullable=True)
    cert_issued_at = Column(DateTime, nullable=True)
    cert_renew_count = Column(Integer, default=0)
    identity_state = Column(String(20), default="none")
    pairing_code = Column(String(16), default="")
    machine_fingerprint = Column(String(96), default="")
    # 存分项而不是只存一个总哈希，才能判断「到底变了几项」→ L1/L2/L3 分级。
    fingerprint_parts = Column(Text, default="")
    revoked = Column(Integer, default=0)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(200), default="")
    auth_mode = Column(String(16), default="hmac")
    last_signature_at = Column(DateTime, nullable=True)
    # P1-1（9998 通道 TLS）：Agent 本地 API 的服务器证书（服务端 CA 签发）。
    # 与 client_cert（Agent 的身份证书）是两回事 —— 这张是给服务端调用 9998 时校验对端用的。
    api_cert = Column(Text, default="")                 # Agent 9998 服务器证书 PEM
    api_cert_not_after = Column(DateTime, nullable=True)

    # ── 2026-09-23 开源加固 ⑤：静态 token 可轮换 ──────────────────────────
    # 轮换时旧密钥挪到这里，只被接受 `secret_key_prev_until` 之前这一段——
    # 给已经跑在外的 Agent 一次"来拿新 token"的机会，窗口一过即失效。
    # ⚠ 不加 index=True（与 __table_args__ 的显式 Index 同名会让全新库 create_all 抛错）
    secret_key_prev = Column(String(64), default="")
    secret_key_prev_until = Column(DateTime, nullable=True)

    # ── 2026-09-23 开源加固 ⑥：Agent 完整性自检（对标 agentTampering）──────
    # Agent 每次心跳回报自己代码的 SHA256；服务端首次登记为基线，之后比对。
    # 版本号变了（合法升级）就顺手更新基线 —— 否则每次升级都会误报"被篡改"。
    self_digest = Column(String(64), default="")
    self_digest_version = Column(String(20), default="")
    self_digest_at = Column(DateTime, nullable=True)
    tamper_at = Column(DateTime, nullable=True)
    tamper_detail = Column(String(300), default="")


class NetworkInterface(Base):
    """S5：SNMP 采回来的端口快照（IF-MIB）。

    一台设备一个端口一行，按 (server_id, if_index) 定位。每次采集就地更新，
    不存历史 —— 历史在 `MetricSnapshot.network_in_mbps/out_mbps`（所有端口汇总），
    单端口的历史曲线目前没必要存（48 口交换机 × 每分钟 = 一天 7 万行）。

    ⚠ 同其它新表：新增列一律不写 `index=True`。
    """
    __tablename__ = "network_interfaces"
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    if_index = Column(Integer, default=0)
    if_name = Column(String(100), default="")
    if_descr = Column(String(200), default="")
    if_alias = Column(String(200), default="")
    if_type = Column(String(60), default="")
    if_speed_mbps = Column(Float, default=0.0)
    admin_status = Column(String(16), default="")
    oper_status = Column(String(16), default="")
    in_octets = Column(Integer, default=0)
    out_octets = Column(Integer, default=0)
    in_errors = Column(Integer, default=0)
    out_errors = Column(Integer, default=0)
    # 单端口速率（Mbps）：SNMP 只给累计字节，速率得自己差分（2026-09-21 加）。
    # 第一轮回采没有基线，存 NULL —— 前端显示"—"，别显示 0 冒充"这口没流量"。
    in_rate_mbps = Column(Float, nullable=True)
    out_rate_mbps = Column(Float, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class SSHHostKey(Base):
    """S5：SSH 主机密钥钉扎（防中间人）。

    钉的是「这台主机出示的 SSH 主机密钥」。指纹变了 = 中间人，或设备重装/换过密钥，
    两者必须区分开 —— 所以**变更时不覆盖旧指纹**（与 S3 漂移分级 L3 一致：留证据），
    新观察到的指纹放进 `pending_*`，管理员确认后才能转正。

    ⚠ 同 AgentKey：新增列一律不写 `index=True`（与显式 Index 重名会让全新库 create_all 失败）。
    """
    __tablename__ = "ssh_host_keys"
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), unique=True, nullable=False)
    hostname = Column(String(100), default="")
    port = Column(Integer, default=22)
    key_type = Column(String(32), default="")
    fingerprint = Column(String(80), default="")
    # 只存指纹是不够的 —— 指纹一样但密钥不同的概率虽低，比对本身应看下完整密钥。
    public_key_b64 = Column(Text, default="")
    status = Column(String(16), default="pinned")
    pending_key_type = Column(String(32), default="")
    pending_fingerprint = Column(String(80), default="")
    pending_public_key_b64 = Column(Text, default="")
    pending_first_seen = Column(DateTime, nullable=True)
    pinned_at = Column(DateTime, nullable=True)
    last_verified_at = Column(DateTime, nullable=True)
    last_change_at = Column(DateTime, nullable=True)


class Role(Base):
    """角色。权限以 JSON 存储，结构见 backend/services/rbac.py。"""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(String(300), default="")
    builtin = Column(Integer, default=0)
    is_admin = Column(Integer, default=0)
    permissions = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RoleServer(Base):
    """角色授权的主机。严格白名单：角色只可管理这里列出的主机。"""
    __tablename__ = "role_servers"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)


class HostGroup(Base):
    """全局主机分组（所有用户共享，在「主机管理 - 分组管理」维护）。"""
    __tablename__ = "host_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(300), default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class HostGroupMember(Base):
    """分组内的主机。"""
    __tablename__ = "host_group_members"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("host_groups.id"), nullable=False, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    full_name = Column(String(100), default="")
    password = Column(String(200), nullable=False)
    email = Column(String(200), default="")
    role = Column(String(20), default="viewer")  # 冗余的角色 code，仅用于展示/兼容；鉴权以 role_id 为准
    role_id = Column(Integer, ForeignKey("roles.id"))
    status = Column(String(20), default="active")
    preferences = Column(JSON, default=dict)
    must_reset_password = Column(Integer, default=0)  # 1 = 登录后必须修改密码
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    valid_until = Column(DateTime, nullable=True)
    # 首次登录时间：NULL = 还没登录过。配合「首登强制改密」策略判定。
    last_login_at = Column(DateTime, nullable=True)
    # 最近一次改密时间：NULL = 该功能上线前就存在的老账号，按"不过期"处理，
    # 免得一升级把所有人锁在改密页上。
    password_changed_at = Column(DateTime, nullable=True)


class GlobalConfig(Base):
    __tablename__ = "global_config"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(String(200), nullable=False)
    description = Column(String(300), default="")
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


class TrapEvent(Base):
    """事件驱动（Trap / Webhook）上报的实时事件。

    定时采集（Agent 心跳推指标）和按需采集（页面打开时拉一次）都有延迟，
    状态突变（进程崩溃、服务停止、设备端口 DOWN…）等不到下一轮。这类事件由
    Agent / 网络设备**主动 POST** 到 `/api/traps/ingest`，落这张表，
    前端「事件日志」和告警链路直接读它。

    source: agent / snmp / webhook —— 谁报上来的
    event_type: process_crash / service_stop / disk_full / link_down / custom ...
    """
    __tablename__ = "trap_events"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)
    source = Column(String(20), default="agent")
    event_type = Column(String(50), default="custom")
    level = Column(String(20), default="warning")
    message = Column(Text, default="")
    # 上报方附带的原始结构（进程名 / 端口 / 退出码…），原样存 JSON，不猜字段
    payload = Column(JSON, default=dict)
    # 事件在**上报方**本地发生的时间（可能与入库时间差几秒，以这个为准展示）
    occurred_at = Column(DateTime, nullable=True)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    acknowledged = Column(Integer, default=0)
    acknowledged_by = Column(String(100), default="")
    acknowledged_at = Column(DateTime, nullable=True)

    server = relationship("Server")


class DeviceLogEntry(Base):
    """方案 B / 路线 A：从网络设备**内部**拉回来的运行日志（2026-09-21 加）。

    为什么要有这张表
    ────────────────
    网络设备装不上 Agent，也没有 Windows 事件日志可拉；而它自己肚子里是有日志的
    （华为的 logbuffer / trapbuffer）。这些日志**只存在设备内存里**：交换机重启就丢、
    缓冲区满了就覆盖（实测 1024 条缓冲区已被覆盖 2207 次）。所以要趁它在的时候
    主动拉回来存档 —— 这就是「路线 A：只读 SSH 轮询」，四条候选路线里唯一
    **不需要改设备任何配置**的一条。

    只读，怎么保证
    ──────────────
    采集端只发 `screen-length 0 temporary` + `display logbuffer` / `display trapbuffer`
    两条 display 命令，不进 system-view、不 save、不下任何配置。

    去重
    ────
    缓冲区是环形的，每隔几分钟拉一次必然大量重复。用 `fingerprint`
    （设备时间 + 模块 + 助记符 + 正文的哈希）做唯一键，重复的直接跳过，
    只留第一次入库的那条。`seq` 是设备给的序号，会随重启归零，**不能**当唯一键。
    """
    __tablename__ = "device_logs"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    source = Column(String(20), default="logbuffer")
    # 设备侧记录的日志级别（华为 0=EMERG 1=ALERT 2=CRIT 3=ERR 4=WARN 5=NOTICE 6=INFO 7=DEBUG）
    level_code = Column(Integer, default=6)
    level = Column(String(16), default="info")
    module = Column(String(40), default="")
    mnemonic = Column(String(80), default="")
    message = Column(Text, default="")
    raw = Column(Text, default="")
    # 设备本地时间（设备通常没有配 NTP，可能与服务端时钟差很多，**以它为准展示**）
    device_time = Column(String(40), default="")
    occurred_at = Column(DateTime, nullable=True)
    seq = Column(Integer, default=0)
    fingerprint = Column(String(64), default="")
    collected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AgentUpdateTask(Base):
    __tablename__ = "agent_update_tasks"

    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False, index=True)
    package_path = Column(String(500), nullable=False)
    target_version = Column(String(50), default="")
    status = Column(String(20), default="pending")
    progress = Column(Integer, default=0)
    stage = Column(String(100), default="")
    error = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    server = relationship("Server")


class AgentNonce(Base):
    """2026-09-23 开源加固 ⑦：Agent 请求签名的 nonce 落库。

    以前 nonce 只存在进程内存的字典里（`services/agent_identity._NONCE_SEEN`），
    后端一重启就清空 —— 而签名的防重放完全依赖"这个 nonce 我用过了"这件事。
    攻击者截获一个合法签名请求后，只要等到后端重启（升级、改配置、崩一次
    都行），就能把它重放一遍，服务端认。

    落库之后，重放窗口跨越重启依然有效。表很小（每次请求一行，过期即删），
    由 `check_nonce()` 顺手清理。

    ⚠ 与本文件其它新表一致：不写 `index=True`。
    """
    __tablename__ = "agent_nonces"

    id = Column(Integer, primary_key=True, index=True)
    nonce_key = Column(String(160), nullable=False, unique=True)
    seen_at = Column(Float, nullable=False)
