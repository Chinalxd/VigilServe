# VigilServe

面向中小团队的服务器监控与运维平台：把 Windows / Linux 主机与网络设备纳管到一个控制台，
做状态采集、远程操作、Web 终端与远程桌面，并用**按钮级**权限控制每一次敏感动作。

全部数据留在使用者自己的机器与内网，服务端不依赖任何外部云服务。

- 当前版本：服务端 **1.1.59** / Agent **1.1.68**
- 许可证：[GPL-3.0](LICENSE)

---

## 一、软件说明

VigilServe 由三部分组成：

| 组成 | 运行位置 | 作用 |
|---|---|---|
| **服务端** | 一台 Windows 主机 | 后端 API + Web 前端 + 托盘守护程序，提供控制台界面与数据库 |
| **Agent** | 每台被监控主机 | 采集本机状态、执行远程操作、提供 Web 终端与屏幕推送 |
| **托盘程序** | 服务端本机 | 拉起并守护后端，提供开机自启与本地控制面板 |

通信方向：**Agent 主动向服务端注册并上报**（出站连接），服务端不主动连被监控主机。
因此被监控主机不需要放行任何入站端口，跨网段、跨 NAT 的场景也能纳管。

---

## 二、功能说明

**主机管理**
- 主机分组（拖拽调整、折叠），按组筛选查看
- 实时状态采集：CPU / 内存 / 磁盘 / 网络，服务与进程清单
- 远程电源操作：重启、关机（走 Agent，无需 WinRM）
- 资源管理器：浏览与管理远程主机文件系统
- 主机信息台账：操作系统、硬件、业务系统备注
- 应用管理、启动项查看

**远程操作**
- Web 终端：浏览器里开 SSH / WinRM 会话
- 远程桌面：自研 Guacamole 协议实现，支持键鼠注入与屏幕推流

**网络设备**
- 交换机 / 路由器 / 防火墙 / NAS 纳管
- SNMPv3 采集（authNoPriv / authPriv），端口与流量监控；v1 / v2c 明文团体名不支持
- **WEB 管理反向代理**：在控制台里直接打开设备的 WEB 管理页面（独立源，避免跨源干扰）
- 设备日志读取（读取华为 / 华三等设备的运行日志缓冲）

**告警与日志**
- 阈值告警：CPU、内存、磁盘、服务状态、离线
- 邮件推送（SMTP 可在后台配置）
- 审计日志：记录登录、配置变更、远程操作等敏感动作

**权限与准入**
- 角色管理 + 按钮级权限点：每个操作按钮单独受控
- 设备准入：新 Agent 上线须管理员核对配对码批准
- 登录失败锁定（同时防用户名枚举）

---

## 三、部署环境

### 运行时

- 目前暂未适配Windows以外的其他系统

| 组件 | 要求 |
|---|---|
| 服务端 | Windows 10 / Windows Server 2016 及以上（x64），内存 ≥ 4 GB，磁盘 ≥ 2 GB |
| Agent | Windows 10 / Windows Server 2016 及以上（x64） |
| 浏览器 | Chrome / Edge 等现代浏览器 |
| 网络 | 被监控主机需能访问服务端 8001 端口（**出站**即可） |
| 网络设备 | 设备侧无需安装任何软件，开启 SNMPv3（或 SSH / Telnet）后由服务端主动采集 |

安装包自带便携 Python 运行时，目标机**不需要预装 Python**。

### 兼容范围（Windows 主机与网络设备）

> 一句话结论：被监控的 Windows 主机需要 **Windows 10 / Windows Server 2016 及以上（64 位）**；
> 服务端（含托盘）需 **Windows 8.1 / Server 2012 R2 及以上**。
>
> **网络设备不看品牌看通道**：只要开启 **SNMPv3**，接口、流量、CPU、内存、存储卷等基础指标
> 与品牌无关，全部可采；厂商私有增强（温度 / 风扇 / 电源 / 磁盘 / RAID）目前覆盖
> **华为、群晖、思科**三家，其余品牌走标准 MIB 自动兜底。

**Windows 兼容性**

| 组件 | 支持范围 | 状态 | 说明 |
|---|---|---|---|
| Agent 客户端 | Windows 10 / 11、Windows Server 2016 / 2019 / 2022（x64） | 支持 | 由 CPython 3.14 打包（PEP 11 官方口径），安装**不需要管理员权限** |
| Windows Server 2019 / 2022 | 内核与 Windows 10 同源 | 未实测 | 理论可运行，尚未在这两个版本上做真机验证 |
| 远程桌面（屏幕推流） | Windows 10 1903 及以上 | 附加要求 | 依赖 Windows Graphics Capture；低于此版本仅影响远程桌面 |
| 服务端 + 托盘 | Windows 8.1 / 10 / 11、Windows Server 2012 R2 及以上 | 支持 | 运行于便携 Python 3.13 运行时 |
| 无 Agent 的主机 | Windows（WinRM）、Linux（SSH） | 基础采集 | 无需安装客户端即可远程采集基础指标与进程服务，功能少于 Agent |
| — | Windows Server 2012 R2 / 8.1 / 7 及以下、32 位 Windows、ARM64 | 不支持 | 所用 Python 运行时官方支持下限更高；仅发布 x64 安装包 |

真机验证记录：Windows 11（本机）、Windows 10、Windows Server 2016。

**网络设备：采集通道**

| 通道 | 支持范围 | 是否挑品牌 | 说明 |
|---|---|---|---|
| SNMP 轮询 | **仅 SNMPv3**（authNoPriv / authPriv）；鉴权 MD5、SHA、SHA224/256/384/512；加密 DES、AES128/192/256 | 否 | v1 / v2c 明文团体名有意不实现 |
| 基础指标 | 系统信息、运行时间、接口（名称 / 状态 / 64 位流量 / 错包 / 速率）、CPU、内存、存储卷 | 否 | 基于标准 MIB（系统组、IF-MIB、ifXTable、HOST-RESOURCES） |
| 硬件健康 | 温度、风扇、电源、整机功率 | 部分 | 按「厂商私有 → ENTITY-MIB → ENTITY-SENSOR」三级自动择优 |
| 磁盘 / RAID | 名称、型号、状态、温度、RAID 容量 | 群晖 | 依赖群晖私有 MIB；其余品牌按标准存储表采集容量 |
| 命令行终端 | SSH（22）、Telnet（23） | 否 | 凭据独立加密保存，支持主机密钥钉扎 |
| 设备内部日志 | 华为 / 华三 / 锐捷 / 思科 / 中兴 | 有命令表 | 只读拉取日志缓冲区；未识别厂商按 VRP 命令兜底 |
| WEB 管理（反向代理） | 任意带 Web 界面的设备 | 否 | iframe 沙箱 + 一次性票据；账号口令**只填不提交** |

**按设备类别的品牌覆盖**

| 类别 | 可自动识别的品牌 / 型号 | 采集能力 | 真机状态 |
|---|---|---|---|
| 交换机 | 华为 S / CE、华三 S、思科 Catalyst / Nexus、锐捷 RG-S / RG-NBS、Juniper EX、NETGEAR、TP-LINK、D-Link | 全量接口与流量、CPU、内存；华为另有温度 / 风扇 / 电源 / 功率 | 华为实测 |
| 路由器 | 华为 AR / NE、华三 MSR / SR、思科 ISR / ASR、锐捷 RG-EG / RG-RSR、MikroTik RouterOS | 通用指标（接口、流量、CPU、内存） | 未实测 |
| 防火墙 | 华为 USG、华三 F1000、思科 ASA、Juniper SRX、FortiGate、深信服、山石、Palo Alto | 接口、CPU、内存；思科 ENVMON 提供电源与风扇状态 | 未实测 |
| NAS / 存储 | 群晖 DS / RS 全系、QNAP TS-x、运行 net-snmp 的 Linux 存储 | 群晖：整机状态、温度、电源、风扇、磁盘、RAID；QNAP 与通用：HOST-RESOURCES + UCD 内存细分 | 群晖实测 |
| 无线 AP | 华为 AP / WA、思科 Aironet、锐捷 RG-AP、Aruba、UniFi | 通用指标 | 未实测 |

厂商、型号、类别均通过 SNMP 的 `sysObjectID` 企业号与设备自述串自动识别；识别不出时显示「未识别」并由人工填写，不做猜测。
未列出的品牌仍可通过通用 MIB 采集基础指标。

**接入前请确认**

- **设备必须开启 SNMPv3。** 仅支持 v1 / v2c 的老设备（部分家用路由器、早期 NAS）无法接入。
- **群晖 / QNAP 无法采集设备内部日志。** 其运行日志为文件形态，没有可轮询的命令行缓冲区。
- **网络设备无法安装 Agent。** 指标采集、命令行、WEB 管理均由服务端主动发起，设备侧无需安装任何软件。
- **所有设备的 WEB 登录都只填不提交。** 系统把账号与口令填进登录页，登录按钮与两步验证验证码始终由人工处理。
- SNMP 认证连续失败时，华为等品牌会临时锁定来源 IP，系统已内置失败熔断，批量扫描前请确认凭据正确。

### 构建环境（仅在从源码打包时需要）

| 工具 | 版本 |
|---|---|
| Python | 3.13 |
| Node.js | 18 及以上 |
| [Inno Setup](https://jrsoftware.org/isinfo.php) | 7（打 Windows 安装包） |
| PyInstaller | 6.x（打托盘程序与 Agent） |

---

## 四、快速开始

### 1. 安装服务端

运行 `VigilServe-Setup-<版本>.exe`，按向导完成安装。默认安装目录：

```
C:\Program Files\VigilServe
```

安装完成后托盘程序会自动启动后端，浏览器访问：

```
https://<服务端IP>:8001
```

> 证书由服务端首次启动时自动签发（自签证书），浏览器会提示"不安全"，选择继续访问即可。
> 托盘图标上右键可以打开控制面板、重启服务等。

### 2. 首次登录与初始管理员口令

**系统不再使用任何固定初始口令。** 首次安装时由服务端**随机生成**一个管理员口令，
明文写在服务端本机这个文件里：

```
C:\Program Files\VigilServe\backend\data\initial_admin_password.txt
```

> Windows 下即 `%ProgramFiles%\VigilServe\backend\data\initial_admin_password.txt`。

- 用该口令登录 `admin` 账号，**服务端会强制先修改口令**才能继续使用；
- 改密成功后文件会被**自动删除**；
- 口令文件任何人可读 ⇒ 拿到它等于拿到管理员，**首次登录后务必确认它已消失**；
- 忘记口令，可在安装目录运行 `重置管理员密码.bat`（等价于
  `python backend\reset_admin_password.py`），重置后**需重启服务端**生效。

### 3. 纳管一台被监控主机

1. 在被监控主机上运行 `VigilServeAgent-Setup-<版本>.exe`；
2. Agent 托盘里打开配置面板，填写**服务端地址**（`https://<服务端IP>:8001`）；
3. Agent 自动注册，控制台「设备管理 → 注册管理」出现待批准设备；
4. 核对 Agent 面板显示的 **8 位配对码**与控制台一致，点击批准即可开始采集。

### 4. 端口一览

| 端口 | 方向 | 用途 |
|---|---|---|
| 8001 | 入站（服务端） | 后端 API + Web 前端（HTTPS） |
| 8009 | 入站（服务端） | 网络设备 WEB 管理反向代理（独立源） |
| 9998 | 本机（被监控主机） | Agent 本地 API，默认仅本机 + 服务端证书校验 |

---

## 五、目录结构

| 目录 | 说明 |
|---|---|
| `backend/` | FastAPI + SQLAlchemy 后端，SQLite 库位于 `backend/monitor.db` |
| `frontend/` | React + Vite 前端，构建产物 `frontend/dist/` |
| `tray/` | Windows 托盘守护程序（PyInstaller 打包） |
| `agent/` | 被监控主机上的采集 Agent（PyInstaller 打包） |
| `installer/` | Inno Setup 打包脚本（`build_installer.py` + `setup.iss`） |
| `verify_version.py` | 版本号一致性自检 |
| `DEPLOY.md` | 更详细的部署方式与环境变量 |

---

## 六、从源码构建

构建顺序有依赖，**不要跳过前置步骤**：

```bash
cd frontend && npm install && npm run build          # ① 前端产物
python -m PyInstaller tray/VigilServeTray.spec       # ② 托盘 exe
cd agent && python build_installer.py                # ③ Agent 安装包
cd installer && python build_installer.py            # ④ 服务端安装包（内含托盘）
```

`installer/build_installer.py` 自带两道护栏：

1. **前置产物校验** —— `frontend/dist`、`tray/dist/VigilServeTray.exe`、
   `agent/dist/VigilServeAgent/VigilServeAgent.exe`、`agent/agent_config.json`
   缺一个就拒绝出包，避免打出"半新半旧"的安装包；
2. **版本一致性校验** —— staged 树里的服务端 / Agent 版本必须与源码一致。

开发模式直接运行：

```bash
cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000
cd frontend && npm run dev
```

---

## 七、部署后必读

- **备份迁移要带两样东西**：`backend/monitor.db` 与 `backend/data/secret.key`。
  主机凭据是用 `secret.key` 加密后存进数据库的，**只拷 .db 会导致密文永久无法解密**。
- 证书私钥（`backend/certs/ca.key`、`server.key`）与 `secret.key` 绝不能打包进安装包，
  `installer/build_installer.py` 已把它们列为敏感文件排除。
- 卸载时选择"清除全部数据"，会连同安装目录、运行期缓存与用户数据一并删除；
  选择保留则只删程序文件，数据留在原地便于重装后继续使用。
- 生产环境保持 HTTPS。设 `VIGILSERVE_TLS=0` 会让后端明文运行，仅限排障。

---

## 八、许可证

本项目采用 [GNU GPL v3.0](LICENSE) 许可证。

---

## 九、相关文档

- [DEPLOY.md](DEPLOY.md) —— 详细部署方式与环境变量清单
