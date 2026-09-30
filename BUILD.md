# VigilServe 纯净源码副本 · 构建说明

本目录是一份**可直接用于打包、也可直接推送到 GitHub / Gitee** 的源码副本，
不含任何运行数据、密钥、日志、数据库与构建产物。

> 本副本对应 **服务端 1.1.65 / Agent 1.1.68**（2026-09-30 导出）。
> 许可证 **GPL-3.0**（根目录 `LICENSE`）。
>
> 本次（相对上一版 1.1.59）的实质改动集中在两处：**SNMP 排障的正确性**，
> 以及**打包链路自身"静默带旧产物"的两个洞**：
>
> 1. **1.1.62** 设备用 `errorStatus` 明确回了错，却被显示成「设备未返回 sysDescr」；
>    失败框下面那句固定的「常见原因：IP 不通 / 端口被挡」也改由后端判定归属
>    （只在设备**确实没响应**时才显示）。
> 2. **1.1.63** 设备回的**报告 PDU**（pysnmp 把计数器 OID 原样塞进 `errorIndication`，
>    界面上就是一串裸 OID 如 `1.3.6.1.6.3.11.2.1.3`）翻成人话：
>    MPD 三条 + USM 六条，每条给结论并说明下一步查什么。
> 3. **1.1.64** 本机异常不再被当成"设备回了话"：缺 pysnmp 这类问题现在归
>    `local`，并直接点名"问题出在**装 VigilServe 服务端的这台机器**上"。
>
> 4. **1.1.65（一）托盘版本号没跟上**：托盘 exe 不在构建链路里重建（只校验"在不在"），
>    1.1.63/1.1.64 只改了版本常量，结果安装包是新的、托盘界面还写着 1.1.62。
>    现已加 **托盘版本闸门**：exe 内嵌 FileVersion 与 `TRAY_VERSION` 不符即拒绝出包。
> 5. **1.1.65（二）安装还没点「完成」就弹配置面板**：`[Run]` 里那条没有 `postinstall`，
>    会在安装一结束就执行。已改到 `[Code]` 的 `ssDone`（用户点完「完成」之后）再拉起。
>
> 详见 `CHANGELOG.md` 的 1.1.62 / 1.1.63 / 1.1.64 / 1.1.65 四条。

代码分两部分：

| 部分 | 目录 | 说明 |
|---|---|---|
| **服务端** | `backend/`、`frontend/`、`tray/`、`installer/` | 后端 API、Web 前端、Windows 托盘、Inno Setup 打包脚本 |
| **Agent** | `agent/` | 被控端采集程序 + 自身打包脚本（`agent/installer/VigilServeAgent.iss`） |

目录结构与开发时的源码树**完全一致**，`installer/build_installer.py` 无需任何改动即可在此运行。

---

## 一、从零打出安装包

前置：Windows + Python（项目依赖见各 `requirements.txt`）+ Node.js + Inno Setup 7。

```bat
:: 1) 前端（产出 frontend/dist）
cd frontend && npm install && npm run build

:: 2) 托盘（产出 tray/dist/VigilServeTray.exe）
cd ..\tray && pip install -r requirements.txt && python build.py

:: 3) Agent（产出 agent\dist\VigilServeAgent\VigilServeAgent.exe 与 agent\installer\output\*.exe）
cd ..\agent && pip install -r requirements.txt
python build_installer.py

:: 4) 便携 Python 运行时（可选，产出 installer\portable_runtime）
cd ..\installer && python build_python_runtime.py

:: 5) 打服务端安装包（产出 installer\output\VigilServe-Setup-<ver>.exe）
python build_installer.py
```

`build_installer.py` 自带两道闸：构建前置产物缺失会直接失败（除非显式 `--allow-stale`）；
产物版本号与源码树、与 `setup.iss` 的 `MyAppVersion` 不一致也会失败。
发布前可先跑 `python verify_version.py` 校验 **15 处**版本号（服务端 / Agent 两个真源）。

另有两个外部素材需要从 `F:\VigilServe` 取：`logo_定稿.png`（转 ico）与
`VigilServe用户协议.docx`（转 license.txt）。

## 二、首次运行会自动生成的东西（**不在仓库里，也不该进仓库**）

- `backend/certs/` —— 本地 CA 与服务器证书（含私钥）
- `backend/data/secret.key` —— 主机口令的 Fernet 密钥
- `agent/identity/` —— Agent 客户端 RSA 私钥与证书
- `backend/monitor.db` —— SQLite 运行库

这些由目标机器首次启动生成，每台机器一套；打进安装包会让所有部署共用同一把密钥。

管理员口令忘记时，用 `reset_admin_password.bat`（或 `python backend\reset_admin_password.py`）离线重置。

## 三、本副本已排除的内容

数据库与 WAL（`*.db*`）、日志（`*.log`）、备份（`*.bak*`）、
`__pycache__`、`node_modules`、全部 `dist/ build/ output/ outputs/ installer/source/ installer/portable_runtime/`、
`backend/data/`、`backend/certs/`、`agent/logs/`、`agent/ca/`、`agent/identity/`、
`.workbuddy/`、`VigilServe_backup/`、`.git/`、
以及 **`tray/docs/`（4 个原始 .docx，852 KB，含个人联系方式与捐赠收款码）**。

⚠ 反向说明（两条例外）：`agent/agent_config.json` 与 `backend/email_config.json`
虽落在被忽略的目录/路径规则上，但已在 `.gitignore` 里**显式放行**（`!` 规则）——
它们是**全空模板**，`installer/build_installer.py` 的前置校验明确要求
`agent_config.json` 存在，缺了从仓库 clone 出来直接打包失败。

## 四、清理注释的说明

副本中的注释已按"只留核心"精简，规则为：

- **保留**：模块 / 类 / 函数 docstring、JSDoc；安全警告、业务口径与约束说明；
  TODO / FIXME；工具指令（`# noqa`、`# type:`、`# ruff:`、`# fmt:`）；版权与许可头。
- **删除**：复述代码的行内注释、分节横线、装饰性块注释、步骤流水账。

清理过程经过等价性校验：Python 用 `tokenize` 逐一比对 token 序列、
JS/JSX 用 `@babel/parser` 比对抽象语法树（去掉位置信息），
**确认只删了注释，未改动任何一个代码字符**。

## 五、环境相关残留的清理情况

本副本已清除开发/测试环境的硬编码，交付给外部时不会带上具体部署信息：

- **内网 IP 全部移除**：原先 `backend/routes/file_explorer.py`（14 处）、`backend/main.py`
  把某个内网地址写进了"本机地址"白名单元组 —— 已删除，现只保留
  `0.0.0.0` / `127.0.0.1` / `localhost` 这三个与部署无关的通用值。
  注释里提到的具体设备地址（含真机型号与 IP）也已改为中性描述或去掉地址。
- **机器专属绝对路径改为相对路径**：`agent/installer/VigilServeAgent.iss` 原先有 11 处
  `C:\Users\<某人>\...` 的绝对路径（别人拿到根本编译不过），现全部改成相对 `.iss` 文件的
  `..\` 路径，`OutputDir` 改为 `output`。
- **打包工具路径不再写死**：`agent/build_installer.py` 原先硬编码某个 venv 里的
  `pyinstaller.exe`，现改为三级回退：环境变量 `VIGILSERVE_PYINSTALLER` → PATH 上的
  `pyinstaller` → `python -m PyInstaller`。
- **示例数据脱敏**：`frontend/src/services/hostInfoMock.js` 里的真实主机名与内网地址
  已换成 `EXAMPLE-HOST` 与 RFC 5737 文档地址（`192.0.2.x`）。
- **CHANGELOG 现场案例脱敏**（2026-09-30 新增）：1.1.60 ~ 1.1.64 几条为说明问题引用了
  真机地址（一台交换机、一台装服务端的主机），已换成 RFC 5737 文档地址
  `192.0.2.10` / `192.0.2.11`。**案例结论本身保留**（例如"缺 group 导致
  `snmpUnknownPDUHandlers`"），只换掉地址。

## 六、托盘内嵌文档

`tray/docs_bundle.py` 已内嵌"用户协议 / 免责声明 / 支持作者 / 联系作者"的正文，
**源 .docx 不再随代码分发**（`tray/docs/` 已移除）。

因此 `tray/build_docs_bundle.py` 需要自备 docx 才能运行：
把 4 个源文件放回 `tray/docs/`（`VigilServe用户协议.docx`、`VigilServe免责声明.docx`、
`支持作者.docx`、`联系作者.docx`）后再执行。若不需要重新生成，可直接忽略该脚本。

> 2026-09-29：免责声明里的**第三方组件表格已删除**（4 张表：后端服务 / Web 前端 /
> Agent 客户端 / 系统级依赖）。这些版本号随迭代必然失效，留在托盘界面里是误导。
> 「第三方组件：…受各自许可协议约束…」这句责任条款保留。

## 七、本副本的复查结果（2026-09-30）

导出后做的四项检查：

| 检查项 | 结果 |
|---|---|
| 缓存 / 构建产物残留 | **0** —— 无 `__pycache__`、`node_modules`、`dist/`、`build/`、`output/`、`.git/` |
| 调试产物 / 敏感文件 | **0** —— 无 `*.db*`、`*.log`、`*.tmp`、`*.bak*`、`*.pyc`、`*_old*`、`*.key`、初始口令文件 |
| 环境残留（IP / 绝对路径 / 主机名） | **0 处真问题** —— 源树本次同步脱敏（`CHANGELOG.md` 两台真机地址换成 `192.0.2.10` / `192.0.2.11`），副本与源树两侧一致；扫描命中全是白名单误报：SNMP OID 片段（`1.3.6.1.6.3.15.1.1.x` 被读成 `6.3.15.1`）、版本号（`1.1.65.0`）、SVG path 坐标、`C:\Users\Administrator` 通用示例值 |
| 代码等价性 | Python **84/84** token 一致 + ast.parse 通过、问题 0；JS/JSX **46/46** AST 等价；`verify_version.py` 15/15。**本次 `--allow-diff` 留空即通过**（源树也已脱敏） |
| 体量 | 209 个文件 / 5.6 MB（含 `BUILD.md`） |

**已知保留项**（有意不删，详见下文）：

- **约 20 个零引用的顶层函数**（如 `agent/api_server.py` 的 `open_web_config_browser`、
  `agent/config.py` 的 `get_auto_start`、`backend/services/rbac.py` 的 `op_codes`）。
  未清理：部分是对外工具 / 排障入口，且 agent 侧的会触发 `self_check` 指纹变化。

> **2026-09-29 晚追加**：39 处未使用的 import **已清理完毕**（后端 30 / Agent 7 / 托盘 2）。
> 有意保留 3 处——`backend/main.py` 的 `GlobalConfig` / `AgentUpdateTask`（`create_all` 的
> **建表注册清单**，删了会让这两张表可能不建）与 `backend/services/__init__.py` 的
> `collect_all_servers`（包级重导出）。详见 `CHANGELOG.md` 的 1.1.58 条。
- `backend/services/agent_identity.py` 的 `cert_is_trusted()`：1.1.51 方案 A 之后的
  死代码，已把 docstring 改为明示「不参与认证路径」，保留是因为回归脚本在测它。
- `backend/services/collector.py` 等处的 `print(...)` 采集日志：项目既有的运行日志口径
  （非调试残留），与 `logger` 并存。前端 `console.log` **0 处**。
