# 变更日志

> 本文件自 **v1.1.43** 起开始维护。更早的变更没有留档，需要查历史请翻 `docs/`
> 下的评估文档与 git 记录。

格式参照 Keep a Changelog：`新增` / `修复` / `变更` / `安全`。

## [1.1.65] - 2026-09-30（服务端；Agent 仍 1.1.68）—— 托盘版本没跟上 + 安装没点完成就弹窗

### 🚨 修复一：托盘界面版本号停在 1.1.62

现场：覆盖安装 1.1.64 后，交换机等网络设备采集正常，但**托盘界面仍显示 1.1.62**。

**根因：托盘 exe 不在构建链路里重建。** `tray/dist/VigilServeTray.exe` 只是
`REQUIRED_ARTIFACTS` 里的一项 —— 构建脚本**只校验它在不在**，真正的打包得单独跑
PyInstaller。1.1.63 / 1.1.64 只改了 `tray_app.py` 的版本常量与 `tray/version_info.txt`，
exe 还是上一轮（12:13）那版。结果安装包是新的、后端代码是新的、托盘界面是旧的，
**全程没有任何告警**。

改动：

* 按 1.1.65 重新构建托盘 exe（内嵌版本资源已核对为 `1.1.65.0`）；
* `installer/build_installer.py` 新增 **托盘版本闸门** `check_tray_exe_fresh()`
  （挂在 phase 3.5）：比对 exe 内嵌的 FileVersion 与 `tray_app.py` 的 `TRAY_VERSION`，
  不一致**直接拒绝出包**（`--allow-stale` 可强制）。
  思路同 1.1.60 那道运行时依赖闸门：**先验后拷，"静默带旧产物"必须变成硬失败**。

### 🚨 修复二：安装向导还没点「完成」，配置面板就弹出来了

**根因**：`[Run]` 里拉起托盘的那条**没有 `postinstall`**。不带这个 flag 的 [Run] 条目
会在**安装步骤一结束、「完成」页还没点**的时候执行 —— 于是安装窗口还开着，
托盘已经起来并把配置面板推到前台。

为什么不是简单加回 `postinstall`：那会让「安装完成」页多出一个与 `[Tasks]` 里
`launchtray` 同义的勾选框，同一样事问两次（这正是当初去掉它的原因）。

改动：删掉该 `[Run]` 条目，改在 `[Code]` 的 **`ssDone`**（用户点完「完成」、
向导关闭之后）里按 `WizardIsTaskSelected('launchtray')` 拉起托盘；
静默安装保持原行为（不启动）。勾选仍然只在「选择附加任务」页出现一次。

## [1.1.64] - 2026-09-30（服务端；Agent 仍 1.1.68）—— 本机缺依赖不能再被当成"设备回了话"

### 🚨 修复：`ModuleNotFoundError` 被判成 device-reply

现场：用一套**没装 pysnmp** 的 Python 运行时起服务端，探测交换机返回
`ModuleNotFoundError: No module named 'pysnmp'`，`error_kind` 却判成了
`device-reply`（"设备收到了请求并明确回了错"）—— 界面据此**不显示**任何本地排查提示，
等于把人往设备凭据方向带。1.1.60 修的正是"随包的运行时缺 pysnmp"，
这个判定会让同类问题再次变得难发现。

改动：

* `error_kind()` 判定顺序改为 **local → no-response → device-reply**，新增
  `_LOCAL_ERROR_MARKERS`：`ModuleNotFoundError` / `ImportError` / `AttributeError` /
  `TypeError` / `NameError` / `NotImplementedError` / `PyAsn1UnicodeEncodeError` /
  `ZeroDivisionError` / `WrongValueError` —— 这些**只可能是本机抛的**，
  设备永远不会"说"出这些词；
* `collect_snmp_device()` 新增 `except ImportError` 分支（`ModuleNotFoundError` 是其子类）：
  文案直接点名「问题出在**装 VigilServe 服务端的这台机器**上，请重新安装或修复服务端」，
  并且不再套 `SNMP 交互失败`（那个前缀是给设备/网络类错误用的）。

验证：回归 34 项全绿（新增 G1~G10 十条）；另在**真实缺失环境**里跑了一次真探测，
`error_kind='local'`、文案指明"装服务端的这台机器"。

## [1.1.63] - 2026-09-30（服务端；Agent 仍 1.1.68）—— 把设备回的报告 PDU 翻成人话

### 🚨 修复：失败框里甩一串裸 OID，没有人看得懂

现场：交换机（192.0.2.10）测试连接只显示 `1.3.6.1.6.3.11.2.1.3`，
管理员拿到这一串无从下手 —— 既不知道设备是回应了还是没回应，也不知道该改什么。

**这是什么**：设备回的不是错误码，而是一份 **报告 PDU**（report）。pysnmp 把里面那个
计数器 OID **原样**塞进 `errorIndication`，于是界面上就是一串数字。这一串其实是设备的
自述（RFC 3412 的 MPD 计数器、RFC 3414 的 USM 计数器），必须翻译。

改动：

* 新增 `_REPORT_OID_HINTS`：MPD 三条（`1.3.6.1.6.3.11.2.1.1~3`）+ USM 六条
  （`1.3.6.1.6.3.15.1.1.1~6`），每条给一句结论并说明下一步查什么；
* `friendly_snmp_error()` 先认 `1.3.6.1.` 前缀再走原有逻辑；**没收录的 OID 明说**
  「这一串还没收录，把它发给我们就能补进去」，不再假装没看见；
* 这类错误归属判为 `device-reply` —— 设备确实回了话，不能提示去查防火墙。

配套现场工具 `.workbuddy/tools/snmp_v3_probe.py`：四项
（`errorIndication` / `errorStatus` / `errorIndex` / `varbinds`）**永远全打**，
成功时也打，方便打包前核对"是不是真的干净地成功了"。

### 现场结论：192.0.2.10（华为 S5731S-H48T4X-A）

交换机上有 `snmp-agent usm-user v3 admin group admin`，但**从未定义
`snmp-agent group`** —— group 不存在就没有 read-view，VACM 放行不了，
MPD 于是回 `snmpUnknownPDUHandlers`（`1.3.6.1.6.3.11.2.1.3`）。
用户名、鉴权、加密三步其实全都通过了。

已在设备上补齐 `snmp-agent group v3 admin privacy read-view/write-view/notify-view
ViewDefault`（配置已 `save`，回滚 `undo snmp-agent group v3 admin`），
端到端复测通过：vendor=华为 / model=S5731S-H48T4X-A / category=switch / sysName=HUAWEI。

## [1.1.62] - 2026-09-30（服务端；Agent 仍 1.1.68）—— 把"设备回了什么"原样说出来

### 🚨 修复：设备明确回了错，却被显示成「设备未返回 sysDescr」

现场：交换机（192.0.2.10）测试连接报 `设备未返回 sysDescr`，管理员照失败框下面
那句固定的「常见原因：IP 不通 / UDP 161 被防火墙挡了 / 用户名或口令不对…」
去查网络和防火墙 —— 方向全错。

**根因**：`_collect_once()` 只看了 `errorIndication`，**把回应 PDU 里的 `errorStatus`
整个丢掉了**。而按 RFC 3416 §4.2.4，`errorStatus` 非 0 时设备会把 varbind 的值填成
`unSpecified` —— pysnmp 里就是一个 `Null('')`（实测其 `prettyPrint()` 是空串、
`isinstance(x, OctetString)` 为 `False`），于是掉进"未返回 sysDescr"分支。
**设备收到了请求、写了原因，我们却当它没说话。**

改动：

* 新增 `_ERROR_STATUS_HINTS`（RFC 3416 的 1~18 全部取值）+ `error_status_hint()`：
  `errorStatus ≠ 0` 直接给中文结论，并标注「设备收到了请求并作出了回应」，
  把"设备回了错"和"没响应"明确区分开；
* 新增 `_status_code()`（容错取整）与 `describe_varbind()`：sysDescr 为空时把
  **实际拿到的类型 / 几个 varbind** 一并说清，不再只丢一句"未返回"；
* 新增错误归属 `KIND_NO_RESPONSE / KIND_DEVICE_REPLY / KIND_LOCAL` 与 `error_kind()`，
  失败结果里带 `kind` 并透传给界面；判不出来按 `device-reply`
  （宁可少提示一句，也不能对着已回应的设备提示"查防火墙"）。

### 修复：失败框不再无脑提示网络类原因

`NetworkDevices.jsx` 那段「常见原因」改为**只在 `error_kind === 'no-response'` 时**
才渲染，文案也换成真正对得上"没响应"的几条（IP / 端口被挡 / 没开 SNMP /
源 IP 被限流临时锁），并保留一句"少数设备在凭据不符时也会静默丢包"的兜底。

### 附带：现场诊断脚本

`.workbuddy/tools/snmp_v3_probe.py` —— 直接用 pysnmp 发包，把
`errorIndication / errorStatus / errorIndex / varbinds` 原样打出来并区分三种情况
（没收到 / 收到了并明确回错 / 正常回值），支持 `--sweep` 扫协议组合。
（脚本在工作区工具目录，不随安装包分发。）

## [1.1.61] - 2026-09-30（服务端；Agent 仍 1.1.68）—— SNMPv3 短口令误报 + 网络设备口令显隐

### 修复：SNMPv3 口令不足 8 位，被报成「设备不接受这组 SNMPv3 参数」

现场现象：新增 / 测试网络设备时提示
`设备不接受这组 SNMPv3 参数（…）（设备返回：WrongValueError({'name': (1, 3, 6, 1, 4, 1, 20408, …`

`1.3.6.1.4.1.20408` 是 **pysnmp 自家的企业号**；被拒的那一列是 `pysnmpUsmSecretAuthKey`
（`PYSNMP-USM-MIB` 的鉴权口令列，约束 `ValueSizeConstraint(8, 65535)`，`.3` 是加密口令列）。
也就是说 —— **这是本机 pysnmp 在发包之前就拒绝，设备与网络全程没有参与**。
对着 RFC 5737 保留地址 `192.0.2.1`（永不路由）一样能复现：口令 6 / 7 位必报，
8 / 64 / 100 位正常发出（**没有上界**），含中文报 `PyAsn1UnicodeEncodeError`。

改动（`backend/services/snmp_collector.py`）：

- 新增 `SnmpCredentialError` + `validate_credentials()`，**发包前**校验
  非空 / 纯 ASCII / 至少 8 位（RFC 3414 对 passphrase 的硬性要求）；
- `_usm_candidates()` 透传该异常，不让「换个方言再试」把它吞掉、再拿另一套参数撞设备；
- `collect_snmp_device()` 直接把结论抛给前端，不再套「SNMP 交互失败：」前缀、不再附一堆 OID；
- 删掉 `_ERROR_HINTS` 里那条错误映射（它会把管理员引到设备侧去查），
  `friendly_snmp_error()` 改为单独拦 `wrongvalueerror` / `pyasn1unicodeencodeerror`。

顺带更正两处错误归因：注释里写的「v3 用户名不存在时会抛 WrongValueError」是错的 ——
实测用户名不存在时 pysnmp 回的是可正常翻译的 `usmStatsUnknownUserNames`，与本错无关。
另外实测 `authKey=""`（空串）在 pysnmp 7.1.29 下会抛 `ZeroDivisionError`，
新的前置校验把它一并盖住。

### 变更：新增 / 编辑网络设备窗口，鉴权口令与加密口令各加一个明文切换图标

`.nd-pwd-wrap` / `.nd-pwd-toggle`，与登录页 `.pwd-toggle` 用的是同一套
`ui-eye` / `ui-eye-off`（15px、`currentColor`、无底无边、默认半透明）。
输入框被禁用时（noAuthNoPriv 下的鉴权口令、authNoPriv 下的加密口令）开关同步禁用；
重新打开弹窗时明文自动收回。

## [1.1.60] - 2026-09-30（服务端；Agent 仍 1.1.68）—— 修复安装包静默带出陈旧 Python 运行时

现象：192.0.2.11 上「测试连接网络设备 NAS」失败，报 `No module named 'pysnmp'`。

根因不在现场而在构建：`installer/build_installer.py` 只是把 `portable_runtime`
原样 `copytree` 进包里，**从不校验它是否装齐 `requirements.txt`** —— 于是事后
往 requirements 里加的依赖会静默带病发包。顺带查出已发货的 1.1.59 包内其实是旧栈
（fastapi 0.115.6 / starlette 0.41.3，含 14 条 starlette 漏洞 + CVE-2026-24486），
那次升级从未落到任何环境。

改动：新增 **phase 4.0 运行时依赖闸门** —— 先验后拷，复用 `build_python_runtime.py`
的三道判据（requirements 全量可导入 + 版本对账），不过闸就不进包。

## [1.1.59] - 2026-09-29（服务端 + Agent 1.1.68）—— 卸载残留：勾选清数据后连目录一起删

### 修复：服务端卸载后 `C:\Program Files\VigilServe` 残留约 30 MB

现场现象：1.1.57 卸载时勾选「清除全部数据」，程序目录里仍剩下 `backend` 与
`python_runtime` 两个文件夹、约 30.5 MB 删不掉。

根因不是"权限不够"，而是 **Inno 只删它自己安装时记录过的文件**：

- `backend\__pycache__`、`python_runtime\Lib\**\__pycache__` 是 python 一导入
  就生成的**运行期产物**，从来没出现在安装清单里；
- Inno 删完它认识的文件后再试着移除目录 —— 目录里只要还剩一个它不认识的文件，
  整个目录就删不掉。剩的正是这些 `.pyc`。

改动（`installer/setup.iss`）：

- `[UninstallDelete]` 补 `python_runtime` / `frontend` / `tray` / `branding` /
  `scripts` / `logs` / `docs_bundle` 的 `filesandordirs` 整树删除，并加一条
  `dirifempty {app}` 兜底；
- `[Code]` 新增 `CleanupInstallDir`（选清除时把 `{app}` 清空）、`RemovePyCache`
  （保留数据时清掉 `backend` 下的 `__pycache__`）、`ScheduleDeferredDirRemove`
  （延迟 5 秒的 `rd /s /q`，专门对付"卸载器自己删不掉自己"）；
- 卸载回调顺序调整为 **先停服、再删库**：以前是先删数据后停服，后端 python
  正握着 `monitor.db` 的句柄，删除必然失败。

已用最小工程做过对照实验：不加修复时 `backend` / `python_runtime` 两个目录连同
其中的 `.pyc` 完整残留；加上后目标目录在卸载结束数秒内彻底消失。

### 修复：Agent 勾选「清除配置」后 `VigilServe` 目录与空文件夹残留

`agent/installer/VigilServeAgent.iss`：

- `ApplyPurgeConfigOnUninstall` 从只删 `Config\Agent` 改为删整个 `Config`；
- `CleanupLeftovers` 在勾选清除时用同样的延迟 `rd /s /q` 把
  `%LOCALAPPDATA%\VigilServe` 连同里面残留的空文件夹一并抹掉；
  未勾选时仍保持原行为（仅在目录已空时才 `RemoveDir`，配置不会被误删）。

## [1.1.58] - 2026-09-29（服务端 + Agent 1.1.67）—— 死代码清理 + 重打安装包

### 变更：清理 39 处未使用的 import

对源码树做死代码复查，清掉 39 处"导入了但全仓一次都没用"的名字：

- **后端 30 处**：`routes/agent.py`（`json`/`base64`/`hashlib`/`SessionLocal`/`Alert`/`AESGCM`）、
  `routes/servers.py`（`get_current_user_full`/`timedelta`/`_try_real_or_sim`）、
  `routes/logs.py`（`and_`/`get_current_user_full`）、`routes/file_explorer.py`
  （`socket`/`unquote`/`tempfile`）、`routes/rdp.py`、`routes/config.py`、
  `routes/metrics.py`、`routes/network_web.py`、`routes/auth.py`、
  `routes/agent_update.py`、`services/*`、`web_proxy_server.py`、`main.py`
  （`codecs`）、两个运维脚本。
- **Agent 7 处**：`agent.py`（顶层 `json`、函数内 `socket`）、`api_server.py`
  （`asyncio`、`unquote`）、`connector.py`（`hmac`/`base64`）、
  `remote_desktop.py`（`sys`/`urllib.request`）、`uninstall_report.py`（`os`）、
  `agent_headless.py`（`logger as log`）。
- **托盘 2 处**：`build_docs_bundle.py`（`os`、`Inches`/`Pt`）。

⚠ 清理时**刻意保留了两处**，它们看着像死导入、实际是"注册性导入"：

- `backend/main.py` 的 `GlobalConfig` / `AgentUpdateTask` —— 这两个模型类只在
  main.py 被导入时才会注册进 `Base.metadata`。`init_db()` 走
  `Base.metadata.create_all()`，删掉它们等于把建表正确性押在"别的路由模块
  恰好也 import 了"上。这是**建表清单**，不是死代码。
- `backend/services/__init__.py` 的 `collect_all_servers` —— 包级重导出，是
  `services` 包对外 API 的一部分，删了会让 `import services` 不再连带加载
  collector。

另有 3 处"疑似"经人工确认为**假阳性，不动**：`routes/agent.py` 的 `Optional`
（字符串注解里的类型引用）、`_operation_level_from_legacy`（try-import + fallback
定义集合的一员，删了兜底不完整）、`remote_desktop.py` 的 `windows_capture`
（带 `# noqa: F401`，是依赖可用性探测）。

### 验收

- `py_compile` **84/84** 通过；`find_undefined_names.py` 对 `backend/ agent/ tray/`
  三目录 **0 处可疑**（76 处全部在 `installer/portable_runtime/` 第三方代码里）。
- 复扫剩余未使用 import：**3 处**，且恰好就是上面有意保留的 3 个。
- 版本号 15/15（服务端 1.1.58 / Agent 1.1.67）。
- 重打：前端 dist、托盘 exe、Agent 安装包、服务端安装包。

## [1.1.57] - 2026-09-29（服务端 + Agent 1.1.66）—— 第五轮安全审计整改

本轮是 `docs/安全审计与交付审查-v1.1.56.md`（P0×0 / P1×1 / P2×5 / P3×4）的落地。

### 安全

- **S-3（P2）Agent 9998 未注册窗口收窄**：`agent/api_server.py` 的 `_authorized()`
  在 token 为空（尚未注册）时，原来只要来源是 loopback 就**任何路径**都放行。
  Agent 通常以 SYSTEM 权限运行，本机任意用户态进程因此能匿名打到
  `/ws/terminal`（直起 cmd.exe）和 `/power`（重启/关机）。现在未注册一律 401，
  只留 `/ping` 与「loopback + 本机配置口令」的 `/config`。
- **S-8（P3）`_gate()` 判定顺序**：`routes/network_web.py` 原来先判设备类型、
  后判权限与归属。无权用户拿 400/403 就能区分"这个 id 是不是网络设备"
  （实测 id=1/4 → 400、id=3 → 403），等于白送资产清单。改为**先鉴权、后业务**，
  无权一律 403。
- **S-4（P2）`check_nonce()` 不再替调用方提交**：它在认证路径里对路由
  `Depends(get_db)` 传进来的业务会话做 `db.commit()`，等于把路由还没写完的改动
  一起落盘，之后 `db.rollback()` 撤不回来（请求被判 401，副作用却留下了）。
  改为：借来的会话只 `flush()`，会话是自己开的才 `commit()`。

### 变更

- **托盘免责声明去掉第三方组件表格**：`tray/docs_bundle.py` 的免责声明由 29 块
  减到 **21 块、0 张表格**。删的是「第三方组件如下表格所示…」引导句 + 4 个小标题
  + 4 张表（后端服务 / Web 前端 / Agent 客户端 / 系统级依赖）；这些版本号本就
  随迭代失效（表里还写着 FastAPI 0.115.6，实际 0.141.1）。
  「第三方组件：…受各自许可协议约束…」这句责任条款**保留**。
- **S-2（P2）测试启动器改用 backup API**：`.workbuddy/tools/` 下的
  `run_backend_test.py`、`run_backend_test_tls.py`、`run_webproxy_test_tls.py`
  原来是 `shutil.copy` 字节拷贝被 8001 占用的生产库 —— 会拷出"A 页新、B 页旧"
  的混合体，测试库报 `database disk image is malformed`、一批接口 500，
  极易误判成业务 bug。改为 sqlite3 backup API 且**失败即退出**。
  另：`vigilserve/.workbuddy/tools/run_backend_test.py` 去掉了
  「backup 失败回退 shutil.copy2」这条兜底 —— 字节拷贝正是要避免的做法。
- **S-7（P3）`cert_is_trusted()` 注释纠正**：它是 1.1.51 方案 A 之后遗留的死代码
  （零业务调用点），但 docstring 仍在暗示"证书链在被校验"。已改为明示
  「不参与认证路径，仅供存量排查与回归脚本使用」——保留函数是因为
  `t_round4_cert_nonce.py` 在测它。
- **S-10（P3）`_PUBKEY_CACHE` 拆分**：`load_public_key()`（公钥 PEM）与
  `cert_public_key()`（证书 PEM）原来共用一个缓存字典，两者返回的对象类型不同。
  拆成 `_PUBKEY_CACHE` / `_CERT_PUBKEY_CACHE`。
- **S-5 / S-6 清理**：`outputs/`（56 个含真实内网 IP 的调试产物，2.7 MB）与
  8 处 `_moved_*` 构建残留移出源码树到 `_audit_trash_20260929/leftover/`。

### 验收

- Agent 1.1.66 重新打包（self_check 15 文件，digest=e7a04f24889b…），
  tkinter / cryptography / CA 三道自检通过。
- 版本号 15/15 全绿（服务端 1.1.57 / Agent 1.1.66）。

## [1.1.56] - 2026-09-28（服务端；Agent 仍 1.1.65）—— 上线时间语义、设备管理卡片宽度

### 修复（一）未加入管理的主机「上线时间」永远停在第一次安装

现象：未加入管理的主机断线再连上、甚至卸载重装之后，主机列表里的「上线时间」
还是**第一次安装上线**那一刻；已纳管的主机则是正常的。

根因是 `online_time` 挂在"状态迁移"上 —— 只有 `offline/unknown/warning/critical`
→ 在管 那一步才写。而未加入管理的主机状态**恒为 `registered`**：
`services/collector.py` 每轮都会把 `join_time` 为空、状态是 offline/online 的记录
回滚成 `registered`（否则它会落进"受管状态"集合，管理员既删不掉也看不懂），
它永远走不到那条分支，只剩"为空时补一次"，也就是安装那一次。

改法：判据改成"这次联系之前是不是离线"，与状态字段彻底解耦 ——
用统一的在线判定（`services/device_status.py` 的「采集周期 × 2.5」）去看**旧的**
`last_seen`：

- 过期（或从来没连过）→ 这次算重新上线，写 `online_time`；
- 还新鲜 → 主机一直在线，不动。

第二条是刻意的：否则 5 秒一次的心跳会把「上线时间」刷成「最后一次心跳时间」，
那就不叫上线时间了。

由此带来的两处（正确的）行为变化：
- 已纳管的主机同样按"是否曾离线"刷新，不再依赖 collector 先把它置成 offline；
- `warning` / `critical`（在线但有告警）不再刷新上线时间 —— 它并没有掉线，
  刷新反而会把"最近一次上线"写成告警持续的那一刻。

⚠ `services/device_status.py` 的周期需要 db，所以 `_record_agent_online()` 新增了
可选参数 `db`（`/register`、`/enroll`、`/push`、`/heartbeat`、`/config` 五处调用点
都已传）。调用点必须**在写 `last_seen` 之前**，否则比不出"上一次联系"的时间。

### 变更（二）设备管理卡片宽度与日志管理一致

`.reg-management` 的 `max-width` 由 1400px 改为 **1600px**（与 `.log-management`
相同）。本页两个页签（主机管理 / 网络设备）的卡片都是 `.reg-section`，都在这个
容器里，改一处即全页生效。

### 验收

- 新增 `t_online_time_0928.py` **18/18**：未纳管 / 已纳管两条路径的"持续在线不刷新
  + 断线再连刷新 + 卸载重装刷新"，并回归「加入 / 移出管理不动上线时间」。
  ⚠ 断言取样点：注册后的**第一次**心跳也会刷新 —— `/enroll` 不写 `last_seen`，
  此刻仍是"从来没连过"，那一次就是真正上线。
- 回归：`t_uninstall_report_0928.py` 48/48、`t_plan_a_0924.py` 28/28、
  `t_online_pending_0928.py` 27/27、`t_fix_0928.py` 23/23、
  `t_api_cert_ca_rotate_0928.py` 20/20；`find_undefined_names.py` 76 文件 0 可疑。
- 版本号 15/15（源树与构建目录两侧）。**Agent 源码本轮未改，版本号仍 1.1.65、
  不重打 Agent 包**（升了却不重打会被 `build_installer.py` 的 phase 4.5 版本闸拦下）。

## [1.1.55] - 2026-09-28（服务端 + Agent 1.1.65）—— Agent 卸载上报

Agent 卸载时向服务端通报一次，主机列表**当场**置离线；是否清除本机配置决定
要不要一并移出管理。

### 新增（一）卸载上报：`POST /api/agent/uninstall-report`

以前 Agent 被卸载后，服务端要等「采集周期 × 2.5」才发现 `last_seen` 不再更新，
这期间主机列表上它还是绿的。而「卸载时有没有勾『清除本机配置』」更是只有本机
才知道的事实，服务端猜不出来 —— 两种结局完全不同：

| 场景 | 卸载时的选择 | 服务端的结果 |
|---|---|---|
| 已注册、**未加入管理** | 清除配置 | 立刻离线；状态仍是 `registered`，「加入管理」置灰 |
| 已加入管理并在线 | **保留**配置 | 保持纳管、正常显示离线；重装后心跳一到自动恢复在线 |
| 已加入管理并在线 | **清除**配置 | 自动移出管理并离线，「加入管理」置灰；重装后须重新注册再加入管理 |

清配置时为什么要连设备身份一起清：私钥与 `node_id` 都存在配置目录里
（`identity\node.key`），配置一删就是**另一台设备**了。服务端若留着旧的
`node_id` 与 `pub_key`，新 `node_id` 永远登不上（1.1.49 修的就是这个死循环），
界面却显示"已加入管理" —— 而实际没有任何一台机器握着对应的私钥。
所以清配置时清空 `node_id` / `pub_key` / `pending_pub_key` / `key_fingerprint`，
并把 `join_time` 置空、状态回到 `registered`。

刻意保留：`secret_key`（9998 下行凭据与 `update_key` 由它派生）、`pairing_code`
（重新准入时要跟 Agent 面板上的码核对）、`machine_fingerprint`（重装后靠它接住
原记录，不会产生重复条目）。

### 新增（二）Agent 侧 `--report-uninstall [--purge]`

新增 `agent/uninstall_report.py`（已登记进 spec 的 `datas` 与 `hiddenimports`），
`agent.py` 的 `main()` 在**互斥量与托盘初始化之前**处理这个参数 —— 卸载时 Agent
进程正被结束，抢不到单实例锁也不该影响上报。带 6 秒超时，失败静默退出，
绝不影响卸载本身。

### 变更（三）卸载脚本的时序

「是否清除本机配置」的询问从 `usUninstall` 提到 `InitializeUninstall`（那一步才
能中止卸载），结果存**全局**变量（Inno 的 `[Code]` 里函数内 `var` 是局部的，
跨过程传不出去）。顺序固定为：**关进程 → 询问 → 上报 → 才删配置** ——
上报要用配置目录里的私钥签名，先删就什么都发不出去。

`InitializeUninstall` 里的 `Exit` 一并改成 `Break`，否则"忽略并继续"那条路径
会跳过询问与上报。

### 变更（四）未纳管且离线时「加入管理」不可用

`RegisterManagement.jsx`：行内「加入管理」按钮在未加入管理**且**离线时置灰并
给出悬浮说明；批量「加入管理」同样排除这类主机并说明原因（两条判据必须是同一条，
否则批量就成了绕过单台限制的口子）。

### 验收

- 新增 `t_uninstall_report_0928.py` **48/48**：三条场景逐条覆盖，含「重装后靠
  机器指纹接住原记录、不产生重复条目」与「换私钥冒用 node_id → 401」
- 回归：`t_plan_a_0924.py` 28/28、`t_online_pending_0928.py` 27/27、
  `t_fix_0928.py` 23/23、`t_api_cert_ca_rotate_0928.py` 20/20
- `find_undefined_names.py` 76 个文件 0 处可疑；前端构建通过
- Agent 安装脚本：ISCC 编译通过（`forward` 声明已补 —— Pascal 要先声明后使用）

## [1.1.54] - 2026-09-28（服务端 + Agent 1.1.64）—— 在线与准入解耦、卸载关进程、面板弹出时机

### 修复（一）未加入管理的主机一律显示「离线」

现象：新装的 Agent 已注册成功、与业务机网络连通，但主机列表里状态一直是**离线**，
必须等管理员点「加入管理」并刷新才显示在线。

根因在认证与"在线"的判据被绑在一起了：

- `last_seen` 是"在线"的唯一依据，而它**只在心跳里更新**；
- `_authenticate()` 拿「`pub_key` 有没有登记」当"是否已准入"的判据，而 `/enroll`
  故意**不**给未准入的设备登记公钥；
- 于是未准入的设备连心跳都签不了名（401）→ `last_seen` 永远为空 → 判离线。

改法是把两件事拆开：

- 未准入时把公钥**暂存**到新列 `AgentKey.pending_pub_key`（不登记进 `pub_key`）；
- `_authenticate(allow_pending=True)` 允许用暂存的公钥验签，返回 `pubkey-pending`。
  **只有心跳**走这一条（`/push`、`/config` 等一律照旧拒绝）；
- 心跳响应新增 `authorized` 字段。Agent 收到 `false` 时显示「待加入管理」、
  跳过指标上报、也不再去轮询 `/config`（那两处同样要过准入，未准入只会拿到 401，
  白白在日志里每 60 秒刷一条"推送失败"、把托盘图标点红）；
- 领 9998 服务器证书 / `update_key` / 轮换 token 同样要求已准入；未准入设备
  不再登记完整性基线、也不再做漂移分级（还没被承认的机器，记这些只是噪音）。

⚠ 这条**不是**"放开一条免鉴权通道"：未准入的机器照样要拿私钥签名，服务端用暂存的
公钥验 —— 否则任何人报一个 `node_id` 就能把主机刷成在线。在线 = 网络连通（机器事实），
准入 = 能不能上报数据（管理动作），两者不再互相拖累。

### 修复（二）卸载时关不掉 Agent，残留配置与运行文件

以前卸载只是跑一遍 `stop_agent.bat` 就算完事，而那个脚本不论有没有杀掉进程都
`exit /b 0`：Agent 若曾以管理员身份启动过，没提权的卸载程序 `taskkill` 会失败、
错误被吞掉，安装程序完全看不出区别。表现就是"卸载很顺利"，但安装目录里留下
exe/dll，或最后弹「部分文件无法删除」。

- `stop_agent.bat`：结束之后再**数一遍**进程，数到 0 才返回 0，否则返回 1（最多试 3 轮）；
- `VigilServeAgent.iss`：新增 `StopAgentAndWait()`，跑脚本 + 等 + 复核，任意一轮数为 0 才算成功；
- 卸载入口 `InitializeUninstall()` 先做这件事。结束不掉就提示用户手动退出
  （右键托盘图标「退出」／任务管理器结束 `VigilServeAgent.exe`／以管理员身份重跑卸载程序），
  可选「是」重试、「否」忽略继续、「取消」中止卸载；
- 老版本装出来的目录里没有 `stop_agent.bat`，这时直接 `taskkill` 兜底，不再静默跳过；
- 收尾 `CleanupLeftovers()`：删掉开机自启项
  （`HKCU\...\Run\VigilServeAgent` —— 删文件删不到注册表，留着下次登录会去找不存在的 exe），
  并在 `%LOCALAPPDATA%\VigilServe` 空了时一并删掉。

### 变更（三）配置面板改为安装向导关闭后再弹出

`[Run]` 段里的条目是在**向导窗口还开着**的时候就执行的，配了 `nowait` 更是
"完成 VigilServe Agent 安装向导"那一页还没关、配置面板就蹦出来了。

现在改为在 `DeinitializeSetup()` 里拉起 —— 它在用户点「完成」、向导关闭之后才被调用。
推送更新（`/UPDATEFLOW`）保持静默拉起后台 Agent，不弹面板。

### 变更（四）修正程序资源里的版本号漂移

`tray/version_info.txt` 与 `agent/version_info.txt` 里同时存在四档版本号。以往升版
只改了 `StringTable` 的 `FileVersion` 字符串，`FixedFileInfo` 的 `filevers`/`prodvers`
与 `ProductVersion` 字符串都不跟随，于是 exe 资源里是混合值
（托盘 `FixedFileInfo=1.1.52.0` + `FileVersion=1.1.54.0` + `ProductVersion=1.1.53.0`）。
装完后在资源管理器「属性-详细信息」里看到的**产品版本是上一个版本**。

- 两个文件四档已对齐到 1.1.54.0 / 1.1.64.0；
- `verify_version.py` 补了 `ProductVersion` 与 `FixedFileInfo` 两处校验（共 15 个校验点），
  缺一处即 FAIL，以后不会再漂；
- 不影响功能：`version_info.txt` 不在 `self_check` 的 14 个 `.py` 哈希范围内，
  指纹不变，重打包不触发 `agent_tamper_suspected`。

### 验收

- 服务端在线判定：`t_online_pending_0928.py`（未准入心跳放行 + `/push` 仍拒 + 准入后恢复）
- 回归：`t_fix_0928.py` 23/23、`t_plan_a_0924.py` 27/27、`t_api_cert_ca_rotate_0928.py` 20/20
- Agent 安装脚本：ISCC 编译通过
- 版本号：`verify_version.py` 15/15（源树与构建目录两侧均全绿）
- 包内容：`installer/source/backend` 内含 `pending_pub_key` / `allow_pending`；
  Agent exe 的 CArchive `agent` 条目内含 `_authorized` /「待加入管理」；
  两个安装包与其内部主程序的版本资源均为 1.1.54.0 / 1.1.64.0，三档一致

## [1.1.53] - 2026-09-28（服务端 + Agent 1.1.63）—— 设备认领死分支、准入状态提示、卸载询问

### 修复（一）已纳管主机换 IP 后认不回来

`/register` 里按设备身份认领记录的判据还是 `_k.client_cert`。方案 A（1.1.51）砍掉
客户端证书之后该字段**再无写入点**，这一支恒假，于是：

- 已纳管的主机换了 IP 就认不回来，掉到「按 IP 匹配」这一步；
- 匹配不上就在待审核队列里多出一条同名副本。

判据改为方案 A 下的等价条件 `pub_key` 非空且未吊销。

### 修复（二）吊销后配对码回不到 Agent，人工核对断链

`/enroll` 是否回传配对码，看的是「这台设备有没有登记过公钥」。但吊销时 `pub_key`
是**刻意保留**的（审计要留痕，吊销靠 `revoked` 标记生效），于是吊销后重新生成的
新配对码永远不下发，管理员没法核对「重来的这台是不是同一台机器」。

判据改为「登记过公钥**且未被吊销**」。

### 变更（三）卸载时询问是否清除数据

以前服务端卸载无条件删 `backend\data`（含主机凭据的 Fernet 密钥 `secret.key`），
却**保留** `monitor.db`。重装后密钥是新生成的、库里还是旧密文，`decrypt_secret()`
解密失败又静默返回空串 —— 结果是所有主机凭据集体失效且**没有任何告警**。

两者必须同进同退，故改为卸载时询问，选择后**一并处理**监控数据库、凭据密钥与服务端证书：

- 服务端：询问后删 `backend\data` + `backend\certs` + `backend\monitor.db`；
- Agent：询问后删 `%LOCALAPPDATA%\VigilServe\Config\Agent`（设备私钥、9998 证书、连接配置）。

默认选项为「否」。推送升级走的是静默卸载，保留配置才能不丢设备身份。

### 变更（四）Agent 配置面板区分「已加入管理」与「待加入管理」

- 设备与服务端握手成功、但尚未被管理员纳管时，显示**「待加入管理」**并提示
  「请在服务端『主机管理』中加入管理，并核对配对码」；
- 已纳管时显示「公钥已登记，设备已授权」，提示自动消失；
- 「测试连接」的结果分两态：「已加入管理」/「注册成功，待加入管理」。
  以前一律显示「注册成功」，容易让人以为接入已经完成。

### 变更（五）主机列表操作按钮的提示文案精简

「轮换凭据」「重登记基线」「吊销设备」三个按钮的确认框与悬浮提示改为简洁书面用语；
吊销的提示补上重新接入路径（**先「移出管理」再「加入管理」**）；
清理方案 A 之前的「客户端证书」「吊销证书」等过时表述。

### 验收

`t_fix_0928.py` 23/23、`t_plan_a_0924.py` 27/27、`t_api_cert_ca_rotate_0928.py` 20/20。

## [1.1.52] - 2026-09-28（服务端 + Agent 1.1.62）—— 修 9998 下行通道永久失联

现场症状：设备上报正常（注册管理里显示「已加入、公钥已登记、在线」），但主机详情页
的**设备信息 / 资源管理 / 应用管理 / 远程桌面全部报「无法连接到 Agent {ip}:9998」**。

根因是**三层叠在一起**，任何一层单独存在都不会这么难查：

### 修复（一）方案 A 留下的回归：9998 证书链路整条静默失效

1.1.51 改 `identity.py` 时，把紧贴在 `needs_enroll()` 下面的 6 个路径常量
（`API_TLS_DIR` / `API_KEY_PATH` / `API_CSR_PATH` / `API_CERT_PATH` / `API_SELF_CERT` /
`API_SELF_KEY`）**连带删掉了**。后果是 `load_api_cert_pem()` / `save_api_cert()` /
`build_api_csr()` 一律抛 `NameError`。

而**所有调用点都写在 `except Exception: pass` 里**（注释是"申请失败不影响主流程"），
于是这条链路彻底失效却一声不响：Agent 不再申请、不再续签 9998 服务器证书，
服务端侧只看到"连不上"，两边日志都没有一行错误。已恢复常量并加醒目警告注释。

同一批回归里还清掉两处：

- `backend/routes/agent.py` 的 `/enroll` 里有**一整段 33 行的死代码**（真 return 之后
  又跟了一个 return 块），仍在引用已被删除的 `cert_out` /
  `agent_key.client_cert`。当前不可达所以没炸，但任何人调整顺序就会立刻 NameError。
- `identity.short_summary()` 仍在调方案 A 删掉的 `load_cert_pem()` / `cert_not_after()`。
  调用点包着 try/except，所以只是身份摘要恒为空。已按新语义重写
  （"有没有证书"→"公钥登记没有"，并补上 `api_cert_trusted` / `api_not_after`）。

### 修复（二）Agent 侧：`needs_api_cert()` 增加「CA 归属」判据

原判据只有两条：文件在不在、`not_after` 有没有进续签窗口。**完全不看这张证书是不是
由"当前信任的服务端 CA"签的**。而 `AGENT_API_DAYS = 365`，签一次能撑一年 ——
服务端重装 / 重建 CA 之后，本机那张证书**依然"没到期"**，于是永远不上送 `api_csr`，
服务端也就永远没机会补签。

新增 `identity.api_cert_signed_by_current_ca()`：用 `tls_util.ca_path()`（TOFU 取回的
那把优先于随包内置的）验签。判不出来时返回 `None`，调用方按"不折腾"处理，避免
每 10 秒白送一次 `api_csr`。

### 修复（三）服务端侧：不再把旧 CA 的证书原样发回

`_maybe_issue_api_cert()` 原先只要库里那份证书公钥没变、`cert_needs_renew()` 为假就
原样返回 —— 而 `cert_needs_renew()` **同样只看日期**。新增
`services/tls.cert_issued_by_current_ca()`，不满足就往下走重签。

### 安全

判据收紧的方向只有一个：**该重签的一律重签**。同公钥重复登记仍然允许（重装 / 重新
入户是正常场景），换公钥仍必须管理员先吊销 —— 这两条地基没动。

### 工具 / 验收

- 新增 `.workbuddy/tools/find_undefined_names.py`：找"只被使用、从未在本文件里定义"的
  模块级名字。这次的坑正是这一类 —— 语法合法、`py_compile` 抓不到、异常还被
  `except: pass` 吞掉，必须有工具专门扫。全量扫 75 个文件现在 0 可疑。
- 新增 `.workbuddy/tools/t_api_cert_ca_rotate_0928.py`：**20/20**（服务端 10 项 +
  Agent 10 项），含"服务端 CA 变了 → Agent 必须主动申请新证书"这条核心断言。
- `t_plan_a_0924.py` 回归 **27/27** 仍全绿。

### 已知影响（交付须知）

9998 通道断了，**推送升级也走不了**（`agent_update.py` 就是往 9998 发的）。所以已经
带着旧证书的存量主机**无法靠推包自愈**：需要手工重装 Agent，或手工删掉
`%LOCALAPPDATA%\VigilServe\Config\Agent\api_tls\server.crt`（保留 `server.key`）
让下一个心跳触发重新申请。凡涉及服务端 CA 变更，交付文档里都要写明这一步。

## [1.1.51] - 2026-09-24（服务端 + Agent 1.1.61）—— 认证体系简化（方案 A）

**这是一次架构改动，不是修 bug。** 背景与完整论证见 `docs/认证体系简化评估.md`。

### 一句话

设备身份从「客户端证书 + 静态 token 双轨、互相回落」简化成 **「node_id + 服务端登记的
公钥」一条路**：上行请求一律用私钥签名，服务端拿登记的公钥验。没有第二条路，没有回落。

### 砍掉了什么

- **客户端证书**：不再有 CSR、CA 签发、90 天有效期、30 天续期窗口、"这张证是不是当前
  服务端 CA 签的"这些概念。`AgentKey` 上的 `client_cert` / `cert_*` 不再参与认证。
- **静态 token 当身份用**：`X-Auth-Token` **不能**再让一台机器被认证 —— 它是配置文件
  里的一把静态串，本机任意进程读到就能冒充这台主机上报，且吊销机制拦不住。这是本次
  安全上最大的一笔收益。
- **双轨 + 回落**：`_authenticate()` 从 15 个分支、两条主路径互相回落，缩成单路径。
  回落的边界情况穷举不完 —— 光"服务端换机器部署"一个场景就长出两条 401
  （未知 node_id、IP mismatch），现象相同、根因不同，排查只能靠猜。

### 留下了什么

- `node_id`、私钥签名、时间戳窗口、nonce 防重放（**防冒充的核心就是"私钥不出本机"，
  这一点两种方案完全一样**）。
- 配对码（首次人工核对）、吊销（一行字段）、9998 的 `api_cert`（**传输层**，与设备
  身份是两件事）、机器指纹漂移分级、Agent 代码完整性自检。
- `token` 降级为**仅服务端回调本机 9998 用的下行凭据** —— 它不再能用于上行认证。

### 兼容性

- `/enroll` 同时接受 `pub_key_pem`（新）和 `csr`（老，服务端自己从 CSR 取同一把公钥）。
- Agent 侧 `register()` 保留为薄壳，内部转 `enroll()`，主循环调用点不用改。
- **老版本 Agent（≤1.1.60）连新服务端会认证失败** —— 它们不会发公钥。测试期可接受，
  正式升级时所有 Agent 需一并升到 1.1.61。

### 修掉的连带问题

- `services/cert_reclaim.py`（失联主机自动吊销）原本筛的是"有没有 `client_cert`"，
  方案 A 下新设备没有证书 → **这条定时任务会静默失效**。改为按"有没有登记公钥"筛。
- `agent_headless.py` 判心跳失败的 `if not _hb:` 永远进不去（`heartbeat()` 失败时返回
  非空 dict）→ 无托盘模式下心跳失败既不清注册也不自愈。已改为 `not _hb or "error" in _hb`。

### 验证

`.workbuddy/tools/t_plan_a_0924.py` **27 项全绿**，覆盖：pending 阶段不给通行 /
未批准不能上报 / 只带 token 被拒（后门已拆）/ 批准后自动登记 / 伪造签名被拒 /
换服务端清库后能自愈 / 换 IP 不影响 / 换公钥被拒 / 吊销后拒绝。
`t_orphan_nodeid_0924.py` 与 `t_ip_mismatch_0924.py` 已标注为 1.1.51 前的历史场景，
不再作为验收标准（IP 那条回归并入前者的 F 组）。

## [1.1.50] - 2026-09-24（服务端 + Agent 1.1.60）

### 修复

- **心跳不再因为「IP 变了」把设备踢下线**（1.1.49 之后 1.12 仍然掉线的直接原因）。
  1.1.49 修掉了「未知 node_id」那条 401，可心跳里还有**第二条**：
  非证书通道（`auth_mode != "cert"`）下，只要上报 IP 与库里不同就 `401 IP mismatch`。
  从证书分支回落下来的设备正好走这条 —— 于是换了个 401 原因，界面现象一模一样：
  注册成功 → 心跳 401 → Agent 清空本地注册 → 再注册 → 再 401。

  现在 IP **一律只更新、不拒绝**（与证书通道一致的处理）。理由：
  · 这条防护挡的是「拷贝安装配置指向别的主机」，但它**挡不住** ——
    `ip_address` 是 Agent 在 payload 里自己填的字段，真要冒充照填即可；
  · 而它对正常机器的误伤是硬的：DHCP 重分配、多网卡选中另一个、NAT、搬机房、
    上云都会变 IP；
  · 真正的防冒充不靠 IP，靠身份本身（私钥签名 + 「已发证设备不许退回静态
    token」），这两条都没动。
  · 服务端回调本机 9998 用的也是 `server.ip_address`，不更新就会打到旧地址上。

### 变更

- **Agent：心跳失败时把服务端给的拒绝原因显示出来**。服务端一直把原因放在 401 的
  detail 里（未知 node_id / IP mismatch / 时间戳超差 / 证书不是本 CA 签的 …… 十几种），
  但 Agent 只写一句「心跳失败，清除本地注册信息」就把它丢了。现象一样、根因完全不同，
  看不到这个原因排障只能靠猜。现在状态和日志里都会带上原文。

### 已知待办（本轮未动，等确认）

- `agent_headless.py` 里判心跳失败用的是 `if not _hb:`，而 `heartbeat()` 失败时返回的是
  **非空** dict（`{"error": True, ...}`）→ 这个分支**永远进不去**，无托盘模式下心跳
  失败不会清注册、也不会自愈。`agent.py` 用的是 `not hb or "error" in hb`（正确）。
  是否统一成后者待定：改了会让无托盘机器也开始"清注册→重注册"循环。

## [1.1.49] - 2026-09-24（服务端 + Agent 1.1.59）

### 修复

- **「注册成功几秒后又变回未注册、服务端一直离线」**（换服务端部署后必现）。
  现象是只有**服务端本机**新装的 Agent 连得上，从别的服务端迁过来的机器一律反复掉线。
  根因是两处叠在一起：
  1. `/register` 建 `AgentKey` 时**只写 `secret_key`、不写 `node_id`** —— 走 register
     入户的机器在库里永远没有设备身份记录；
  2. `_authenticate()` 对「库里查不到这个 node_id」是**硬拒 401**。当初为防死循环加的
     回落只覆盖了「记录还在、只是还没发证」，漏了更常见的「记录整个不存在」（服务端
     重装 / 清库 / 换机器部署）。

  于是链路是：Agent 本地证书没到期 → 不调 `/enroll` → 走 `/register` → 库里没 node_id
  → 心跳带上证书签名头 → 服务端查无此 node_id → 401 → Agent 判心跳失败并**清空本地
  server_id/token 存盘** → 界面回到「未注册」→ 重新 register → 再被拒……
  现在：① `/register` 补登记 `node_id`（node_id 已被别的设备占用时不抢）；② 查不到
  记录时与「尚未发证」同等对待，回落到遗留 token 通道而不是硬拒。

  ⚠ 回落的**安全边界不变**：「已发证设备不许改用静态 token」（开源加固 ⑤）按
  `server_id` 判定，仍然照常拒绝；吊销也照常拒绝。回归测试里这两条都有断言钉住。

### 变更

- **Agent：换了服务端之后能自己重新入户**。以前 `needs_enroll()` 只看本地证书有没有
  过期，所以一张**别家 CA 签的**证书（服务端换机器部署后必然如此）会被当成有效的，
  这台机器于是一直挂在遗留 HMAC 通道上：能连，但拿不到新服务端签发的证书，身份也从
  「证书 + 私钥签名」退回「一把静态 token」。现在多一条判据 —— 本地证书不是**当前信任
  的服务端 CA** 签的就触发重新入户（判据用 `tls_util.ca_path()`，TOFU 取回的 CA 优先
  于随包内置的，所以认的是当前这台服务端）。拿不到 CA 文件时不猜，维持原行为，避免
  误判成「每轮都要重新入户」。

## [1.1.48] - 2026-09-24（服务端 + Agent 1.1.58）

### 修复

- **登录页不再直接抛 `Failed to fetch`**。这个英文串是浏览器的原生 `TypeError`，
  只在「请求压根没送到后端」时出现 —— 没有状态码、没有响应体，全新部署的人看到它
  只会以为是账号密码错了。现在 `auth.jsx` 捕获连接层异常，改写成可照着排查的文案：
  把**实际请求的 URL** 摆出来，依次列出四个常见成因（后端未启动 / 写成了 http 而服务
  端只开 HTTPS / 自签证书未信任 / 代理或安全软件拦截），末尾提示按 F12 看 Network。
  注意这四类都**不是应用层的 bug**：同样的全新实例在干净环境里登录接口返回 200。
- **安装向导结束页不再重复勾一次「启动托盘」**。`[Run]` 那条同时写了 `Tasks: launchtray`
  和 `Description`，而 `Description` + `postinstall` 会让 Inno 在完成页再画一个**同名的
  勾选框** —— 与「选择附加任务」页那一个重复问了两遍。去掉 `postinstall`（以及随之无用
  的 `Description`）后，勾选只出现一次，勾了就在收尾阶段直接拉起托盘。

### 变更

- **Agent：配置面板的三个入口**。① 首次安装结束自动打开配置面板（推送更新除外 —— 那
  种场景要静默重启后台，不能弹窗打搅正在正常工作的主机）；② 桌面快捷方式带 `--config`，
  双击即开面板；③ 双击托盘图标开面板（pystray 菜单项设 `default=True`：Windows 下
  pystray 不派发 `WM_LBUTTONDBLCLK`，双击走的是 `WM_LBUTTONUP` → 菜单默认项）。
- **Agent：带 `--config` 启动时会顺带拉起后台 Agent**。配置面板这条进程分支本身不跑
  采集循环，而所有开面板的入口现在都直接走 `--config`；不这么做的话，全新安装时会变成
  「填完服务端地址、保存 —— 结果 Agent 依然是离线的」。判断用的是 `OpenMutexW` 探针
  （只 open、不 take ownership），不会把后续真正的互斥锁申请挤掉。

---

## [1.1.47] - 2026-09-24（服务端 + Agent 1.1.57）

### 修复

- **覆盖安装（升级）前也会停服了**。1.1.45 只改了卸载钩子，升级走的 `ssInstall` 路径
  没做同样处理 —— Inno 自带的 `CloseApplications` 只给「有窗口」的程序发 `WM_CLOSE`，
  对无窗口的 python（`main.py`:8001 / `web_proxy_server.py`:8009）无效，
  升级照样卡在「文件被占用」。现在 `setup.iss` 在 `CurStepChanged(ssInstall)` 里
  也调一次 `stop_services.bat`。
- **Agent 同样处理**：新增 `agent/stop_agent.bat`，`VigilServeAgent.iss` 在
  `ssInstall` 与 `usUninstall` 都调用它（Agent 常驻托盘、主窗口平时隐藏，
  `CloseApplications` 对它同样不完全可靠）。

### 两处实现细节（踩过才知道）

- 🚨 **脚本要能从 `{tmp}` 跑**：升级走到 `ssInstall` 时**新文件还没落地**，而旧版本
  的 `{app}` 里根本没有这份脚本。所以 `[Files]` 里额外嵌一份 `Flags: dontcopy`，
  用 `ExtractTemporaryFile()` 取到 `{tmp}` 再执行。只认 `{app}` 的路径在升级场景会直接落空。
- 🚨 **`%~dp0` 不等于安装目录**：从 `{tmp}` 跑时它指向临时目录，所以两个脚本都新增了
  `%1` 参数由安装程序传入 `{app}`，并统一补齐结尾反斜杠
  （`StartsWith` 比对没有它的话，`...\VigilServe` 会把 `...\VigilServe2\` 下的进程也算进来）。

---

## [1.1.46] - 2026-09-24（服务端 + Agent 1.1.56）

### 新增

- **密码规则提示**：口令输入框下方现在显示当前生效的规则（如「长度至少 8 位，且必须包含
  大写字母、小写字母、数字」）。文案由后端 `security_policy.describe_password_rules()`
  生成，与 `validate_password()` 读**同一份 policy** —— 提示口径和实际拦截口径永远一致，
  不会出现「提示说 8 位、实际要 10 位」。新增 `GET /api/security/password-rules`
  （刻意 `enforce_password_reset=False`：首登待改密账号全站 403，唯独这里必须放行）。
  挂在三处：首登强制改密弹窗、用户管理新增、用户管理编辑。改完安全策略会重新拉取。
- **托盘控制面板「服务端 IP」**：插在「服务状态」与「端口配置」之间，列出本机网卡地址
  （排除回环 / APIPA / 未启用网卡），多网卡可下拉选择，选中即写入配置，
  并在下方提示「Agent 端『服务端地址』请填这个 IP」。
- **Agent 一键信任服务端证书（TOFU）**：换机器部署服务端后首次连接的唯一出路。
  Agent 配置面板新增「信任服务端证书」按钮。

### 修复

- **换机部署后 Agent 连不上服务端**（报「证书未被信任（缺少本地 CA）」）。
  根因不是配置问题：**每台服务端首次启动会自签一把本地 CA**（`backend/certs/ca.crt`），
  而**预置在 Agent 安装包里的 CA 只对打包那台机器有效**，换机器部署必然
  `CERTIFICATE_VERIFY_FAILED`。修法：新增**免鉴权**的 `GET /api/agent/ca`
  （必须免鉴权 —— 还没注册的 Agent 拿不到任何凭据，鉴权了就是鸡生蛋），
  Agent 拉取后展示 CA 的 SHA-256 指纹供人工核对，确认后落盘为信任根
  （`%LOCALAPPDATA%\VigilServe\Config\Agent\vigilserve-ca.crt`，优先级高于内置 CA），
  随后自动重测。无头模式在日志里给出同样的操作提示。
  ⚠ 落盘后必须清 `ssl` 上下文缓存，否则新 CA 不会生效。

### 说明

- 随包内置 CA 的定位从「唯一来源」降级为「开箱即用的便利」：它只对打包那台机器有效，
  现在有 TOFU 兜底，不再需要为换机部署重新打包。

---

## [1.1.45] - 2026-09-24（服务端）

### 修复

- **卸载时两个 python 进程关不掉、导致卸载失败**。后端 `main.py`(8001) 与设备 WEB 代理
  `web_proxy_server.py`(8009) 都是**无窗口**进程（托盘用 `CREATE_NO_WINDOW` 拉起）：
  Inno 自带的 `CloseApplications` 只发 `WM_CLOSE`，对它们完全无效；原先那句
  `taskkill /FI "WINDOWTITLE eq VigilServe*"` 同样永远 0 命中 —— 没有窗口就没有标题。
  结果 `python_runtime\python.exe` 一直占着文件，卸载卡死。

### 新增

- `installer/scripts/stop_services.bat`，三道筛子，**只认属于本安装目录的进程**：
  ① 托盘连子进程树（`taskkill /F /T`）；② python 映像路径落在安装目录下（便携运行时）；
  ③ 按监听端口 8001 / 8009 兜底，且先确认占用者确实是 python 才动手
  （覆盖「python 来自系统 PATH、路径不在安装目录内」的情况）。
  🚨 全程不用 `taskkill /F /IM python.exe` —— 那会杀掉机器上所有 Python。

---

## [1.1.44] - 2026-09-24（服务端）

### 修复

- **缺陷1：默认管理员账号建不出来**。`seed_admin()` 从「只在 `POST /login`」
  挪到 `main.py` 的 `lifespan`（`init_db()` + `_seed_demo_data()` 之后，`try/except` 包住）；
  `/login` 里那句保留作兜底。此前不登录一次就没有 admin，而登录又需要 admin。
- **缺陷2**：`reset_admin_password.py:165` 那句「重启服务端会自动建 admin」已不准确，
  改为提示「先启动一次服务端（1.1.44 起启动即建号）」并给出日志关键字。

### 变更

- **用户管理**：登录名改为可编辑（前端去 `disabled`，后端去 `raise 400 "登录名不可修改"`，
  改为非空 + 唯一性校验）。
- **系统默认用户的角色不可编辑，且补上了后端强制**：以前只有前端置灰，改个请求就能把
  内置 admin 降权。新增 `_is_builtin_admin(user)`，判据统一为 **`id == 1`**。
  ⚠ 不能用 `username == 'admin'`：登录名可改之后改名即漏判，别人新建账号取名 admin 又会误伤。
  前端角色 / 状态 / 删除三处的判据一并从 `username === 'admin'` 改成 `id !== 1`。
- **安装包三项**：桌面快捷方式默认勾选；桌面 + 开始菜单快捷方式带 `--panel`
  （装完直接打开控制面板）；**开机自启项故意不带** `--panel`（每次登录弹窗很烦）。
- **托盘 `--panel`**：新增 `_wants_panel()` / `_activate_existing_panel()`；
  关闭面板改为 **withdraw 不销毁**（句柄要留给第二次双击）；`TrayApp.run()` 启动时
  预建隐藏面板，托盘已在跑时靠 `FindWindowW` 按标题 `VigilServeTray - <ver>` 找到并激活。
  `_refresh_loop` 在 withdrawn 状态跳过刷新，避免后台每秒空转。

---

## [1.1.43] - 2026-09-23（服务端，含本轮交付审查修复）

### 安全（本轮交付审查，详见 `docs/安全审计与交付审查-v1.1.43.md`）

- **P1-8** 「WEB管理」代理票据现在随会话结束失效。票据载荷里带上用户级会话代号，
  登出 / 改密码 / 改角色 / 停用 / 删号时代号 +1，该用户**所有**已签发的票据立刻作废
  （以前只是 30 分钟自然过期，登出后票据在 URL 里还能继续用满 30 分钟）。
  代号落在 `backend/data/web_ticket_epoch.json`，主进程与独立源代理进程（8009）共享。
- **P1-9** 代理页的 `Referrer-Policy` 从 `unsafe-url` 收紧为
  `strict-origin-when-cross-origin`。实测沙箱 iframe 里 Chrome 连 `unsafe-url` 都无视，
  而它唯一生效的"顶层窗口"场景会把**含票据的完整 URL** 作为 Referer 发给外站。
  收紧后：同源内跳仍带完整 Referer（`recover_redirect()` 照常工作），对外站只带 origin。
- **P1-10** `GET /api/dashboard/` 按角色「管理主机」收敛，非管理员不再能拿到全网
  主机清单与告警明细（以前只验登录就返回全部）。
- **P2-1** 新增全局安全响应头（`X-Content-Type-Options` / `X-Frame-Options` /
  `Referrer-Policy` / `Permissions-Policy` / HTTPS 下的 HSTS）。
  刻意不加 CSP：代理链路依赖注入的内联 `<script>` 做票据自救。
- **P2-1** 后端证书准备失败时**不再静默降级为 HTTP**，改为拒绝启动
  （显式 `VIGILSERVE_TLS_INSECURE_FALLBACK=1` 才可临时放行）。
- **P2-2** 「WEB管理 - 新窗口打开」改为在空白窗口里写一张**同样带 sandbox 的 iframe**，
  不再让设备页面裸奔在顶层窗口里；`allow-popups-to-escape-sandbox` 只在独立源形态下给。
- **P2-3** `GET /api/roles/manifest` 补登录校验（以前匿名可读，等于对外公布整套权限点）。
- **P2-4** `PUT /api/servers/reorder` 里不存在的权限点 `sys/servers/edit`
  改为显式管理员校验（该权限点在注册表里根本不存在，对非管理员恒为 False）。
- **P2-6** Agent 9998 拿不到 TLS 材料时默认 **fail closed**（不监听），
  不再静默退回明文（该 listener 绑 `0.0.0.0`）。证书领到后由 watcher 自动补起。
- **P2-7** 上传加了大小硬约束并修掉静默截断：以前 `read(MAX_UPLOAD)` 会把超限部分
  **悄悄丢弃**，客户端以为成功、落地的文件其实坏了；现在边读边计数，超限回 413 并删半成品。
- **P2-8** 卸载应用不再走 `shell=True`：命令来自注册表 `UninstallString`（HKCU 下
  普通用户可写），`shell=True` 会把 `uninstall.exe & evil.exe` 当两条命令执行。

### 变更

- **D-1** `installer/build_installer.py` 加两道护栏（前置产物校验 + 版本一致性校验），
  `installer/source/` 已重新同步到源码（此前是 1.1.34 / 1.1.49 的旧快照）。
- **D-2** 新增 `verify_version.py`：9 处版本号一致性自检，真源为
  `backend/main.py` 与 `agent/api_server.py`。
- **D-4** 新增 README / 本文件；`DEPLOY.md` 删掉了不存在的 Docker Compose 部署方式
  （仓库里只有两个 Dockerfile、没有编排文件），并修正了环境变量表
  （`DB_PATH` 并不是环境变量）。
- **D-5** 构建脚本改为按**文件名里的版本号**挑安装包，不再按 mtime —— 旧包被复制/扫描
  touch 一下就会盖过真正的最新版，导致版本号与代码对不上。

- **P1-6（第 1 处，设备 WEB 代理）** 连设备不再 `verify=False` 裸奔，改成 **TOFU
  证书指纹钉扎**：首次连接记下叶子证书 SHA-256，之后每次比对，不一致直接 502。
  设备重装/换证书后需**显式重钉**（`POST /api/servers/{id}/web/repin-tls`），
  不允许自动接受新指纹（否则中间人等一次换证就进来了）。
  `VIGILSERVE_DEVICE_TLS_PIN=off|tofu|strict` 可切换，默认 `tofu`。
- **P1-6（第 2 处，WinRM）** 原先 URL 写死 `http://`，那个 `server_cert_validation='ignore'`
  其实是**死参数**（http 没有 TLS）。现在按端口选协议：5986 → https + 本地 CA 校验；
  其余维持 http，**现有部署行为不变**，但代码不再自欺欺人。
- **P1-6（第 3/4/5 处，复核后判定无需改）**
  - `services/agent_auth.py`：`verify_mode=CERT_REQUIRED` + 本地 CA，**本来就在校验**，
    只是 `check_hostname=False`（Agent 证书 SAN 是签发时的 IP，DHCP 换址会不匹配）。已补注释。
  - `agent/tls_util.py`：默认走 CA 校验，`verify_tls=false` 是**显式 opt-out**，
    只是以前静默生效。现在关掉时会告警一次。
  - `tray/tray_app.py`：只用于判断本机后端讲 http 还是 https（拼浏览器地址用），
    连接目标是 127.0.0.1 回环。有本地 CA 时走 `CERT_REQUIRED`。已补注释。
- **P1-1** 设备 WEB 管理的**口令不再随页面下发**：注入脚本里现在只有一个随机
  `cred_id`，真正的口令由脚本运行时向 `.../web/<票据>/__vs_cred?c=<id>` 按需取回
  （要求有效票据 + 该设备权限，TTL 60 秒）。此前口令明文嵌在 `<script>` 里，而那个
  script 标签会一直挂在 DOM 上，设备页面任何脚本都能读到；口令还会进页面源码、
  浏览器缓存和截图。「**只填不提交**」的决策不变 —— 登录那一击仍由人按。

### 已知问题 / 待办

- `PUT /api/servers/reorder` 实际不可达：`PUT /{server_id}`（servers.py:520）注册在它之前，
  请求会被吃掉并回 422；前端目前也没调用它（侧边栏排序只存 localStorage）。
- 初始化仍使用硬编码默认管理员口令，需改成随机生成 + 强制首登改密
  （2026-09-23 已与用户确认：**本轮不做**）。
- 代码签名（D-3）尚未做，需要证书。
- 填充脚本执行完后没有自毁（仍可通过 DOM 读到 script 节点，但里面已无口令）。
  要彻底清掉得改填充状态机的收尾分支，留待下一轮。
