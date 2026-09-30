"""通用权限点框架（RBAC）。

权限模型
--------
权限分两个作用域（scope）：

* ``sys``  —— 系统级页面（侧边栏菜单项 / 系统设置里的页面）
* ``host`` —— 主机详情页签

每个页面有两级权限：

* ``view`` 查看：能否看到该菜单项 / 页签
* ``edit`` 编辑：该页面内写操作的**总开关**
* ``ops``  操作项：编辑权限的细粒度拆分，颗粒度到按钮、页签、菜单项对应的具体动作

存储格式（``Role.permissions``，JSON）：

    {
      "sys":  {"dashboard": {"view": true, "edit": false, "ops": {}}},
      "host": {"status":    {"view": true, "edit": false, "ops": {"power": false}}}
    }

框架是**通用**的：新增页面或操作项只需往下面的 ``PAGES`` 里加一条，
不需要改动校验逻辑与前端配置界面。
"""

from typing import Any, Dict, Optional

# sys.name 使用「页面/页签」完整路径；ops.name 与页面上实际按钮文字一致
PAGES: Dict[str, list] = {
    "sys": [
        {"code": "dashboard", "name": "仪表盘", "ops": []},
        {
            "code": "register",
            "name": "主机管理/主机管理",
            "ops": [
                {"code": "approve", "name": "加入管理"},
                {"code": "delete", "name": "移出管理"},
                {"code": "edit", "name": "编辑主机"},
            ],
        },
        {
            "code": "host_groups",
            "name": "主机管理/分组管理",
            "ops": [
                {"code": "create", "name": "创建分组"},
                {"code": "edit", "name": "编辑"},
                {"code": "delete", "name": "删除"},
            ],
        },
        {
            "code": "agent_update",
            "name": "主机管理/Agent更新",
            "ops": [
                {"code": "update", "name": "一键更新"},
                {"code": "retry", "name": "重试"},
            ],
        },
        {
            "code": "network_devices",
            "name": "主机管理/网络设备",
            "ops": [
                {"code": "add", "name": "新增设备"},
                {"code": "connect", "name": "连接/断开"},
                {"code": "collect", "name": "测试连接/立即采集"},
                {"code": "edit", "name": "编辑设备"},
                {"code": "delete", "name": "删除设备"},
            ],
        },
        {
            "code": "logs",
            "name": "日志管理",
            "ops": [
                {"code": "export", "name": "导出 Excel"},
                {"code": "cleanup", "name": "清除日志"},
            ],
        },
        {
            "code": "settings",
            "name": "系统设置",
            "ops": [
                {"code": "security_manage", "name": "安全设置"},
                {"code": "roles_manage", "name": "角色管理"},
                {"code": "users_manage", "name": "用户管理"},
                {"code": "email_config", "name": "邮件配置"},
                {"code": "period_config", "name": "周期配置"},
                {"code": "alert_config", "name": "告警配置"},
            ],
        },
    ],
    "host": [
        {
            "code": "status",
            "name": "状态",
            "ops": [{"code": "power", "name": "电源操作（重启/关机）"}],
        },
        {
            "code": "info",
            "name": "主机信息",
            "ops": [],
        },
        {
            "code": "apps",
            "name": "应用管理",
            "ops": [
                {"code": "uninstall", "name": "一键卸载"},
                {"code": "startup", "name": "启动项管理（启用/禁用）"},
            ],
        },
        {
            "code": "services",
            "name": "进程管理",
            "ops": [
                {"code": "config", "name": "筛选/黑白名单配置"},
                {"code": "start", "name": "启动服务"},
                {"code": "stop", "name": "停止服务"},
                {"code": "restart", "name": "重启服务"},
                {"code": "terminate", "name": "结束进程"},
            ],
        },
        {
            # 第二轮复查 R-13：以前「资源管理」只有一个空的 ops 列表 —— 非管理员要么
            # 全不能碰（P0-2 之后读类被抬到管理员，等于半残），要么只能一把全给。
            # 现在按**具体操作**细分，管理员不受影响（has_perm 对 is_admin 恒真）。
            #
            # 「可见」由页面级的 view 承担（能不能列目录/看到这个页签），
            # 下面 7 项是具体操作。注意 `read` 标了 needs_edit=False ——
            # 只读角色不该被迫勾上"编辑"才能下载文件，详见 `can()`。
            "code": "resources",
            "name": "资源管理",
            "ops": [
                {"code": "read", "name": "查看/下载文件", "needs_edit": False},
                {"code": "rename", "name": "重命名文件/目录"},
                {"code": "copy", "name": "复制文件/目录"},
                {"code": "mkdir", "name": "新建目录"},
                {"code": "upload", "name": "上传文件"},
                {"code": "write", "name": "修改/新建文件（含解压）"},
                {"code": "delete", "name": "删除文件/目录"},
            ],
        },
        {
            "code": "terminal",
            "name": "WEB终端",
            "ops": [{"code": "connect", "name": "连接终端"}],
        },
        {
            # 方案 B：设备自带 Web 管理界面的代理入口（只有网络设备有数据来源）
            "code": "webadmin",
            "name": "WEB管理",
            "ops": [{"code": "connect", "name": "打开设备 Web 页面"}],
        },
        {
            "code": "rdp",
            "name": "远程桌面",
            "ops": [{"code": "connect", "name": "连接/断开"}],
        },
        {
            "code": "events",
            "name": "事件日志",
            "ops": [],
        },
        {
            # S5：网络设备（交换机 / 路由器 / 防火墙）——SNMPv3 采集 + SSH 主机密钥钉扎
            "code": "network",
            "name": "网络",
            "ops": [
                {"code": "config", "name": "SNMP 凭据配置"},
                {"code": "collect", "name": "立即采集/测试连接"},
                {"code": "repin", "name": "SSH 主机密钥重新钉扎"},
            ],
        },
    ],
}

SCOPES = ["sys", "host"]


def _page_def(scope: str, page: str) -> Optional[dict]:
    for p in PAGES.get(scope, []):
        if p["code"] == page:
            return p
    return None


def _op_def(scope: str, page: str, op: str) -> Optional[dict]:
    p = _page_def(scope, page)
    if not p:
        return None
    for o in p.get("ops") or []:
        if o["code"] == op:
            return o
    return None


def page_codes(scope: str) -> list:
    return [p["code"] for p in PAGES.get(scope, [])]


def op_codes(scope: str, page: str) -> list:
    p = _page_def(scope, page)
    return [o["code"] for o in (p["ops"] if p else [])]


def manifest() -> list:
    """返回给前端渲染权限勾选界面的完整清单。"""
    out = []
    for scope in SCOPES:
        pages = []
        for p in PAGES.get(scope, []):
            pages.append({
                "code": p["code"],
                "name": p["name"],
                "ops": [{"code": o["code"], "name": o["name"]} for o in p["ops"]],
            })
        out.append({
            "code": scope,
            "name": "系统权限" if scope == "sys" else "主机权限",
            "pages": pages,
        })
    return out



def empty_permissions() -> dict:
    """全部关闭。"""
    perms: Dict[str, dict] = {}
    for scope in SCOPES:
        perms[scope] = {}
        for p in PAGES[scope]:
            perms[scope][p["code"]] = {
                "view": False,
                "edit": False,
                "ops": {o["code"]: False for o in p["ops"]},
            }
    return perms


def full_permissions() -> dict:
    """全部开启（系统管理员）。"""
    perms: Dict[str, dict] = {}
    for scope in SCOPES:
        perms[scope] = {}
        for p in PAGES[scope]:
            perms[scope][p["code"]] = {
                "view": True,
                "edit": True,
                "ops": {o["code"]: True for o in p["ops"]},
            }
    return perms


def readonly_permissions() -> dict:
    """只看不改：所有页面可查看，编辑与操作项全部关闭。"""
    perms = empty_permissions()
    for scope in SCOPES:
        for page in perms[scope]:
            perms[scope][page]["view"] = True
    return perms


def normalize(perms: Any) -> dict:
    """把任意来源（可能缺字段、可能有多余字段）的权限数据补全成标准结构。

    缺失一律按**关闭**处理，避免新增权限点后旧数据意外放行。
    """
    base = empty_permissions()
    if not isinstance(perms, dict):
        return base
    for scope in SCOPES:
        src = perms.get(scope)
        if not isinstance(src, dict):
            continue
        for page in base[scope]:
            entry = src.get(page)
            if not isinstance(entry, dict):
                continue
            base[scope][page]["view"] = bool(entry.get("view", False))
            base[scope][page]["edit"] = bool(entry.get("edit", False))
            src_ops = entry.get("ops")
            if isinstance(src_ops, dict):
                for op in base[scope][page]["ops"]:
                    base[scope][page]["ops"][op] = bool(src_ops.get(op, False))
    return base



def can(perms: Any, scope: str, page: str, action: str, op: Optional[str] = None) -> bool:
    """统一判定入口。

    action 取 ``view`` / ``edit``；传 ``op`` 时判定具体操作项。
    未知 scope/page/op 一律返回 False（安全失败）。
    """
    if action not in ("view", "edit"):
        return False
    if scope not in PAGES or _page_def(scope, page) is None:
        return False
    data = normalize(perms)
    entry = data[scope][page]
    if op is not None:
        if op not in entry["ops"]:
            return False
        # 操作项默认受页面「编辑」总开关约束（既有语义，不能改）。
        # 但像「查看/下载文件」这种**只读**操作，要求勾了 edit 才给就很别扭 ——
        # 只读角色会被迫拿到编辑总开关。op 定义里标 `needs_edit: False` 即可豁免。
        odef = _op_def(scope, page, op) or {}
        if odef.get("needs_edit", True) and not entry["edit"]:
            return False
        return bool(entry["ops"][op])
    return bool(entry[action])


def ops_without_edit() -> Dict[str, list]:
    """返回「不要求页面 edit 总开关」的操作项，形如 `{"host/resources": ["read"]}`。

    前端 `services/permissions.jsx` 的 `lookup()` 判 op 时也要求 `edit` 为真，
    与后端 `can()` 是同一套口径。加了 `needs_edit: False` 之后两边必须同步，
    否则会出现「后端放行、前端按钮却不显示」的错位。所以把规则下发下去，
    让前端也按同一份判定。
    """
    out: Dict[str, list] = {}
    for scope in SCOPES:
        for p in PAGES.get(scope, []):
            for o in p.get("ops") or []:
                if o.get("needs_edit") is False:
                    out.setdefault(f"{scope}/{p['code']}", []).append(o["code"])
    return out


def has_any_of(perms: Any, scope: str, page: str) -> bool:
    """该页面是否有任意权限（用于隐藏空页签/菜单）。"""
    data = normalize(perms)
    entry = data.get(scope, {}).get(page)
    if not entry:
        return False
    return bool(entry["view"] or entry["edit"] or any(entry["ops"].values()))
