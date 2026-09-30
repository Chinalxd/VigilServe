"""「WEB管理」页签的账号口令**自动填充**（2026-09-22 由"自动登录"退成"只填不提交"）。

## 为什么退这一步

原来是"把表单填好**并点一下登录**"。实测失败率高，而且原因都在设备侧：

* 群晖 DSM 7.1 的登录是**两步的 Vue 路由**：`/signin`（先问账号）→ 点箭头才进
  `/signin/password`（问口令）。**口令框在第二步之前根本不存在**；
* 更要命的是 `dsmAccountPanel.vue`（真机分包核对）里**账号页就藏着一个
  `input[type=password][hidden]` 的诱饵**。老脚本"看见口令框才动手"的判定被它
  骗住，把口令填进了隐藏框 —— 页面上该填的那个自始至终是空的。

这条路本身就不该由我们走：填错口令**可能锁死设备账号**（华为"输入错误密码
次数达到上限"、DSM 同样会锁），收益只是替人省一下鼠标。各家固件还会随时改。

所以契约收窄成一句话：**只把账号和口令填进登录页，绝不点登录。**
登录那一击永远由人按 —— 我们连碰都不碰，也就不存在消耗失败次数的可能。

## 唯一的例外：群晖的"下一步"箭头

DSM 的口令框在第二步，不点箭头就看不见，光填账号等于没填。所以给群晖单独放行
一次**前进**动作，选择器来自真机分包（`dsm.login.bundle.js` 及其分包）：

    [syno-id="account-panel-next-btn"]    ← 账号页的"下一步"，点它
    [syno-id="password-panel-next-btn"]   ← 密码页的**登录**按钮，代码里显式拉黑

那一下只调 `SYNO.API.Auth.Type&method=get&account=<账号>`（查该账号支持哪些
验证方式），**不发口令、不计失败次数**，不是登录尝试。

## 触发条件（三条全满足才做）

1. 设备自己**返回了登录页** —— 有会话时设备直接给主页，走不到这里，
   所以"是不是登录页"本身就是"有没有会话"的判定，不需要额外维护会话状态。
2. 管理员在这台设备的编辑弹窗里**存了账号口令并打开了开关**。
3. 当前厂商**有对应适配器**（`ADAPTERS`）。识别不出来一律不动，
   宁可让人手敲，也不猜一个表单乱填。

## 安全边界（2026-09-22 起）

* **只填空框** —— 框里已有内容（设备自己记住的上次用户名）不覆盖；
* **不跟人抢** —— 检测到真人敲键盘（可信 `keydown`）或光标已经落在框里，
   立刻收手，绝不覆盖人正在输入的内容；
* **排除隐藏框** —— `hidden` / 不可见的输入框一律不算（群晖那个诱饵就死在这）；
* 账号口令全走 `_js_str` 转义，口令里带 `</script>` 也闭合不了标签。
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
from typing import Optional

# ── 凭据按需发放（P1-1，2026-09-23）─────────────────────────────────
# 以前账号口令是**明文拼进注入的 `<script>`** 里的，而那个 script 标签会一直挂在
# 就能把明文口令读走（设备被入侵时这是现成的通道）。口令还会跟着页面源码一起进
# 现在改成：注入的脚本里**只有一个随机 cred_id**，口令由脚本在运行时向**我们自己的**
# 代理端点按需拉取。端点要求：有效票据 + 该用户对这台设备的 WEB 管理权限，
# 且凭据只在很短的 TTL 内可取。于是：
#   * 口令不会流到设备页面自己的脚本能静态扫到的地方。
# 「只填不提交」的决策不变 —— 登录那一击仍然永远由人按（见模块 docstring）。
CRED_TTL = 60.0
CRED_PATH = "__vs_cred"
_cred_lock = threading.Lock()
_creds: dict = {}


def _sweep_creds() -> None:
    now = time.time()
    for k in [k for k, v in _creds.items() if v["exp"] < now]:
        _creds.pop(k, None)


def issue_cred(server_id: int, user_id: int, username: str, password: str) -> str:
    """登记一份待取的凭据，返回随机 cred_id（只放进注入脚本里）。"""
    cid = secrets.token_urlsafe(24)
    with _cred_lock:
        _sweep_creds()
        _creds[cid] = {
            "server_id": int(server_id),
            "user_id": int(user_id),
            "u": username,
            "p": password,
            "exp": time.time() + CRED_TTL,
        }
    return cid


def take_cred(cid: str, server_id: int, user_id: int) -> Optional[dict]:
    """取出凭据。认不出 / 过期 / 换了设备或用户，一律 None。

    ⚠ 刻意**不消费**（第二轮复查 R-10）：取走后仍然留在表里，直到 CRED_TTL 到期
    才被清掉。原因是填充脚本最多要试 `MAX_FILL_ATTEMPTS` 次（页面重渲染会把值
    冲掉、需要补写），取一次就失效的话第二次补写必然拿不到。
    安全上成立的前提是：**同一个 cid 只对同一 (server_id, user_id) 生效**，
    且是 24 字节随机值、60 秒就过期 —— 重复取的人本来就已经通过了票据与权限校验。
    以前这里的注释写"被取走…都不再说第二遍"，与实现不符，已改正。
    """
    if not cid:
        return None
    with _cred_lock:
        _sweep_creds()
        e = _creds.get(cid)
        if not e:
            return None
        # 别把 A 设备的口令交给 B 设备的页面，也别给别人用
        if e["server_id"] != int(server_id) or e["user_id"] != int(user_id):
            return None
        return {"u": e["u"], "p": e["p"]}


def revoke_cred(cid: str) -> None:
    with _cred_lock:
        _creds.pop(cid, None)


#: 不是"防锁"用的（我们本来就不提交），而是防两件事：
#:   ② 人手删掉内容后我们没完没了地填回去 → 写满这么多次就撒手。
MAX_FILL_ATTEMPTS = 5



class _Adapter:
    """各家登录页的差异只有四个选择器 + 两个节奏参数。

    `is_login_page()` 负责"是不是登录页"的判定（认不出来就不注入），
    `script()` 交给下面统一的填充脚本。

    ⚠ **能认出来的厂商才做适配器**：认不出来的厂商 `supported()` 为 False，
    编辑弹窗会提示"暂不支持"，绝不会去猜一个表单乱填。
    """

    label = ""

    #: 账号框 / 口令框 / "下一步"按钮选择器（空串 = 没有这个元素）
    user_sel = ""
    pass_sel = ""
    #: 分步登录才有的"前进"按钮 —— **只有群晖有**，其余一律空串（绝不点任何东西）
    advance_sel = ""

    #: 轮询节奏。分两段（2026-09-22 提速）：开头 `fast_ms` 毫秒内每 `fast_step`
    #: 毫秒探一次（登录框往往几百毫秒内就渲染出来了），之后降频到 `step`，
    #: 最多 `wait` 次。
    #: ⚠ 轮询只是兜底 —— 真正让它"一出现就填上"的是脚本里的 MutationObserver。
    fast_step = 50
    fast_ms = 3000
    step = 250
    wait = 80

    def is_login_page(self, path: str, html: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def script(self, username: str, cred_url: str) -> str:
        """生成填充脚本。

        ⚠ 第二个参数从「口令」改成了「凭据地址」（P1-1）：口令不再拼进这段脚本，
        而是脚本运行时去 `cred_url` 取。这样页面源码里永远没有明文口令。
        """
        return _FILL_SCRIPT \
            .replace("__USEL__", _js_str(self.user_sel)) \
            .replace("__PSEL__", _js_str(self.pass_sel)) \
            .replace("__ADV__", _js_str(self.advance_sel)) \
            .replace("__U__", _js_str(username)) \
            .replace("__CURL__", _js_str(cred_url or "")) \
            .replace("__WAIT__", str(int(self.wait))) \
            .replace("__STEP__", str(int(self.step))) \
            .replace("__FASTSTEP__", str(int(self.fast_step))) \
            .replace("__FASTMS__", str(int(self.fast_ms))) \
            .replace("__MAXFILL__", str(int(MAX_FILL_ATTEMPTS)))


class HuaweiAdapter(_Adapter):
    """华为 VRP 的 Web 管理（S 系列交换机 / AR 路由器的"易维版"界面）。

    真机核对过（华为 S5731S-H48T4X-A）：
      - 入口 `GET /` → 301 → `/simple/view/login.html`
      - 账号框 `id="UserName"`，口令框 `id="userPassword"`
      - 登录按钮 `<div id="goBtn" onclick="loginWeb();">`
        ⇒ **我们不再碰它**（2026-09-22 前是自动点它，现改为只填）

    单页表单、口令框一开始就在，所以没有 `advance_sel`。
    """

    label = "华为"
    user_sel = "#UserName"
    pass_sel = "#userPassword"

    _USER_RE = re.compile(r"""id\s*=\s*["']UserName["']""", re.I)
    _PASS_RE = re.compile(r"""id\s*=\s*["']userPassword["']""", re.I)

    def is_login_page(self, path: str, html: str) -> bool:
        # 认 DOM 不认路径：固件改了登录页的摆放位置也不会失效
        return bool(self._USER_RE.search(html) and self._PASS_RE.search(html))


class SynologyAdapter(_Adapter):
    """群晖 DSM 7 的登录页（DS918+ 真机核对，2026-09-22）。

    🚨 **静态 HTML 是空壳**，表单是 bundle.js 运行时渲染的：

        <div id="sds-login-vue"></div>
        <script src="webman/login/dist/dsm.login.bundle.js"></script>

    服务端拿到的 HTML 里一个 input 都没有，所以只能用"壳子特征"判定，填充靠轮询。

    真机分包里核对到的关键事实：

    1. **两步路由**：`/signin`（`DSMAccountPanel`）→  `/signin/password`
       （`DSMPasswordPanel`）。两个面板各有自己的"下一步"按钮：

           [syno-id="account-panel-next-btn"]    → onClickNext，进第二步
           [syno-id="password-panel-next-btn"]   → onLogin，**这才是登录**

    2. **账号页有个 `input[type=password][hidden]` 的诱饵**（v-model 绑着
       `password`、`tabindex=-1`）—— 老脚本正是栽在它上面。所以填充脚本必须
       按**可见性**挑框。

    3. 输入框走 Vue 2 的 v-model（`domProps:{value}` + `on:{input}`）⇒
       直接 `el.value=xxx` Vue 收不到，必须**原生 setter + `input` 事件**。

    4. 首屏要拉 100 多个分片（见 routes/network_web.py 的连接池注释），
       渲染慢 ⇒ 轮询窗口给到 30 秒（150×200ms）。

    ⚠ 开了两步验证（2FA）时 OTP 框会跟着口令框一起出现 —— 我们本来就不提交，
    所以那种情况下照样只填，管理员自己补验证码。
    """

    label = "群晖 DSM"

    #: 真机登录页的两个特征（静态 HTML 里就有的，不依赖 JS 渲染）
    _SHELL_RE = re.compile(r"""id\s*=\s*["']sds-login-vue["']""", re.I)
    _BUNDLE_RE = re.compile(r"""webman/login/dist/dsm\.login\.bundle\.js""", re.I)

    user_sel = '[syno-id="username"]'
    pass_sel = '[syno-id="password"]'
    #: ⚠ 只有这个选择器被允许点击，且只在"口令框还没出现"时点一次
    advance_sel = '[syno-id="account-panel-next-btn"]'

    #: DSM 首屏 100+ 分片，登录卡片是懒加载 chunk 渲染的 → 高频窗口给长一点
    fast_ms = 8000
    fast_step = 50
    step = 400
    wait = 120

    def is_login_page(self, path: str, html: str) -> bool:
        return bool(self._SHELL_RE.search(html) or self._BUNDLE_RE.search(html))


class _FormAdapter(_Adapter):
    """静态表单登录页的通用适配器（账号框 + 口令框）。

    ⚠ **这一族都没有真机核对过**（除华为另有专用类）：字段是按各厂商 Web UI
    的公开惯例写的，`is_login_page` 要求**账号框和口令框同时命中**才认，
    认不出来就不注入 —— 宁可让人手填，也不在错误的页面上乱填。

    拿到真机后只改 `user_re` / `pass_re` / `user_sel` / `pass_sel` 即可。
    """

    label = ""
    user_re = re.compile(r"""name\s*=\s*["']username["']""", re.I)
    pass_re = re.compile(r"""type\s*=\s*["']password["']""", re.I)

    def is_login_page(self, path: str, html: str) -> bool:
        return bool(self.user_re.search(html) and self.pass_re.search(html))


class QnapAdapter(_FormAdapter):
    """QNAP QTS 登录页（**未实测**，按 QTS 登录表单惯例写）。

    QTS 5 的登录页字段是 `user` / `pwd`。**只填不提交**，所以不再需要猜它的
    登录按钮（原 `#btnLogin` / `login()` 那套已删除）。
    """

    label = "QNAP QTS"
    user_re = re.compile(r"""name\s*=\s*["'](?:user|username)["']""", re.I)
    user_sel = 'input[name="user"],input[name="username"]'


class H3cAdapter(_FormAdapter):
    """华三 Comware Web 登录页（**未实测**，按 Comware Web 惯例写）。"""

    label = "华三"
    user_re = re.compile(r"""name\s*=\s*["'](?:username|user_name)["']""", re.I)
    user_sel = 'input[name="username"],input[name="user_name"]'


class RuijieAdapter(_FormAdapter):
    """锐捷 RGOS Web 登录页（**未实测**，按 RGOS Web 惯例写）。"""

    label = "锐捷"
    user_re = re.compile(r"""name\s*=\s*["'](?:username|user)["']""", re.I)
    user_sel = 'input[name="username"],input[name="user"]'


class FortinetAdapter(_FormAdapter):
    """飞塔 FortiGate 登录页（**未实测**）。

    FortiGate 的口令框名字不是 password 而是 **`secretkey`**，这是它家的老传统，
    所以判定和定位都要单独写。
    """

    label = "飞塔 FortiGate"
    user_re = re.compile(r"""name\s*=\s*["']username["']""", re.I)
    pass_re = re.compile(r"""name\s*=\s*["']secretkey["']""", re.I)
    user_sel = 'input[name="username"]'
    pass_sel = 'input[name="secretkey"]'


class CiscoAdapter(_FormAdapter):
    """思科 Catalyst / IOS-XE 的 Web 登录页（**未实测**，且**适用范围很窄**）。

    ⚠ 思科各型号的 Web 管理差异极大：很多型号（含部分 Catalyst 9x00、
    IOS-XE）用的是 **HTTP Basic 认证**（浏览器弹原生认证框），那条路上
    根本不存在登录表单，填充脚本**不适用**，只能人工在弹框里输。这里只覆盖
    "确实是表单登录页"的那一小部分，命中不了就不动。
    """

    label = "思科（仅表单登录页）"
    user_re = re.compile(r"""name\s*=\s*["'](?:username|user)["']""", re.I)
    user_sel = 'input[name="username"],input[name="user"]'


ADAPTERS = {
    "huawei": HuaweiAdapter(),
    "synology": SynologyAdapter(),
    "qnap": QnapAdapter(),
    "h3c": H3cAdapter(),
    "ruijie": RuijieAdapter(),
    "fortinet": FortinetAdapter(),
    "cisco": CiscoAdapter(),
}

#: 中文厂商名 → 小写代码（`device_profile` 走企业号时存的是中文，如"群晖"）
_ALIASES = {
    "华为": "huawei",
    "华三": "h3c",
    "思科": "cisco",
    "锐捷": "ruijie",
    "中兴": "zte",
    # 别让"群晖识别得出来却匹配不到适配器"这种事再发生一次。
    "群晖": "synology",
    "Synology": "synology",
    "QNAP": "qnap",
    "威联通": "qnap",
    "飞塔": "fortinet",
    "Fortinet": "fortinet",
}


def vendor_code(vendor: str) -> str:
    """把 `device_vendor`（可能是中文也可能是小写代码）归一成适配器 key。"""
    v = (vendor or "").strip()
    if not v:
        return ""
    if v in ADAPTERS:
        return v
    if v in _ALIASES:
        return _ALIASES[v]
    return v.lower()


def adapter_for(server) -> Optional[_Adapter]:
    """按 `device_vendor` 选适配器；认不出来返回 None（不做任何动作）。"""
    return ADAPTERS.get(vendor_code(getattr(server, "device_vendor", "") or ""))


def supported(server) -> bool:
    return adapter_for(server) is not None



#: 统一填充脚本。**没有任何一处点击登录按钮的逻辑** —— 整个脚本里 `click()`
#: 只出现在 `__ADV__` 那一个分支（群晖的"下一步"），其余一律只赋值。
#: 🚨 **别等 `DOMContentLoaded`**（2026-09-22 提速的要点）：DSM 那种页面要拉
#: 100+ 个分片、登录卡片还是懒加载 chunk 渲染的，DCL 往往比"卡片出现"还晚好几秒，
#: 注意别用 Python 的 str.format：这段 JS 里全是 `{}`。
_FILL_SCRIPT = (
    "<script>(function(){"
    # ⚠ 口令**不在这里**：P 先置空，真正的口令由下面的 fetch 从服务端按需取回
    # （见本文件顶部「凭据按需发放」）。注入的这段代码里只有账号和一个随机
    # cred 地址，页面源码被谁看到都不会泄露口令。
    "var US=__USEL__,PS=__PSEL__,ADV=__ADV__,U=__U__,P='',CU=__CURL__;"
    "var uFills=0,pFills=0,adv=false,sawForm=false,sawBanner=false,quit=false,n=0,busy=false;"
    "var userTouched=false;"
    "var t0=Date.now(),lastPoke=0,obs=null;"
    "function unhook(){try{if(obs){obs.disconnect();obs=null;}}catch(e){}}"
    "function stop(){quit=true;unhook();}"
    # 真人一敲键盘就收手，绝不覆盖人正在输入的内容。
    # 我们自己派发的 input/change 不算（只监听 keydown）；点按钮是脚本触发的
    # 非可信事件（isTrusted=false），也不会误触发。
    "document.addEventListener('keydown',function(e){if(e.isTrusted){stop();}},true);"
    # 🚨 **别拿 `activeElement` 当"人正在输入"的判据**（2026-09-22 真机踩到）：
    # DSM 打开登录页会**自动聚焦**用户名框（真机实测 activeElement 就是它），
    # 那是页面自己的动作、不是人 —— 用它当守卫会让填充被无限期跳过，表现得
    # 时好时坏（人工点别处 blur 掉之后才补上）。这里只认**人的动作**：
    # 敲键（上面那个 keydown）或**点进输入框**（下面的 pointerdown）。
    "document.addEventListener('pointerdown',function(e){"
    " if(e.isTrusted&&e.target&&e.target.tagName==='INPUT'){userTouched=true;}},true);"
    "function banner(){return document.getElementById('vigilFillBanner');}"
    "function hideBanner(){var b=banner();if(b&&b.parentNode){b.parentNode.removeChild(b);}}"
    # 横幅上的关闭按钮由脚本挂事件（不用内联 onclick，免得撞设备页的 CSP）
    "function bindClose(){"
    " var b=banner();if(!b||b.__vBound)return;b.__vBound=true;"
    " var c=document.getElementById('vigilFillClose');"
    " if(c&&c.addEventListener){c.addEventListener('click',function(ev){"
    "  if(ev){if(ev.preventDefault){ev.preventDefault();}if(ev.stopPropagation){ev.stopPropagation();}}"
    "  hideBanner();});}"
    "}"
    # 可见性判定：群晖账号页那个 hidden 口令框就是死在这一条上
    "function vis(el){"
    " if(!el||el.disabled||el.readOnly||el.hidden)return false;"
    " if(el.type==='hidden')return false;"
    " if(el.offsetParent===null&&(!el.getClientRects||el.getClientRects().length===0))return false;"
    " return true;}"
    "function setVal(el,v){try{"
    " var d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');"
    " if(d&&d.set){d.set.call(el,v);}else{el.value=v;}"
    " el.dispatchEvent(new Event('input',{bubbles:true}));"
    " el.dispatchEvent(new Event('change',{bubbles:true}));"
    "}catch(e){el.value=v;}}"
    "function one(sel){if(!sel)return null;try{return document.querySelector(sel);}catch(e){return null;}}"
    # 先按厂商选择器找，找不到再退回"页面上第一个可见的文本框/口令框"
    "function pick(sel,fb){"
    " var e=one(sel);if(vis(e))return e;"
    " var ls=document.querySelectorAll(fb),i;"
    " for(i=0;i<ls.length;i++){if(vis(ls[i]))return ls[i];}"
    " return null;}"
    "function work(){"
    " if(quit)return;"
    # 横幅被点掉 = 管理员不想再看到它，那就连填充也一起收工
    " var b=banner();"
    " if(b){sawBanner=true;bindClose();}"
    " else if(sawBanner){stop();return;}"
    " var u=pick(US,'input[type=text],input:not([type])'),"
    "     p=pick(PS,'input[type=password]');"
    " if(u||p){sawForm=true;}"
    # 只填空框；人动过页面（敲键/点进输入框）就整轮不碰。
    # 被重渲染冲掉可以补写，但最多 __MAXFILL__ 次（也不会没完没了地跟人抢）。
    " if(!userTouched){"
    "  if(u&&!u.value&&uFills<__MAXFILL__){setVal(u,U);uFills++;}"
    "  if(p&&!p.value&&pFills<__MAXFILL__){setVal(p,P);pFills++;}"
    " }"
    # 口令框还没出现、但账号已经填好 → 只对"分步登录"（ADV 非空）点一次前进。
    " if(!p&&ADV&&!adv&&u&&u.value){"
    "  var bt=one(ADV);"
    "  if(bt&&bt.classList&&!bt.classList.contains('disable')&&!bt.classList.contains('disabled')){"
    "   adv=true;bt.click();}"
    " }"
    # 登录成功（登录框整组没了）→ 撤掉横幅、收工，别再挡设备界面
    " if(sawForm&&!u&&!p){hideBanner();stop();}"
    "}"
    # MutationObserver 只做"催一下"，40ms 节流；自己派发的事件不改 DOM，不会自激
    "function poke(){if(quit||busy)return;var t=Date.now();if(t-lastPoke<40)return;lastPoke=t;"
    " busy=true;try{work();}finally{busy=false;}}"
    "function tick(){"
    " if(quit)return;"
    " busy=true;try{work();}finally{busy=false;}"
    " if(quit)return;"
    " if(++n>__WAIT__){unhook();return;}"
    " setTimeout(tick,(Date.now()-t0<__FASTMS__)?__FASTSTEP__:__STEP__);"
    "}"
    "try{obs=new MutationObserver(poke);"
    " obs.observe(document.documentElement,{childList:true,subtree:true});}catch(e){}"
    # 口令按需取回后再开工。取不到（票据过期 / 端点异常）也不拖着不干活 ——
    # 照样把账号填了，口令留给人自己敲。
    "function go(){tick();}"
    "if(CU){try{"
    " fetch(CU,{credentials:'omit',headers:{'Accept':'application/json'}})"
    " .then(function(r){return r.ok?r.json():null})"
    " .then(function(j){try{if(j){if(j.u)U=j.u;if(j.p)P=j.p;}}catch(e){} go();})"
    " .catch(function(){go();});"
    "}catch(e){go();}}else{go();}"
    "})();</script>"
)



#: 填好之后在设备页面顶部挂一条说明。**不是报错**，所以用平静的蓝灰而不是红 ——
#: 2026-09-22 之前那条红条写的是"自动登录 N 次仍未成功"，现在不会有这种事了。
#: 🚨 2026-09-22 二改：**必须能关掉**（`vigilFillClose`）—— 它压在设备页面顶栏上，
#: 关不掉就挡住了设备自己的操作。关闭动作由填充脚本挂事件（不用内联 `onclick`），
#: 另外登录成功后脚本会自动把它撤掉，不会跟着进桌面。
_FILLED_BANNER = (
    "<div id=\"vigilFillBanner\" style=\"position:fixed;left:0;right:0;top:0;"
    "z-index:2147483647;display:flex;align-items:center;justify-content:center;"
    "padding:8px 46px 8px 14px;background:#2c5c8f;color:#fff;"
    "font:13px/1.6 'Microsoft YaHei',sans-serif;text-align:center\">"
    "<span>VigilServe:将为你自动填入登录账号与口令，为避免设备锁定账号，"
    "请手动点击登录按钮完成登录。</span>"
    "<button id=\"vigilFillClose\" type=\"button\" title=\"关闭提示\" aria-label=\"关闭提示\" "
    "style=\"position:absolute;right:8px;top:50%;transform:translateY(-50%);"
    "width:22px;height:22px;padding:0;border:0;border-radius:3px;cursor:pointer;"
    "background:rgba(255,255,255,.2);color:#fff;font:15px/22px 'Microsoft YaHei',sans-serif\">"
    "×</button>"
    "</div>"
)


def filled_banner() -> str:
    return _FILLED_BANNER


def inject(html: str, snippet: str) -> str:
    """把 snippet 插到 `</body>` 前；没有 body 就贴到末尾。"""
    if not snippet:
        return html
    lower = html.lower()
    pos = lower.rfind("</body>")
    if pos >= 0:
        return html[:pos] + snippet + html[pos:]
    return html + snippet


def _js_str(s: str) -> str:
    """字符串 → 可安全嵌进 `<script>` 的 JS 字面量。

    `json.dumps` 不转义 `<`，口令里带 `</script>` 会提前闭合标签，所以补一道。
    """
    return json.dumps(s or "").replace("<", "\\u003c").replace(">", "\\u003e")
