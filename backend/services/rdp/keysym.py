"""X11 keysym -> Windows 输入。

Guacamole 前端 `sendKeyEvent(pressed, keysym)` 发的是 **X11 keysym**，不是浏览器
`event.code`，所以不能直接喂给 injector 原有的 code->VK 表。

keysym 取值（已核对官方 guacamole-common-js 1.5.0 `keycodeKeysyms` / `keyidentifier_keysym`）：
  * 特殊键        0xFF08 退格 / 0xFF0D 回车 / 0xFF1B ESC / 0xFF51-54 方向 ...
  * 可打印 ASCII  0x20-0x7E 直接等于码点
  * Latin-1      0xA0-0xFF 直接等于码点
  * Unicode      0x01000000 | codepoint
  * 控制字符      0xFF00 | codepoint（如 Ctrl+C = 0xFF03）

转换策略（按优先级）：
  1. 特殊键表 -> VK
  2. 可打印字符 -> `VkKeyScanW` 取 VK，**并保留"是否需要 Shift"这一位**
  3. 当前键盘布局上没有的字符 -> `SendInput` + `KEYEVENTF_UNICODE` 直注字符
  4. 控制字符 0xFF01-0xFF1A -> Ctrl + 字母（成对按下/抬起，不会留下粘滞修饰键）

⚠️ 大小写坑（2026-09-11 实测）：Guacamole 发的是**最终字符**的 keysym——按 Shift+V
浏览器 `event.key === "V"`，前端直接发 `0x56`，**不会额外发 Shift 按下**。
早期版本无条件丢弃 `VkKeyScanW` 的修饰位，于是 `V` -> `VK_V` -> 无 Shift 注入 -> 打出
小写 `v`，整串 "VigilServe" 变成 "vigilserve"。现在把 Shift 需求位带出去，由调用方
（hub）结合"Shift 当前是否已被按住"决定是否补按。

⚠️ CapsLock 坑（2026-09-15 实测）：按下 CapsLock 后打字母仍然是**小写**。
原因同上——字母的最终大小写 = **CapsLock ⊕ Shift**（Windows 上两者是"异或"关系）：
  * 远端 CapsLock **关**：补 Shift 才出大写（上面那条修复的路径）；
  * 远端 CapsLock **开**：再补 Shift 反而变成**小写**。
用户本地开着 CapsLock 时浏览器 `event.key` 就是大写（发 `0x41`），旧逻辑照抄
`VkKeyScanW` 的"需要 Shift"再去补一次 Shift，于是远端 CapsLock(开) + Shift = 小写。
所以字母必须按"期望字符 vs CapsLock 基数是否一致"来判定，见 `shift_needed()`。
"""

from __future__ import annotations

import ctypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.VkKeyScanW.argtypes = [ctypes.c_wchar]
user32.VkKeyScanW.restype = ctypes.c_short

UNICODE_OFFSET = 0x01000000


_SPECIAL: dict[int, int] = {
    0xFF08: 0x08,
    0xFF09: 0x09,
    0xFF0B: 0x0C,
    0xFF0D: 0x0D,
    0xFF8D: 0x0D,
    0xFF1B: 0x1B,
    0xFFFF: 0x2E,
    0xFF63: 0x2D,
    0xFF50: 0x24,
    0xFF57: 0x23,
    0xFF55: 0x21,
    0xFF56: 0x22,
    0xFF51: 0x25,
    0xFF52: 0x26,
    0xFF53: 0x27,
    0xFF54: 0x28,
    0xFFE1: 0xA0,
    0xFFE2: 0xA1,
    0xFFE3: 0xA2,
    0xFFE4: 0xA3,
    0xFFE5: 0x14,
    0xFFE6: 0x14,
    0xFFE7: 0x5B,
    0xFFE8: 0x5C,
    0xFFE9: 0xA4,
    0xFFEA: 0xA5,
    0xFE03: 0xA5,
    0xFFEB: 0x5B,
    0xFFEC: 0x5C,
    0xFFED: 0x5B,
    0xFFEE: 0x5C,
    0xFF67: 0x5D,
    0xFF7E: 0x5D,
    0xFF7F: 0x90,
    0xFF14: 0x91,
    0xFF13: 0x13,
    0xFF6B: 0x13,
    0xFF61: 0x2C,
    0xFF62: 0x2C,
    0xFF6A: 0x2F,
    0xFF65: 0x5D,
    0xFF60: 0x29,
    0xFF68: 0x29,
}

# 小键盘（Guacamole 发的是"位置"键，与 NumLock 状态无关，guacd 也是这么处理）
for _i in range(10):
    _SPECIAL[0xFFB0 + _i] = 0x60 + _i
_SPECIAL.update({
    0xFFAA: 0x6A,
    0xFFAB: 0x6B,
    0xFFAC: 0x6C,
    0xFFAD: 0x6D,
    0xFFAE: 0x6E,
    0xFFAF: 0x6F,
})

for _i in range(24):
    _SPECIAL[0xFFBE + _i] = 0x70 + _i



def keysym_to_char(keysym: int) -> str | None:
    """把可打印 keysym 还原成字符；不可打印返回 None。"""
    if 0x20 <= keysym <= 0xFF:
        return chr(keysym)
    if (keysym & 0xFFFF0000) == UNICODE_OFFSET:
        cp = keysym & 0x00FFFFFF
        try:
            return chr(cp)
        except ValueError:
            return None
    return None


_SHIFT_BIT = 1
_CTRL_BIT = 2
_ALT_BIT = 4


def vk_from_char(ch: str) -> tuple[int, bool] | None:
    """用 VkKeyScanW 取 VK 与"是否需要 Shift"。

    返回 `(vk, need_shift)`；字符在当前键盘布局上不存在则返回 None。
    Ctrl/Alt 位只在极少数 AltGr 字符上出现，那种情况交给 Unicode 直注更稳。
    """
    res = user32.VkKeyScanW(ch)
    if res == -1:
        return None
    vk = res & 0xFF
    if not vk:
        return None
    mods = (res >> 8) & 0xFF
    if mods & (_CTRL_BIT | _ALT_BIT):
        return None
    return vk, bool(mods & _SHIFT_BIT)


_ASCII_LETTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


def shift_needed(ch: str, need_shift: bool, caps_on: bool = False,
                 cmd_held: bool = False) -> bool:
    """结合远端 CapsLock / 是否按住 Ctrl-Alt-Win，判断这个字符要不要补按 Shift。

    `need_shift` 是 `VkKeyScanW` 给出的"在本机键盘布局上打出该字符是否需要 Shift"，
    对数字/符号它是对的；但**字母**不行——Windows 上字母的最终大小写是
    CapsLock 与 Shift 的异或：

        CapsLock=关 + 无 Shift -> 小写      CapsLock=关 + Shift -> 大写
        CapsLock=开 + 无 Shift -> 大写      CapsLock=开 + Shift -> 小写

    所以期望字符是大写且 CapsLock 已开时，**再补 Shift 就会打出小写**——
    这正是"按下 CapsLock 后打字母仍是小写"的根因。字母一律按"期望字符与
    CapsLock 基数是否一致"判定，非字母沿用 `VkKeyScanW` 的结论。

    `cmd_held`（按住 Ctrl/Alt/Win）时 keysym 表示的是**按键**而不是最终字符
    （Ctrl+C 浏览器发的是 `'c'`），此时字母不能补 Shift，否则 Ctrl+C 会变成
    Ctrl+Shift+C 这种另一个快捷键。
    """
    if ch in _ASCII_LETTERS:
        if cmd_held:
            return False
        return ch.isupper() != caps_on
    return need_shift


def resolve(keysym: int) -> tuple[str, object] | None:
    """把 keysym 解析成注入动作。

    返回：
      ("vk", vk)                 —— 直接按虚拟键（特殊键）
      ("vkshift", (vk, need))    —— 可打印字符：need=True 表示需要补按 Shift
                                    （字母的 need 还要过一遍 shift_needed()，
                                      因为远端 CapsLock 开着时补 Shift 会反过来变小写）
      ("char", ch)               —— SendInput unicode 直注字符
      ("ctrlchar", vk)           —— Ctrl+字母 组合（成对注入，不留粘滞修饰键）
      None                       —— 不认识，丢弃
    """
    vk = _SPECIAL.get(keysym)
    if vk is not None:
        return ("vk", vk)

    if 0xFF01 <= keysym <= 0xFF1A:
        return ("ctrlchar", ord("A") + (keysym - 0xFF01))

    ch = keysym_to_char(keysym)
    if ch is None:
        return None
    mapped = vk_from_char(ch)
    if mapped is not None:
        return ("vkshift", mapped)
    return ("char", ch)


if __name__ == "__main__":
    samples = {
        "a": 0x61, "A": 0x41, "1": 0x31, "!": 0x21, "space": 0x20,
        "Enter": 0xFF0D, "Esc": 0xFF1B, "Left": 0xFF51,
        "Shift_L": 0xFFE1, "Ctrl_L": 0xFFE3, "Alt_L": 0xFFE9,
        "F5": 0xFFC2, "KP_7": 0xFFB7, "中": UNICODE_OFFSET | ord("中"),
        "CtrlC(控制字符)": 0xFF03, "Home": 0xFF50, "Delete": 0xFFFF,
    }
    for name, ks in samples.items():
        print(f"{name:>16}  0x{ks:08X}  ->  {resolve(ks)}")

    # CapsLock x 期望字符 -> 是否补 Shift（远端打出的大小写应恒等于期望值）
    print("\n[shift_needed] 期望字符 / CapsLock -> 补 Shift")
    for ch, ks in (("a", 0x61), ("A", 0x41)):
        for caps in (False, True):
            _kind, (vk, need) = resolve(ks)
            print(f"  '{ch}'  caps={'开' if caps else '关'}  ->  "
                  f"{'补 Shift' if shift_needed(ch, need, caps) else '不补'}  (VK=0x{vk:02X})")
