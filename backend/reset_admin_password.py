#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""VigilServe 管理员口令重置工具（交互式，离线）。

什么时候用：唯一的管理员把密码忘了、登不进去，又没有第二个管理员能在
「用户管理」页面帮他改。

怎么用：
    Windows：双击 `重置管理员密码.bat`（与 start.bat 同级），或
             python reset_admin_password.py
    然后按提示输入**用户名**和**新密码**（密码不回显，要输两遍）。

设计上的几条硬约束：
  * **口令只在交互里输入，绝不做命令行参数** —— 命令行会进进程列表和历史记录。
  * **不 import 项目的 services 包**：`services/__init__.py` 会拉起 sqlalchemy，
    而本工具要在"只有 Python 标准库"的机器上也能跑。用 importlib 直接加载
    `services/password_hash.py` 这一个文件（它只用 hashlib / bcrypt）。
  * 改库前先做整库快照（sqlite3 backup API，生产库 WAL 占用时也能安全复制）。
  * 只改一行，改完回读并用 verify_password 反验，确保真能登录。
  * 往 operation_logs 补一条审计，如实写明是线下脚本改的，不假冒前台操作。

⚠ 改完**必须重启 VigilServe 服务端**：
    TOKENS 是进程内存字典（routes/auth.py），改库不会清掉旧会话令牌，
    旧会话在过期前照样能用；登录失败锁定计数也在内存里，重启顺带解锁。
"""

import datetime
import getpass
import importlib.util
import os
import re
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "monitor.db")
PH_PATH = os.path.join(HERE, "services", "password_hash.py")
DEFAULT_USER = "admin"

if sys.platform == "win32":  # pragma: no cover
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def line(ch="=", n=62):
    print(ch * n)


_echo_warned = False


def prompt_password(prompt):
    """读口令：真控制台下隐藏回显；被管道/重定向时退化成普通 input。

    ⚠ Windows 的 `getpass` 在 stdin 不是 TTY 时会去打开控制台输入设备 `CONIN$`，
    在管道 / 重定向 / 无人值守场景下会把进程直接搞死（实测：SIGTERM，无任何输出）。
    所以这里必须先判 isatty。退化时输入会明文显示，因此要**明确告知用户** ——
    双击 .bat 运行是正常 TTY，走的仍是隐藏输入那条路。
    """
    global _echo_warned
    is_tty = False
    try:
        is_tty = bool(sys.stdin) and sys.stdin.isatty()
    except Exception:
        is_tty = False
    if is_tty:
        try:
            return getpass.getpass(prompt)
        except Exception:
            pass
    if not _echo_warned:
        _echo_warned = True
        print("  ⚠ 当前不是交互终端，密码输入会显示在屏幕上，注意周围。")
    return input(prompt)


def die(msg):
    print(f"\n[失败] {msg}")
    print("未做任何修改。")
    sys.exit(1)


def load_password_hash():
    if not os.path.isfile(PH_PATH):
        die(f"找不到口令哈希模块：{PH_PATH}\n"
            f"请在 VigilServe 服务端的 backend 目录下运行本脚本。")
    spec = importlib.util.spec_from_file_location("_vs_password_hash", PH_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_pwd_policy(con):
    keys = ("pwd_min_length", "pwd_require_upper", "pwd_require_lower",
            "pwd_require_digit", "pwd_require_symbol")
    pol = {"pwd_min_length": 8}
    for k in keys:
        row = con.execute(
            "SELECT value FROM global_config WHERE key=?", ("security." + k,)).fetchone()
        v = str(row[0]).strip() if row and row[0] is not None else ""
        pol[k] = int(v) if v.lstrip("-").isdigit() else 0
    return pol


def policy_hint(pol):
    need = [f"至少 {pol['pwd_min_length']} 位"]
    for k, txt in (("pwd_require_upper", "大写字母"),
                   ("pwd_require_lower", "小写字母"),
                   ("pwd_require_digit", "数字"),
                   ("pwd_require_symbol", "特殊字符")):
        if pol.get(k):
            need.append(txt)
    return "、".join(need)


def check_pw(pw, pol):
    errs = []
    if len(pw) < pol["pwd_min_length"]:
        errs.append(f"长度不能少于 {pol['pwd_min_length']} 位（当前 {len(pw)} 位）")
    if pol.get("pwd_require_upper") and not re.search(r"[A-Z]", pw):
        errs.append("必须包含大写字母")
    if pol.get("pwd_require_lower") and not re.search(r"[a-z]", pw):
        errs.append("必须包含小写字母")
    if pol.get("pwd_require_digit") and not re.search(r"[0-9]", pw):
        errs.append("必须包含数字")
    if pol.get("pwd_require_symbol") and not re.search(r"[^A-Za-z0-9]", pw):
        errs.append("必须包含特殊字符")
    return errs


def main():
    line()
    print("  VigilServe 管理员口令重置工具")
    line()

    if not os.path.isfile(DB):
        die(f"找不到数据库：{DB}\n"
            f"请在 VigilServe 服务端的 backend 目录下运行本脚本。")
    ph = load_password_hash()

    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row

    users = con.execute(
        "SELECT id, username, full_name, role, status, must_reset_password "
        "FROM users ORDER BY id").fetchall()
    if not users:
        con.close()
        # 2026-09-24 更正：以前这里写的是"重启一次服务端会自动建 admin 账号"，
        # 但当时 seed_admin 只挂在登录接口里，重启根本不会建号 —— 这句话把人
        # 带进死循环（没口令 → 登不进去 → 不登录就不建号 → 还是没口令）。
        # 1.1.44 起改为启动时建号，下面的指引才成立。
        die("users 表是空的：服务端还没有建过 admin 账号。\n"
            "  ① 先启动一次 VigilServe 服务端（1.1.44 起启动时自动建 admin，\n"
            "     初始口令写入 backend\\data\\initial_admin_password.txt）；\n"
            "  ② 若服务端已经起过而这里还是空，去看 logs\\ 下的后端日志，\n"
            "     搜「启动时初始化默认管理员账号失败」—— 多半是 backend 目录不可写\n"
            "     （装在 C:\\Program Files 下又没以管理员身份运行就是这种症状）。\n"
            "  本工具只改已有账号、不负责建号。")

    print("\n当前账号：")
    print(f"  {'ID':<4}{'用户名':<20}{'角色':<16}{'状态':<10}{'需改密'}")
    for u in users:
        print(f"  {u['id']:<4}{u['username']:<20}{str(u['role'] or ''):<16}"
              f"{str(u['status'] or ''):<10}{'是' if u['must_reset_password'] else '否'}")

    print()
    username = input(f"要重置的用户名（直接回车 = {DEFAULT_USER}）：").strip()
    if not username:
        username = DEFAULT_USER
    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        con.close()
        die(f"用户 {username!r} 不存在。上面列表里挑一个。")

    print(f"  已选中：{username}（id={row['id']}，角色 {row['role'] or ''}）")

    pol = load_pwd_policy(con)
    print(f"\n口令要求：{policy_hint(pol)}")
    print("（输入时屏幕上不会显示任何字符，这是正常的）")
    for attempt in range(3):
        pw1 = prompt_password("新密码：")
        if not pw1:
            print("  密码不能为空。")
            continue
        errs = check_pw(pw1, pol)
        if errs:
            for e in errs:
                print(f"  ✗ {e}")
            continue
        pw2 = prompt_password("再输一遍：")
        if pw1 != pw2:
            print("  两次输入不一致。")
            continue
        break
    else:
        con.close()
        die("连续 3 次没输对，已退出。")

    # 4) 备份整库（backup API：生产库 WAL 占用时也能安全复制）
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = f"{DB}.bak-{stamp}"
    src = sqlite3.connect(DB)
    dst = sqlite3.connect(bak)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()
    print(f"\n① 整库快照已存：{os.path.basename(bak)}")

    new_hash = ph.hash_password(pw1)
    algo = new_hash.split("$", 1)[0] if "$" in new_hash else "legacy"
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET password=?, must_reset_password=1,"
        " password_changed_at=?, status='active' WHERE id=?",
        (new_hash, now, row["id"]))
    if cur.rowcount != 1:
        con.rollback()
        con.close()
        die(f"UPDATE 影响行数 {cur.rowcount}（应为 1），已回滚。")

    # 6) 审计（如实标注是线下脚本改的）
    try:
        cur.execute(
            "INSERT INTO operation_logs (timestamp, level, category, action, username,"
            " user_id, ip_address, status, target_type, target_id, message, details)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (now, "warning", "security", "password_reset_offline", username,
             row["id"], "127.0.0.1", "success", "user", str(row["id"]),
             f"管理员口令由离线重置工具修改（账号 {username}），"
             f"已置 must_reset_password=1 强制下次登录改密",
             '{"via": "offline-script", "algo": "' + algo + '"}'))
    except Exception as e:  # noqa: BLE001
        print(f"  （审计日志写入失败，不影响口令已重置：{e}）")

    con.commit()

    after = con.execute(
        "SELECT password, must_reset_password, status FROM users WHERE id=?",
        (row["id"],)).fetchone()
    ok_new = ph.verify_password(pw1, after["password"])
    con.close()

    print(f"② 口令已更新（算法 {algo}），must_reset_password=1，status=active")
    print(f"③ 回读反验：新密码能登录 = {'是' if ok_new else '否 ★异常★'}")

    line()
    if ok_new:
        print("  重置成功。")
    else:
        print("  ★ 反验失败，请用快照恢复后重试。")
    print()
    print("  ⚠ 接下来**必须重启 VigilServe 服务端**：")
    print("     会话令牌存在进程内存里，改库不会让旧会话失效；")
    print("     登录失败的锁定计数也在内存里，重启会一并清掉。")
    print()
    print(f"  ⚠ 该账号下次登录会被强制要求修改密码。")
    print(f"  ⚠ 回滚用这份快照：{os.path.basename(bak)}")
    line()
    sys.exit(0 if ok_new else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n已取消，未做任何修改。")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"\n[异常] {type(e).__name__}: {e}")
        sys.exit(1)
