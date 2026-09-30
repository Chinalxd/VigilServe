"""方案 B：网络设备的命令行连接（SSH / Telnet）。

为什么要有这个模块
──────────────────
SNMP 只能读指标，改不了配置。管理员真正要动交换机的时候还是得敲命令，
而「WEB终端」原来只有一条路：服务端 → Agent 9998 → 本机 PTY。网络设备装不上
Agent，那条路走不通，所以这里由**服务端直接发起** SSH / Telnet 到设备。

为什么不复用 `protocol` / `username` / `password`
───────────────────────────────────────────────
那几个字段是主机侧的：`protocol` 对网络设备固定是 `snmp`（collector 靠它跳过
主机采集循环），`connection_port` 在主机语境里是 SSH/WinRM 端口。混用会让
`remote_agent` / `service_monitor` 的判断失真。所以 CLI 凭据单独占
`cli_protocol` / `cli_port` / `cli_username` / `cli_password` / `cli_enable_password`。

安全
────
* SSH 走 `services/ssh_pinning.py` 的主机密钥钉扎，端口用 `cli_port`（不是
  `connection_port`）—— 否则钉扎记录永远对不上。
* 口令只在库里存 Fernet 密文，解密入口是 `Server.cli_password_plain`。
"""
from __future__ import annotations

import socket
import threading
import time

CONNECT_TIMEOUT = 15


class CliError(Exception):
    """CLI 连接失败（口令错 / 端口不通 / 设备拒绝 / 主机密钥不匹配 …）。"""




def cli_target(server) -> dict:
    """把设备的 CLI 凭据整理成一份连接参数（口令不给明文，只给解密函数）。"""
    proto = str(getattr(server, "cli_protocol", "") or "ssh").strip().lower()
    if proto not in ("ssh", "telnet"):
        proto = "ssh"
    port = int(getattr(server, "cli_port", 0) or 0)
    if port <= 0:
        port = 23 if proto == "telnet" else 22
    return {
        "protocol": proto,
        "host": server.ip_address,
        "port": port,
        "username": getattr(server, "cli_username", "") or "",
    }


def cli_credential_hint(server) -> str:
    """给前端/审计用的「连到哪里」描述，不含任何口令。"""
    t = cli_target(server)
    return f"{t['protocol']}://{t['username'] or '<未填用户名>'}@{t['host']}:{t['port']}"




_IAC = b"\xff"
_DONT = b"\xfe"
_WONT = b"\xfc"
_NOP = b"\xf1"


class TelnetSession:
    """极简 Telnet 客户端。

    只做三件事：把 IAC 协商从数据流里剥掉、把控制键原样发出去、把服务端回显
    原样交回前端。不做 RFC 854 的完整状态机 —— 交换机那点协商（ECHO / SGA /
    TERMINAL-TYPE）用「一律拒绝 + 剥字节」就能稳定工作，真要做全反而容易在
    不同厂商的实现上踩坑。
    """

    def __init__(self, host: str, port: int = 23, timeout: int = CONNECT_TIMEOUT):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(0.2)
        self._buf = b""
        self._lock = threading.Lock()
        self._closed = False

    def _strip_iac(self, raw: bytes) -> bytes:
        out = bytearray()
        i = 0
        n = len(raw)
        while i < n:
            b = raw[i]
            if b != 0xFF:
                out.append(b)
                i += 1
                continue
            if i + 1 < n and raw[i + 1] == 0xFF:
                out.append(0xFF)
                i += 2
                continue
            if i + 1 < n and raw[i + 1] in (0xFB, 0xFC, 0xFD, 0xFE):
                opt = raw[i + 2] if i + 2 < n else 0
                try:
                    # 一律回绝：我们不支持任何选项，也不想让设备改终端行为
                    self.sock.sendall(_IAC + (_WONT if raw[i + 1] in (0xFB, 0xFC) else _DONT)
                                      + bytes([opt]))
                except Exception:  # noqa: BLE001
                    pass
                i += 3
                continue
            if i + 1 < n and raw[i + 1] == 0xF1:
                i += 2
                continue
            if i + 1 < n and raw[i + 1] == 0xFA:
                end = raw.find(_IAC + b"\xf0", i + 2)
                i = n if end < 0 else end + 2
                continue
            i += 2
        return bytes(out)

    def recv(self, size: int = 8192) -> bytes:
        """非阻塞读一次；没数据返回 b''，连接已断抛 CliError。"""
        with self._lock:
            if self._closed:
                raise CliError("Telnet 连接已关闭")
            try:
                raw = self.sock.recv(size)
            except socket.timeout:
                return b""
            except OSError as e:
                raise CliError(f"Telnet 读取失败：{e}")
            if not raw:
                raise CliError("设备已断开 Telnet 连接")
            return self._strip_iac(raw)

    def send(self, data: bytes) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.sock.sendall(data.replace(_IAC, _IAC + _IAC))
            except OSError as e:
                raise CliError(f"Telnet 发送失败：{e}")

    def resize(self, cols: int, rows: int) -> None:
        pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self.sock.close()
            except Exception:  # noqa: BLE001
                pass




class CliSession:
    """包装 SSH channel 或 Telnet socket，给 WS 端一个统一的读写接口。"""

    def __init__(self, kind: str, client, channel):
        self.kind = kind
        self.client = client
        self.channel = channel

    def recv(self, size: int = 8192) -> bytes:
        try:
            if self.kind == "ssh":
                if self.channel.recv_ready():
                    return self.channel.recv(size)
                if self.channel.closed:
                    raise CliError("设备已断开 SSH 连接")
                return b""
            return self.channel.recv(size)
        except CliError:
            raise
        except Exception as e:  # noqa: BLE001
            raise CliError(f"读取失败：{e}")

    def send(self, data: bytes) -> None:
        try:
            self.channel.send(data)
        except CliError:
            raise
        except Exception as e:  # noqa: BLE001
            raise CliError(f"发送失败：{e}")

    def resize(self, cols: int, rows: int) -> None:
        try:
            self.channel.resize_pty(width=cols, height=rows)
        except Exception:  # noqa: BLE001
            pass

    def closed(self) -> bool:
        try:
            if self.kind == "ssh":
                return bool(self.channel.closed)
            return False
        except Exception:  # noqa: BLE001
            return True

    def close(self) -> None:
        try:
            self.channel.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.client is not None:
                self.client.close()
        except Exception:  # noqa: BLE001
            pass


def open_cli_session(server, cols: int = 80, rows: int = 24, db=None, timeout: int = CONNECT_TIMEOUT) -> CliSession:
    """登录设备并拿到一个交互式 shell。失败抛 `CliError`（消息可直接给管理员看）。

    ⚠ 这里是同步阻塞的，WS 端点必须放线程池里跑，别直接 await。
    """
    t = cli_target(server)
    username = t["username"]
    if not username:
        raise CliError("还没有配置该设备的 CLI 登录用户名（在「主机管理 - 网络设备」里编辑）")
    password = getattr(server, "cli_password_plain", "") or ""

    if t["protocol"] == "telnet":
        return _open_telnet(t, cols, rows, timeout)

    return _open_ssh(server, t, username, password, cols, rows, db, timeout)


def _open_ssh(server, t, username, password, cols, rows, db, timeout) -> CliSession:
    try:
        import paramiko
    except ImportError:  # pragma: no cover
        raise CliError("服务端未安装 paramiko，无法使用 SSH 终端")

    from services import ssh_pinning as pin

    client = paramiko.SSHClient()
    pin.prepare_client(client, server, db=db, port=t["port"])
    try:
        from paramiko.transport import Transport
        Transport._preferred_hostkeys = (
            'ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519',
        )
    except Exception:  # noqa: BLE001
        pass

    try:
        client.connect(
            hostname=t["host"],
            port=t["port"],
            username=username,
            password=password or None,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001
        try:
            pin.note_connect_failure(server, client)
        except Exception:  # noqa: BLE001
            pass
        raise CliError(f"SSH 连接失败：{e}")

    try:
        pin.verify_after_connect(server, client, db=db, port=t["port"])
    except pin.HostKeyRejected:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        raise

    try:
        # 网络设备多数认 vt100；少数只要 dumb。先试 vt100，失败再退回无终端类型。
        try:
            chan = client.invoke_shell(term="vt100", width=cols, height=rows)
        except Exception:  # noqa: BLE001
            chan = client.invoke_shell(width=cols, height=rows)
        chan.settimeout(0.1)
    except Exception as e:  # noqa: BLE001
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        raise CliError(f"打开设备命令行失败：{e}")

    # 登录后给一点时间让设备吐出 banner / 提示符，免得前端第一屏是空的
    time.sleep(0.4)
    return CliSession("ssh", client, chan)


def _open_telnet(t, cols, rows, timeout) -> CliSession:
    try:
        sess = TelnetSession(t["host"], t["port"], timeout=timeout)
    except (OSError, socket.gaierror) as e:
        raise CliError(f"Telnet 连接失败：{e}")
    return CliSession("telnet", None, sess)
