"""Guacamole 协议层（服务端侧编码 / 客户端侧解码）。

语法（已逐行核对官方 guacamole-common-js 1.5.0 源码）：

    指令 := 元素 ("," 元素)* ";"
    元素 := <十进制长度> "." <值>

关键事实（不要凭记忆改）：
  * 长度是值的 **UTF-8 字节数**；我们只发 ASCII（数字 / base64 / mimetype），字节数=字符数
  * 握手走 **WebSocket URL query**，客户端不发 select/connect
  * WebSocket 子协议必须注册为 "guacamole"
  * 服务端发第一条 sync 后客户端才 setState(CONNECTED)，并会 echo 一条 sync 回来
  * jpeg 指令把 base64 内联，比 img+blob+end 少两条指令：
        jpeg,<channelMask>,<layer>,<x>,<y>,<base64>;
  * layer 0 = default layer
"""

from __future__ import annotations

import base64


def _s(value: object) -> str:
    return value if isinstance(value, str) else str(value)


def instr(opcode: object, *args: object) -> str:
    """编码一条指令。

    返回 **str**（不是 bytes）：Guacamole 的 WebSocket 隧道走文本帧，客户端拿到
    `event.data` 后直接调 `.indexOf()`。发二进制帧会让 event.data 变成 Blob，
    客户端每条指令都抛 "indexOf is not a function"。

    例：instr("size", 0, 1920, 1080) -> '4.size,1.0,4.1920,4.1080;'
    """
    elems = [opcode, *args]
    body = ",".join(f"{len(_s(e).encode('utf-8'))}.{_s(e)}" for e in elems)
    return body + ";"



def size(layer: int, width: int, height: int) -> bytes:
    return instr("size", layer, width, height)


def sync(timestamp: int, frames: int | None = None) -> bytes:
    """sync 是帧的结束标记，也是握手的完成标记。"""
    if frames is None:
        return instr("sync", timestamp)
    return instr("sync", timestamp, frames)


def img(stream: int, channel_mask: int, layer: int, mimetype: str, x: int, y: int) -> bytes:
    return instr("img", stream, channel_mask, layer, mimetype, x, y)


def blob(stream: int, data: bytes | str) -> bytes:
    payload = data if isinstance(data, bytes) else data.encode("utf-8")
    return instr("blob", stream, base64.b64encode(payload).decode("ascii"))


def end(stream: int) -> bytes:
    return instr("end", stream)



CLIPBOARD_STREAM = 1
_CLIPBOARD_MIME = "text/plain"


def clipboard_begin(stream: int = CLIPBOARD_STREAM, mimetype: str = _CLIPBOARD_MIME) -> str:
    return instr("clipboard", stream, mimetype)


def clipboard_text(text: str, stream: int = CLIPBOARD_STREAM) -> str:
    """blob(base64 utf-8) + end。必须紧跟 clipboard_begin。"""
    return blob(stream, text) + end(stream)


_JPEG_MIME = "image/jpeg"


def jpeg_frame(data: bytes, timestamp: int, layer: int = 0, x: int = 0, y: int = 0,
               channel_mask: int = 0x0E) -> bytes:
    """一帧：jpeg + sync。

    channel_mask 必须是 **0x0E (R|G|B，不含 alpha)**，不是 0x0F：
    guacamole-common-js 把 mask 当合成操作用（Layer.setChannelMask ->
    globalCompositeOperation），14 -> "source-over"（正常覆盖），而
    15 -> "lighter"（加法混合）。发 0x0F 会导致每帧叠加、几十帧后
    全画面饱和成纯白（画面"加载成功却一片白"的元凶）。
    """
    return (instr("jpeg", channel_mask, layer, x, y,
                  base64.b64encode(data).decode("ascii"))
            + sync(timestamp))


def img_frame(data: bytes, timestamp: int, stream: int = 1, layer: int = 0,
              x: int = 0, y: int = 0, channel_mask: int = 0x0E) -> str:
    """img+blob+end+sync 形式（jpeg 指令的等价长写法，保留做协议兼容验证）。"""
    return (img(stream, channel_mask, layer, _JPEG_MIME, x, y)
            + blob(stream, data)
            + end(stream)
            + sync(timestamp))



class InstructionParser:
    """流式解析客户端指令。feed() 返回本次可完整解析出的指令列表。

    每条指令是 list[str]，args[0] 为 opcode。
    """

    def __init__(self) -> None:
        self._buf = ""
        self._cur: list[str] = []

    def feed(self, text: str) -> list[list[str]]:
        self._buf += text
        out: list[list[str]] = []
        while self._buf:
            dot = self._buf.find(".")
            if dot < 0:
                # 长度前缀都还没收全；异常长的垃圾直接丢弃防卡死
                if len(self._buf) > 64:
                    self._buf = ""
                break
            head = self._buf[:dot]
            if not head.isdigit():
                self._buf = self._buf[dot + 1:]
                self._cur = []
                continue
            length = int(head)
            start = dot + 1
            stop = start + length
            if len(self._buf) < stop + 1:
                break
            value = self._buf[start:stop]
            sep = self._buf[stop]
            self._buf = self._buf[stop + 1:]
            self._cur.append(value)
            if sep == ";":
                if self._cur:
                    out.append(self._cur)
                self._cur = []
            elif sep != ",":
                self._cur = []
        return out



def jpeg_size(data: bytes) -> tuple[int, int] | None:
    """从 JPEG 二进制里读 SOF 段拿宽高（省掉一次 PIL/cv2 解码）。"""
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        return None
    i = 2
    n = len(data)
    while i + 9 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker in (0xD9, 0xDA):
            return None
        seg_len = int.from_bytes(data[i + 2:i + 4], "big")
        if seg_len < 2:
            return None
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            height = int.from_bytes(data[i + 5:i + 7], "big")
            width = int.from_bytes(data[i + 7:i + 9], "big")
            return width, height
        i += 2 + seg_len
    return None


if __name__ == "__main__":
    # 严格对齐官方实现：指令走文本帧，长度前缀 = UTF-16 码元数（我们只发 ASCII，等价）
    assert instr("size", 0, 1024, 768) == "4.size,1.0,4.1024,3.768;"
    p = InstructionParser()
    print(p.feed("4.size,1.0,4.1024,3.768;"))
    # 跨 feed 边界的半条指令：用 instr 自己生成再切分，避免手算长度
    wire = instr("mouse", 100, 200, 0).decode()
    print(p.feed(wire[:7]))
    print(p.feed(wire[7:]))
    print(p.feed(instr("nop")))
    here = __import__("pathlib").Path(__file__).parent
    for name in ("sample_frame.jpg", "sample_wgc.jpg"):
        f = here / name
        if f.exists():
            print(name, jpeg_size(f.read_bytes()))
