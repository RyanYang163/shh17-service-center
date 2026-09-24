"""内核监听套接字表（``/proc/net/tcp`` 与 ``/proc/net/tcp6``）的解析。

**为什么不调 ss / netstat**：本应用要求「不代用户执行任何命令」，而 ``/proc`` 是内核
直接暴露的只读接口——读文件比调外部命令依赖更少、安全面更小，也不需要额外权限。

``man 5 proc`` 给出的行格式::

    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt ...
     0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 ...

有两个反直觉点（不实测很容易写反）：

1. **IP 是「小端十六进制」**——IPv4 的 4 个字节要整体倒过来，所以 ``0100007F`` 是
   ``127.0.0.1`` 而不是 ``1.0.0.127``。IPv6 更绕：16 字节被拆成 4 个 32 位字，
   **每个字各自小端**，于是 ``::1`` 被写成 ``00000000000000000000000001000000``。
2. **端口是「大端十六进制」**——``1F90`` 就是 8080，**不要**倒。

``st`` 为 ``0A`` 即 LISTEN。

**非 Linux 环境**（本应用的开发机是 Windows）：``/proc/net/tcp`` 不存在时返回
``source="unavailable"`` 与空列表，**绝不抛异常**。测试通过 ``proc_root`` 注入一个
临时的假 ``/proc`` 目录，因此这套解析在没有 /proc 的机器上同样可测。
"""

import ipaddress
import os

#: LISTEN 状态的十六进制码（``man 5 proc`` 的 socket 状态表）
LISTEN = "0A"

#: 其余状态码 → 可读名。只用于统计，不参与「端口地图」的判定。
STATE_NAMES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

MAX_PORT = 65535


def _hex_to_ipv4(hex_text):
    """``0100007F`` → ``127.0.0.1``（4 字节，小端）。"""
    raw = bytes.fromhex(hex_text)
    if len(raw) != 4:
        raise ValueError("IPv4 地址应为 4 字节，实际 %d" % len(raw))
    return ".".join(str(byte) for byte in reversed(raw))


def _hex_to_ipv6(hex_text):
    """``…01000000`` → ``::1``（4 个 32 位字，每个各自小端）。"""
    raw = bytes.fromhex(hex_text)
    if len(raw) != 16:
        raise ValueError("IPv6 地址应为 16 字节，实际 %d" % len(raw))
    # 每个 4 字节组内倒序，拼成网络字节序，再交给 ipaddress 做压缩显示（::1 之类）
    packed = b"".join(raw[offset:offset + 4][::-1] for offset in range(0, 16, 4))
    return str(ipaddress.IPv6Address(packed))


def scope_of(address):
    """绑定范围：``all``（所有网卡）/ ``localhost``（仅本机）/ ``specific``。"""
    if address in ("0.0.0.0", "::"):
        return "all"
    if address in ("127.0.0.1", "::1") or address.startswith("127."):
        return "localhost"
    return "specific"


def parse_proc_net(text, protocol="tcp"):
    """解析一份 ``/proc/net/tcp`` 内容，返回套接字列表（含非 LISTEN 的）。

    :param protocol: ``tcp`` 或 ``tcp6``——决定地址按 IPv4 还是 IPv6 解。

    解析不出端口、或端口为 0 / 超过 65535 的行**直接丢弃**：那是读取瞬间的残渣或
    坏行，收进端口地图只会让用户困惑。
    """
    family = "ipv6" if str(protocol).endswith("6") else "ipv4"
    sockets = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        if fields[0] == "sl":  # 表头
            continue
        local = fields[1]
        if ":" not in local:
            continue
        address_hex, _, port_hex = local.rpartition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        # 端口 0 与 >65535：明确丢弃（端口 0 是「未绑定」，不是真实监听）
        if not 0 < port <= MAX_PORT:
            continue
        try:
            address = _hex_to_ipv4(address_hex) if family == "ipv4" else _hex_to_ipv6(address_hex)
        except ValueError:
            continue

        state = fields[3].upper()
        sockets.append({
            "port": port,
            "protocol": protocol,
            "family": family,
            "address": address,
            "scope": scope_of(address),
            "state": STATE_NAMES.get(state, state),
            "listening": state == LISTEN,
        })
    return sockets


def unavailability_detail(proc_root, name="tcp"):
    """``/proc`` 不可用时的说明文字。

    路径**手工拼正斜杠**而不是 ``os.path.join``：这是给用户看的一句话，
    在 Windows 上 ``os.path.join("/proc", "net", "tcp")`` 会拼出
    ``/proc\\net\\tcp``，读起来像坏了；``/proc`` 在任何平台上都写作正斜杠。
    """
    return "当前系统没有 %s/net/%s（非 Linux 或 /proc 未挂载）" \
           % (str(proc_root).rstrip("/\\"), name)


def read_proc_ports(proc_root="/proc"):
    """读取一份监听端口快照。

    返回::

        {
          "source": "proc" | "partial" | "unavailable",
          "detail": "…给用户看的一句话原因…",
          "proc_root": "/proc",
          "files": ["/proc/net/tcp", "/proc/net/tcp6"],
          "listeners": [ {port, protocol, address, scope, state, …}, … ],
          "socket_count": 137,          # 含非 LISTEN，仅用于统计
          "listen_count": 12,
        }

    ``source="unavailable"`` 时 ``listeners`` 为空列表——**调用方无须特殊分支**。
    """
    files = []
    missing = []
    listeners = []
    socket_count = 0

    for name in ("tcp", "tcp6"):
        path = os.path.join(proc_root, "net", name)
        if not os.path.isfile(path):
            missing.append(path)
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as exc:
            missing.append("%s（%s）" % (path, exc))
            continue
        files.append(path)
        sockets = parse_proc_net(text, name)
        socket_count += len(sockets)
        listeners.extend(sock for sock in sockets if sock["listening"])

    if not files:
        return {
            "source": "unavailable",
            "detail": unavailability_detail(proc_root),
            "proc_root": proc_root,
            "files": [],
            "missing": missing,
            "listeners": [],
            "socket_count": 0,
            "listen_count": 0,
        }

    if missing:
        detail = "只能读到 %d 张表（%s 不可用）" % (len(files), "、".join(
            os.path.basename(str(item)) for item in missing))
        source = "partial"
    else:
        detail = "已从 %d 张内核表解出 %d 个监听套接字" % (len(files), len(listeners))
        source = "proc"

    listeners.sort(key=lambda item: (item["port"], item["protocol"], item["address"]))
    return {
        "source": source,
        "detail": detail,
        "proc_root": proc_root,
        "files": files,
        "missing": missing,
        "listeners": listeners,
        "socket_count": socket_count,
        "listen_count": len(listeners),
    }
