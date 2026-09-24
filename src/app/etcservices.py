"""``/etc/services`` 的解析 —— 端口号 → 服务名的反查表。

行格式（``man 5 services``）::

    ftp             21/tcp
    domain          53/udp     nameserver
    http-alt        8080/tcp   webcache    # 注释以 # 开头到行尾

三个要点：

* ``端口/协议`` 是**一条记录的两半**：必须按 ``(协议, 端口)`` 建索引，否则 UDP 的 53
  会把 TCP 的 53 覆盖掉。
* 别名（第三列起）同样能反查，但本应用只取**主名**——别名往往带变体后缀
  （``http-alt`` 之外还有 ``webcache``），对用户没有帮助。
* 端口可能是**区间**（``6000-6063/tcp``），区间对「反查某个具体端口」没有意义，直接跳过。

文件缺失、某行格式异常都**不抛异常**：``/etc/services`` 只是一个锦上添花的名称来源，
拿不到就退化成「只显示指纹」，不能因此让端口地图整体失败。
"""

import os

DEFAULT_PATH = "/etc/services"

#: 只认这两种传输层协议；``ddp`` / ``sctp`` 之类的行一律算格式异常
KNOWN_PROTOCOLS = ("tcp", "udp")


def parse_etc_services(text):
    """解析 ``/etc/services`` 内容。

    返回 ``{"by_proto": {(proto, port): name}, "by_port": {port: name}, "malformed": n}``。
    ``malformed`` 只用于如实汇报「这份文件有多少行不符合格式」，不参与判定。
    """
    by_proto = {}
    by_port = {}
    malformed = 0

    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 2:
            malformed += 1
            continue
        name = fields[0]
        spec = fields[1]
        if "/" not in spec:
            malformed += 1
            continue
        port_text, _, protocol = spec.partition("/")
        protocol = protocol.strip().lower()
        if protocol not in KNOWN_PROTOCOLS:
            # 既不是格式错（ddp/sctp 是合法写法），也不是本应用关心的协议：安静跳过
            continue
        if "-" in port_text:
            continue
        try:
            port = int(port_text)
        except ValueError:
            malformed += 1
            continue
        if not 0 < port <= 65535:
            malformed += 1
            continue
        # 同名端口先到先得：文件本身按端口升序，第一条即最常用名
        by_proto.setdefault((protocol, port), name)
        by_port.setdefault(port, name)

    return {"by_proto": by_proto, "by_port": by_port, "malformed": malformed}


def read_etc_services(path=DEFAULT_PATH):
    """读取并解析 ``/etc/services``。文件不存在时返回 ``source="unavailable"``。"""
    if not os.path.isfile(path):
        return {
            "source": "unavailable",
            "path": path,
            "detail": "当前系统没有 %s，端口 → 服务名反查不可用" % path,
            "by_proto": {},
            "by_port": {},
            "malformed": 0,
            "count": 0,
        }
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        return {
            "source": "error",
            "path": path,
            "detail": "无法读取 %s：%s" % (path, exc),
            "by_proto": {},
            "by_port": {},
            "malformed": 0,
            "count": 0,
        }

    table = parse_etc_services(text)
    count = len(table["by_port"])
    table.update({
        "source": "file",
        "path": path,
        "detail": "已从 %s 解析 %d 条端口定义" % (path, count),
        "count": count,
    })
    return table


def lookup(table, port, protocol=None):
    """按 ``(协议, 端口)`` 反查服务名；该协议没有时退回「任意协议同名端口」。"""
    if not table:
        return None
    by_proto = table.get("by_proto") or {}
    if protocol:
        found = by_proto.get((str(protocol).lower(), int(port)))
        if found:
            return found
    return (table.get("by_port") or {}).get(int(port))
