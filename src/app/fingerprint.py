"""服务指纹表 —— 端口号 → 「这个端口通常是做什么的」。

**这是建议，不是权威结论。** 端口号只是约定俗成的分配，任何程序都可以占用任意端口：
真正的结论只能来自「谁在监听」这个事实本身（那是 ``/proc/net/tcp`` 给的），
以及进程信息（本应用**刻意不读**——只读铁律下不引入任何可能失败或越权的来源）。
因此每一条指纹都会带上 ``confidence="suggestion"``，界面上也必须标注「仅供参考」。

覆盖范围按设计文档 §15 的清单：SSH、HTTP(S)、SMB、NFS、FTP、WebDAV、TOS Web、
MySQL、PostgreSQL、Redis、Jellyfin、Plex、qBittorrent、Docker，外加 TOS 与 NAS 场景
常见的若干端口（AFP、iSCSI、rsync、DLNA、Transmission、Portainer 等）。
"""

#: 指纹类别 → 界面展示名。前端「概览」的分类统计也用它。
KIND_LABELS = {
    "web": "网页服务",
    "file": "文件共享",
    "remote": "远程管理",
    "database": "数据库",
    "cache": "缓存",
    "media": "媒体服务",
    "download": "下载工具",
    "container": "容器运行时",
    "network": "网络服务",
    "print": "打印服务",
    "other": "其它",
}

#: 所有指纹都是「按端口号推断」，这句话必须随数据一起给到前端。
CONFIDENCE = "suggestion"
NOTE = "按端口号推断，仅供参考 —— 任何程序都可以占用任意端口"

#: 端口 → 指纹。
#: ``web=True`` 表示「通常有网页界面」，可以在浏览器里直接打开（据此决定是否给「打开」按钮）；
#: ``scheme`` 决定拼接协议，默认 http。
KNOWN = {
    # ---- 系统与远程管理 ----
    22: {"name": "SSH", "kind": "remote", "note": "安全远程登录（终端 / SFTP）"},
    23: {"name": "Telnet", "kind": "remote", "note": "明文远程登录，建议关闭"},
    3389: {"name": "RDP", "kind": "remote", "note": "Windows 远程桌面"},

    # ---- 网页服务 ----
    80: {"name": "HTTP", "kind": "web", "web": True, "note": "标准网页服务端口"},
    443: {"name": "HTTPS", "kind": "web", "web": True, "scheme": "https",
          "note": "标准加密网页服务端口"},
    5443: {"name": "TOS 网页管理（HTTPS）", "kind": "web", "web": True, "scheme": "https",
           "note": "TerraMaster TOS 的加密管理界面"},
    8181: {"name": "TOS 网页管理（HTTP）", "kind": "web", "web": True,
           "note": "TerraMaster TOS 的管理界面"},

    # ---- 文件共享 ----
    21: {"name": "FTP", "kind": "file", "note": "文件传输协议（控制端口）"},
    20: {"name": "FTP-DATA", "kind": "file", "note": "FTP 主动模式的数据端口"},
    139: {"name": "SMB / NetBIOS", "kind": "file", "note": "Windows 文件共享（旧式）"},
    445: {"name": "SMB", "kind": "file", "note": "Windows / macOS 文件共享"},
    137: {"name": "NetBIOS-NS", "kind": "file", "note": "NetBIOS 名称服务"},
    138: {"name": "NetBIOS-DGM", "kind": "file", "note": "NetBIOS 数据报服务"},
    548: {"name": "AFP", "kind": "file", "note": "Apple 文件共享 / Time Machine"},
    111: {"name": "RPCbind", "kind": "file", "note": "NFS 依赖的 RPC 端口映射服务"},
    2049: {"name": "NFS", "kind": "file", "note": "网络文件系统"},
    5005: {"name": "WebDAV", "kind": "file", "web": True, "note": "基于 HTTP 的文件共享"},
    5006: {"name": "WebDAV（HTTPS）", "kind": "file", "web": True, "scheme": "https",
           "note": "基于 HTTPS 的文件共享"},
    873: {"name": "rsync", "kind": "file", "note": "增量文件同步服务"},
    3260: {"name": "iSCSI", "kind": "file", "note": "块级存储目标服务"},

    # ---- 数据库与缓存 ----
    3306: {"name": "MySQL / MariaDB", "kind": "database", "note": "关系型数据库"},
    5432: {"name": "PostgreSQL", "kind": "database", "note": "关系型数据库"},
    27017: {"name": "MongoDB", "kind": "database", "note": "文档型数据库"},
    6379: {"name": "Redis", "kind": "cache", "note": "内存键值缓存"},

    # ---- 媒体服务 ----
    8096: {"name": "Jellyfin", "kind": "media", "web": True, "note": "开源媒体中心"},
    8920: {"name": "Jellyfin（HTTPS）", "kind": "media", "web": True, "scheme": "https",
           "note": "开源媒体中心"},
    32400: {"name": "Plex", "kind": "media", "web": True, "note": "Plex 媒体服务器"},
    8200: {"name": "DLNA", "kind": "media", "note": "DLNA / UPnP 媒体服务常用端口"},

    # ---- 下载工具 ----
    8080: {"name": "qBittorrent", "kind": "download", "web": True,
           "note": "BT 下载工具网页界面"},
    9091: {"name": "Transmission", "kind": "download", "web": True,
           "note": "BT 下载工具网页界面"},
    6800: {"name": "Aria2", "kind": "download", "web": True, "note": "多协议下载工具"},

    # ---- 容器与运维 ----
    2375: {"name": "Docker API（未加密）", "kind": "container",
           "note": "Docker 引擎远程接口，明文暴露风险很高"},
    2376: {"name": "Docker API（TLS）", "kind": "container",
           "note": "Docker 引擎远程接口，带 TLS"},
    9000: {"name": "Portainer", "kind": "container", "web": True,
           "note": "容器管理面板（也可能是其它 9000 端口服务）"},
    9443: {"name": "Portainer（HTTPS）", "kind": "container", "web": True, "scheme": "https",
           "note": "容器管理面板"},
    3000: {"name": "Grafana", "kind": "container", "web": True, "note": "监控面板常用端口"},
    9090: {"name": "Prometheus", "kind": "container", "web": True, "note": "监控采集常用端口"},
    8123: {"name": "Home Assistant", "kind": "container", "web": True,
           "note": "智能家居网关"},

    # ---- 其它 ----
    161: {"name": "SNMP", "kind": "network", "note": "网络管理协议"},
    631: {"name": "IPP / CUPS", "kind": "print", "note": "打印服务"},
    53: {"name": "DNS", "kind": "network", "note": "域名解析"},
    25: {"name": "SMTP", "kind": "network", "note": "邮件发送"},
}


def lookup(port):
    """按端口取指纹；未收录返回 ``None``。

    返回的是**副本**——调用方会往里面塞 ``open_url`` 之类的会话数据，
    直接返回表里的字典会让下一次请求读到上一次的残留。
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    found = KNOWN.get(port)
    if not found:
        return None
    entry = dict(found)
    entry.setdefault("web", False)
    entry.setdefault("scheme", "http")
    entry.setdefault("kind", "other")
    entry.setdefault("note", "")
    entry["port"] = port
    entry["confidence"] = CONFIDENCE
    entry["confidence_note"] = NOTE
    return entry


def table():
    """给前端「指纹说明」用的完整表（按端口升序）。"""
    rows = []
    for port in sorted(KNOWN):
        entry = lookup(port)
        entry["kind_label"] = KIND_LABELS.get(entry["kind"], entry["kind"])
        rows.append(entry)
    return rows
