"""把三个来源合成一张「端口地图」。

三个来源各自独立、各自可能不可用，合成时**互不牵连**：

============  ==========================================  ==========================
来源          提供什么                                    不可用时
============  ==========================================  ==========================
``/proc``     「谁真的在监听」——端口、协议、绑定地址       空列表 + 原因（非 Linux）
``/etc/services``  端口 → 服务名（ftp、http-alt…）        只用指纹，字段留空
``docker ps`` 容器发布的宿主端口 + 容器名 / 镜像 / 状态    标「不可用」，不影响其它
============  ==========================================  ==========================

**指纹是建议**：``fingerprint`` 模块按端口号给出「这通常是做什么的」，界面上必须标注
「仅供参考」。真正的结论只有「有进程在监听这个端口」这一条，那是 /proc 给的。

**「打开」地址由当前访问地址推导**（指引 8.4.3 禁止硬编码 IP）：从请求的
``X-Forwarded-Host`` / ``Host`` 头取出主机名，拼成 ``http://<host>:<port>``。
请求头是**客户端可控**的，所以 :func:`sanitize_host` 只放行合法主机名与 IP 字面量，
其余一律返回 ``None``（宁可不给按钮，也不把用户带到他处）。
"""

import ipaddress
import os
import re
import time

from . import docker_engine, etcservices, fingerprint, procnet

DEFAULT_PROC_ROOT = "/proc"
DEFAULT_SERVICES_PATH = etcservices.DEFAULT_PATH

#: 合法主机名：字母数字开头，允许 ``.`` ``-`` ``_``，长度按 DNS 上限留足
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def sanitize_host(raw):
    """把 ``Host`` / ``X-Forwarded-Host`` 的值收敛成一个可安全拼接的主机名。

    返回不含端口的主机名（IPv6 保留方括号），取不到或不合法时返回 ``None``。

    **不信任请求头**：``Host`` 完全由客户端控制，直接拼进 URL 再让前端渲染成链接，
    就等于给自己开了一个「把用户带到他处」的口子。所以这里只放行
    「字母数字 + ``.`` ``-`` ``_``」的主机名与合法的 IPv4 / IPv6 字面量；
    端口部分必须是纯数字（否则 ``http://evil`` 会被切成主机名 ``http``，
    拼出 ``http://http:8181`` 这种怪地址）。
    """
    text = str(raw or "").split(",")[0].strip()
    if not text:
        return None

    # IPv6 字面量：[::1]:8080 或 [::1]
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None
        inner = text[1:end]
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return None
        return "[%s]" % inner

    # 裸 IPv6（没有方括号，也就没有端口可剥）
    if text.count(":") > 1:
        try:
            ipaddress.IPv6Address(text)
        except ValueError:
            return None
        return "[%s]" % text

    # 主机名或 IPv4，可能带 :port
    if ":" in text:
        host, _, port = text.partition(":")
        if not port.isdigit():
            return None
        text = host
    if not text or not _HOST_RE.match(text):
        return None
    return text


def host_from_headers(headers):
    """按「先 X-Forwarded-Host、后 Host」的顺序取主机名。

    代理形态下（平台 Nginx 转发）``Host`` 是后端 socket 的名字（``localhost``），
    真实的访问地址只在 ``X-Forwarded-Host`` 里，所以优先取它。
    """
    if headers is None:
        return None
    for key in ("X-Forwarded-Host", "Host"):
        try:
            value = headers.get(key)
        except AttributeError:
            value = None
        host = sanitize_host(value)
        if host:
            return host
    return None


def build_open_url(host, port, scheme="http"):
    """``http://<host>:<port>``。host 为空时返回 ``None``。"""
    if not host:
        return None
    return "%s://%s:%d" % (scheme or "http", host, int(port))


def _open_info(host, port, mark, scope):
    """给一条记录算「打开」相关的三个字段。

    ``open_reachable=False`` 表示**按钮该置灰**：地址拼得出来，但那个绑定根本
    不从网络上可达（例如只绑了 127.0.0.1），点了也只会连接失败。
    """
    if not mark or not mark.get("web"):
        return {"open_url": None, "open_reachable": False, "open_note": None}
    url = build_open_url(host, port, mark.get("scheme") or "http")
    if not url:
        return {"open_url": None, "open_reachable": False,
                "open_note": "无法从当前访问地址推导出主机名"}
    if scope == "localhost":
        return {"open_url": url, "open_reachable": False,
                "open_note": "该服务只绑定了本机回环地址，从浏览器无法访问"}
    return {"open_url": url, "open_reachable": True, "open_note": None}


def container_names_for(containers, protocol, port):
    """哪些容器发布了这个宿主端口。"""
    names = []
    for container in containers or []:
        for mapping in container.get("ports") or []:
            if mapping.get("host_port") == port and mapping.get("protocol") == protocol:
                name = container.get("name") or container.get("id") or "未命名容器"
                if name not in names:
                    names.append(name)
                break
    return names


def _entry_from_socket(sock, services, host, containers):
    port = sock["port"]
    protocol = sock["protocol"]
    etc_name = etcservices.lookup(services, port, protocol)
    mark = fingerprint.lookup(port)
    names = container_names_for(containers, protocol, port)

    entry = {
        "port": port,
        "protocol": protocol,
        "address": sock["address"],
        "family": sock["family"],
        "scope": sock["scope"],
        "state": sock["state"],
        "listening": True,
        "service": etc_name,
        "fingerprint": mark,
        "service_name": mark["name"] if mark else (etc_name or "未知服务"),
        "service_source": ("fingerprint" if mark else
                           ("etc-services" if etc_name else "unknown")),
        "containers": names,
        "source": "docker" if names else "listen",
    }
    entry.update(_open_info(host, port, mark, sock["scope"]))
    return entry


def _entry_from_docker(mapping, container, services, host):
    """容器发布了、但内核监听表里没有对应行的宿主端口。

    正常情况下 ``docker-proxy`` 会在宿主上监听这个端口，于是它本该出现在 /proc 里；
    走到这个分支通常意味着：容器用了 host 网络模式、内核表读不到（非 Linux）、
    或者发布发生在两次读取之间。如实标出来比装作没看见好。
    """
    port = mapping["host_port"]
    protocol = mapping["protocol"]
    address = mapping.get("host_ip") or "0.0.0.0"
    etc_name = etcservices.lookup(services, port, protocol)
    mark = fingerprint.lookup(port)
    name = container.get("name") or container.get("id") or "未命名容器"

    entry = {
        "port": port,
        "protocol": protocol,
        "address": address,
        "family": "ipv6" if ":" in address else "ipv4",
        "scope": procnet.scope_of(address),
        "state": "published",
        "listening": False,
        "service": etc_name,
        "fingerprint": mark,
        "service_name": mark["name"] if mark else (etc_name or "未知服务"),
        "service_source": ("fingerprint" if mark else
                           ("etc-services" if etc_name else "unknown")),
        "containers": [name],
        "source": "docker",
    }
    entry.update(_open_info(host, port, mark, entry["scope"]))
    return entry


def _category_stats(entries):
    counts = {}
    for entry in entries:
        mark = entry.get("fingerprint") or {}
        kind = mark.get("kind") or "unknown"
        bucket = counts.setdefault(kind, {"kind": kind, "count": 0, "ports": []})
        bucket["count"] += 1
        if entry["port"] not in bucket["ports"]:
            bucket["ports"].append(entry["port"])
    rows = []
    for kind, bucket in counts.items():
        rows.append({
            "kind": kind,
            "label": fingerprint.KIND_LABELS.get(kind, "未识别"),
            "count": bucket["count"],
            "ports": sorted(bucket["ports"]),
        })
    rows.sort(key=lambda row: (-row["count"], row["label"]))
    return rows


def collect(proc_root=DEFAULT_PROC_ROOT, services_path=DEFAULT_SERVICES_PATH,
            docker_enabled=True, docker_all=False, host=None):
    """采集一次完整快照。

    每个来源的失败都被关在自己的字段里（``proc`` / ``services`` / ``docker``），
    整体**永远返回一份可用结果**——上游接口不必为「这台机器没有 /proc」写分支。
    """
    proc = procnet.read_proc_ports(proc_root)
    services = etcservices.read_etc_services(services_path)

    if docker_enabled:
        docker = docker_engine.list_containers(all_containers=docker_all)
    else:
        docker = {"available": False, "detail": "本次采集未启用容器探测",
                  "containers": [], "malformed": 0}
    containers = docker.get("containers") or []

    entries = [_entry_from_socket(sock, services, host, containers)
               for sock in proc["listeners"]]

    known = {(entry["protocol"], entry["port"]) for entry in entries}
    for container in containers:
        for mapping in container.get("ports") or []:
            key = (mapping["protocol"], mapping["host_port"])
            if key in known:
                continue
            entries.append(_entry_from_docker(mapping, container, services, host))
            known.add(key)

    entries.sort(key=lambda item: (item["port"], item["protocol"], item["address"]))

    return {
        "collected_at": time.time(),
        "entries": entries,
        "listen_count": len([item for item in entries if item["listening"]]),
        "mapped_count": len(entries),
        "socket_count": proc["socket_count"],
        "open_count": len([item for item in entries if item.get("open_reachable")]),
        "containers": containers,
        "container_count": len(containers),
        "categories": _category_stats(entries),
        "proc": {
            "source": proc["source"],
            "detail": proc["detail"],
            "proc_root": proc["proc_root"],
            "files": proc["files"],
        },
        "services": {
            "source": services["source"],
            "detail": services["detail"],
            "path": services["path"],
            "count": services["count"],
        },
        "docker": {
            "available": docker.get("available", False),
            "detail": docker.get("detail", ""),
            "malformed": docker.get("malformed", 0),
        },
    }


def strip_session_fields(entries):
    """入库前剥掉随请求变化的字段。

    ``open_url`` 依赖「你这次是从哪个地址访问的」，同一个端口换个访问入口就不一样；
    把它写进历史快照，之后对比差异时会得到一堆假变化。历史只记录事实本身。
    """
    cleaned = []
    for entry in entries:
        item = dict(entry)
        item.pop("open_url", None)
        item.pop("open_reachable", None)
        item.pop("open_note", None)
        cleaned.append(item)
    return cleaned


def default_proc_root(settings):
    """运行期可覆盖的 ``/proc`` 位置（测试用假目录注入，见 ``tests/proc_fixture.py``）。"""
    value = settings.get("proc_root") if settings else None
    return str(value) if value else DEFAULT_PROC_ROOT


def default_services_path(settings):
    value = settings.get("services_path") if settings else None
    return str(value) if value else DEFAULT_SERVICES_PATH


def describe_source(settings):
    """给「设置」页显示的采集来源说明。"""
    proc_root = default_proc_root(settings)
    return {
        "proc_root": proc_root,
        "proc_available": os.path.isfile(os.path.join(proc_root, "net", "tcp")),
        "services_path": default_services_path(settings),
        "services_available": os.path.isfile(default_services_path(settings)),
    }
