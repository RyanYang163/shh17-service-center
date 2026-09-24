"""可选的 Docker 引擎 —— 只在系统上存在 ``docker`` 命令时启用。

**核心功能不依赖它。** 端口地图来自 ``/proc``，容器清单只是「检测到就用」的增强：
``shutil.which("docker")`` 返回 ``None`` 时，接口照常 200，只是 ``available=false``
并带上原因，界面上显示空状态——**绝不让它成为应用启动的前提**。

安全上刻意做窄：

* 只用 ``subprocess`` 的**参数列表**形式调用，**绝不** ``shell=True``——没有 shell，
  也就没有命令注入面（指引 38.3）。
* 命令是**写死的**：只有 ``docker ps``，参数只能选「看运行中的 / 看全部」。
  API 无法传入任意 docker 子命令。**本应用不会启动、停止、重启容器，也不做 exec。**
* 带超时：docker 守护进程没起来时 ``docker ps`` 可能长时间挂住，不能拖死请求线程。
"""

import json
import shutil
import subprocess
import threading

#: ``docker ps`` 的超时（秒）。守护进程未运行时命令可能挂住，必须兜住。
PS_TIMEOUT = 8

_state = {"checked": False, "available": False, "path": None, "version": "", "error": None}
_lock = threading.Lock()


def find_docker():
    """在 ``PATH`` 里找 docker 命令；找不到返回 ``None``。

    单独抽成函数是为了让测试能整体替换它（``mock.patch`` 掉就没有「探测到 docker」
    这条分支以外的不确定性了）。
    """
    return shutil.which("docker")


def detect(force=False):
    """检测 docker 是否可用。结果会缓存（每次请求都跑一次 ``docker version`` 太贵）。"""
    with _lock:
        if _state["checked"] and not force:
            return dict(_state)
        _state["checked"] = True
        path = find_docker()
        if not path:
            _state.update(available=False, path=None, version="",
                          error="系统上没有找到 docker 命令（容器清单不可用）")
            return dict(_state)
        try:
            completed = subprocess.run(
                [path, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, timeout=PS_TIMEOUT, check=False,
            )
        except subprocess.TimeoutExpired:
            _state.update(available=False, path=path, version="",
                          error="docker 命令响应超时（%d 秒）" % PS_TIMEOUT)
            return dict(_state)
        except OSError as exc:
            _state.update(available=False, path=path, version="",
                          error="无法执行 docker：%s" % exc)
            return dict(_state)

        stdout = (completed.stdout or b"").decode("utf-8", "replace").strip()
        stderr = (completed.stderr or b"").decode("utf-8", "replace").strip()
        if completed.returncode != 0:
            # 命令在、但守护进程没起来：仍然是「不可用」，原因要能读
            first_line = (stderr or stdout).splitlines()
            _state.update(available=False, path=path, version="",
                          error="docker 命令存在，但无法连接守护进程：%s"
                                % (first_line[0] if first_line else "无输出"))
            return dict(_state)
        _state.update(available=True, path=path, version=stdout, error=None)
        return dict(_state)


def status():
    """给前端 / ``App(engines=...)`` 用的引擎状态。"""
    info = detect()
    return {
        "name": "docker",
        "available": info["available"],
        "version": info["version"],
        "detail": ("已检测到 Docker %s" % info["version"]) if info["available"] else info["error"],
        "enables": ["containers"],
    }


def parse_ports(text):
    """解析 ``docker ps`` 的 Ports 字段。

    形如 ``0.0.0.0:8080->8080/tcp, :::8080->8080/tcp`` 或只有 ``8080/tcp``（未发布到宿主）。
    未发布的（没有 ``->``）不进端口地图——宿主上根本没有它，列出来只会误导。
    """
    published = []
    seen = set()
    for chunk in (text or "").split(","):
        chunk = chunk.strip()
        if not chunk or "->" not in chunk:
            continue
        left, _, right = chunk.partition("->")
        container_text, _, protocol = right.partition("/")
        host_ip, _, host_text = left.rpartition(":")
        try:
            container_port = int(container_text)
            host_port = int(host_text)
        except ValueError:
            continue
        protocol = (protocol or "tcp").strip().lower()
        if not 0 < host_port <= 65535 or not 0 < container_port <= 65535:
            continue
        key = (host_ip, host_port, protocol)
        if key in seen:
            continue
        seen.add(key)
        published.append({
            "host_ip": host_ip or "0.0.0.0",
            "host_port": host_port,
            "container_port": container_port,
            "protocol": protocol,
        })
    return published


def parse_ps_output(text):
    """解析 ``docker ps --format '{{json .}}'`` 的逐行 JSON 输出。

    坏行**跳过而不是抛异常**：docker 的输出版本之间偶有差异，
    一行读不懂不该让整个容器清单失败。
    """
    containers = []
    malformed = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(raw, dict):
            malformed += 1
            continue
        container_id = str(raw.get("ID") or "")
        containers.append({
            "id": container_id[:12],
            "name": str(raw.get("Names") or ""),
            "image": str(raw.get("Image") or ""),
            "status": str(raw.get("Status") or ""),
            "state": str(raw.get("State") or ""),
            "running_for": str(raw.get("RunningFor") or ""),
            "ports": parse_ports(raw.get("Ports") or ""),
            "ports_text": str(raw.get("Ports") or ""),
        })
    return containers, malformed


def list_containers(all_containers=False, timeout=PS_TIMEOUT):
    """列出容器。返回 ``{"available", "detail", "containers", "malformed"}``。

    ``available=False`` 表示系统上没有 docker（或守护进程连不上）——调用方据此显示
    「不可用」而不是报错。
    """
    info = detect()
    if not info["available"]:
        return {"available": False, "detail": info["error"] or "docker 不可用",
                "containers": [], "malformed": 0}

    argv = [info["path"], "ps", "--format", "{{json .}}"]
    if all_containers:
        argv.insert(2, "-a")
    try:
        completed = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"available": True, "detail": "docker ps 超时（%d 秒）" % timeout,
                "containers": [], "malformed": 0}
    except OSError as exc:
        return {"available": True, "detail": "无法执行 docker ps：%s" % exc,
                "containers": [], "malformed": 0}

    stdout = (completed.stdout or b"").decode("utf-8", "replace")
    if completed.returncode != 0:
        stderr = (completed.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return {
            "available": True,
            "detail": "docker ps 退出码 %d：%s" % (completed.returncode,
                                                   stderr[-1] if stderr else "无输出"),
            "containers": [], "malformed": 0,
        }

    containers, malformed = parse_ps_output(stdout)
    detail = "共 %d 个容器" % len(containers)
    if malformed:
        detail += "（%d 行输出无法解析，已跳过）" % malformed
    return {"available": True, "detail": detail, "containers": containers, "malformed": malformed}
