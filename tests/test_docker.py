"""Docker 引擎（可选）的测试。

这一层要证明三件事：

1. **检测不到就「不可用」**，而不是报错，更不是启动前提；
2. 调用方式**只有参数列表、没有 shell**，且**只允许 ``docker ps``**（本应用绝不
   启动 / 停止 / 重启容器，也不 exec）；
3. 输出读不懂时跳过坏行，不让整个容器清单失败。
"""

import json
import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from app import docker_engine  # noqa: E402

#: 真机 ``docker ps --format '{{json .}}'`` 的一行（字段名逐字照抄）
PS_LINE = json.dumps({
    "Command": "\"/init\"",
    "CreatedAt": "2026-09-01 10:00:00 +0800 CST",
    "ID": "3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a",
    "Image": "jellyfin/jellyfin:latest",
    "Labels": "",
    "LocalVolumes": "1",
    "Mounts": "/Volume1/media:/media",
    "Names": "jellyfin",
    "Networks": "bridge",
    "Ports": "0.0.0.0:8096->8096/tcp, :::8096->8096/tcp",
    "RunningFor": "3 days ago",
    "Size": "0B (virtual 1.2GB)",
    "State": "running",
    "Status": "Up 3 days",
})

#: 没有发布到宿主端口的容器（Ports 里没有 ``->``）
PS_LINE_INTERNAL = json.dumps({
    "ID": "aaaabbbbccccdddd0000000000000000",
    "Image": "redis:7-alpine",
    "Names": "cache",
    "Ports": "6379/tcp",
    "RunningFor": "2 hours ago",
    "State": "running",
    "Status": "Up 2 hours",
})


class _Completed:
    """``subprocess.run`` 的返回值替身。"""

    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _FakeRunner:
    """按子命令分发的假 docker。同时记录每次调用的参数，供「只用 ps」的断言使用。"""

    def __init__(self, ps_stdout="", ps_returncode=0, version_stdout=b"24.0.7\n",
                 version_returncode=0, raise_timeout_for=None):
        self.calls = []
        self.ps_stdout = ps_stdout
        self.ps_returncode = ps_returncode
        self.version_stdout = version_stdout
        self.version_returncode = version_returncode
        self.raise_timeout_for = raise_timeout_for or set()

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), "kwargs": dict(kwargs)})
        if not isinstance(argv, (list, tuple)):
            raise AssertionError("docker 必须以参数列表方式调用，绝不能拼 shell 字符串")
        if kwargs.get("shell"):
            raise AssertionError("docker 调用绝不能使用 shell=True")
        subcommand = argv[1] if len(argv) > 1 else ""
        if subcommand in self.raise_timeout_for:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=1)
        if subcommand == "ps":
            return _Completed(stdout=self.ps_stdout.encode("utf-8"),
                              returncode=self.ps_returncode)
        return _Completed(stdout=self.version_stdout, returncode=self.version_returncode)


class DockerEngineTest(unittest.TestCase):
    def setUp(self):
        # detect() 结果会缓存，测试之间必须清掉，否则先跑的用例会把结论带给后一个
        self._saved = dict(docker_engine._state)
        docker_engine._state.update(checked=False, available=False, path=None,
                                    version="", error=None)

    def tearDown(self):
        docker_engine._state.clear()
        docker_engine._state.update(self._saved)

    # ---------------------------------------------------------- 降级

    def test_missing_command_degrades_to_unavailable(self):
        with mock.patch.object(docker_engine, "find_docker", return_value=None):
            info = docker_engine.detect(force=True)
            self.assertFalse(info["available"])
            self.assertIn("没有找到 docker", info["error"])

            result = docker_engine.list_containers()
            self.assertFalse(result["available"])
            self.assertEqual(result["containers"], [])
            self.assertTrue(result["detail"])

            status = docker_engine.status()
            self.assertFalse(status["available"])
            self.assertEqual(status["name"], "docker")

    def test_daemon_down_is_reported_as_unavailable(self):
        runner = _FakeRunner(version_returncode=1,
                             version_stdout=b"")
        with mock.patch.object(docker_engine, "find_docker", return_value="/usr/bin/docker"), \
                mock.patch.object(docker_engine.subprocess, "run", runner):
            info = docker_engine.detect(force=True)
        self.assertFalse(info["available"])
        self.assertIn("守护进程", info["error"])

    def test_timeout_on_version_is_handled(self):
        runner = _FakeRunner(raise_timeout_for={"version"})
        with mock.patch.object(docker_engine, "find_docker", return_value="/usr/bin/docker"), \
                mock.patch.object(docker_engine.subprocess, "run", runner):
            info = docker_engine.detect(force=True)
        self.assertFalse(info["available"])
        self.assertIn("超时", info["error"])

    def test_timeout_on_ps_is_handled(self):
        runner = _FakeRunner(ps_stdout=PS_LINE, raise_timeout_for={"ps"})
        with mock.patch.object(docker_engine, "find_docker", return_value="/usr/bin/docker"), \
                mock.patch.object(docker_engine.subprocess, "run", runner):
            result = docker_engine.list_containers()
        self.assertTrue(result["available"])
        self.assertEqual(result["containers"], [])
        self.assertIn("超时", result["detail"])

    def test_ps_failure_keeps_engine_available_but_reports_reason(self):
        runner = _FakeRunner(ps_returncode=1)
        with mock.patch.object(docker_engine, "find_docker", return_value="/usr/bin/docker"), \
                mock.patch.object(docker_engine.subprocess, "run", runner):
            result = docker_engine.list_containers()
        self.assertTrue(result["available"])
        self.assertIn("退出码 1", result["detail"])

    # ---------------------------------------------------------- 解析

    def test_parse_ports_handles_ipv4_ipv6_and_duplicates(self):
        ports = docker_engine.parse_ports("0.0.0.0:8080->8080/tcp, :::8080->8080/tcp")
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0]["host_port"], 8080)
        self.assertEqual(ports[0]["container_port"], 8080)
        self.assertEqual(ports[0]["protocol"], "tcp")
        self.assertEqual(ports[1]["host_ip"], "::")

    def test_parse_ports_ignores_unpublished(self):
        self.assertEqual(docker_engine.parse_ports("6379/tcp"), [])
        self.assertEqual(docker_engine.parse_ports(""), [])
        self.assertEqual(docker_engine.parse_ports("garbage"), [])

    def test_parse_ports_rejects_out_of_range(self):
        self.assertEqual(docker_engine.parse_ports("0.0.0.0:70000->80/tcp"), [])

    def test_parse_ps_output_skips_bad_lines(self):
        text = PS_LINE + "\n" + "this is not json\n" + "[1,2,3]\n" + PS_LINE_INTERNAL + "\n"
        containers, malformed = docker_engine.parse_ps_output(text)
        self.assertEqual(len(containers), 2)
        self.assertEqual(malformed, 2)

        first = containers[0]
        self.assertEqual(first["id"], "3f2a1b0c9d8e")  # 截断到 12 位，与 docker ps 一致
        self.assertEqual(first["name"], "jellyfin")
        self.assertEqual(first["image"], "jellyfin/jellyfin:latest")
        self.assertEqual(first["state"], "running")
        self.assertEqual(first["running_for"], "3 days ago")
        self.assertEqual(first["ports"][0]["host_port"], 8096)

        second = containers[1]
        self.assertEqual(second["name"], "cache")
        self.assertEqual(second["ports"], [], "未发布到宿主的端口不进端口地图")

    def test_parse_ps_output_on_empty_text(self):
        self.assertEqual(docker_engine.parse_ps_output(""), ([], 0))

    # ---------------------------------------------------------- 调用方式

    def test_only_ps_is_ever_invoked_and_never_via_shell(self):
        runner = _FakeRunner(ps_stdout=PS_LINE)
        with mock.patch.object(docker_engine, "find_docker", return_value="/usr/bin/docker"), \
                mock.patch.object(docker_engine.subprocess, "run", runner):
            result = docker_engine.list_containers()

        self.assertTrue(result["available"])
        self.assertEqual(len(result["containers"]), 1)
        subcommands = {call["argv"][1] for call in runner.calls}
        self.assertTrue(subcommands.issubset({"version", "ps"}),
                        "只允许 docker version / docker ps，实际调用了：%s" % subcommands)
        for call in runner.calls:
            self.assertFalse(call["kwargs"].get("shell"))
            self.assertIn("timeout", call["kwargs"], "docker 调用必须带超时")

    def test_all_flag_only_adds_dash_a(self):
        runner = _FakeRunner(ps_stdout=PS_LINE)
        with mock.patch.object(docker_engine, "find_docker", return_value="/usr/bin/docker"), \
                mock.patch.object(docker_engine.subprocess, "run", runner):
            docker_engine.list_containers(all_containers=True)
        ps_calls = [call["argv"] for call in runner.calls if call["argv"][1] == "ps"]
        self.assertEqual(ps_calls[0][2], "-a")
        self.assertEqual(set(ps_calls[0][2:]), {"-a", "--format", "{{json .}}"})

    def test_engines_status_shape_matches_framework_expectation(self):
        with mock.patch.object(docker_engine, "find_docker", return_value=None):
            status = docker_engine.status()
        for key in ("name", "available", "detail", "enables"):
            self.assertIn(key, status)
        self.assertEqual(status["enables"], ["containers"])


if __name__ == "__main__":
    unittest.main()
