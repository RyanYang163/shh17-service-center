"""合成层（``collect.py``）的单元测试。

这一层最容易出安全问题：**「打开」地址是拿请求头拼出来的**，而 Host 完全由客户端控制。
所以这里把 :func:`collect.sanitize_host` 的各种坏输入钉死——不合法就必须返回 ``None``，
宁可不给按钮，也不能把用户带去别的地址。

另外覆盖「合并」这一步：容器发布的宿主端口要能挂到对应的监听记录上；
内核表里没有的容器端口要如实标出来，而不是凭空断定它没在监听。
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from app import collect, fingerprint, procnet  # noqa: E402
from tests import proc_fixture  # noqa: E402


class SanitizeHostTest(unittest.TestCase):
    def test_accepts_normal_hosts(self):
        self.assertEqual(collect.sanitize_host("nas.local"), "nas.local")
        self.assertEqual(collect.sanitize_host("tnas-01"), "tnas-01")
        self.assertEqual(collect.sanitize_host("192.168.1.5"), "192.168.1.5")
        self.assertEqual(collect.sanitize_host("nas.local:5443"), "nas.local")
        self.assertEqual(collect.sanitize_host("  nas.local  "), "nas.local")

    def test_accepts_ipv6_literals(self):
        self.assertEqual(collect.sanitize_host("[::1]:8080"), "[::1]")
        self.assertEqual(collect.sanitize_host("[fe80::1]"), "[fe80::1]")
        self.assertEqual(collect.sanitize_host("::1"), "[::1]")

    def test_rejects_everything_that_could_redirect_the_user(self):
        for bad in ("", "   ", None, "bad host", "nas.local/../evil", "evil.com:80:90",
                    "http://evil", "user@nas", "nas\nlocal", "[not-an-ipv6]",
                    "<script>", "a" * 300, "nas.local?x=1", "#frag"):
            self.assertIsNone(collect.sanitize_host(bad), bad)

    def test_takes_the_first_of_a_forwarded_chain(self):
        self.assertEqual(collect.sanitize_host("first.example, second.example"),
                         "first.example")


class HostFromHeadersTest(unittest.TestCase):
    def test_prefers_x_forwarded_host(self):
        headers = {"Host": "localhost:18017", "X-Forwarded-Host": "tnas.example"}
        self.assertEqual(collect.host_from_headers(headers), "tnas.example")

    def test_falls_back_to_host(self):
        self.assertEqual(collect.host_from_headers({"Host": "nas.local:8181"}), "nas.local")

    def test_falls_through_when_forwarded_host_is_bogus(self):
        headers = {"Host": "nas.local", "X-Forwarded-Host": "bad host"}
        self.assertEqual(collect.host_from_headers(headers), "nas.local")

    def test_no_headers_at_all(self):
        self.assertIsNone(collect.host_from_headers(None))
        self.assertIsNone(collect.host_from_headers({}))


class OpenUrlTest(unittest.TestCase):
    def test_build(self):
        self.assertEqual(collect.build_open_url("nas.local", 8181), "http://nas.local:8181")
        self.assertEqual(collect.build_open_url("nas.local", 5443, "https"),
                         "https://nas.local:5443")
        self.assertIsNone(collect.build_open_url(None, 8181))

    def test_localhost_binding_is_flagged_unreachable(self):
        info = collect._open_info("nas.local", 8080, fingerprint.lookup(8080), "localhost")
        self.assertEqual(info["open_url"], "http://nas.local:8080")
        self.assertFalse(info["open_reachable"])
        self.assertIn("回环", info["open_note"])

    def test_all_interface_binding_is_reachable(self):
        info = collect._open_info("nas.local", 8181, fingerprint.lookup(8181), "all")
        self.assertTrue(info["open_reachable"])
        self.assertIsNone(info["open_note"])

    def test_non_web_service_has_no_url(self):
        info = collect._open_info("nas.local", 22, fingerprint.lookup(22), "all")
        self.assertIsNone(info["open_url"])
        self.assertFalse(info["open_reachable"])

    def test_unknown_host_has_no_url(self):
        info = collect._open_info(None, 8181, fingerprint.lookup(8181), "all")
        self.assertIsNone(info["open_url"])
        self.assertIn("主机名", info["open_note"])


class CollectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shh17-collect-")
        self.proc_root = proc_fixture.default_proc(os.path.join(self.tmp, "proc"))
        self.services = proc_fixture.write_services(os.path.join(self.tmp, "services"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _collect(self, host="nas.local", **kwargs):
        kwargs.setdefault("docker_enabled", False)
        return collect.collect(proc_root=self.proc_root, services_path=self.services,
                               host=host, **kwargs)

    def test_merges_all_sources(self):
        result = self._collect()
        self.assertEqual(result["listen_count"], 15)
        self.assertEqual(result["proc"]["source"], "proc")
        self.assertEqual(result["services"]["source"], "file")
        self.assertFalse(result["docker"]["available"])
        self.assertEqual(result["container_count"], 0)
        self.assertGreater(result["socket_count"], result["listen_count"])
        self.assertEqual(len(result["entries"]), result["mapped_count"])

    def test_entries_are_sorted_by_port(self):
        entries = self._collect()["entries"]
        keys = [(item["port"], item["protocol"], item["address"]) for item in entries]
        self.assertEqual(keys, sorted(keys))

    def test_entry_carries_everything_the_table_needs(self):
        entry = [item for item in self._collect()["entries"]
                 if item["port"] == 445 and item["protocol"] == "tcp"][0]
        for key in ("port", "protocol", "address", "scope", "state", "service_name",
                    "fingerprint", "open_url", "open_reachable", "containers", "source"):
            self.assertIn(key, entry)
        self.assertEqual(entry["service_name"], "SMB")
        self.assertEqual(entry["scope"], "all")
        self.assertEqual(entry["source"], "listen")

    def test_collect_without_proc_still_returns_a_usable_payload(self):
        """非 Linux 上拿不到内核表 —— 其它字段照常齐备，调用方不用写分支。"""
        result = collect.collect(proc_root=os.path.join(self.tmp, "nope"),
                                 services_path=self.services, host="nas.local",
                                 docker_enabled=False)
        self.assertEqual(result["entries"], [])
        self.assertEqual(result["proc"]["source"], "unavailable")
        self.assertEqual(result["categories"], [])
        self.assertIn("没有", result["proc"]["detail"])

    def test_collect_without_etc_services_keeps_fingerprints(self):
        result = collect.collect(proc_root=self.proc_root,
                                 services_path=os.path.join(self.tmp, "nope"),
                                 host="nas.local", docker_enabled=False)
        self.assertEqual(result["services"]["source"], "unavailable")
        entry = [item for item in result["entries"] if item["port"] == 8181][0]
        self.assertEqual(entry["service_name"], "TOS 网页管理（HTTP）")
        self.assertIsNone(entry["service"])

    def test_docker_ports_annotate_matching_listeners(self):
        """容器发布的宿主端口要挂到同端口的监听记录上，而不是另起一行。"""
        containers = [{"id": "abc", "name": "jellyfin", "image": "jellyfin/jellyfin",
                       "state": "running", "status": "Up 2 days", "running_for": "2 days",
                       "ports": [{"host_ip": "0.0.0.0", "host_port": 5005,
                                  "container_port": 5005, "protocol": "tcp"}],
                       "ports_text": "0.0.0.0:5005->5005/tcp"}]
        # 直接走内部合并函数，避免依赖本机是否装了 docker
        listeners = procnet.read_proc_ports(self.proc_root)["listeners"]
        entries = [collect._entry_from_socket(sock, {"by_proto": {}, "by_port": {}},
                                             "nas.local", containers)
                   for sock in listeners]
        annotated = [item for item in entries if item["port"] == 5005
                     and item["protocol"] == "tcp"]
        self.assertEqual(len(annotated), 1)
        self.assertEqual(annotated[0]["containers"], ["jellyfin"])
        self.assertEqual(annotated[0]["source"], "docker")
        # 没有挂上容器的记录不该被误标
        other = [item for item in entries if item["port"] == 445][0]
        self.assertEqual(other["containers"], [])
        self.assertEqual(other["source"], "listen")

    def test_docker_published_port_without_listener_is_listed_but_not_claimed_as_listening(self):
        containers = [{"id": "abc", "name": "app", "image": "app:1", "state": "running",
                       "status": "Up", "running_for": "1h",
                       "ports": [{"host_ip": "0.0.0.0", "host_port": 9999,
                                  "container_port": 80, "protocol": "tcp"}],
                       "ports_text": "0.0.0.0:9999->80/tcp"}]
        entries = []
        known = set()
        for container in containers:
            for mapping in container["ports"]:
                key = (mapping["protocol"], mapping["host_port"])
                if key in known:
                    continue
                entries.append(collect._entry_from_docker(
                    mapping, container, {"by_proto": {}, "by_port": {}}, "nas.local"))
                known.add(key)
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["listening"])
        self.assertEqual(entries[0]["state"], "published")
        self.assertEqual(entries[0]["containers"], ["app"])
        self.assertEqual(entries[0]["source"], "docker")

    def test_category_stats(self):
        result = self._collect()
        by_kind = {row["kind"]: row["count"] for row in result["categories"]}
        self.assertIn("file", by_kind)
        self.assertIn("web", by_kind)
        self.assertIn("database", by_kind)
        for row in result["categories"]:
            self.assertIn(row["label"], fingerprint.KIND_LABELS.values())

    def test_strip_session_fields(self):
        entries = self._collect()["entries"]
        stripped = collect.strip_session_fields(entries)
        self.assertEqual(len(stripped), len(entries))
        for item in stripped:
            self.assertNotIn("open_url", item)
            self.assertNotIn("open_reachable", item)
            self.assertNotIn("open_note", item)
        # 不能就地改原对象（同一个 entries 列表还要拿去回响应）
        self.assertIn("open_url", entries[0])

    def test_describe_source(self):
        class _Settings:
            def __init__(self, values):
                self.values = values

            def get(self, key, default=None):
                return self.values.get(key, default)

        described = collect.describe_source(_Settings({
            "proc_root": self.proc_root, "services_path": self.services}))
        self.assertTrue(described["proc_available"])
        self.assertTrue(described["services_available"])

        missing = collect.describe_source(_Settings({}))
        self.assertEqual(missing["proc_root"], collect.DEFAULT_PROC_ROOT)


if __name__ == "__main__":
    unittest.main()
