"""``/etc/services`` 解析与「服务指纹」表的测试。

指纹这一层最容易被误当成结论，所以测试里既验「该认出来的认出来了」，
也验「每条都老老实实标着 suggestion」。
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from app import etcservices, fingerprint  # noqa: E402
from tests import proc_fixture  # noqa: E402


class ParseServicesTest(unittest.TestCase):
    def setUp(self):
        self.table = etcservices.parse_etc_services(proc_fixture.SERVICES_TEXT)

    def test_normal_lines(self):
        self.assertEqual(self.table["by_port"][22], "ssh")
        self.assertEqual(self.table["by_port"][80], "http")
        self.assertEqual(self.table["by_port"][8080], "http-alt")

    def test_udp_and_tcp_are_kept_apart(self):
        self.assertEqual(self.table["by_proto"][("udp", 53)], "domain")
        self.assertNotIn(("tcp", 53), self.table["by_proto"])

    def test_aliases_are_not_used_as_the_primary_name(self):
        # "http 80/tcp www" 里 www 是别名，反查必须给主名
        self.assertEqual(self.table["by_port"][80], "http")

    def test_ranges_and_unknown_protocols_are_skipped_quietly(self):
        self.assertNotIn(6000, self.table["by_port"])
        self.assertNotIn(9999, self.table["by_port"])

    def test_malformed_lines_are_counted_not_raised(self):
        # 三行确实不合格式：没有端口号的、端口为 0 的、端口超范围的。
        # 区间行与 ddp 协议行是合法写法，只是不受理，不计入 malformed。
        self.assertEqual(self.table["malformed"], 3)

    def test_empty_and_comment_only(self):
        table = etcservices.parse_etc_services("# 只有注释\n\n   \n")
        self.assertEqual(table["by_port"], {})
        self.assertEqual(table["malformed"], 0)


class ReadServicesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shh17-svc-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_file_is_a_graceful_degradation(self):
        result = etcservices.read_etc_services(os.path.join(self.tmp, "services"))
        self.assertEqual(result["source"], "unavailable")
        self.assertEqual(result["by_port"], {})
        self.assertIn("没有", result["detail"])

    def test_reads_real_file(self):
        path = proc_fixture.write_services(os.path.join(self.tmp, "services"))
        result = etcservices.read_etc_services(path)
        self.assertEqual(result["source"], "file")
        self.assertGreater(result["count"], 10)

    def test_lookup_prefers_protocol_then_falls_back(self):
        path = proc_fixture.write_services(os.path.join(self.tmp, "services"))
        table = etcservices.read_etc_services(path)
        self.assertEqual(etcservices.lookup(table, 80, "tcp"), "http")
        # 53 只声明了 udp，按 tcp 查时退回「任意协议同名端口」
        self.assertEqual(etcservices.lookup(table, 53, "tcp"), "domain")
        self.assertIsNone(etcservices.lookup(table, 65000, "tcp"))

    def test_lookup_on_empty_table(self):
        self.assertIsNone(etcservices.lookup({}, 80, "tcp"))


class FingerprintTest(unittest.TestCase):
    #: 设计文档 §15 点名要覆盖的端口
    REQUIRED = [22, 80, 443, 445, 139, 2049, 111, 21, 5005, 5006, 8181,
                3306, 5432, 6379, 8096, 32400, 8080, 2375, 2376]

    def test_all_required_ports_are_covered(self):
        missing = [port for port in self.REQUIRED if fingerprint.lookup(port) is None]
        self.assertEqual(missing, [], "指纹表缺少端口：%s" % missing)

    def test_names_match_the_documented_services(self):
        cases = {
            22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 2049: "NFS",
            21: "FTP", 3306: "MySQL / MariaDB", 6379: "Redis", 8096: "Jellyfin",
            32400: "Plex", 2375: "Docker API（未加密）",
        }
        for port, expected in cases.items():
            self.assertEqual(fingerprint.lookup(port)["name"], expected, port)
        self.assertIn("WebDAV", fingerprint.lookup(5005)["name"])
        self.assertIn("TOS", fingerprint.lookup(8181)["name"])

    def test_web_flag_and_scheme(self):
        self.assertTrue(fingerprint.lookup(8181)["web"])
        self.assertTrue(fingerprint.lookup(32400)["web"])
        self.assertFalse(fingerprint.lookup(22)["web"])
        self.assertFalse(fingerprint.lookup(3306)["web"])
        # Docker 的远程 API 不是给人用浏览器打开的
        self.assertFalse(fingerprint.lookup(2375)["web"])
        self.assertEqual(fingerprint.lookup(443)["scheme"], "https")
        self.assertEqual(fingerprint.lookup(8181)["scheme"], "http")

    def test_every_entry_is_labelled_as_a_suggestion(self):
        for row in fingerprint.table():
            self.assertEqual(row["confidence"], fingerprint.CONFIDENCE)
            self.assertIn("仅供参考", row["confidence_note"])
            self.assertIn(row["kind"], fingerprint.KIND_LABELS)

    def test_unknown_port_returns_none(self):
        self.assertIsNone(fingerprint.lookup(65000))
        self.assertIsNone(fingerprint.lookup(None))
        self.assertIsNone(fingerprint.lookup("not-a-port"))

    def test_lookup_returns_a_copy(self):
        """调用方会往结果里塞 open_url —— 不能污染下一次查询。"""
        first = fingerprint.lookup(8181)
        first["open_url"] = "http://nas:8181"
        first["name"] = "被改过"
        self.assertNotIn("open_url", fingerprint.lookup(8181))
        self.assertEqual(fingerprint.lookup(8181)["name"], "TOS 网页管理（HTTP）")

    def test_table_is_sorted_and_complete(self):
        rows = fingerprint.table()
        self.assertEqual(len(rows), len(fingerprint.KNOWN))
        self.assertEqual([row["port"] for row in rows], sorted(row["port"] for row in rows))


if __name__ == "__main__":
    unittest.main()
