"""``/proc/net/tcp`` 与 ``/proc/net/tcp6`` 的解析测试。

重点是把两个「容易写反」的地方钉死：

* 小端 IP —— ``0100007F`` 是 ``127.0.0.1``；
* 大端端口 —— ``1F90`` 是 8080。

以及所有降级路径：文件缺失、坏行、端口 0 / 超范围。
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from app import procnet  # noqa: E402
from tests import proc_fixture  # noqa: E402


class AddressParsingTest(unittest.TestCase):
    def test_ipv4_is_little_endian(self):
        self.assertEqual(procnet._hex_to_ipv4("0100007F"), "127.0.0.1")
        self.assertEqual(procnet._hex_to_ipv4("00000000"), "0.0.0.0")
        # 192.168.1.5 在 /proc 里写成 0501A8C0（整字倒序），不是 C0A80105
        self.assertEqual(procnet._hex_to_ipv4("0501A8C0"), "192.168.1.5")

    def test_ipv4_wrong_length_is_rejected(self):
        with self.assertRaises(ValueError):
            procnet._hex_to_ipv4("010000")

    def test_ipv6_words_are_each_little_endian(self):
        # ::1 在 /proc 里写成 4 个 32 位字，最后一个字是 01000000
        self.assertEqual(
            procnet._hex_to_ipv6("00000000000000000000000001000000"), "::1")
        self.assertEqual(
            procnet._hex_to_ipv6("00000000000000000000000000000000"), "::")

    def test_ipv6_wrong_length_is_rejected(self):
        with self.assertRaises(ValueError):
            procnet._hex_to_ipv6("01000000")


class ParseProcNetTest(unittest.TestCase):
    def test_sample_line_is_127_0_0_1_8080(self):
        """设计文档点名的样例：``0100007F:1F90`` = ``127.0.0.1:8080``。"""
        text = (proc_fixture.TCP_HEADER + "\n"
                "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000"
                " 00:00000000 00000000     0        0 10008 1\n")
        sockets = procnet.parse_proc_net(text, "tcp")
        self.assertEqual(len(sockets), 1)
        sock = sockets[0]
        self.assertEqual(sock["port"], 8080)
        self.assertEqual(sock["address"], "127.0.0.1")
        self.assertEqual(sock["family"], "ipv4")
        self.assertEqual(sock["scope"], "localhost")
        self.assertEqual(sock["state"], "LISTEN")
        self.assertTrue(sock["listening"])

    def test_big_endian_port(self):
        text = "   0: 00000000:0050 00000000:0000 0A 00000000:00000000\n"
        self.assertEqual(procnet.parse_proc_net(text, "tcp")[0]["port"], 80)

    def test_header_and_short_lines_are_skipped(self):
        text = proc_fixture.TCP_HEADER + "\n  15: 00000000:0016\n\n"
        self.assertEqual(procnet.parse_proc_net(text, "tcp"), [])

    def test_bad_hex_line_is_skipped_not_raised(self):
        text = "  13: ZZZZZZZZ:0016 00000000:0000 0A 00000000:00000000\n"
        self.assertEqual(procnet.parse_proc_net(text, "tcp"), [])

    def test_port_zero_is_dropped(self):
        text = "  10: 00000000:0000 00000000:0000 0A 00000000:00000000\n"
        self.assertEqual(procnet.parse_proc_net(text, "tcp"), [])

    def test_port_above_65535_is_dropped(self):
        # 0x11170 = 70000，超过 65535
        text = "  10: 00000000:11170 00000000:0000 0A 00000000:00000000\n"
        self.assertEqual(procnet.parse_proc_net(text, "tcp"), [])

    def test_non_listening_state_is_kept_but_flagged(self):
        text = ("  14: 0100007F:1F90 0100007F:C001 01 00000000:00000000\n"
                "  01: 00000000:0016 00000000:0000 0A 00000000:00000000\n")
        sockets = procnet.parse_proc_net(text, "tcp")
        self.assertEqual(len(sockets), 2)
        states = {sock["state"]: sock["listening"] for sock in sockets}
        self.assertEqual(states["ESTABLISHED"], False)
        self.assertEqual(states["LISTEN"], True)

    def test_protocol_tag_is_carried_through(self):
        text = "   0: 00000000000000000000000001000000:1F90 0:0 0A 0:0\n"
        sock = procnet.parse_proc_net(text, "tcp6")[0]
        self.assertEqual(sock["protocol"], "tcp6")
        self.assertEqual(sock["family"], "ipv6")
        self.assertEqual(sock["address"], "::1")


class ReadProcPortsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shh17-proc-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_default_proc_root_missing_file_is_a_graceful_degradation(self):
        """非 Linux 上 ``/proc/net/tcp`` 不存在 —— 必须返回不可用说明而不是抛异常。"""
        missing_root = os.path.join(self.tmp, "no-such-proc")
        result = procnet.read_proc_ports(missing_root)
        self.assertEqual(result["source"], "unavailable")
        self.assertEqual(result["listeners"], [])
        self.assertIn("没有", result["detail"])
        self.assertIn("net/tcp", result["detail"].replace("\\", "/"))

    def test_reads_both_tables(self):
        proc_fixture.default_proc(self.tmp)
        result = procnet.read_proc_ports(self.tmp)
        self.assertEqual(result["source"], "proc")
        self.assertEqual(len(result["files"]), 2)
        self.assertEqual(result["listen_count"], len(result["listeners"]))
        self.assertGreater(result["listen_count"], 10)

        ports = {(item["protocol"], item["port"]) for item in result["listeners"]}
        self.assertIn(("tcp", 22), ports)
        self.assertIn(("tcp", 8080), ports)
        self.assertIn(("tcp6", 8080), ports)
        # 端口 0 与坏行都不该出现
        self.assertNotIn(("tcp", 0), ports)

    def test_socket_count_includes_non_listening(self):
        proc_fixture.default_proc(self.tmp)
        result = procnet.read_proc_ports(self.tmp)
        self.assertGreater(result["socket_count"], result["listen_count"])

    def test_partial_when_only_one_table_exists(self):
        proc_fixture.write_proc(self.tmp, tcp=proc_fixture.DEFAULT_TCP, tcp6=None)
        result = procnet.read_proc_ports(self.tmp)
        self.assertEqual(result["source"], "partial")
        self.assertEqual(len(result["files"]), 1)
        self.assertIn("tcp6", result["detail"] + " ".join(result["missing"]))
        self.assertTrue(result["listeners"])

    def test_empty_table_is_not_an_error(self):
        proc_fixture.write_proc(self.tmp, tcp=proc_fixture.TCP_HEADER + "\n", tcp6="")
        result = procnet.read_proc_ports(self.tmp)
        self.assertEqual(result["source"], "proc")
        self.assertEqual(result["listeners"], [])

    def test_result_is_sorted_by_port(self):
        proc_fixture.default_proc(self.tmp)
        ports = [item["port"] for item in procnet.read_proc_ports(self.tmp)["listeners"]]
        self.assertEqual(ports, sorted(ports))


if __name__ == "__main__":
    unittest.main()
