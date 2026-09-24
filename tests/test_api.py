"""端到端功能测试：把应用真的跑起来，逐个打接口。

用的是**与 deb 包内同一份**代码，只是把 Unix socket 换成 TCP（Windows 上没有
Unix socket）。测试注入了一个假的 ``/proc`` 与假的 ``/etc/services``，
因此「内核表解析 → 服务名 → 指纹 → 打开地址 → 快照 → 差异」这一整条链路
在本机就能被真实地走一遍，而不需要一台 Linux 设备。
"""

import ast
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from tnasapp.paths import AppPaths  # noqa: E402

from app import docker_engine, main as app_main  # noqa: E402
from tests import proc_fixture  # noqa: E402

APP_ID = app_main.APP_ID

#: 差异测试专用：一个不在指纹表里的端口（9001 = 0x2329），
#: 这样服务名只能来自 /etc/services，才能测出「服务名变了」
DIFF_TCP = "\n".join([
    proc_fixture.TCP_HEADER,
    "   0: 00000000:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0"
    "        0 30001 1 0000000000000000 100 0 0 10 0",
])

#: 追加一个端口 9999（0x270F）
DIFF_TCP_EXTRA = DIFF_TCP + "\n" + (
    "   1: 00000000:270F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0"
    "        0 30002 1 0000000000000000 100 0 0 10 0")

#: 只含 8080 端口的假 /proc —— 用于「TOS 自身端口提醒」这类定点断言
DOCKER_API_TCP = "\n".join([
    proc_fixture.TCP_HEADER,
    "   0: 00000000:0947 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0"
    "        0 40001 1 0000000000000000 100 0 0 10 0",
])


def q(path):
    return urllib.parse.quote(str(path), safe="")


class ApiClient:
    def __init__(self, base):
        self.base = base

    def raw(self, method, path, payload=None, headers=None):
        """返回 ``(status, bytes, headers)``。"""
        data = None
        outgoing = {"Content-Type": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        if headers:
            outgoing.update(headers)
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=outgoing, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers or {})

    def request(self, method, path, payload=None, headers=None):
        status, body, _headers = self.raw(method, path, payload, headers)
        try:
            return status, json.loads(body.decode("utf-8"))
        except ValueError:
            return status, {"raw": body.decode("utf-8", "replace")}

    def get(self, path, headers=None):
        return self.request("GET", path, None, headers)

    def post(self, path, payload=None):
        return self.request("POST", path, payload)


def find_entry(entries, port, protocol="tcp", address=None):
    for entry in entries:
        if entry["port"] != port or entry["protocol"] != protocol:
            continue
        if address is not None and entry["address"] != address:
            continue
        return entry
    return None


class ServiceCenterApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="shh17-api-")
        cls.proc_root = os.path.join(cls.tmp, "proc")
        proc_fixture.default_proc(cls.proc_root)
        cls.services_path = proc_fixture.write_services(
            os.path.join(cls.tmp, "etc", "services"))
        cls.export_dir = os.path.join(cls.tmp, "export")
        cls.outside_dir = os.path.join(cls.tmp, "outside")
        os.makedirs(cls.export_dir)
        os.makedirs(cls.outside_dir)

        # install_dir 指向仓库根：webui_dir 由它推导，测试要能取到真的前端文件
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        paths = AppPaths(APP_ID, install_dir=repo, data_dir=os.path.join(cls.tmp, "data"))
        cls.app = app_main.create_app(paths=paths, log_level="ERROR")

        # 注入假的 /proc 与 /etc/services —— 本机不是 Linux，这是唯一的办法
        cls.app.settings.update({
            "proc_root": cls.proc_root,
            "services_path": cls.services_path,
            "snapshot_keep": 50,
        })
        # 白名单在启动前设好，用例之间不依赖执行顺序
        cls.app.set_allowed_roots([cls.export_dir])

        # ---- 测试专用任务类型 ----
        # 快照任务本身太快（读两个文件 + 写一行），用它测不出「取消生效」与
        # 「失败原因可读」。这里注册两个只在测试里存在的类型，专门覆盖队列的
        # 两个分支；生产代码里的任务类型仍然只有 snapshot 一个。
        @cls.app.jobs.register("test-slow")
        def _slow(ctx):
            for _ in range(400):
                ctx.checkpoint()
                time.sleep(0.02)

        @cls.app.jobs.register("test-boom")
        def _boom(ctx):
            raise ValueError("故意失败：用于验证失败原因可读")

        cls.server = cls.app.run(host="127.0.0.1", port=0, background=True)
        cls.client = ApiClient("http://127.0.0.1:%d" % cls.server.server_address[1])
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.app.shutdown()
        except Exception:
            pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---------------------------------------------------------- 辅助

    def wait_job(self, job_id, timeout=90):
        deadline = time.time() + timeout
        job = None
        while time.time() < deadline:
            _status, body = self.client.get("/api/jobs/%d" % job_id)
            job = body["job"]
            if job["state"] in ("completed", "failed", "canceled"):
                return job
            time.sleep(0.05)
        return job

    def submit(self, job_type, params=None):
        status, body = self.client.post("/api/jobs", {"type": job_type, "params": params or {}})
        self.assertEqual(status, 201, body)
        return body["job"]

    def use_sources(self, proc_root, services_path):
        """临时换一整套采集来源，返回原来的值供恢复。"""
        saved = {
            "proc_root": self.app.settings.get("proc_root"),
            "services_path": self.app.settings.get("services_path"),
        }
        self.app.settings.update({"proc_root": proc_root, "services_path": services_path})
        return saved

    def restore_sources(self, saved):
        self.app.settings.update(saved)

    def entries(self, record=False, headers=None):
        status, body = self.client.get(
            "/api/services/ports?record=%d" % (1 if record else 0), headers=headers)
        self.assertEqual(status, 200, body)
        return body

    # ---------------------------------------------------------- 基础

    def test_health(self):
        status, body = self.client.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["app"], APP_ID)

    def test_app_info(self):
        status, body = self.client.get("/api/app")
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], app_main.APP_VERSION)
        self.assertIn("snapshot", body["job_types"])
        self.assertIn("docker", body["engines"])

    def test_index_html_served_with_relative_paths(self):
        status, body, _headers = self.client.raw("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"service.js", body)
        self.assertIn(b'data-app-id="%s"' % APP_ID.encode(), body)
        # F7 白屏守卫：绝对路径在 /<appid>/ 前缀下必然 404
        self.assertNotIn(b'src="/', body)
        self.assertNotIn(b'href="/', body)

    def test_prefix_compatibility(self):
        for prefix in ("", "/" + APP_ID, "/v2/proxy/" + APP_ID):
            status, body = self.client.get(prefix + "/api/app")
            self.assertEqual(status, 200, prefix)
            self.assertEqual(body["app"], APP_ID)

    def test_static_assets_exist(self):
        for name in ("service.js", "app.js", "app.css", "icons.js"):
            status, body, _headers = self.client.raw("GET", "/" + name)
            self.assertEqual(status, 200, name)
            self.assertTrue(body, name)

    def test_unknown_api_route_is_404(self):
        status, body = self.client.get("/api/services/does-not-exist")
        self.assertEqual(status, 404)
        self.assertFalse(body["ok"])

    def test_unsupported_method_is_405(self):
        status, body = self.client.request("DELETE", "/api/services/ports")
        self.assertEqual(status, 405)
        self.assertFalse(body["ok"])

    # ---------------------------------------------------------- 端口地图

    def test_port_map_parses_little_endian_hex_end_to_end(self):
        """``0100007F:1F90`` 一路走到接口，必须是 ``127.0.0.1:8080``。"""
        body = self.entries()
        entry = find_entry(body["entries"], 8080, "tcp", "127.0.0.1")
        self.assertIsNotNone(entry, "假 /proc 里的 0100007F:1F90 没有被解出来")
        self.assertEqual(entry["family"], "ipv4")
        self.assertEqual(entry["scope"], "localhost")
        self.assertEqual(entry["state"], "LISTEN")
        self.assertTrue(entry["listening"])
        self.assertEqual(entry["service_name"], "qBittorrent")

    def test_port_map_covers_required_services(self):
        body = self.entries()
        expected = {
            (22, "0.0.0.0"): "SSH",
            (80, "0.0.0.0"): "HTTP",
            (443, "0.0.0.0"): "HTTPS",
            (445, "0.0.0.0"): "SMB",
            (2049, "0.0.0.0"): "NFS",
            (8181, "0.0.0.0"): "TOS 网页管理（HTTP）",
            (3306, "0.0.0.0"): "MySQL / MariaDB",
            (5005, "0.0.0.0"): "WebDAV",
            (32400, "0.0.0.0"): "Plex",
        }
        for (port, address), name in expected.items():
            entry = find_entry(body["entries"], port, "tcp", address)
            self.assertIsNotNone(entry, "缺少端口 %d" % port)
            self.assertEqual(entry["service_name"], name, port)

    def test_port_map_fingerprint_carries_confidence_note(self):
        body = self.entries()
        entry = find_entry(body["entries"], 8181)
        mark = entry["fingerprint"]
        self.assertEqual(mark["confidence"], "suggestion")
        self.assertIn("仅供参考", mark["confidence_note"])
        self.assertIn("仅供参考", body["fingerprint_note"])

    def test_port_map_uses_etc_services_as_fallback_name(self):
        """指纹表没有的端口，服务名应当来自 /etc/services。"""
        saved = self.use_sources(self.proc_root, self.services_path)
        try:
            custom = os.path.join(self.tmp, "proc-etcname")
            services = proc_fixture.write_services(
                os.path.join(self.tmp, "etc", "services-etcname"),
                "# 9001 不在指纹表里\nsvc-elsewhere\t9001/tcp\nftp\t21/tcp\n")
            proc_fixture.write_proc(custom, tcp=DIFF_TCP, tcp6=None)
            self.app.settings.update({"proc_root": custom, "services_path": services})

            body = self.entries()
            entry = find_entry(body["entries"], 9001)
            self.assertIsNotNone(entry)
            self.assertEqual(entry["service"], "svc-elsewhere")
            self.assertEqual(entry["service_name"], "svc-elsewhere")
            self.assertEqual(entry["service_source"], "etc-services")
            self.assertIsNone(entry["fingerprint"])
        finally:
            self.restore_sources(saved)

    def test_fingerprint_wins_over_etc_services(self):
        body = self.entries()
        entry = find_entry(body["entries"], 5005)
        self.assertEqual(entry["service"], "webdav")
        self.assertEqual(entry["service_source"], "fingerprint",
                         "指纹比 /etc/services 更贴近「这是什么服务」")
        self.assertEqual(entry["service_name"], "WebDAV")

    def test_port_map_marks_tcp6_listeners(self):
        body = self.entries()
        entry = find_entry(body["entries"], 8080, "tcp6", "::1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["family"], "ipv6")
        self.assertEqual(entry["scope"], "localhost")

    def test_open_url_derived_from_host_header(self):
        body = self.entries()
        entry = find_entry(body["entries"], 8181)
        self.assertTrue(entry["open_reachable"])
        self.assertTrue(entry["open_url"].startswith("http://127.0.0.1:"),
                        entry["open_url"])

    def test_open_url_prefers_x_forwarded_host(self):
        body = self.entries(headers={"X-Forwarded-Host": "tnas.example.com"})
        entry = find_entry(body["entries"], 8181)
        self.assertEqual(entry["open_url"], "http://tnas.example.com:8181")

    def test_open_url_takes_first_forwarded_host(self):
        body = self.entries(headers={"X-Forwarded-Host": "first.example, second.example"})
        entry = find_entry(body["entries"], 8181)
        self.assertEqual(entry["open_url"], "http://first.example:8181")

    def test_open_url_uses_https_for_https_ports(self):
        body = self.entries(headers={"X-Forwarded-Host": "nas.local"})
        entry = find_entry(body["entries"], 443)
        self.assertEqual(entry["open_url"], "https://nas.local:443")

    def test_open_url_rejected_for_bogus_host(self):
        """Host 是客户端可控的 —— 不合法时宁可不给按钮。"""
        body = self.entries(headers={"Host": "bad host/../evil"})
        entry = find_entry(body["entries"], 8181)
        self.assertIsNone(entry["open_url"])
        self.assertFalse(entry["open_reachable"])

    def test_open_url_falls_back_when_forwarded_host_is_bogus(self):
        """X-Forwarded-Host 不合法时退回 Host（尽力而为），而不是整个不给地址。"""
        body = self.entries(headers={"X-Forwarded-Host": "bad host", "Host": "nas.local"})
        entry = find_entry(body["entries"], 8181)
        self.assertEqual(entry["open_url"], "http://nas.local:8181")

    def test_localhost_only_services_are_not_reachable(self):
        body = self.entries(headers={"X-Forwarded-Host": "nas.local"})
        entry = find_entry(body["entries"], 8080, "tcp", "127.0.0.1")
        self.assertEqual(entry["open_url"], "http://nas.local:8080")
        self.assertFalse(entry["open_reachable"],
                         "只绑回环地址的服务从浏览器打不开，按钮必须置灰")
        self.assertIn("回环", entry["open_note"])

    def test_non_web_services_get_no_open_button(self):
        body = self.entries()
        entry = find_entry(body["entries"], 22)
        self.assertIsNone(entry["open_url"])
        entry = find_entry(body["entries"], 3306)
        self.assertIsNone(entry["open_url"])

    def test_smb_and_nfs_are_listed_as_file_services(self):
        body = self.entries()
        kinds = {row["kind"] for row in body["categories"]}
        self.assertIn("file", kinds)
        smb = find_entry(body["entries"], 445)
        self.assertEqual(smb["fingerprint"]["kind"], "file")

    # ---------------------------------------------------------- 快照记录

    def test_ports_endpoint_records_snapshot_by_default(self):
        _status, before = self.client.get("/api/services/snapshots?limit=1")
        body = self.entries(record=True)
        self.assertTrue(body["recorded"])
        self.assertIsNotNone(body["snapshot"])
        self.assertEqual(body["snapshot"]["listening"], body["counts"]["listening"])

        _status, after = self.client.get("/api/services/snapshots?limit=1")
        self.assertEqual(after["count"], before["count"] + 1)

    def test_snapshot_does_not_store_open_url(self):
        """open_url 取决于「你从哪访问」，进历史会造出一堆假变化。"""
        self.entries(record=True)
        status, body = self.client.get("/api/services/snapshot/latest")
        self.assertEqual(status, 200)
        self.assertIsNotNone(body["snapshot"])
        for entry in body["snapshot"]["ports"]:
            self.assertNotIn("open_url", entry)
            self.assertNotIn("open_reachable", entry)

    def test_ports_endpoint_can_skip_recording(self):
        _status, before = self.client.get("/api/services/snapshots?limit=1")
        self.entries(record=False)
        _status, after = self.client.get("/api/services/snapshots?limit=1")
        self.assertEqual(after["count"], before["count"])

    def test_snapshot_history_is_bounded(self):
        """快照不能无界增长：保留条数由 snapshot_keep 决定。"""
        saved = self.app.settings.get("snapshot_keep")
        try:
            self.app.settings.update({"snapshot_keep": 3})
            for _ in range(5):
                self.entries(record=True)
            _status, body = self.client.get("/api/services/snapshots?limit=50")
            self.assertLessEqual(body["count"], 3)
        finally:
            self.app.settings.update({"snapshot_keep": saved})

    # ---------------------------------------------------------- 概览

    def test_summary_reports_counts_and_categories(self):
        status, body = self.client.get("/api/services/summary")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["counts"]["listening"], 15)
        self.assertGreaterEqual(body["counts"]["mapped"], body["counts"]["listening"])
        self.assertGreater(body["counts"]["web"], 0)
        self.assertTrue(body["categories"])
        self.assertTrue(body["read_only"])

    def test_summary_reports_both_sources(self):
        status, body = self.client.get("/api/services/summary")
        self.assertEqual(body["sources"]["proc"]["source"], "proc")
        self.assertEqual(body["sources"]["services"]["source"], "file")
        self.assertIn("proc_root", body["sources"]["proc"])

    def test_summary_does_not_record_a_snapshot(self):
        _status, before = self.client.get("/api/services/snapshots?limit=1")
        self.client.get("/api/services/summary")
        self.client.get("/api/services/summary")
        _status, after = self.client.get("/api/services/snapshots?limit=1")
        self.assertEqual(after["count"], before["count"],
                         "概览是纯读接口，不该被反复刷新灌满历史")

    def test_summary_reports_snapshot_state(self):
        self.entries(record=True)
        status, body = self.client.get("/api/services/summary")
        self.assertGreaterEqual(body["snapshots"]["count"], 1)
        self.assertTrue(body["snapshots"]["latest"])
        self.assertIn("has_previous", body["changes"])

    def test_summary_warns_about_plaintext_docker_api(self):
        saved = self.use_sources(self.proc_root, self.services_path)
        try:
            custom = os.path.join(self.tmp, "proc-docker-api")
            proc_fixture.write_proc(custom, tcp=DOCKER_API_TCP, tcp6=None)
            self.app.settings.update({"proc_root": custom})
            _status, body = self.client.get("/api/services/summary")
            titles = [item["title"] for item in body["findings"]]
            self.assertTrue(any("Docker" in title for title in titles), titles)
        finally:
            self.restore_sources(saved)

    # ---------------------------------------------------------- 容器

    def test_containers_endpoint_degrades_gracefully(self):
        """本机没有 docker 时必须 200 + available=false + 可读原因，而不是 500。"""
        status, body = self.client.get("/api/services/containers")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIn("available", body)
        self.assertIn("detail", body)
        self.assertIsInstance(body["containers"], list)
        self.assertTrue(body["read_only"])
        if not docker_engine.detect()["available"]:
            self.assertFalse(body["available"])
            self.assertEqual(body["containers"], [])
            self.assertTrue(body["detail"])
            self.assertFalse(body["engine"]["available"])

    def test_containers_endpoint_reports_unavailable_when_disabled(self):
        saved = self.app.settings.get("docker_enabled")
        try:
            self.app.settings.update({"docker_enabled": False})
            status, body = self.client.get("/api/services/containers")
            self.assertEqual(status, 200)
            self.assertFalse(body["available"])
            self.assertEqual(body["containers"], [])
            self.assertIn("关闭", body["detail"])

            ports = self.entries()
            self.assertFalse(ports["sources"]["docker"]["available"])
            self.assertIn("未启用", ports["sources"]["docker"]["detail"])
        finally:
            self.app.settings.update({"docker_enabled": saved})

    # ---------------------------------------------------------- 变化历史

    def test_changes_before_any_snapshot_is_not_an_error(self):
        """没有快照时接口给出说明而不是 500。"""
        fresh = self._fresh_app()
        try:
            client = fresh["client"]
            status, body = client.get("/api/services/changes")
            self.assertEqual(status, 200)
            self.assertFalse(body["has_snapshot"])
            self.assertEqual(body["added"], [])
            self.assertIn("还没有", body["detail"])
        finally:
            self._close_fresh(fresh)

    def test_changes_reports_added_port(self):
        saved = self.use_sources(self.proc_root, self.services_path)
        try:
            custom = os.path.join(self.tmp, "proc-diff-add")
            services = proc_fixture.write_services(
                os.path.join(self.tmp, "etc", "services-diff"), "svc-old\t9001/tcp\n")
            proc_fixture.write_proc(custom, tcp=DIFF_TCP, tcp6=None)
            self.app.settings.update({"proc_root": custom, "services_path": services})

            self.entries(record=True)
            proc_fixture.write_proc(custom, tcp=DIFF_TCP_EXTRA, tcp6=None)
            self.entries(record=True)

            status, body = self.client.get("/api/services/changes")
            self.assertEqual(status, 200)
            self.assertTrue(body["has_snapshot"])
            self.assertTrue(body["has_previous"])
            added = {item["port"] for item in body["added"]}
            self.assertEqual(added, {9999})
            self.assertEqual(body["removed"], [])
        finally:
            self.restore_sources(saved)

    def test_changes_reports_removed_port(self):
        saved = self.use_sources(self.proc_root, self.services_path)
        try:
            custom = os.path.join(self.tmp, "proc-diff-del")
            services = proc_fixture.write_services(
                os.path.join(self.tmp, "etc", "services-diff"), "svc-old\t9001/tcp\n")
            proc_fixture.write_proc(custom, tcp=DIFF_TCP_EXTRA, tcp6=None)
            self.app.settings.update({"proc_root": custom, "services_path": services})

            self.entries(record=True)
            proc_fixture.write_proc(custom, tcp=DIFF_TCP, tcp6=None)
            self.entries(record=True)

            _status, body = self.client.get("/api/services/changes")
            removed = {item["port"] for item in body["removed"]}
            self.assertEqual(removed, {9999})
            self.assertEqual(body["added"], [])
        finally:
            self.restore_sources(saved)

    def test_changes_reports_service_renamed_on_same_port(self):
        saved = self.use_sources(self.proc_root, self.services_path)
        try:
            custom = os.path.join(self.tmp, "proc-diff-rename")
            proc_fixture.write_proc(custom, tcp=DIFF_TCP, tcp6=None)
            name_a = proc_fixture.write_services(
                os.path.join(self.tmp, "etc", "services-a"), "svc-old\t9001/tcp\n")
            name_b = proc_fixture.write_services(
                os.path.join(self.tmp, "etc", "services-b"), "svc-new\t9001/tcp\n")

            self.app.settings.update({"proc_root": custom, "services_path": name_a})
            self.entries(record=True)
            self.app.settings.update({"services_path": name_b})
            self.entries(record=True)

            _status, body = self.client.get("/api/services/changes")
            self.assertEqual(len(body["changed"]), 1)
            change = body["changed"][0]
            self.assertEqual(change["before"], "svc-old")
            self.assertEqual(change["after"], "svc-new")
            self.assertEqual(change["port"], 9001)
        finally:
            self.restore_sources(saved)

    def test_changes_without_previous_explains_itself(self):
        fresh = self._fresh_app()
        try:
            client = fresh["client"]
            client.get("/api/services/ports?record=1")
            status, body = client.get("/api/services/changes")
            self.assertEqual(status, 200)
            self.assertTrue(body["has_snapshot"])
            self.assertFalse(body["has_previous"])
            self.assertIn("第一次", body["detail"])
        finally:
            self._close_fresh(fresh)

    def test_snapshot_listing_and_lookup(self):
        self.entries(record=True)
        status, body = self.client.get("/api/services/snapshots?limit=5")
        self.assertEqual(status, 200)
        self.assertTrue(body["snapshots"])
        self.assertEqual(body["limit"], 5)

        snapshot_id = body["snapshots"][0]["id"]
        status, body = self.client.get("/api/services/snapshots?id=%d" % snapshot_id)
        self.assertEqual(status, 200)
        self.assertEqual(body["snapshot"]["id"], snapshot_id)
        self.assertTrue(body["snapshot"]["ports"])

    def test_snapshot_lookup_rejects_bad_id(self):
        status, body = self.client.get("/api/services/snapshots?id=not-a-number")
        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])
        self.assertTrue(body["hint"])

    def test_snapshot_lookup_missing_id_is_404(self):
        status, body = self.client.get("/api/services/snapshots?id=999999")
        self.assertEqual(status, 404)

    def test_snapshot_latest_endpoint_has_no_snapshot_yet(self):
        fresh = self._fresh_app()
        try:
            status, body = fresh["client"].get("/api/services/snapshot/latest")
            self.assertEqual(status, 200)
            self.assertIsNone(body["snapshot"])
            self.assertEqual(body["count"], 0)
            self.assertIn("还没有", body["detail"])
        finally:
            self._close_fresh(fresh)

    # ---------------------------------------------------------- 导出

    def test_fingerprint_table_endpoint(self):
        status, body = self.client.get("/api/services/fingerprints")
        self.assertEqual(status, 200)
        self.assertEqual(body["confidence"], "suggestion")
        ports = {row["port"] for row in body["fingerprints"]}
        for port in (22, 80, 443, 445, 2049, 8181, 3306, 5432, 6379, 8096, 32400, 8080):
            self.assertIn(port, ports)

    def test_export_json_inline(self):
        status, body, headers = self.client.raw("GET", "/api/services/export?format=json")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        payload = json.loads(body.decode("utf-8"))
        self.assertTrue(payload["entries"])
        self.assertTrue(payload["extra"]["read_only"])
        self.assertEqual(payload["counts"]["listening"], len(
            [item for item in payload["entries"] if item["listening"]]))

    def test_export_csv_inline(self):
        status, body, headers = self.client.raw("GET", "/api/services/export?format=csv")
        self.assertEqual(status, 200)
        self.assertIn("csv", headers.get("Content-Type", ""))
        # 带 BOM，Excel 直接双击打开中文表头不乱码
        self.assertTrue(body.startswith(b"\xef\xbb\xbf"))
        text = body.decode("utf-8-sig")
        self.assertIn("端口", text.splitlines()[0])
        self.assertIn("8181", text)

    def test_export_rejects_unknown_format(self):
        status, body = self.client.get("/api/services/export?format=xlsx")
        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])
        self.assertIn("csv", body["hint"])

    def test_export_writes_into_allowed_directory(self):
        status, body = self.client.get(
            "/api/services/export?format=json&dir=" + q(self.export_dir))
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        path = body["path"]
        self.assertTrue(path.startswith(os.path.realpath(self.export_dir)))
        self.assertTrue(os.path.isfile(path))
        with open(path, "r", encoding="utf-8") as handle:
            written = json.load(handle)
        self.assertTrue(written["entries"])

    def test_export_refuses_directory_outside_whitelist(self):
        status, body = self.client.get(
            "/api/services/export?format=json&dir=" + q(self.outside_dir))
        self.assertEqual(status, 403)
        self.assertFalse(body["ok"])
        self.assertIn("白名单", body["hint"])
        self.assertEqual(os.listdir(self.outside_dir), [], "越界目录里不该出现任何文件")

    def test_export_refuses_traversal_outside_whitelist(self):
        sneaky = os.path.join(self.export_dir, "..", "outside")
        status, body = self.client.get(
            "/api/services/export?format=csv&dir=" + q(sneaky))
        self.assertEqual(status, 403)
        self.assertEqual(os.listdir(self.outside_dir), [])

    def test_export_refuses_when_whitelist_is_empty(self):
        saved = list(self.app.allowed.roots())
        try:
            self.app.set_allowed_roots([])
            status, body = self.client.get(
                "/api/services/export?format=json&dir=" + q(self.export_dir))
            self.assertEqual(status, 403)
            self.assertFalse(body["ok"])
        finally:
            self.app.set_allowed_roots(saved)

    def test_fs_listing_is_whitelisted_too(self):
        status, body = self.client.get("/api/fs/list?path=" + q(self.export_dir))
        self.assertEqual(status, 200)
        status, body = self.client.get("/api/fs/list?path=" + q(self.outside_dir))
        self.assertFalse(body.get("ok", False))

    # ---------------------------------------------------------- 任务

    def test_snapshot_job_completes_and_records(self):
        job = self.submit("snapshot")
        job = self.wait_job(job["id"])
        self.assertEqual(job["state"], "completed", json.dumps(job, ensure_ascii=False))
        self.assertGreater(job["result"]["listening"], 10)
        self.assertEqual(job["result"]["proc_source"], "proc")
        self.assertIsNotNone(job["result"]["snapshot_id"])
        self.assertEqual(job["progress"], 100)

    def test_snapshot_job_logs_are_readable(self):
        job = self.submit("snapshot")
        job = self.wait_job(job["id"])
        status, body = self.client.get("/api/jobs/%d/logs" % job["id"])
        self.assertEqual(status, 200)
        self.assertTrue(body["logs"])
        messages = " ".join(entry["message"] for entry in body["logs"])
        self.assertIn("只读", messages)
        self.assertIn("内核表来源", messages)

    def test_snapshot_job_via_services_endpoint(self):
        status, body = self.client.post("/api/services/snapshot", {"all": False})
        self.assertEqual(status, 201)
        job = self.wait_job(body["job"]["id"])
        self.assertEqual(job["state"], "completed")

        status, body = self.client.post("/api/services/snapshot", "not-an-object")
        self.assertEqual(status, 400)

    def test_job_failure_reports_readable_reason(self):
        job = self.submit("test-boom")
        job = self.wait_job(job["id"])
        self.assertEqual(job["state"], "failed")
        self.assertIn("故意失败", job["error"])
        status, body = self.client.get("/api/jobs/%d/logs" % job["id"])
        levels = {entry["level"] for entry in body["logs"]}
        self.assertIn("ERROR", levels)

    def test_job_cancel_takes_effect(self):
        job = self.submit("test-slow")
        time.sleep(0.3)
        status, body = self.client.post("/api/jobs/%d/cancel" % job["id"])
        self.assertEqual(status, 200, body)
        job = self.wait_job(job["id"], timeout=30)
        self.assertEqual(job["state"], "canceled")
        self.assertIn("取消", job["message"])

    def test_unknown_job_type_is_rejected(self):
        status, body = self.client.post("/api/jobs", {"type": "no-such-job"})
        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])

    def test_job_list_and_counts(self):
        job = self.submit("snapshot")
        self.wait_job(job["id"])
        status, body = self.client.get("/api/jobs?limit=50")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["counts"]["total"], 1)
        self.assertIn("completed", body["counts"])

    # ---------------------------------------------------------- 只读铁律

    def test_sources_never_start_stop_or_exec(self):
        """只读铁律的机器化守卫：源码里不许出现任何「会改变系统」的调用。

        这道检查刻意走语法树而不是全文 grep —— 文档字符串里正是要**写明**
        「本应用不做 docker exec、不调 systemctl」，全文 grep 会把说明文字
        当成违规（这个门禁自己的第一版就误报了 4 处）。所以这里只收集
        「真的会被执行的东西」：函数调用、以及非 docstring 的字符串常量。
        """
        src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "src", "app")
        forbidden_calls = {"system", "popen", "call", "check_call", "check_output",
                           "Popen", "eval", "exec", "spawnv", "spawnl"}
        forbidden_strings = ["docker exec", "docker start", "docker stop", "docker restart",
                             "docker rm", "docker kill", "docker-compose", "systemctl",
                             "/bin/sh", "sh -c", "cmd.exe"]
        found = []

        for name in sorted(os.listdir(src)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(src, name), "r", encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=name)

            docstrings = set()
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if not isinstance(body, list) or not body:
                    continue
                first = body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                        and isinstance(first.value.value, str):
                    docstrings.add(id(first.value))

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    callee = func.attr if isinstance(func, ast.Attribute) else getattr(
                        func, "id", "")
                    if callee in forbidden_calls:
                        found.append("%s 中调用了 %s(...)" % (name, callee))
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and not (
                                isinstance(keyword.value, ast.Constant)
                                and keyword.value.value is False):
                            found.append("%s 中使用了 shell= 参数" % name)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                        and id(node) not in docstrings:
                    lowered = node.value.lower()
                    for needle in forbidden_strings:
                        if needle in lowered:
                            found.append("%s 的字符串里出现 %r" % (name, needle))

        self.assertEqual(sorted(set(found)), [], "本应用必须严格只读：%s" % sorted(set(found)))

    def test_job_types_are_only_the_documented_ones(self):
        """生产代码里只能注册 .lang 承诺过的那一个任务类型。"""
        status, body = self.client.get("/api/app")
        self.assertEqual(status, 200)
        production = [name for name in body["job_types"] if not name.startswith("test-")]
        self.assertEqual(production, ["snapshot"])

    # ---------------------------------------------------------- 内部助手

    def _fresh_app(self):
        """另起一个数据目录全新的实例 —— 用来测「还没有快照」这类初始状态。"""
        root = tempfile.mkdtemp(prefix="shh17-fresh-")
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        paths = AppPaths(APP_ID, install_dir=repo, data_dir=root)
        app = app_main.create_app(paths=paths, log_level="ERROR")
        app.settings.update({"proc_root": self.proc_root,
                             "services_path": self.services_path})
        server = app.run(host="127.0.0.1", port=0, background=True)
        time.sleep(0.1)
        return {"app": app, "server": server, "root": root,
                "client": ApiClient("http://127.0.0.1:%d" % server.server_address[1])}

    def _close_fresh(self, fresh):
        try:
            fresh["app"].shutdown()
        except Exception:
            pass
        shutil.rmtree(fresh["root"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
