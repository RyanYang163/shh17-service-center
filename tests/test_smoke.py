"""冒烟测试：不依赖任何外部数据，验证「装得上、起得来」。

包的形态、前端资源、以及一个全新数据目录下能不能冷启动 —— 这三件事任何一项坏掉，
用户在 TOS 上看到的就是「装了但打不开」。三条都只在几秒内跑完，所以单独放一处。
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

import tnasapp  # noqa: E402

from app import main as app_main  # noqa: E402


class SmokeTest(unittest.TestCase):
    def test_framework_importable(self):
        self.assertTrue(hasattr(tnasapp, "server"))

    def test_webui_assets_present_and_relative(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        webui = os.path.join(repo, "webui")
        for name in ("index.html", "service.js", "app.js", "app.css", "icons.js"):
            self.assertTrue(os.path.isfile(os.path.join(webui, name)), name)
        with open(os.path.join(webui, "index.html"), "r", encoding="utf-8") as handle:
            html = handle.read()
        self.assertIn("service.js", html)
        self.assertNotIn('src="/', html)
        self.assertNotIn('href="/', html)

    def test_cold_start_with_a_fresh_data_directory(self):
        """全新数据目录（模拟刚装好的设备）：能建库、能起服务、首页可访问。"""
        tmp = tempfile.mkdtemp(prefix="shh17-smoke-")
        try:
            from tnasapp.paths import AppPaths
            import urllib.request

            repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            paths = AppPaths(app_main.APP_ID, install_dir=repo,
                             data_dir=os.path.join(tmp, "data"))
            app = app_main.create_app(paths=paths, log_level="ERROR")
            server = app.run(host="127.0.0.1", port=0, background=True)
            try:
                base = "http://127.0.0.1:%d" % server.server_address[1]
                with urllib.request.urlopen(base + "/health", timeout=10) as response:
                    self.assertEqual(response.status, 200)
                with urllib.request.urlopen(base + "/", timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"service-center", response.read()[:4096]
                                  .replace(b"shh17-service-center", b"service-center"))
                self.assertTrue(os.path.isfile(paths.db_path))
            finally:
                app.shutdown()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
