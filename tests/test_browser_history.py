import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from warp_scanner import downloads_browser as browser
from warp_scanner.report import build, envelope


class ExportHistoryTests(unittest.TestCase):
    def setUp(self):
        storage = TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        self.root = Path(storage.name)
        (self.root / "Download").mkdir()
        self.export = self.root / "Download" / "History.json"
        self.ctx = SimpleNamespace(storage=self.root, consent={"browser_history": True},
                                   args=SimpleNamespace(history_export=self.export.name))

    def history(self):
        return browser.browser_history(self.ctx, 1000, 2000)

    def write(self, records):
        self.export.write_text(json.dumps({"Browser History": records}), encoding="utf-8")

    def test_counts_only_visits_in_window_at_matching_hosts(self):
        urls = ["https://www.pastebin.com/private", "https://sub.pastebin.com./?token=SECRET",
                "https://www.mediafire.com/file/id", "https://pastebin.com.evil.test/",
                "https://mediafire.com@other.test", "https://elsewhere.test/mediafire.com"]
        self.write([{"url": url, "time_usec": "1500000", "title": "PRIVATE"} for url in urls] +
                   [{"url": urls[0], "time_usec": n} for n in [999999, 2001000]])
        check, counts = self.history()
        self.assertEqual(check["status"], "OK")
        self.assertEqual(counts, {"Pastebin": 2, "MediaFire": 1})
        for secret in ("private", "SECRET", "elsewhere.test", "PRIVATE", "History.json"):
            self.assertNotIn(secret, json.dumps([check, counts]))

    def test_missing_or_bad_timestamp_never_produces_clean_result(self):
        self.write([{"url": "https://pastebin.com", "time_usec": None}, {"url": "https://mediafire.com", "time_usec": 1500000}])
        check, counts = self.history()
        self.assertEqual(check["status"], "PARCIAL")
        self.assertEqual(counts["MediaFire"], 1)

    def test_declined_or_no_file_performs_no_open(self):
        with patch.object(browser, "read_bounded_file", side_effect=AssertionError("unexpected read")):
            self.ctx.consent["browser_history"] = False
            self.assertEqual(self.history()[0]["status"], "NÃO VERIFICADO")
            self.ctx.consent["browser_history"] = True
            self.ctx.args.history_export = None
            self.assertEqual(self.history()[0]["status"], "NÃO VERIFICADO")

    def test_invalid_paths_or_format_or_size_are_unavailable(self):
        self.write([])
        for invalid in [self.root / "private.json", "../private.json", "History.zip", "absent.json"]:
            with self.subTest(path=invalid):
                self.ctx.args.history_export = invalid
                self.assertEqual(self.history()[1], {})
        self.ctx.args.history_export = self.export
        with patch.object(browser, "HISTORY_LIMIT", 3):
            self.assertEqual(self.history()[0]["status"], "NÃO VERIFICADO")
        self.export.write_text('{"bookmarks":[]}', encoding="utf-8")
        self.assertEqual(self.history()[0]["status"], "NÃO VERIFICADO")
        self.write([])
        self.assertEqual(self.history()[0]["status"], "OK")

    def test_selected_and_known_exports_are_reserved_for_history_reader(self):
        self.assertTrue(browser.is_history_export(self.export, self.root))
        selected = "Takeout/Chrome/personal.json"
        renamed = self.root / "Download" / selected
        self.assertTrue(browser.is_history_export(renamed, self.root, selected))
        self.assertFalse(browser.is_history_export(self.root / "sample.json", self.root, selected))

    def test_report_counts_visits_without_scoring_a_host_or_sending_its_url(self):
        stamp = time.time_ns() // 1000 - 1000000
        self.write([{"url": "https://pastebin.com/PRIVATE_PATH", "time_usec": stamp}])
        self.ctx.args.window_days = 14
        self.ctx.args.session_code = "WARP-TESTE"
        self.ctx.signatures = {"entries": []}
        self.ctx.privilege = {"root": False, "adb": False}
        self.ctx.settings = {"thresholds": {"high_risk": 60, "suspect": 20}}
        m5 = browser.collect(self.ctx)
        self.assertEqual(m5["status"], "PARCIAL")
        report = build(self.ctx, [m5], {"status": "OK"})
        self.assertEqual(report["score"], 0)
        data = envelope(report)
        self.assertIn("Pastebin 1 • MediaFire 0", data["payload"]["embeds"][0]["description"])
        self.assertNotIn("PRIVATE_PATH", json.dumps(data))
