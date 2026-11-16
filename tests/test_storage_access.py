import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from types import SimpleNamespace
from warp_scanner import storage_access


class StorageTests(unittest.TestCase):
    def test_zarchiver_only_launches_with_opt_in_and_visible_package(self):
        ctx = SimpleNamespace(consent={"files": False}, run=Mock())
        installed = (SimpleNamespace(ok=True, text="package:/data/app/base.apk"), "adb", [])
        ask, wait = Mock(return_value=True), Mock()
        with patch.object(storage_access, "query", return_value=installed) as probe:
            storage_access.offer_zarchiver(ctx, ask, wait)
            probe.assert_not_called()
            ctx.consent["files"] = True
            storage_access.offer_zarchiver(ctx, lambda _: False, wait)
            ctx.run.assert_not_called()
            ctx.run.return_value = SimpleNamespace(ok=True, text="Starting: Intent")
            storage_access.offer_zarchiver(ctx, ask, wait)
            self.assertEqual(ctx.run.call_args.args[0][-1], "ru.zdevs.zarchiver")
            wait.assert_called_once()

    def test_accessible_directory_does_not_request_permission(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertTrue(storage_access.prepare(Path(root), Mock(side_effect=AssertionError)))

    def test_refusal_does_not_run_setup(self):
        with patch.object(storage_access, "accessible", return_value=False), patch.object(storage_access, "run_command") as run:
            self.assertFalse(storage_access.prepare(Path("/storage/example"), lambda _: False))
            run.assert_not_called()

    def test_permission_checked_again_after_android_prompt(self):
        with patch.object(storage_access, "accessible", side_effect=[False, True]), patch.object(storage_access, "run_command", return_value=SimpleNamespace(ok=True)), patch("builtins.print"):
            self.assertTrue(storage_access.prepare(Path("/storage/example"), lambda _: True, lambda _: None))
