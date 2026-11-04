import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from types import SimpleNamespace
from warp_scanner import storage_access


class StorageTests(unittest.TestCase):
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
