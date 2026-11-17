import os
from pathlib import PurePosixPath
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from warp_scanner import tas_android


class NativeTasTests(unittest.TestCase):
    def setUp(self):
        self.area = SimpleNamespace(path=PurePosixPath("/data"), prune=(PurePosixPath("/data/media"),))
        self.ctx = SimpleNamespace(privilege={"adb": True}, args=SimpleNamespace(adb_serial="127.0.0.1:43210"))

    def test_eligible_paths_retained_on_timeout_or_failed_find(self):
        for outcome in ("tempo", "acesso", "saída"):
            with self.subTest(outcome=outcome), patch.object(tas_android, "_capture", return_value=(
                    b".\0./data/game/a file.TAS\0./data/game/\niname.tas\0./incomplete", outcome)):
                paths, status, _ = tas_android.scan_area(self.ctx, self.area, "adb", 3)
                self.assertEqual(paths, ["/data/data/game/a file.TAS", "/data/data/game/\niname.tas"])
                self.assertEqual(status, "PARCIAL")

    def test_no_match_distinguished_from_inaccessible_or_invalid_response(self):
        for output, outcome, expected in ((b".\0", "ok", "OK"), (b"", "acesso", "NÃO VERIFICADO"),
                                          (b".\0./../x.tas\0", "ok", "PARCIAL")):
            with self.subTest(output=output), patch.object(tas_android, "_capture", return_value=(output, outcome)):
                paths, status, _ = tas_android.scan_area(self.ctx, self.area, "none", 3)
                self.assertEqual((paths, status), ([], expected))

    def test_adb_only_verified_local_serial_and_no_unconfirmed_root(self):
        for level, serial in (("adb", "10.0.0.4:43210"), ("root", "")):
            self.ctx.args.adb_serial = serial
            with patch.object(tas_android, "_capture", side_effect=AssertionError):
                self.assertEqual(tas_android.scan_area(self.ctx, self.area, level, 1)[1], "NÃO VERIFICADO")

    def test_virtual_paths_or_unrelated_prune_cannot_be_traversed(self):
        for root, skip in (("/dev", ()), ("/proc/1", ()), ("/sys", ()),
                           ("/storage/emulated/0/../../proc", ()), ("/data", (PurePosixPath("/sys"),))):
            area = SimpleNamespace(path=PurePosixPath(root), prune=skip)
            with self.subTest(root=root), patch.object(tas_android, "_capture", side_effect=AssertionError):
                self.assertEqual(tas_android.scan_area(self.ctx, area, "none", 3)[1], "NÃO VERIFICADO")

    def test_device_root_has_mandatory_prunes_and_apex_oem_partitions_accepted(self):
        for name in ("/", "/apex", "/manufacturer", "/mnt/media_rw/9FAB-42AF"):
            area = SimpleNamespace(path=PurePosixPath(name), kind="system", prune=())
            argv = tas_android._argv(self.ctx, area, "none", 1)
            if name == "/":
                self.assertIn("./proc", argv)
                self.assertIn("./dev", argv)
                self.assertIn("./sys", argv)
            self.assertIn("*.tas", argv)

    @unittest.skipUnless(os.name == "posix", "Local POSIX equivalents of Android sh/find")
    def test_native_expression_skips_pruned_directories_links_and_zip_entries(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "ordinary").mkdir()
            (root / "ordinary" / "found.TaS").touch()
            (root / "media").mkdir()
            (root / "media" / "skip.tas").touch()
            (root / "alias").symlink_to(root / "ordinary", target_is_directory=True)
            (root / "bundle.zip").write_bytes(b"secret.tas")
            cmd = tas_android._argv(self.ctx, self.area, "adb", 1)
            remote = shlex.split(cmd[-1])
            expression = remote[remote.index("tas-find") + 2:]
            result = subprocess.run(["sh", "-c", tas_android._FIND.replace("/system/bin/toybox find", "find"),
                                     "tas-find", str(root), *expression], stdout=subprocess.PIPE, check=True)
            self.assertEqual(set(result.stdout.split(b"\0")), {b"", b".", b"./ordinary/found.TaS"})

    @unittest.skipUnless(os.name == "posix", "Termux uses POSIX pipes")
    def test_subprocess_failure_preserves_stdout(self):
        data, outcome = tas_android._capture([sys.executable, "-c",
            'import sys; sys.stdout.buffer.write(b".\\0./match.tas\\0"); sys.exit(1)'], 3)
        self.assertEqual((data, outcome), (b".\0./match.tas\0", "acesso"))
