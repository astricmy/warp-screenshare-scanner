import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from warp_scanner import tas_android
from warp_scanner import tas_roots as roots


class TasAreaTests(unittest.TestCase):
    def test_fixture_never_enumerates_host(self):
        areas, notes = roots.discover(SimpleNamespace(storage=Path("fixture")))
        self.assertEqual([a.path for a in areas], [Path("fixture")])
        self.assertEqual(notes, [])

    def test_android_areas_aliases_and_fallback(self):
        mountinfo = """1 0 0:3 / /storage/emulated rw - fuse emulated rw
2 0 0:8 / /storage/89AB-CDEF rw - vfat disk rw
3 0 0:9 / /mnt/media_rw/1122-3344 rw - exfat disk rw
4 0 0:6 / /apex/com.android.mock@1 ro - ext4 disk ro
5 0 0:6 / /apex/com.android.mock ro - ext4 disk ro
6 0 0:5 / /data rw - f2fs disk rw
7 0 0:7 / /oem_extra ro - erofs disk ro
8 0 0:10 / /storage/89AB-CDEF/Android/data rw - fuse media rw
9 0 0:11 / /proc rw - proc proc rw
"""
        listing = "private:1,2 mounted 01234567-0123-0123-0123-0123456789ab\npublic:12 mounted 1122-3344"
        ctx = SimpleNamespace(storage=Path("/storage/emulated/0"), privilege={}, run=Mock(return_value=SimpleNamespace(ok=True,text=listing)))
        dirs = {"/storage": ["emulated","self","89AB-CDEF"], "/storage/emulated": ["0","10"]}
        with patch.object(Path, "is_file", return_value=True), patch("builtins.open", return_value=io.StringIO(mountinfo)), \
             patch.object(roots, "_directories", side_effect=dirs.get), patch.object(Path, "home", return_value=Path("/data/data/com.termux/files/home")), \
             patch("os.path.isdir", side_effect=lambda p: p in ("/system", "/apex")), patch("os.path.islink", return_value=False):
            areas, notes = roots.discover(ctx)
        found = {a.path.as_posix():a for a in areas}
        for path in ("/storage/89AB-CDEF", "/mnt/media_rw/1122-3344", "/storage/emulated/10", "/system",
                     "/mnt/expand/01234567-0123-0123-0123-0123456789ab", "/oem_extra", "/data/data/com.termux/files",
                     "/apex", "/data/local/tmp", "/"):
            self.assertIn(path, found)
        self.assertEqual(notes, [])
        self.assertIn(Path("/apex/com.android.mock@1"), found["/apex"].prune)
        for area in areas:
            with self.subTest(area=area.label):
                self.assertIn(area.path.as_posix(), tas_android._argv(ctx, area, "none", 10))
        self.assertIn(Path("/proc"), found["/"].prune)
        manual = found["/mnt/media_rw/1122-3344"]
        self.assertEqual(manual.key(manual.path/"jogo.tas"), "/storage/1122-3344/jogo.tas")
        nested = found["/storage/89AB-CDEF/Android/data"]
        self.assertNotIn("89AB-CDEF", nested.display_path(nested.path/"arquivo.tas"))
        self.assertIn("Android/data/arquivo.tas", nested.display_path(nested.path/"arquivo.tas"))
        self.assertEqual(found["/data"].key("/data/media/0/d/a.TAS"), "/storage/emulated/0/d/a.TAS")
