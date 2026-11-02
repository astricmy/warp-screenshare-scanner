import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

from warp_scanner import capture


def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


def sample(width=1, height=1):
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(4))) + chunk(b"IEND", b"")


def context():
    return SimpleNamespace(args=SimpleNamespace(test=False, dry_run=False, adb_serial="127.0.0.1:40000"),
                           privilege={"adb": True, "root": False}, consent={"screenshot": True})


def report():
    return {"scan_id": "12345678-1234-4123-8123-123456789abc", "synthetic": False, "findings": [
        {"id": "12345678-1234-4123-8123-123456789abd", "evidence": {"caminho": "Download/exemplo.lua"}}]}


class CaptureTest(unittest.TestCase):
    def test_png_requires_complete_sane_image(self):
        png = sample()
        self.assertEqual(capture.png_dimensions(png), (1, 1))
        for invalid in (png[:-1], png + b"extra", png[:-5] + b"abcde", sample(8193), sample(4097, 4097),
                        b"\x89PNG" + b"x" * capture.MAX_PNG_BYTES):
            with self.subTest(size=len(invalid)), self.assertRaises(ValueError):
                capture.png_dimensions(invalid)

    def test_binary_command_only_local_peer_or_confirmed_root(self):
        ctx = context()
        self.assertIn("exec-out", capture.capture_command(ctx))
        ctx.args.adb_serial = "192.0.2.1:5555"
        self.assertIsNone(capture.capture_command(ctx))
        ctx.privilege["root"] = True
        self.assertEqual(capture.capture_command(ctx), ["su", "-c", "/system/bin/screencap -p"])

    def test_disabled_or_fixture_never_calls_capture(self):
        with patch.object(capture, "_capture", side_effect=AssertionError), patch("builtins.print"):
            ctx = context()
            ctx.consent["screenshot"] = False
            self.assertEqual(capture.review(ctx, report()), [])
            ctx.consent["screenshot"] = True
            r = report()
            r["synthetic"] = True
            self.assertEqual(capture.review(ctx, r), [])

    def run_review(self, consent=True, accept=True, image=None):
        with tempfile.TemporaryDirectory() as prefix, ExitStack() as stack:
            tmp = Path(prefix) / "tmp"
            tmp.mkdir()
            stack.enter_context(patch.dict(os.environ, {"PREFIX": prefix}))
            stack.enter_context(patch.object(capture.sys.stdin, "isatty", return_value=True))
            stack.enter_context(patch.object(capture.sys.stdout, "isatty", return_value=True))
            stack.enter_context(patch.object(capture.shutil, "which", return_value="termux-open"))
            stack.enter_context(patch("builtins.input", side_effect=["1", "VER"]))
            stack.enter_context(patch("builtins.print"))
            stack.enter_context(patch.object(capture, "yes_no", side_effect=[consent, accept]))
            stack.enter_context(patch.object(capture.time, "sleep"))
            raw = sample() if image is None else image
            reader = stack.enter_context(patch.object(capture, "_capture", return_value=raw))

            def view(argv, **kwargs):
                self.assertEqual(Path(argv[-1]).read_bytes(), raw)
                self.assertEqual(Path(argv[-1]).parent, tmp)
                return SimpleNamespace(returncode=0)
            viewer = stack.enter_context(patch.object(capture.subprocess, "run", side_effect=view))
            r = report()
            attachments = capture.review(context(), r)
            self.assertEqual(list(tmp.iterdir()), [])
            return r, attachments, reader.call_count, viewer.call_count

    def test_fresh_consent_refused_skips_command(self):
        r, attachments, called, viewed = self.run_review(consent=False)
        self.assertEqual((attachments, called, viewed), ([], 0, 0))
        self.assertFalse(r["capture"]["reviewed"])

    def test_invalid_output_never_opens_preview(self):
        _, attachments, called, viewed = self.run_review(image=b"permission denied")
        self.assertEqual((attachments, called, viewed), ([], 1, 0))

    def test_preview_refusal_discards_file_and_bytes(self):
        r, attachments, called, viewed = self.run_review(accept=False)
        self.assertEqual((attachments, called, viewed), ([], 1, 1))
        self.assertNotIn("sha256", r["capture"])

    def test_reviewed_bytes_identical_to_attached_png(self):
        r, files, called, viewed = self.run_review()
        self.assertEqual((len(files), called, viewed), (1, 1, 1))
        self.assertEqual(base64.b64decode(files[0]["content"]), sample())
        self.assertNotIn(files[0]["content"], json.dumps(r))
        self.assertEqual(r["capture"]["sha256"], hashlib.sha256(sample()).hexdigest())
        self.assertEqual(r["capture"]["finding_id"], r["findings"][0]["id"])


if __name__ == "__main__":
    unittest.main()
