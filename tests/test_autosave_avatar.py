"""Provas do salvamento anterior ao envio e do avatar público opcional."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import zlib

import scan
from warp_scanner import avatar


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def sample_png(extra=b"", color=6, depth=8, pixels=None):
    size = avatar.SIZE
    header = struct.pack(">IIBBBBB", size, size, depth, color, 0, 0, 0)
    if pixels is None:
        pixels = bytes(size * (1 + size * 4))
    return avatar.MAGIC + chunk(b"IHDR", header) + extra + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")


def fixture():
    return {"scan_id": str(uuid.uuid4()), "modules": [
        {"module": "M2", "status": "PARCIAL", "data": {"userId": 42, "profile_url": "https://www.roblox.com/users/42/profile"}}
    ]}


class AvatarTests(unittest.TestCase):
    def test_fetch_is_bounded_to_roblox_cdn_and_discards_metadata(self):
        image = sample_png(extra=chunk(b"tEXt", b"fixture\x00PRIVATE_SENTINEL"))
        row = {"targetId": 42, "state": "Completed", "imageUrl": "https://tr.rbxcdn.com/fixture/150/150/AvatarHeadshot/Png/noFilter"}
        with patch.object(avatar, "request", side_effect=[json.dumps({"data": [row]}).encode(), image]) as fetch:
            result = avatar.fetch_headshot(42)
        self.assertEqual(len(fetch.call_args_list), 2)
        self.assertLessEqual(fetch.call_args_list[1].kwargs["max_bytes"], 128 * 1024)
        self.assertIn("userIds=42", fetch.call_args_list[0].args[0])
        self.assertEqual(result, sample_png())
        self.assertNotIn(b"PRIVATE_SENTINEL", result)

    def test_untrusted_url_state_and_target_never_trigger_second_request(self):
        valid = "https://tr.rbxcdn.com/fixture/150/150/AvatarHeadshot/Png/noFilter"
        overrides = [
            {"imageUrl": "https://tr.rbxcdn.com.evil.test/a"},
            {"imageUrl": "http://tr.rbxcdn.com/a"},
            {"imageUrl": "https://private@tr.rbxcdn.com/a"},
            {"imageUrl": "https://tr.rbxcdn.com:8443/a"},
            {"imageUrl": valid + "?sensitive=fixture"},
            {"targetId": 43}, {"targetId": True}, {"state": "Pending"},
        ]
        for override in overrides:
            row = {"targetId": 42, "state": "Completed", "imageUrl": valid, **override}
            with patch.object(avatar, "request", return_value=json.dumps({"data": [row]}).encode()) as fetch:
                self.assertIsNone(avatar.fetch_headshot(42))
                self.assertEqual(fetch.call_count, 1)

    def test_invalid_userid_never_calls_network(self):
        with patch.object(avatar, "request", side_effect=AssertionError("Acesso indevido")) as fetch:
            for uid in (None, "42", True, 0, -1, 2**63):
                self.assertIsNone(avatar.fetch_headshot(uid))
            fetch.assert_not_called()

    def test_timeout_and_malformed_png_are_silent(self):
        with patch.object(avatar, "request", side_effect=TimeoutError("PRIVATE_SENTINEL")), redirect_stdout(io.StringIO()) as stdout:
            self.assertIsNone(avatar.fetch_headshot(42))
            self.assertNotIn("PRIVATE_SENTINEL", stdout.getvalue())
        valid = sample_png()
        for candidate in (valid[:-1], valid + b"x", valid[:40] + bytes(16) + valid[56:],
                          b"\x89PNG\r\n\x1a\n", bytes(avatar.MAX_BYTES + 1),
                          sample_png(pixels=bytes(3_000_000))):
            self.assertIsNone(avatar.clean_png(candidate))

    def test_palette_avatar_converts_to_rgba_and_drops_optional_chunks(self):
        row = b"\x00" + bytes((avatar.SIZE + 7) // 8)
        indexed = sample_png(extra=chunk(b"PLTE", b"\xff\x00\x00") + chunk(b"tRNS", b"\x80"),
                             color=3, depth=1, pixels=row * avatar.SIZE)
        expected_row = b"\x00" + bytes.fromhex("ff000080") * avatar.SIZE
        self.assertEqual(avatar.clean_png(indexed), sample_png(pixels=expected_row * avatar.SIZE))


class AutosaveTests(unittest.TestCase):
    def test_simulated_cli_output_pair_opt_in_and_no_network(self):
        with tempfile.TemporaryDirectory() as root, redirect_stdout(io.StringIO()) as stdout:
            with patch("scan.fetch_headshot", side_effect=AssertionError), patch("scan.send", side_effect=AssertionError):
                self.assertEqual(scan.main(["--test", "--plain", "--output", root]), 0)
            outputs = sorted(Path(root).glob("relatorio_*"))
            self.assertEqual([p.suffix for p in outputs], [".json", ".txt"])
            self.assertTrue(json.loads(outputs[0].read_text(encoding="utf-8"))["synthetic"])
            self.assertIn(str(outputs[1]), stdout.getvalue())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(outputs[0].stat().st_mode), 0o600)

    def test_collision_preserves_existing_file_and_attempts_other_format(self):
        report = fixture()
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            root = Path(folder)
            path = root / f"relatorio_{report['scan_id']}.json"
            path.write_bytes(b"ANTERIOR")
            with patch("scan.render_text", return_value="RELATÓRIO"):
                self.assertFalse(scan.save_report(report, root))
            self.assertEqual(path.read_bytes(), b"ANTERIOR")
            self.assertEqual(path.with_suffix(".txt").read_text(encoding="utf-8"), "RELATÓRIO")

    def test_declining_delivery_saves_in_private_folder_without_avatar(self):
        args = SimpleNamespace(test=False, dry_run=False, output=None, direct=False)
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            folder = Path(folder)
            with patch("scan.Path.home", return_value=folder), patch("scan.render_text", return_value="Fixture"), \
                    patch("scan.fetch_headshot") as image, patch("scan.ui.yes_no", return_value=False), patch("scan.send") as send:
                self.assertEqual(scan.finish_report(fixture(), [], args), 0)
            target = folder / ".local" / "share" / "warp-screenshare" / "relatorios"
            self.assertEqual({p.suffix for p in target.iterdir()}, {".txt", ".json"})
            image.assert_not_called()
            send.assert_not_called()

    def test_failure_to_save_does_not_skip_requested_send(self):
        args = SimpleNamespace(test=False, dry_run=False, output=None, direct=True)
        with patch("scan.save_report", return_value=False), patch("scan.ui.yes_no", return_value=True), \
                patch("scan.deliver", return_value=True) as send, redirect_stdout(io.StringIO()):
            self.assertNotEqual(scan.finish_report(fixture(), [], args), 0)
            send.assert_called_once()

    def test_successful_local_files_survive_remote_failure(self):
        args = SimpleNamespace(test=False, dry_run=False, output=None, direct=True)
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            args.output = Path(folder)
            observation = []
            def failed(*_):
                observation.append({p.suffix for p in args.output.glob("relatorio_*")})
                return False
            with patch("scan.render_text", return_value="Fixture"), patch("scan.ui.yes_no", return_value=True), \
                    patch("scan.deliver", side_effect=failed):
                self.assertNotEqual(scan.finish_report(fixture(), [], args), 0)
            self.assertEqual(observation, [{".json", ".txt"}])

    def test_dry_run_persists_local_report_and_never_fetches_avatar(self):
        args = SimpleNamespace(test=False, dry_run=True, output=None, direct=False)
        with patch("scan.save_report", return_value=True) as save, patch("scan.envelope", return_value={}), \
                patch("scan.deliver", side_effect=AssertionError), redirect_stdout(io.StringIO()):
            self.assertEqual(scan.finish_report(fixture(), [], args), 0)
            save.assert_called_once()

    def test_fetch_failure_sends_without_thumbnail(self):
        report = fixture()
        with patch("scan.fetch_headshot", return_value=None) as image, patch("scan.envelope", return_value={"ok": True}) as pack, \
                patch("scan.send", return_value=(True, "enviado")) as send, redirect_stdout(io.StringIO()):
            self.assertTrue(scan.deliver(report, [], True))
            image.assert_called_once_with(42)
            pack.assert_called_once_with(report, [])
            send.assert_called_once()

    def test_missing_verified_profile_never_fetches_avatar(self):
        report = fixture()
        report["modules"][0]["data"]["profile_url"] = "https://example.test/42"
        with patch("scan.fetch_headshot", side_effect=AssertionError) as image, patch("scan.envelope", return_value={}), \
                patch("scan.send", return_value=(True, "enviado")), redirect_stdout(io.StringIO()):
            self.assertTrue(scan.deliver(report, [], True))
            image.assert_not_called()

    def test_cli_aliases_keep_declared_discord_id_string(self):
        args = scan.arguments(["--discord", "nome", "--discord-id", "123456789012345678"])
        self.assertEqual((args.discord_user, args.discord_id), ("nome", "123456789012345678"))
        self.assertEqual(scan.arguments(["--discord-user", "nome"]).discord_user, "nome")


if __name__ == "__main__":
    unittest.main()
