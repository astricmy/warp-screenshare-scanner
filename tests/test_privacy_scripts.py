"""Fixtures sintéticas; estes testes não afirmam validação em Android real."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from warp_scanner.safety import (
    REDACTED, domain_matches, iter_allowed_files, match_domains,
    normalize_domain, read_bounded_file, redact, safe_url,
)
from warp_scanner.scripts_clipboard import analyze_text, collect

ROOT = Path(__file__).resolve().parents[1]
SIGNATURES = json.loads((ROOT / "signatures.json").read_text(encoding="utf-8"))
LOADER = 'loadstring(game:HttpGet("https://raw.githubusercontent.com/fixture/demo/main/test.lua?discard=1#discard"))()'


class FakeContext:
    def __init__(self, storage, files=(), clipboard="", file_consent=True, clip_consent=False):
        self.storage, self.files = Path(storage), list(files)
        self.signatures = SIGNATURES
        self.args = SimpleNamespace(max_file_kb=512, max_files=20, max_seconds=10)
        self.consent = {"files": file_consent, "clipboard": clip_consent}
        self.privilege = {"root": False, "adb": False}
        self.file_stats, self.calls = {}, []
        self.clipboard = clipboard

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return SimpleNamespace(ok=True, text=self.clipboard, reason="", code=0)

    def finding(self, module, category, description, evidence, level, weight_key, **kwargs):
        return {"module": module, "category": category, "description": description,
                "evidence": evidence, "level": level, "weight_key": weight_key, **kwargs}


class RedactionTests(unittest.TestCase):
    def test_credentials_discard_entire_excerpt(self):
        fixtures = [
            "senha=VALOR_FICTICIO", "password: VALOR_FICTICIO",
            "Authorization: Bearer VALOR_FICTICIO", "token=VALOR_FICTICIO",
            "Código de verificação: 654321", ".ROBLOSECURITY=COOKIE_FICTICIO",
            "_|WARNING:-DO-NOT-SHARE-THIS.COOKIE_FICTICIO",
            "api_key=VALOR_FICTICIO", "cookie=VALOR_FICTICIO",
            "https://discord.com/api/webhooks/123/VALOR_FICTICIO",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture.split("=")[0]):
                self.assertEqual(redact("loadstring() " + fixture), REDACTED)

    def test_email_phone_ansi_and_bidi_are_removed(self):
        text = redact("\x1b[31mabc\u202e user@example.test +55 (11) 99999-9999")
        self.assertNotIn("example.test", text)
        self.assertNotIn("99999", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)

    def test_url_strips_credentials_query_and_fragment(self):
        self.assertEqual(safe_url("https://user:private@RAW.GITHUBUSERCONTENT.COM/a/b/main/file.lua?private=1#private"),
                         "https://raw.githubusercontent.com/a/b/main/file.lua")
        self.assertEqual(safe_url("file:///private"), REDACTED)

    def test_domains_have_label_boundary_and_idna(self):
        self.assertTrue(domain_matches("https://sub.deltaexecutor.co/path", "deltaexecutor.co"))
        self.assertFalse(domain_matches("deltaexecutor.co.evil.test", "deltaexecutor.co"))
        self.assertFalse(domain_matches("evildeltaexecutor.co", "deltaexecutor.co"))
        self.assertEqual(normalize_domain("https://www.TÉSTE.example/"), "xn--tste-bpa.example")
        self.assertFalse(match_domains("https://example.test/?deltaexecutor.co", SIGNATURES))

    def test_max_length(self):
        self.assertLessEqual(len(redact("a" * 500, 160)), 160)


class PatternTests(unittest.TestCase):
    def test_ordinary_roblox_and_standalone_url_are_not_findings(self):
        for text in ["LocalPlayer GetService RunService workspace Instance.new",
                     "https://raw.githubusercontent.com/fixture/demo/main/test.lua",
                     "Rayfield Orion Kavo Fluent Linoria", "Delta Codex Hydrogen Wave"]:
            self.assertIsNone(analyze_text(text, SIGNATURES))

    def test_loader_and_executor_weights(self):
        self.assertEqual(analyze_text("loadstring(x)", SIGNATURES)["level"], "INDÍCIO")
        loader = analyze_text(LOADER, SIGNATURES)
        self.assertEqual(loader["level"], "PROVÁVEL")
        self.assertEqual(loader["weight_key"], "script_loader")
        self.assertEqual(analyze_text(LOADER + " getgenv()", SIGNATURES)["weight_key"], "script_executor")
        self.assertNotIn("discard", json.dumps(loader))
        self.assertLessEqual(len(loader["trecho"]), 160)

    def test_no_arbitrary_context_in_excerpt(self):
        result = analyze_text("Meu nome pessoal fictício deve desaparecer " + LOADER, SIGNATURES)
        self.assertNotIn("pessoal", json.dumps(result))

    def test_possible_credential_erases_derived_urls(self):
        result = analyze_text(LOADER + ' senha="VALOR_FICTICIO"', SIGNATURES)
        self.assertEqual(result["trecho"], REDACTED)
        self.assertEqual(result["urls"], [])
        self.assertTrue(result["credential_warning"])
        self.assertNotIn("VALOR_FICTICIO", json.dumps(result))

    def test_only_verified_hash_confirms_and_clipboard_is_capped(self):
        base = json.loads(json.dumps(SIGNATURES))
        digest = hashlib.sha256(b"fixture").hexdigest()
        base["scripts"]["hashes_script"] = [digest, {"value": digest, "verificado": False}]
        self.assertIsNone(analyze_text("fixture", base, digest=digest))
        base["scripts"]["hashes_script"] = [{"value": digest, "verificado": True}]
        self.assertEqual(analyze_text("fixture", base, digest=digest)["level"], "CONFIRMADO")
        clip = analyze_text(LOADER, base, source="clipboard", digest=digest)
        self.assertEqual(clip["level"], "PROVÁVEL")
        self.assertEqual(clip["weight_key"], "script_clipboard")

    def test_obfuscation_is_only_an_indication(self):
        result = analyze_text("-- MoonSec fixture", SIGNATURES)
        self.assertEqual(result["level"], "INDÍCIO")
        self.assertEqual(result["weight_key"], "obfuscation")


class FilesystemTests(unittest.TestCase):
    def test_allowlist_does_not_descend_personal_or_generic_names(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for rel in ["Download/demo.lua", "Download/DCIM/private.lua", "Pictures/private.lua",
                        "Documents/private.txt", "WhatsApp/private.lua", "Codex/private.lua",
                        "CodexExecutor/scripts/demo.lua", "demo.lua"]:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture", encoding="utf-8")
            seen = {p.relative_to(root).as_posix() for p in iter_allowed_files(root, SIGNATURES)}
            self.assertEqual(seen, {"Download/demo.lua", "CodexExecutor/scripts/demo.lua", "demo.lua"})

    def test_android_access_is_by_explicit_package(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for pkg in ["com.fixture.allowed", "com.fixture.unrelated"]:
                path = root / "Android" / "data" / pkg / "script.lua"
                path.parent.mkdir(parents=True)
                path.write_text("fixture", encoding="utf-8")
            base = {"entries": [{"pacotes": ["com.fixture.allowed"]}]}
            seen = [p.relative_to(root).as_posix() for p in iter_allowed_files(root, base)]
            self.assertEqual(seen, ["Android/data/com.fixture.allowed/script.lua"])

    def test_files_and_entries_are_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for number in range(6):
                (root / f"{number}.lua").write_text("fixture", encoding="utf-8")
            stats = {}
            self.assertEqual(len(list(iter_allowed_files(root, SIGNATURES, max_files=2, stats=stats))), 2)
            self.assertTrue(stats["limited"])

    def test_read_rejects_oversize_outside_and_personal_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "allowed"
            root.mkdir()
            (root / "demo.lua").write_bytes(b"12345")
            (root / "DCIM").mkdir()
            (root / "DCIM" / "private.lua").write_bytes(b"fixture")
            with self.assertRaises(ValueError):
                read_bounded_file(root / "demo.lua", root, 4)
            with self.assertRaises(ValueError):
                read_bounded_file(root.parent / "external.lua", root, 32)
            with self.assertRaises(ValueError):
                read_bounded_file(root / "DCIM" / "private.lua", root, 32)

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "actual.lua"
            target.write_text("fixture", encoding="utf-8")
            link = root / "linked.lua"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("Criação de link simbólico indisponível neste host; repetir no Linux/Android")
            self.assertNotIn(link, list(iter_allowed_files(root, SIGNATURES)))
            with self.assertRaises((OSError, ValueError)):
                read_bounded_file(link, root, 32)


class CollectionTests(unittest.TestCase):
    def test_consent_refusal_does_not_open_file_or_read_clipboard(self):
        ctx = FakeContext("/unused", [Path("/unused/fixture.lua")], file_consent=False)
        with patch("warp_scanner.scripts_clipboard.read_bounded_file", side_effect=AssertionError("leitura proibida")):
            report = collect(ctx)
        self.assertEqual(ctx.calls, [])
        self.assertEqual(report["status"], "NÃO VERIFICADO")

    def test_one_clipboard_read_and_no_secret_in_report(self):
        ctx = FakeContext("/unused", clipboard=LOADER + ' senha="VALOR_FICTICIO"', file_consent=False, clip_consent=True)
        report = collect(ctx)
        self.assertEqual(len(ctx.calls), 1)
        self.assertEqual(report["data"]["clipboard_leituras"], 1)
        self.assertNotIn("VALOR_FICTICIO", json.dumps(report))
        self.assertTrue(report["data"]["credential_warning"])
        self.assertEqual(report["findings"][0]["evidence"]["trecho"], REDACTED)

    def test_empty_clipboard_is_unverified(self):
        report = collect(FakeContext("/unused", clipboard="", file_consent=False, clip_consent=True))
        check = next(c for c in report["checks"] if c["name"] == "clipboard_atual")
        self.assertEqual(check["status"], "NÃO VERIFICADO")

    def test_adb_redacted_clipboard_is_unverified_and_not_retried(self):
        ctx = FakeContext("/unused", clipboard="Primary clip: <redacted>", file_consent=False, clip_consent=True)
        ctx.privilege["adb"] = True
        with patch("warp_scanner.scripts_clipboard.shutil.which", return_value=None):
            report = collect(ctx)
        self.assertEqual(len(ctx.calls), 1)
        self.assertEqual(ctx.calls[0][0], ["dumpsys", "clipboard"])
        self.assertEqual(ctx.calls[0][1]["requires"], "adb")
        check = next(c for c in report["checks"] if c["name"] == "clipboard_atual")
        self.assertEqual(check["status"], "NÃO VERIFICADO")

    def test_collection_preserves_metadata_and_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.lua"
            path.write_text(LOADER, encoding="utf-8")
            report = collect(FakeContext(folder, [path]))
            evidence = report["findings"][0]["evidence"]
            self.assertEqual(evidence["caminho"], "fixture.lua")
            self.assertEqual(evidence["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertIn("mtime", evidence)
            self.assertIn("ctime_metadados", evidence)
            self.assertNotIn("discard", json.dumps(report))

    def test_walker_error_is_not_reported_as_verified(self):
        ctx = FakeContext("/unused")
        ctx.file_stats = {"errors": 1}
        report = collect(ctx)
        self.assertEqual(report["checks"][0]["status"], "NÃO VERIFICADO")

    def test_archive_reads_only_names(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("autoexec/demo.lua", "CONTEUDO_NAO_PODE_SER_LIDO")
            ctx = FakeContext(folder, [path])
            with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("membro aberto")):
                report = collect(ctx)
            self.assertEqual(len(report["findings"]), 1)
            self.assertNotIn("CONTEUDO_NAO_PODE_SER_LIDO", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
