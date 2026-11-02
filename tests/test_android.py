"""Testes com respostas simuladas: não acessam nem alegam testar celulares reais."""
import datetime as dt
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch

from warp_scanner.core import CommandResult, Context
from warp_scanner import cheats, downloads_browser, environment, privilege, processes, roblox, traces


def ok(text):
    return CommandResult(True, text, code=0)


class MockContext(Context):
    def __init__(self, storage, responses=None, entries=None, root=False, adb=False):
        args = SimpleNamespace(window_days=14, adb_serial="localhost:43210" if adb else "", adb_connected=adb)
        weights = {"hint": 10, "root": 20, "confirmed": 100, "probable": 40, "removed": 50, "reinstall": 25, "overlay": 15}
        super().__init__(args, {"entries": entries or [], "roblox": {"official_certificates_sha256": []}}, {"weights": weights}, {"clipboard": False, "files": False}, Path(storage))
        self.privilege.update(root=root, adb=adb)
        self.responses, self.calls = responses or {}, []

    def run(self, argv, requires="none", timeout=8, max_bytes=262144):
        self.calls.append((tuple(argv), requires, timeout, max_bytes))
        result = self.responses.get((requires, tuple(argv)), CommandResult(False, reason="Simulação: capacidade indisponível"))
        return result() if callable(result) else result


def entry(verified=False, category="executor_mobile"):
    return {"id": "example", "nome": "Example Executor", "categoria": category, "pacotes": ["org.example.executor"],
            "rotulos": ["Example"], "pastas": [], "dominios": ["executor.example"], "tokens_contextuais": ["executor", "roblox", "apk", "script"],
            "verificado": verified, "hashes_apk": []}


PACKAGE_DUMP = """Packages:
  Package [com.roblox.client] (abc):
    versionName=2.999.1
    firstInstallTime=2020-01-01 10:00:00
    lastUpdateTime=2026-10-29 10:00:00
    installerPackageName=com.android.vending
    User 0: ceDataInode=42 installed=true hidden=false
"""


class AndroidModulesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.storage = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_denied_zero_exit_does_not_become_success(self):
        ctx = MockContext(self.storage, {("none", ("settings", "get", "global", "adb_enabled")): ok("Permission denial: private detail")})
        result, capability, failed = roblox.query(ctx, ["settings", "get", "global", "adb_enabled"])
        self.assertFalse(result.ok)
        self.assertEqual(result.text, "")
        self.assertEqual(failed, ["none"])

    def test_root_failure_falls_back_to_adb_and_is_recorded(self):
        command = ("dumpsys", "package", "com.roblox.client")
        ctx = MockContext(self.storage, {("root", command): ok("java.lang.SecurityException"), ("adb", command): ok(PACKAGE_DUMP)}, root=True, adb=True)
        info = roblox.package_info(ctx, "com.roblox.client")
        self.assertTrue(info["present"])
        self.assertEqual(info["requires"], "adb")
        self.assertEqual(info["fallback"], ["root"])
        self.assertEqual(len(ctx.calls), 2)

    def test_bad_package_never_reaches_a_command(self):
        ctx = MockContext(self.storage)
        result = roblox.package_info(ctx, "org.example;cat /private")
        self.assertFalse(result["verified"])
        self.assertEqual(ctx.calls, [])

    def test_package_response_discards_unrelated_fields(self):
        dump = PACKAGE_DUMP + "\n    irrelevant=PRIVATE_VALUE_SENTINEL\n"
        ctx = MockContext(self.storage, {("none", ("dumpsys", "package", "com.roblox.client")): ok(dump)})
        report = roblox.collect(ctx)
        encoded = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("PRIVATE_VALUE_SENTINEL", encoded)
        self.assertEqual(report["data"]["certificate"], "NÃO VERIFICADO")
        self.assertEqual(report["data"]["reinstallation"], "indeterminado")
        self.assertFalse(any(f["level"] == "CONFIRMADO" for f in report["findings"]))

    def test_recent_install_does_not_claim_reinstall(self):
        recent = (dt.datetime.now().astimezone() - dt.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        dump = PACKAGE_DUMP.replace("2020-01-01 10:00:00", recent)
        ctx = MockContext(self.storage, {("none", ("dumpsys", "package", "com.roblox.client")): ok(dump)})
        report = roblox.collect(ctx)
        self.assertEqual(report["data"]["reinstallation"], "indeterminado")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["level"], "INDÍCIO")

    def test_official_certificate_mismatch_requires_validated_reference(self):
        apk = "/data/app/known/base.apk"
        ctx = MockContext(self.storage, {
            ("none", ("dumpsys", "package", "com.roblox.client")): ok(PACKAGE_DUMP),
            ("none", ("pm", "path", "com.roblox.client")): ok("package:" + apk),
            ("none", ("apksigner", "verify", "--print-certs", apk)): ok("Signer #1 certificate SHA-256 digest: " + "b" * 64),
        })
        ctx.signatures["roblox"]["official_certificates_sha256"] = ["a" * 64]
        with patch.object(roblox.shutil, "which", return_value="/bin/apksigner"), patch.object(roblox.os.path, "isfile", return_value=True):
            report = roblox.collect(ctx)
        self.assertEqual([f["level"] for f in report["findings"]], ["INDÍCIO"])

    def test_bare_ambiguous_name_does_not_match(self):
        base = entry()
        self.assertFalse(cheats.contextual_match("Example", base))
        self.assertFalse(cheats.contextual_match("Example vacation notes", base))
        self.assertFalse(cheats.contextual_match("SomeExample apk", base))
        self.assertTrue(cheats.contextual_match("Example apk", base))
        self.assertTrue(cheats.contextual_match("Example Executor", base))

    def test_unverified_package_never_confirmed(self):
        dump = PACKAGE_DUMP.replace("com.roblox.client", "org.example.executor")
        ctx = MockContext(self.storage, {("none", ("dumpsys", "package", "org.example.executor")): ok(dump)}, [entry()])
        report = cheats.collect(ctx)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["level"], "INDÍCIO")

    def test_root_manager_is_not_confirmed_cheat_even_if_signature_verified(self):
        dump = PACKAGE_DUMP.replace("com.roblox.client", "org.example.executor")
        ctx = MockContext(self.storage, {("none", ("dumpsys", "package", "org.example.executor")): ok(dump)}, [entry(True, "root")])
        report = cheats.collect(ctx)
        self.assertEqual(report["findings"][0]["level"], "INDÍCIO")

    def test_known_hash_matches_and_unknown_bytes_do_not_leave_module(self):
        fixture = self.storage / "candidate.apk"
        fixture.write_bytes(b"FAKE_APK_FOR_UNIT_TEST")
        base = entry(True)
        base["pacotes"] = []
        base["hashes_apk"] = [hashlib.sha256(fixture.read_bytes()).hexdigest()]
        ctx = MockContext(self.storage, entries=[base])
        ctx.files = [fixture]
        report = cheats.collect(ctx)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["level"], "CONFIRMADO")
        self.assertNotIn("FAKE_APK_FOR_UNIT_TEST", json.dumps(report))

    def test_hash_deadline_and_outside_root_are_enforced(self):
        fixture = self.storage / "candidate.apk"
        fixture.write_bytes(b"fixture")
        with self.assertRaises(TimeoutError):
            cheats.bounded_hash(fixture, self.storage, time.monotonic() - 1)
        with self.assertRaises(ValueError):
            cheats.bounded_hash(fixture, self.storage / "subdir", time.monotonic() + 10)

    def test_file_walker_limit_stays_partial(self):
        ctx = MockContext(self.storage)
        ctx.file_stats = {"limited": True}
        report = cheats.collect(ctx)
        check = next(check for check in report["checks"] if check["name"].startswith("Arquivos em"))
        self.assertEqual(check["status"], "PARCIAL")

    def test_download_parser_discards_query_path_title_and_unmatched_hosts(self):
        stamp = int(time.time() * 1000)
        text = f"Row: 0 uri=https://sub.executor.example/private/path?token=PRIVATE_VALUE, lastmod={stamp}\n"
        text += f"Row: 1 uri=https://executor.example.evil.invalid/, lastmod={stamp}\n"
        text += f"Row: 2 uri=https://other.example/?next=https://executor.example/, lastmod={stamp}\n"
        rows = downloads_browser.parse_download_rows(text, {"executor.example": entry()}, stamp - 1000)
        self.assertEqual(rows, [{"domain": "sub.executor.example", "timestamp_ms": stamp, "signature_domain": "executor.example"}])
        self.assertNotIn("PRIVATE_VALUE", json.dumps(rows))

    def test_download_parser_rejects_old_and_impossible_dates(self):
        stamp = int(time.time() * 1000)
        text = f"Row: 0 uri=https://executor.example/, lastmod={stamp - 5000}\n"
        text += "Row: 1 uri=https://executor.example/, lastmod=999999999999999999999\n"
        self.assertEqual(downloads_browser.parse_download_rows(text, {"executor.example": entry()}, stamp - 1000), [])

    def test_download_query_filters_before_reading_and_does_not_read_history(self):
        ctx = MockContext(self.storage, entries=[entry()], adb=True)
        report = downloads_browser.collect(ctx)
        for command, cap, timeout, bound in ctx.calls:
            self.assertEqual(command[:2], ("content", "query"))
            self.assertIn("--projection", command)
            self.assertIn("--where", command)
            self.assertIn("lastmod >=", command[-1])
            self.assertIn("executor.example", command[-1])
        self.assertEqual(report["status"], "NÃO VERIFICADO")
        self.assertFalse(any("browser" in " ".join(call[0]) for call in ctx.calls))

    def test_process_maps_only_report_unusual_library_paths(self):
        maps = "\n".join("a-b r-xp 0000 00:00 0 " + path for path in [
            "/system/lib64/libc.so", "/apex/runtime/lib.so", "/data/app/com.roblox.client/base/lib.so",
            "/data/user/0/com.roblox.client/files/legitimate.so", "/data/local/tmp/injected.so", "/sdcard/private.txt"])
        self.assertEqual(processes.parse_maps(maps), ["/data/local/tmp/injected.so"])

    def test_processes_without_privilege_do_not_run_commands(self):
        ctx = MockContext(self.storage)
        report = processes.collect(ctx)
        self.assertEqual(report["status"], "NÃO VERIFICADO")
        self.assertEqual(ctx.calls, [])

    def test_environment_does_not_emit_proxy_dns_vpn_literals(self):
        ctx = MockContext(self.storage, {
            ("none", ("settings", "get", "global", "http_proxy")): ok("private-corporate.example:8080"),
            ("none", ("settings", "get", "secure", "always_on_vpn_app")): ok("org.private.vpn"),
            ("none", ("settings", "get", "secure", "enabled_accessibility_services")): ok("org.private.accessibility/PrivateService"),
        })
        report = environment.collect(ctx)
        encoded = json.dumps(report)
        self.assertNotIn("private-corporate", encoded)
        self.assertNotIn("org.private", encoded)
        self.assertNotIn("proxy configurado", report["data"]["settings"])

    def test_recent_empty_download_is_only_hint(self):
        (self.storage / "Download").mkdir()
        os.utime(self.storage / "Download", (time.time() - 60, time.time() - 60))
        ctx = MockContext(self.storage)
        report = traces.collect(ctx)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["level"], "INDÍCIO")
        self.assertFalse(any(command[0][0] in ("logcat", "bugreport") for command in ctx.calls))

    def test_privilege_denied_su_is_not_confirmed_root(self):
        ctx = MockContext(self.storage, {("none", ("id",)): ok("uid=10234(u0_a234)")})
        with patch.object(privilege, "_exists", return_value="não encontrado"), patch.object(privilege.shutil, "which", return_value=None), patch.object(privilege.Path, "open", mock_open(read_data="")):
            state = privilege.privilege_probe(ctx)
        self.assertFalse(state["root"])
        self.assertEqual(state["classification"], "SEM_ROOT")
        self.assertFalse(any(call[0][0] == "adb" for call in ctx.calls))

    def test_privilege_root_requires_uid_zero(self):
        ctx = MockContext(self.storage, {("none", ("id",)): ok("uid=10234"), ("none", ("su", "-c", "id")): ok("uid=0(root) gid=0(root)")})
        with patch.object(privilege, "_exists", return_value="não encontrado"), patch.object(privilege.shutil, "which", return_value=None), patch.object(privilege.Path, "open", mock_open(read_data="")):
            state = privilege.privilege_probe(ctx)
        self.assertTrue(state["root"])
        self.assertEqual(state["mode"], "AVANÇADO")

    def test_adb_probe_requires_explicit_local_target(self):
        ctx = MockContext(self.storage, {("none", ("id",)): ok("uid=10234"), ("none", ("adb", "-s", "localhost:43210", "shell", "id")): ok("uid=2000(shell)")}, adb=True)
        with patch.object(privilege, "_exists", return_value="não encontrado"), patch.object(privilege.shutil, "which", return_value=None), patch.object(privilege.Path, "open", mock_open(read_data="")):
            state = privilege.privilege_probe(ctx)
        self.assertTrue(state["adb"])
        self.assertEqual(state["classification"], "ADB_SHELL")
        self.assertEqual(state["mode"], "PADRÃO+")


if __name__ == "__main__":
    unittest.main()
