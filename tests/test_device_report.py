import datetime as dt
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

from test_android import MockContext, ok
from warp_scanner import device_history, environment, identity, privilege, roblox
from warp_scanner.core import sanitize


class DeviceReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = Path(self.temp.name)

    def test_device_and_android_settings_use_only_public_props_and_binary_states(self):
        props = {"ro.product.brand": "Empresa", "ro.product.model": "Modelo 42",
                 "ro.build.version.release": "14", "ro.build.version.sdk": "34",
                 "ro.build.version.security_patch": "2024-02-01"}
        ctx = MockContext(self.storage, {("none", ("getprop", p)): ok(v) for p, v in props.items()})
        for setting, value in (("auto_time", "0"), ("adb_enabled", "null")):
            ctx.responses["none", ("settings", "get", "global", setting)] = ok(value)
        report = sanitize(environment.collect(ctx))
        self.assertEqual(report["data"]["device"], {"brand": "Empresa", "model": "Modelo 42",
                         "android": "14", "api_level": 34, "security_patch": "2024-02-01"})
        self.assertIs(report["data"]["auto_time"], False)
        self.assertIsNone(report["data"]["usb_debug"])
        self.assertTrue(all(len(argv) == 2 and argv[1] in set(props) | {"ro.kernel.qemu", "ro.hardware"}
                            for argv, *_ in ctx.calls if argv[0] == "getprop"))
        ctx.responses["none", ("getprop", "ro.build.version.security_patch")] = ok("2024-02-31")
        ctx.responses["none", ("settings", "get", "global", "auto_time")] = ok("malformed")
        ctx.responses["none", ("settings", "get", "global", "adb_enabled")] = ok("1")
        data = environment.collect(ctx)["data"]
        self.assertIs(data["usb_debug"], True)
        self.assertIsNone(data["auto_time"])
        self.assertNotIn("security_patch", data["device"])

    def test_root_unavailable_suspicion_and_authority_are_different(self):
        ctx = MockContext(self.storage)
        with patch.object(privilege, "_exists", return_value="não encontrado"), \
             patch.object(privilege.shutil, "which", return_value=None), \
             patch.object(privilege.Path, "open", mock_open(read_data="")):
            self.assertIsNone(privilege.privilege_probe(ctx)["root_result"]["value"])
            ctx.responses["none", ("pm", "path", "com.topjohnwu.magisk")] = ok("package:/data/app/test/base.apk")
            state = privilege.privilege_probe(ctx)
            self.assertIn("Magisk", state["root_result"]["reason"])
            self.assertIs(state["root_result"]["value"], True)
            self.assertIs(state["root"], False)
            ctx.responses["none", ("id",)] = ok("uid=0(root)")
            state = privilege.privilege_probe(ctx)
            self.assertIs(state["root"], True)
            self.assertIn("processo", state["root_result"]["reason"])

    def test_owner_date_is_not_taken_from_work_profile(self):
        dump = """Packages:
  Package [com.roblox.client] (abc):
    User 10: installed=true
      firstInstallTime=2026-10-30 01:02:03
    User 0: installed=true
      firstInstallTime=2026-10-29 02:03:04
"""
        command = ("none", ("dumpsys", "package", "com.roblox.client"))
        info = roblox.package_info(MockContext(self.storage, {command: ok(dump)}), roblox.PACKAGE)
        self.assertEqual(info["owner_first_install"], "2026-10-29 02:03:04")
        info = roblox.package_info(MockContext(self.storage, {command: ok(dump.replace("User 0:", "User 20:"))}), roblox.PACKAGE)
        self.assertNotIn("owner_first_install", info)

    def test_recent_install_needs_prior_activity_in_same_window(self):
        now = 1793498400
        installed = dt.datetime.fromtimestamp(now - 3600).astimezone()
        value = {"present": True, "owner_first_install": installed.isoformat()}
        self.assertIsNone(device_history.reinstall_status(value, None, now)["value"])
        first = int(installed.timestamp() * 1000)
        usage = {"primeiro_inicio_pareado_ms": first}
        self.assertIsNone(device_history.reinstall_status(value, usage, now)["value"])
        usage["primeiro_inicio_pareado_ms"] = first - 1
        self.assertIs(device_history.reinstall_status(value, usage, now)["value"], True)
        self.assertIs(device_history.reinstall_status(value, None, now + 72*3600)["value"], False)
        self.assertIsNone(device_history.reinstall_status(value, usage, now - 7200)["value"])

    @unittest.skipUnless(shutil.which("bash"), "shell Android/POSIX indisponível")
    def test_usage_projection_never_combines_two_android_profiles(self):
        dump = """user=10
Last 24 hour events (beginTime=1793490000000 endTime=1793497200000 )
  time=1793490100000 type=ACTIVITY_RESUMED package=com.roblox.client instanceId=1
user=0
Last 24 hour events (beginTime=1793490000000 endTime=1793497200000 )
  time=1793493600000 type=ACTIVITY_RESUMED package=com.roblox.client instanceId=1
  time=1793493660000 type=ACTIVITY_PAUSED package=com.roblox.client instanceId=1
user=12
Last 24 hour events (beginTime=1793490000000 endTime=1793497200000 )
  time=1793497000000 type=ACTIVITY_PAUSED package=com.roblox.client instanceId=1
"""
        script = device_history.EVENT_PROJECTION.replace("dumpsys usagestats -c com.roblox.client", "cat", 1)
        script = script.replace("PATH=/system/bin:/system/xbin; ", "")
        projected = subprocess.run(["bash", "-c", script], input=dump.encode(), capture_output=True, check=True).stdout.decode()
        self.assertNotIn("1793490100000", projected)
        usage = device_history.observed_usage(projected, 1793497200000)
        self.assertEqual(usage["segundos_pareados_observados"], 60)
        self.assertEqual(usage["primeiro_inicio_pareado_ms"], 1793493600000)

    def test_discord_and_roblox_identity_distinguish_disclosure_from_verification(self):
        self.assertEqual(identity.discord_identity("exemplo", "123456789012345678")["id"], "123456789012345678")
        self.assertNotIn("id", identity.discord_identity("exemplo", "abc"))
        ctx = MockContext(self.storage)
        ctx.args.nick, ctx.args.expected_nick = "Jogador", ""
        for code, description, status in [("", "", "não verificada"), ("WARP-1234", None, "não verificada"),
                                          ("WARP-1234", "outro código", "não confere"),
                                          ("WARP-1234", "WARP-1234", "verificada")]:
            with self.subTest(status=status):
                ctx.args.session_code = code
                profile = {"id": 42, "name": "Jogador", "description": description}
                with patch.object(identity, "get_json", side_effect=[{"data": [{"id": 42}]}, profile]):
                    self.assertEqual(identity.collect(ctx)["data"]["ownership_status"], status)
