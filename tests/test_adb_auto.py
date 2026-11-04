import unittest
from types import SimpleNamespace
from unittest.mock import patch
from warp_scanner.core import CommandResult
from warp_scanner import ui


def ok(text=""):
    return CommandResult(True, text)


class AdbAutoTests(unittest.TestCase):
    def test_reuses_only_local_connected_endpoint(self):
        def run(argv, **kwargs):
            if argv == ["adb", "devices"]:
                return ok("List of devices attached\n192.168.1.3:5555\tdevice\n127.0.0.1:39421\tdevice\n")
            if argv == ["adb", "-s", "127.0.0.1:39421", "shell", "id"]:
                return ok("uid=2000(shell) gid=2000(shell)")
            self.fail(str(argv))
        args = SimpleNamespace()
        with patch.object(ui, "run_command", side_effect=run), patch("builtins.input", side_effect=AssertionError("Sem pergunta")):
            ui.adb_guide(args)
        self.assertTrue(args.adb_connected)
        self.assertEqual(args.adb_serial, "127.0.0.1:39421")

    def test_discovers_tls_port_on_device(self):
        args = SimpleNamespace()
        with patch.object(ui, "run_command", side_effect=[
            ok(""), ok("42123\n"), ok("connected"), ok("uid=2000(shell)")
        ]) as run:
            self.assertTrue(ui._adb_auto(args))
        self.assertEqual(run.call_args_list[2].args[0], ["adb", "connect", "127.0.0.1:42123"])

    def test_connect_text_alone_is_not_a_verified_connection(self):
        args = SimpleNamespace(adb_connected=False)
        with patch.object(ui, "run_command", side_effect=[ok(""),ok("42123"),ok("connected"),ok("uid=10234(termux)")]):
            self.assertFalse(ui._adb_auto(args))
        self.assertFalse(args.adb_connected)

    def test_never_uses_remote_serial_or_invalid_property_as_address(self):
        args = SimpleNamespace()
        with patch.object(ui, "run_command", side_effect=[
            ok("192.168.1.8:5555\tdevice\nemulator-5554\tdevice\n"),
            ok("192.168.1.8:5555")
        ]) as run:
            self.assertFalse(ui._adb_auto(args))
        self.assertEqual(run.call_count, 2)

    def test_bad_port_retries_and_empty_skips(self):
        with patch("builtins.input", side_effect=["bad", "65536", "12345"]):
            self.assertEqual(ui._ask_adb_port("Porta"), "12345")
        with patch("builtins.input", return_value=""):
            self.assertEqual(ui._ask_adb_port("Porta"), "")

    def test_pairing_reconnects_automatically(self):
        args = SimpleNamespace()
        with patch.object(ui, "_adb_auto", side_effect=[False, False, True]), \
             patch("builtins.input", side_effect=["", "12345"]), \
             patch("subprocess.run", return_value=SimpleNamespace(returncode=0)) as pair:
            ui.adb_guide(args)
        self.assertEqual(pair.call_args.args[0], ["adb", "pair", "127.0.0.1:12345"])
