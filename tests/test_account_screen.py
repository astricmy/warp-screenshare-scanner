import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from warp_scanner.account_screen import username, observe
from scan import deliver


class AccountTests(unittest.TestCase):
    def test_account_field_only(self):
        data = '<hierarchy><node package="com.discord" text="Minha conta"/><node package="com.discord" content-desc="Nome de usuário, jogador_123"/></hierarchy>'
        self.assertEqual(username(data, "Discord"), "jogador_123")
        for variant in (data.replace("com.discord", "app.other"), data.replace("Minha conta", "Chat"),
                        data.replace("Nome de usuário", "Nome de exibição"), data.replace('content-desc=', 'password="true" content-desc='),
                        data.replace("</hierarchy>", '<node package="com.discord" text="Username: outro"/></hierarchy>')):
            self.assertIsNone(username(variant, "Discord"))

    def test_no_capture_without_adb_or_if_different_foreground(self):
        ctx = SimpleNamespace(privilege={"adb":False}, run=Mock())
        self.assertIsNone(observe(ctx, "Roblox", Mock(side_effect=AssertionError)))
        ctx.run.assert_not_called()
        ctx.privilege["adb"] = True
        ctx.run.return_value = SimpleNamespace(ok=True, text="topResumedActivity: com.other/.Account")
        self.assertIsNone(observe(ctx, "Roblox", lambda _: True, lambda _: None))
        self.assertEqual(ctx.run.call_count, 1)

    def test_missing_relay_does_not_prompt_for_token(self):
        with patch.dict("os.environ", {"WARP_RELAY_URL":""}), patch("scan.getpass.getpass", side_effect=AssertionError):
            self.assertFalse(deliver({}, [], False))
