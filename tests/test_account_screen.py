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
        self.assertEqual(ctx.run.call_count, 6)
        self.assertEqual(ctx.account_observations["Roblox"]["status"], "NÃO VERIFICADO")

    def test_nested_username_row_with_edit_button_and_inherited_package(self):
        xml = '<hierarchy><node package="com.roblox.client"><node text="Account Info"/><node><node text="Username:"/><node><node text="Player_123"/></node><node text="Edit"/></node></node></hierarchy>'
        self.assertEqual(username(xml, "Roblox"), "Player_123")
        self.assertIsNone(username(xml.replace('<node><node text="Player_123"', '<node password="true"><node text="Player_123"'), "Roblox"))

    def test_late_foreground_is_retried_and_stops_on_success(self):
        foreground = SimpleNamespace(ok=True, text="topResumedActivity=ActivityRecord{ x com.roblox.client/.Activity }")
        other = SimpleNamespace(ok=True, text="topResumedActivity=ActivityRecord{ x com.termux/.Activity }")
        xml = '<hierarchy><node package="com.roblox.client" text="Account Info"/><node package="com.roblox.client" text="Username: Player_123"/></hierarchy>'
        ctx = SimpleNamespace(privilege={"adb":True}, args=SimpleNamespace(), run=Mock(side_effect=[other, foreground, SimpleNamespace(ok=True,text=xml), foreground]))
        self.assertEqual(observe(ctx, "Roblox", lambda _:True, lambda _:None), "Player_123")
        self.assertEqual(ctx.run.call_count, 4)
        self.assertEqual(ctx.args.account_observations["Roblox"]["status"], "OBSERVADO")

    def test_observed_roblox_resolves_profile_and_survives_api_failure(self):
        from warp_scanner.identity import collect
        args = SimpleNamespace(visible_roblox="Player_123",nick="",session_code="WARP-TESTE",expected_nick="")
        ctx = SimpleNamespace(args=args)
        with patch("warp_scanner.identity.get_json", side_effect=[{"data":[{"id":123}]}, {"id":123,"name":"Player_123","description":"WARP-TESTE"}]):
            result = collect(ctx)
        self.assertEqual(result["data"]["profile_url"], "https://www.roblox.com/users/123/profile")
        self.assertFalse(result["data"]["ownership_verified"])
        with patch("warp_scanner.identity.get_json", side_effect=OSError):
            result = collect(ctx)
        self.assertEqual(result["data"]["nick"], "Player_123")
        self.assertEqual(result["status"], "PARCIAL")

    def test_missing_relay_does_not_prompt_for_token(self):
        with patch.dict("os.environ", {"WARP_RELAY_URL":""}), patch("scan.getpass.getpass", side_effect=AssertionError):
            self.assertFalse(deliver({}, [], False))
