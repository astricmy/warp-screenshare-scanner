import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import scan
from warp_scanner.identity import ask_profiles, collect, discord_identity


class ManualProfilesTests(unittest.TestCase):
    def test_prompts_retry_preserve_case_and_link_optional_id(self):
        args = scan.arguments([])
        did = "123456789012345678"
        ask = Mock(side_effect=["???", "@Player_123", "bad user", "@jogador.teste", "invalid", did])
        ask_profiles(args, True, ask)
        self.assertEqual((args.nick, args.discord_user, args.discord_id), ("Player_123", "jogador.teste", did))
        self.assertEqual(discord_identity(args.discord_user, args.discord_id)["profile_url"], "https://discord.com/users/" + did)

    def test_nick_without_discord_id_and_opt_out(self):
        args = scan.arguments(["--nick", "Player_123"])
        ask_profiles(args, True, Mock(side_effect=["jogador", ""]))
        self.assertNotIn("profile_url", discord_identity(args.discord_user, args.discord_id))
        ask_profiles(args, False, Mock(side_effect=AssertionError("Discord recusado")))
        self.assertEqual(args.discord_user, "")

    def test_roblox_nick_survives_public_lookup_failure(self):
        ctx = SimpleNamespace(args=scan.arguments(["--nick", "Player_123"]))
        with patch("warp_scanner.identity.get_json", side_effect=OSError):
            result = collect(ctx)
        self.assertEqual(result["data"]["nick"], "Player_123")
        self.assertNotIn("profile_url", result["data"])
        self.assertEqual(result["status"], "PARCIAL")

    def test_missing_relay_does_not_prompt_for_token(self):
        with patch.dict("os.environ", {"WARP_RELAY_URL":""}), patch("scan.getpass.getpass", side_effect=AssertionError):
            self.assertFalse(scan.deliver({}, [], False))
