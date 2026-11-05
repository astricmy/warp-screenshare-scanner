import io
import unittest
from urllib.error import HTTPError
from unittest.mock import patch
from warp_scanner.discord import cloud_token


class CloudSessionTests(unittest.TestCase):
    def test_transient_failure_retries_without_manual_token(self):
        error = HTTPError("https://fixture.invalid/session", 503, "", {}, io.BytesIO())
        with patch("warp_scanner.discord.request", side_effect=[error, b'{"token":"auto.fixture"}']) as request:
            waits = []
            self.assertEqual(cloud_token("fixture", "WARP-TESTE", waits.append), "auto.fixture")
            self.assertEqual(waits, [1])
            self.assertEqual(request.call_args_list[0], request.call_args_list[1])

    def test_invalid_invite_is_not_retried(self):
        error = HTTPError("https://fixture.invalid/session", 401, "", {}, io.BytesIO())
        with patch("warp_scanner.discord.request", side_effect=error) as request:
            with self.assertRaises(HTTPError):
                cloud_token("fixture", "WARP-TESTE", lambda _: None)
            self.assertEqual(request.call_count, 1)

    def test_rate_limit_delay_is_respected(self):
        error = HTTPError("https://fixture.invalid/session", 429, "", {}, io.BytesIO(b'{"retry_after":4}'))
        with patch("warp_scanner.discord.request", side_effect=[error, b'{"token":"auto.fixture"}']):
            waits = []
            cloud_token("fixture", "WARP-TESTE", waits.append)
            self.assertEqual(waits, [4])
