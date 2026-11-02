import json
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from warp_scanner import authenticity, device_history, network, review


class NewModuleTests(unittest.TestCase):
    def test_sparse_usage_not_extrapolated(self):
        end = 1793550000000
        start = end - 86400000
        text = f"R {start} {end}\nE {start+1000} ACTIVITY_RESUMED 1\nE {start+11000} ACTIVITY_PAUSED 1"
        result = device_history.observed_usage(text, end)
        self.assertEqual(result["segundos_pareados_observados"], 10)
        self.assertIsNone(result["total_exato_72h"])

    def test_verified_signer_needs_correct_package(self):
        sha = "a" * 64
        base = {"roblox":{"official_certificates_sha256":[sha]}}
        self.assertEqual(authenticity.classify(base,"com.roblox.client","1","",[sha],[]),"COMPATÍVEL COM REFERÊNCIA")
        self.assertEqual(authenticity.classify(base,"com.example.fake","1","",[sha],[]),"INCONCLUSIVO")
        self.assertEqual(authenticity.classify(base,"com.roblox.client","1","",["b"*64],[]),"INCONCLUSIVO")

    def test_saved_wifi_keeps_no_ssid_or_proxy_secrets(self):
        text = "SSID MinhaRede\nMODE PAC\nPROXY https://user:segredo@proxy.example/conf.pac?privado=1"
        rows, known = network.parse_wifi(text)
        self.assertTrue(known)
        self.assertEqual(rows[0]["host"],"proxy.example")
        for private in ("MinhaRede","segredo","privado","conf.pac"):
            self.assertNotIn(private,json.dumps(rows))

    def test_optional_network_probes_are_not_made_without_consent(self):
        with patch.object(network,"_system_addresses",side_effect=AssertionError):
            self.assertEqual(network._active_tests(SimpleNamespace(consent={}),{}),([],network.UNKNOWN,[]))

    def test_verified_file_overrides_filename_score(self):
        root = Path("/storage/emulated/0")
        sha = "b"*64
        ctx = SimpleNamespace(storage=root,files=[root/"Download"/"Delta Executor.apk"],review_trusted_hashes={sha},consent={"files":True})
        finding = {"description":"Nome com contexto", "time":"agora","level":"INDÍCIO","weight":10,
                   "evidence":{"path":"Download/Delta Executor.apk","sha256":sha,"signature_id":"delta"}}
        review.apply([{"module":"M3","findings":[finding]}],ctx)
        self.assertEqual(finding["weight"],0)
