import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import config
import scan
from warp_scanner.core import Context, sanitize, unavailable
from warp_scanner import report, discord, integrity, identity


def context():
    args=scan.arguments(["--test","--session-code","WARP-TESTE"])
    return Context(args,json.loads((config.BASE_DIR/"signatures.json").read_text(encoding="utf-8")),
                   json.loads((config.BASE_DIR/"settings.json").read_text()),{"files":False,"clipboard":False},Path("/storage/emulated/0"))


class CoreReportTests(unittest.TestCase):
    def test_test_mode_no_collection_network_or_consent(self):
        with patch("builtins.input",side_effect=AssertionError("input")),patch("warp_scanner.net.request",side_effect=AssertionError("network")),patch("warp_scanner.core.run_command",side_effect=AssertionError("command")),patch("scan.iter_allowed_files",side_effect=AssertionError("storage")),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scan.main(["--test","--plain"]),0)

    def test_refusal_precedes_probe_or_file_scan(self):
        with patch("scan.os.name","posix"),patch("builtins.input",return_value="NÃO"),patch("scan.load_signatures",side_effect=AssertionError("collection")),patch("scan.iter_allowed_files",side_effect=AssertionError("collection")),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scan.main([]),0)

    def test_no_coverage_cannot_be_clean(self):
        ctx=context()
        data=report.build(ctx,[unavailable(f"M{i}","indisponível") for i in range(1,9)],{})
        self.assertEqual(data["score"],0)
        self.assertIn("INCONCLUSIVO",data["verdict"])

    def test_secrets_never_survive_output(self):
        ctx=context()
        found=ctx.finding("M8","scripts","Script",{"trecho":"loadstring senha=UNIQUE_PRIVATE_SENTINEL", "urls":["https://example.com/file?key=UNIQUE_PRIVATE_SENTINEL"]},"INDÍCIO","hint")
        modules=[unavailable(f"M{i}","indisponível") for i in range(1,9)]
        modules[-1]["findings"]=[found]
        data=report.build(ctx,modules,{})
        self.assertNotIn("UNIQUE_PRIVATE_SENTINEL",json.dumps(report.envelope(data)))
        self.assertIn("[REDIGIDO]",report.render_text(data))

    def test_structured_dates_hashes_and_public_profile_preserved(self):
        value={"profile_url":"https://www.roblox.com/users/1234567890/profile","ctime_metadados":"2026-10-30T12:00:00+00:00","sha256":"1"*64}
        self.assertEqual(sanitize(value),value)
        self.assertEqual(sanitize({"time":"senha=PRIVATE"})["time"],"[REDIGIDO]")

    def test_discord_embeds_with_100_findings_fit_limits(self):
        ctx=context()
        modules=[unavailable(f"M{i}","indisponível") for i in range(1,9)]
        modules[-1]["findings"]=[ctx.finding("M8","scripts","Exemplo "*80,{"trecho":"x"*1000},"PROVÁVEL","script_loader") for _ in range(100)]
        data=report.build(ctx,modules,{})
        payload=report.discord_payload(data)
        total=0
        for embed in payload["embeds"]:
            total+=len(embed.get("title",""))+len(embed.get("description",""))+len(embed.get("footer",{}).get("text",""))
            self.assertLessEqual(len(embed.get("description","")),4096)
            for field in embed.get("fields",[]):
                self.assertLessEqual(len(field["value"]),1024)
                total+=len(field["name"])+len(field["value"])
        self.assertLessEqual(total,6000)

    def test_429_retries_identical_payload_and_respects_delay(self):
        error=HTTPError("https://relay.invalid/report",429,"quota",{},io.BytesIO(b'{"retry_after":35}'))
        with patch.dict(os.environ,{"WARP_RELAY_URL":"https://relay.invalid"}),patch("warp_scanner.discord.request",side_effect=[error,b'{"ok":true}']) as req:
            delays=[]
            self.assertTrue(discord.send({"scan_id":"example"},token="temporary",sleep=delays.append)[0])
            self.assertEqual(delays,[35])
            self.assertEqual(req.call_args_list[0],req.call_args_list[1])

    def test_untrusted_signature_origin_does_not_receive_session_token(self):
        raw=b'{"entries":[],"scripts":{}}'
        import hashlib
        with patch.dict(os.environ,{"WARP_RELAY_URL":"https://staff.invalid","WARP_SIGNATURES_URL":"https://other.invalid/signatures","WARP_SIGNATURES_SHA256":hashlib.sha256(raw).hexdigest(),"WARP_SESSION_TOKEN":"private-value"}),patch("warp_scanner.integrity.request",return_value=raw) as req:
            integrity.load_signatures(config.BASE_DIR)
            self.assertNotIn("Authorization",req.call_args.kwargs["headers"])

    def test_identity_only_checks_exact_session_code_and_discards_description(self):
        ctx=context();ctx.args.nick="JogadorTeste"
        with patch("warp_scanner.identity.get_json",side_effect=[{"data":[{"id":1234567890}]},{"id":1234567890,"name":"JogadorTeste","description":"WARP-TESTE-OUTRO texto pessoal","displayName":"Teste"}]):
            result=identity.collect(ctx)
        self.assertFalse(result["data"]["ownership_verified"])
        self.assertNotIn("texto pessoal",json.dumps(result))
        self.assertEqual(result["data"]["profile_url"],"https://www.roblox.com/users/1234567890/profile")

    def test_manifest_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                integrity.verify_manifest(Path(directory),"a"*64+"  ../escape.py")


if __name__=="__main__":
    unittest.main()
