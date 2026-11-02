"""Contratos entre localização, identidade, anexos e instalador verificável."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace

import config
from warp_scanner.discord import multipart
from warp_scanner.identity import discord_identity
from warp_scanner.locations import add_locations


class DeliveryContracts(unittest.TestCase):
    def test_paths_belong_to_previous_observation(self):
        root = Path("/storage/emulated/0")
        ctx = SimpleNamespace(files=[root/"Download"/"Delta Executor.apk"], storage=root)
        module = {"module":"M3","findings":[{"evidence":{"path":value}} for value in
                  ("Download/Delta Executor.apk","../../data/private","Download/not-observed.apk")]}
        add_locations(ctx,[module])
        self.assertEqual(module["findings"][0]["evidence"]["caminho_android"],"/storage/emulated/0/Download/Delta Executor.apk")
        self.assertTrue(all("caminho_android" not in f["evidence"] for f in module["findings"][1:]))

    def test_discord_label_is_not_ownership(self):
        result = discord_identity("@jogador.exemplo")
        self.assertEqual(result["username"],"jogador.exemplo")
        self.assertFalse(result["ownership_verified"])
        for invalid in ("", "pessoa@example.org", "@everyone", "a\nidentidade"):
            self.assertNotIn("username",discord_identity(invalid))

    def test_direct_image_attachment_is_binary(self):
        png = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
        body, _ = multipart({"payload":{"embeds":[]},"attachments":[{
            "filename":"prova_teste.png","content_type":"image/png","content":base64.b64encode(png).decode()}]})
        self.assertIn(png,body)
        self.assertNotIn(base64.b64encode(png),body)

    def test_installer_verifies_and_rejects_changed_asset_before_copy(self):
        # Exercita exatamente o verificador do install.sh em um PREFIX descartável.
        installer = (config.BASE_DIR/"install.sh").read_text(encoding="utf-8")
        verifier = installer.split("<<'PY'\n",1)[1].split("\nPY\n",1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            files={"scan.py":b"pass\n","config.py":b"pass\n","signatures.json":b"{}","settings.json":b"{}"}
            manifest="".join(f"{hashlib.sha256(value).hexdigest()}  {name}\n" for name,value in files.items()).encode()
            pkg=root/"package.zip"
            with zipfile.ZipFile(pkg,"w") as archive:
                for name,value in files.items():
                    archive.writestr(name,value)
                archive.writestr("checksums.txt",manifest)
            (root/"checksums.txt").write_bytes(manifest)
            (root/"SHA256SUMS").write_text(hashlib.sha256(pkg.read_bytes()).hexdigest()+"  package.zip\n")
            prefix=root/"prefix"
            (prefix/"bin").mkdir(parents=True)
            cmd=[sys.executable,"-c",verifier,str(root),pkg.name,str(prefix),"0.1.0"]
            result=subprocess.run(cmd,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue((prefix/"bin"/"warp-scan").is_file())
            pkg.write_bytes(pkg.read_bytes()+b"alterado")
            self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0)
