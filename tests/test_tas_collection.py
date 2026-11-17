import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from warp_scanner import tas
from warp_scanner.tas_roots import Area


class DeviceWideTASTests(unittest.TestCase):
    def test_loose_files_across_volumes_with_one_inaccessible_area(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            areas = [Area(workspace / name, name, kind) for name, kind in (
                ("Interno", "primary"), ("Cartao", "removable"), ("Termux", "termux"), ("Protegida", "data"))]
            for area in areas[:3]:
                nested = area.path / "Jogos" / "replays"
                nested.mkdir(parents=True)
                (nested / "partida.TAS").touch()
            with zipfile.ZipFile(areas[0].path / "copia.zip", "w") as archive:
                archive.writestr("interno.tas", "fixture")
            ctx = SimpleNamespace(storage=areas[0].path, privilege={},
                                  finding=lambda m,c,d,e,l,w,**kw: {"evidence": e})
            with patch.object(tas.tas_roots, "discover", return_value=(areas, [])), \
                 patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("ZIP aberto")):
                matches, summary, checks = tas.collect(ctx, 10)
        self.assertEqual(len(matches), 3)
        self.assertTrue(all(f["evidence"]["caminho_android"].endswith("partida.TAS") for f in matches))
        self.assertEqual(summary["status"], "PARCIAL")
        self.assertEqual([c["status"] for c in checks], ["OK", "OK", "OK", "NÃO VERIFICADO"])
