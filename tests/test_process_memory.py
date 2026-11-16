import unittest
from types import SimpleNamespace
from unittest.mock import patch

from warp_scanner import processes
from warp_scanner.core import CommandResult


def region(flags, name=""):
    return f"1000-2000 {flags} 00000000 00:01 123 {name}"


class ProcessMemoryTests(unittest.TestCase):
    def test_classifies_regions_and_excludes_android_jit(self):
        rows = [region("rwxp"), region("rwxp", "[anon:runtime]"), region("r-xp", "/memfd:jit-cache (deleted)"),
                region("r-xp", "/memfd:anonymous-code (deleted)"), region("rw-p", "/memfd:data"),
                region("r-xp", "/data/app/game/libgame.so (deleted)"), region("r--p", "/data/app/game/libgame.so (deleted)")]
        paths, counts, incomplete = processes.inspect_maps("\n".join(rows))
        self.assertEqual(paths, [])
        self.assertFalse(incomplete)
        self.assertEqual(counts["regiões"], 7)
        self.assertEqual(counts["executáveis"], 5)
        self.assertEqual(counts["jit_reconhecido"], 1)
        self.assertEqual(counts["anônima_gravável_executável"], 2)
        self.assertEqual(counts["memfd_executável"], 1)
        self.assertEqual(counts["biblioteca_executável_removida"], 1)

    def test_partial_on_invalid_or_truncated_map(self):
        with patch.object(processes, "_MAP_LIMIT", 2):
            for text in ("bad\n" + region("r-xp"), "\n".join([region("r-xp")] * 3)):
                self.assertTrue(processes.inspect_maps(text)[2])

    def test_uses_confirmed_process_and_releases_only_metadata(self):
        def run(argv, **kwargs):
            if argv == ["pidof", processes.PACKAGE]:
                return CommandResult(True, "1234")
            if argv[0] == "sh":
                self.assertEqual(argv[3:6], ["warp-proc", "1234", processes.PACKAGE])
                self.assertIn("cmdline", argv[2])
                samples = {"maps": region("r-xp", "/memfd:private-name (deleted)"),
                           "status": "TracerPid:\t0\nVmRSS:\t20 kB\n",
                           "smaps_rollup": "Rss: 24 kB\nPss: 18 kB\nAnonymous: 8 kB\nSwap: 2 kB\n"}
                return CommandResult(True, samples[argv[6]])
            return CommandResult(False)
        ctx = SimpleNamespace(consent={}, privilege={"adb":True}, run=run, finding=lambda *a: a)
        with patch.object(processes, "collect_exit_history", return_value=([], {"status": "NÃO VERIFICADO"})):
            report = processes.collect(ctx)
        self.assertEqual(report["data"]["mapas_observados"]["memfd_executável"], 1)
        self.assertEqual(report["data"]["smaps_rollup_kib"][0]["Pss"], 18)
        self.assertNotIn("private-name", repr(report))
        self.assertEqual(report["findings"][0][4:6], ("INFORMATIVO", "artifact"))
