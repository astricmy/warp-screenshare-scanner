import unittest
import shutil
import subprocess
from unittest.mock import patch
from warp_scanner import network, device_history

class CollectorRegressionTests(unittest.TestCase):
    def test_filtered_permission_denial_stays_unknown(self):
        with patch.object(network, "_read", return_value=("UNAVAILABLE", "adb")):
            result, cap = network._filtered(object(), network.USAGE_FILTER, "test.app")
        self.assertIsNone(result)
        self.assertEqual(cap, "adb")

    def test_partial_filtered_output_not_accepted_after_denial(self):
        with patch.object(network, "_read", return_value=("MODE NONE\nUNAVAILABLE", "root")):
            result, _ = network._filtered(object(), network.WIFI_FILTER)
        self.assertIsNone(result)

    def test_legacy_activity_sequence_with_zero_instance(self):
        end = 1793550000000
        start = end - 86400000
        result = device_history.observed_usage(
            f"R {start} {end}\nE {start+1000} MOVE_TO_FOREGROUND 0\nE {start+11000} MOVE_TO_BACKGROUND 0", end)
        self.assertEqual(result["segundos_pareados_observados"], 10)
        self.assertIsNone(result["total_exato_72h"])


    @unittest.skipUnless(shutil.which("bash"), "Shell POSIX disponível no CI Linux")
    def test_projection_drains_remaining_dump_without_sigpipe(self):
        # Mais que um pipe buffer depois do intervalo útil expõe um break prematuro.
        prefix = """dumpsys() {
  printf '%s\n' '  user=0' '24 hour events (beginTime=1793463600000 endTime=1793550000000)'
  printf '%s\n' 'time=1793463601000 type=MOVE_TO_FOREGROUND package=com.roblox.client instanceId=1'
  printf '%s\n' 'time=1793463611000 type=MOVE_TO_BACKGROUND package=com.roblox.client instanceId=1'
  printf '%s\n' 'In-memory daily stats'
  for ((i=0; i<10000; i++)); do printf '%s\n' 'padding that should be drained and discarded'; done
}
"""
        script = device_history.EVENT_PROJECTION.replace("PATH=/system/bin:/system/xbin; ", "")
        result = subprocess.run(["bash", "-c", prefix + script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 3)
        usage = device_history.observed_usage(result.stdout, 1793550000000)
        self.assertEqual(usage["segundos_pareados_observados"], 10)

    @unittest.skipUnless(shutil.which("bash"), "Shell POSIX disponível no CI Linux")
    def test_projection_denied_is_failure(self):
        script = device_history.EVENT_PROJECTION.replace("PATH=/system/bin:/system/xbin; ", "")
        result = subprocess.run(["bash", "-c", "dumpsys() { printf 'Permission Denial\n'; }; " + script],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
