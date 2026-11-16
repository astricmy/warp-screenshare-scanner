import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from warp_scanner import exit_history, processes, text_model
from warp_scanner.core import CommandResult


class RuntimeReviewTests(unittest.TestCase):
    def test_android_retained_exit_history_is_scoped_and_minimized(self):
        ctx = SimpleNamespace(privilege={"adb": True}, consent={"runtime_logs": False}, run=Mock())
        self.assertEqual(exit_history.collect_exit_history(ctx)[0], {})
        ctx.run.assert_not_called()
        ctx.consent["runtime_logs"] = True
        ctx.run.return_value = CommandResult(True, " process=com.roblox.client reason=5 (CRASH_NATIVE)\n"
                                             " process=com.roblox.client:extra reason=4\n"
                                             " description=process=com.roblox.client reason=6")
        counts, check = exit_history.collect_exit_history(ctx)
        self.assertEqual(counts, {"Falha nativa": 1})
        self.assertEqual(check["status"], "PARCIAL")
        self.assertEqual(ctx.run.call_args.args[0], ["dumpsys", "activity", "exit-info", "com.roblox.client"])

    def test_triage_on_unseen_samples_and_unknown(self):
        self.assertEqual(text_model.review_priority("local myLoader = game:HttpGet('sample'); loadstring(myLoader)()"), text_model.HIGH)
        self.assertEqual(text_model.review_priority("Este tutorial explica como reconhecer chamadas de hookfunction e hookmetamethod."), text_model.NORMAL)
        self.assertEqual(text_model.review_priority("comprar arroz amanhã"), text_model.UNKNOWN)

    def test_log_consent_and_running_process_required(self):
        for consent, pids in ((False, ["200"]), (True, [])):
            ctx = SimpleNamespace(consent={"runtime_logs": consent}, run=Mock())
            findings, check = processes.linker_diagnostics(ctx, pids)
            self.assertEqual(findings, [])
            self.assertEqual(check["status"], "NÃO VERIFICADO")
            ctx.run.assert_not_called()

    def test_diagnostics_filtered_at_source_and_only_marker_retained(self):
        def run(argv, **kwargs):
            if argv[0] == "pm":
                return CommandResult(True, "package:com.roblox.client uid:10023")
            self.assertIn("--uid=10023", argv)
            self.assertIn("--pid=1234", argv)
            self.assertIn("*:S", argv)
            return CommandResult(True, "W/linker  : failed to load /private/libfrida-gadget.so for personal-info\nI/other: libxposed_art.so")
        ctx = SimpleNamespace(consent={"runtime_logs": True}, privilege={"adb":True}, run=run,
                              finding=lambda *args: args)
        findings, check = processes.linker_diagnostics(ctx, ["1234"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][3]["biblioteca"], "libfrida-gadget.so")
        self.assertNotIn("personal-info", repr(findings))
        self.assertEqual(findings[0][4], "INFORMATIVO")
        self.assertEqual(check["status"], "PARCIAL")
