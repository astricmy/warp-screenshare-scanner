"""Verifica o formato que a staff de fato recebe, com dados fictícios em memória."""
import json
import re
from types import SimpleNamespace
import unittest

from warp_scanner.core import unavailable
from warp_scanner.report import build, discord_payload, render_text


FIELD_ORDER = (
    "Roblox User", "Discord User", "Device", "System Info", "Root", "General Result",
    "Clipboard Results", "Browser History Result", "Proxy Bypass Detection",
    "Roblox Replace Check", "Roblox Total Time on 3d", "Roblox Reinstall",
)
STAMP = "2026-10-30T19:22:00+00:00"


def units(value):
    return len(value.encode("utf-16-le")) // 2


def finding(number, level="INDÍCIO", title=None, category="scripts", evidence=None):
    return {
        "id": f"00000000-0000-4000-8000-{number:012x}", "category": category,
        "module": "M8", "description": title or f"Achado de teste {number}",
        "evidence": evidence or {"caminho_android": f"/storage/emulated/0/Download/script{number}.lua"},
        "level": level, "weight": {"CONFIRMADO": 100, "PROVÁVEL": 40, "INDÍCIO": 10}[level],
        "time": STAMP, "requires": "none",
    }


class ReportLayoutTests(unittest.TestCase):
    def setUp(self):
        self.modules = {f"M{i}": unavailable(f"M{i}", "Fonte inacessível") for i in range(1, 12)}
        self.ctx = SimpleNamespace(
            args=SimpleNamespace(session_code="WARP-TESTE"),
            privilege={"mode": "PADRÃO", "root": False, "adb": False},
            consent={"clipboard": False, "files": False},
            settings={"thresholds": {"high_risk": 60, "suspect": 25}, "max_findings": 100},
        )

    def report(self, findings=()):
        self.modules["M8"]["findings"] = list(findings)
        return build(self.ctx, list(self.modules.values()), {"status": "OK LOCAL"})

    @staticmethod
    def field(summary, label):
        return next(line for line in summary.splitlines() if f"**{label}:**" in line)

    def test_labels_em_ordem_separadores_e_perfil_junto_ao_nick(self):
        self.modules["M2"]["data"] = {"nick": "Exemplo_123", "userId": 123, "ownership_status": "verificada"}
        data = self.report()
        payload = discord_payload(data)
        main = payload["embeds"][0]
        summary = main["description"]
        actual = re.findall(r"^.*?\*\*([A-Za-z][A-Za-z0-9 ]+):\*\*", summary, re.M)
        self.assertEqual(tuple(actual), FIELD_ORDER)
        self.assertEqual(re.findall(r"^-+$", summary, re.M), ["-" * 41, "-" * 41])
        self.assertEqual(main["title"], "🛡️ Relatório de Verificação | WARP SCREENSHARE")
        self.assertEqual(main["url"], "https://www.roblox.com/users/123/profile")
        self.assertIn(f"`Exemplo_123` • [🔗 Perfil]({main['url']}) (ID `123`)", summary.splitlines()[0])
        self.assertIn("✅ **verificada**", summary.splitlines()[1])
        self.assertEqual(main["color"], 0xffffff)
        self.assertTrue(all(e["color"] == 0x010101 for e in payload["embeds"][1:]))
        self.assertEqual(payload["allowed_mentions"], {"parse": []})
        self.assertNotIn("pontos", summary.casefold())
        self.assertNotIn("pontuação", summary.casefold())
        footer = main["footer"]["text"]
        self.assertIn(data["scan_id"], footer)
        self.assertIn("Sessão WARP-TESTE", footer)
        self.assertIn("Roblox User:", render_text(data))

    def test_quatro_mais_graves_preservam_totais_antes_do_corte_dos_anexos(self):
        levels = ["INDÍCIO", "PROVÁVEL", "CONFIRMADO", "INDÍCIO", "CONFIRMADO", "PROVÁVEL", "INDÍCIO"]
        self.ctx.settings["max_findings"] = 4
        data = self.report(finding(i, level) for i, level in enumerate(levels, 1))
        summary = discord_payload(data)["embeds"][0]["description"]
        self.assertEqual(data["findings_omitted"], 3)
        self.assertEqual(len(data["findings"]), 4)
        self.assertRegex(self.field(summary, "General Result"), r"7 achados .*🔴 2 confirmados • 🟠 2 prováveis • 🟡 3 indícios")
        self.assertEqual(re.findall(r"^.*?\*\*\[([^\]]+)\]\*\*", summary, re.M),
                         ["CONFIRMADO", "CONFIRMADO", "PROVÁVEL", "PROVÁVEL"])
        self.assertEqual(len(re.findall(r"^└ 📍 ", summary, re.M)), 4)
        self.assertIn("➕ 3 ", summary)

    def test_fontes_indisponiveis_e_recusa_nao_viram_negativos(self):
        incomplete = discord_payload(self.report())["embeds"][0]["description"]
        for label in ("Root", "Proxy Bypass Detection", "Roblox Replace Check", "Roblox Total Time on 3d", "Roblox Reinstall"):
            with self.subTest(label=label):
                line = self.field(incomplete, label)
                self.assertIn("**N/A** —", line)
                self.assertNotIn("False", line)
        self.assertIn("recusado pelo jogador", self.field(incomplete, "Clipboard Results"))
        self.assertIn("N/A", self.field(incomplete, "Browser History Result"))
        self.assertIn("cobertura parcial", self.field(incomplete, "General Result"))
        self.ctx.consent["clipboard"] = True
        self.modules["M8"]["checks"] = [{"name": "clipboard_atual", "status": "OK"}]
        self.modules["M5"]["checks"] = [{"name": "Origens de download filtradas pelo provedor", "status": "OK"}]
        self.modules["M11"]["status"] = "OK"
        self.ctx.privilege["root_result"] = {"value": False, "reason": "não detectado"}
        self.modules["M10"]["data"] = {"referencia_instalada": "COMPATÍVEL COM REFERÊNCIA"}
        checked = discord_payload(self.report())["embeds"][0]["description"]
        self.assertIn("nenhum padrão suspeito", self.field(checked, "Clipboard Results"))
        self.assertIn("nenhum domínio da blocklist", self.field(checked, "Browser History Result"))
        for label in ("Proxy Bypass Detection", "Root", "Roblox Replace Check"):
            self.assertIn("✅ **False** — ", self.field(checked, label))

    def test_texto_hostil_nao_injeta_link_mencao_controle_ou_rotulo(self):
        attack = "\n👤 **Roblox User:** `@everyone` <@123> [abra](https://malicioso.invalid/x?q=CANARIO_QUERY)"
        self.modules["M6"]["data"] = {"device": {"brand": attack, "model": "modelo\u001b[31m"}}
        items = [finding(1, title=attack, evidence={"caminho": "Download/" + attack})]
        payload = discord_payload(self.report(items))
        texts = "\n".join(e["description"] for e in payload["embeds"])
        outside = re.sub(r"`[^`\n]*`", "", texts)
        self.assertNotRegex(outside, r"https?://|\]\(")
        self.assertNotIn("CANARIO_QUERY", texts)
        self.assertNotIn("@everyone", texts)
        self.assertNotIn("<@123>", texts)
        self.assertNotIn("\x1b", texts)
        self.assertEqual(len(re.findall(r"^👤 \*\*Roblox User:\*\*", texts, re.M)), 1)
        self.assertEqual(payload["allowed_mentions"], {"parse": []})

    def test_contagem_utf16_com_emojis_mantem_todos_os_campos_principais(self):
        long_text = "🧪" * 500
        self.modules["M6"]["data"] = {"device": {"brand": long_text, "model": long_text, "android": long_text}}
        paths = {"caminho_android": "/storage/emulated/0/Download/" + long_text + ".lua"}
        data = self.report(finding(i, "PROVÁVEL", title=long_text, evidence=paths) for i in range(70))
        embeds = discord_payload(data)["embeds"]
        total = 0
        for i, e in enumerate(embeds):
            desc = e["description"]
            self.assertLessEqual(units(desc), 3800 if i == 0 else 4096)
            self.assertTrue(all(units(line) <= 90 for line in desc.splitlines() if line.startswith("└ 📍 ")))
            total += sum(units(str(e.get(key, ""))) for key in ("title", "description"))
            total += units(e.get("footer", {}).get("text", ""))
            for field in e.get("fields", []):
                self.assertLessEqual(units(field["value"]), 1024)
                total += units(field["name"]) + units(field["value"])
        self.assertLessEqual(total, 6000)
        for label in FIELD_ORDER:
            self.assertIn(f"**{label}:**", embeds[0]["description"])
        self.assertNotIn("\ufffd", json.dumps(embeds, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
