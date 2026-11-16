"""Resumo do histórico de encerramentos do processo principal mantido pelo Android."""
import re
from collections import Counter

from .roblox import PACKAGE


_REASONS = {3: "Memória insuficiente", 4: "Falha do aplicativo", 5: "Falha nativa", 6: "Aplicativo sem resposta"}
_ROW = re.compile(r"\bprocess=com\.roblox\.client[ \t]+reason=(\d{1,3})\b")


def collect_exit_history(ctx):
    check = {"name": "Histórico de encerramentos do Roblox", "requires": "adb", "status": "NÃO VERIFICADO"}
    if not getattr(ctx, "consent", {}).get("runtime_logs"):
        return {}, dict(check, reason="Leitura de diagnósticos desativada.")
    for capability in ("root", "adb"):
        if not ctx.privilege.get(capability):
            continue
        result = ctx.run(["dumpsys", "activity", "exit-info", PACKAGE], requires=capability,
                         timeout=5, max_bytes=65536)
        if not result.ok:
            continue
        counts = Counter()
        for line in result.text.splitlines():
            # Exclui linhas de descrição livre e processos secundários.
            if not line.lstrip().startswith(("process=", "ApplicationExitInfo #")):
                continue
            match = _ROW.search(line.partition(" description=")[0])
            if match:
                counts[_REASONS.get(int(match[1]), "Outros motivos")] += 1
        if counts:
            return dict(counts), dict(check, requires=capability, status="PARCIAL",
                                      reason="Registros retidos pelo Android: " + ", ".join(f"{k} ({v})" for k, v in counts.items()) + ".")
    return {}, dict(check, reason="Histórico indisponível ou sem registros reconhecíveis do Roblox.")
