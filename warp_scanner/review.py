"""Revisão explicável antes de calcular o risco. Mantém o histórico das decisões."""
from .cheats import bounded_hash
from pathlib import Path
import time


def apply(modules, ctx):
    trusted = getattr(ctx, "review_trusted_hashes", set())
    observed = {p.relative_to(ctx.storage).as_posix(): p for p in ctx.files if p.is_relative_to(ctx.storage)}
    deadline = time.monotonic() + 6
    seen = set()
    for module in modules:
        for finding in module.get("findings", []):
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                continue
            path = evidence.get("path") or evidence.get("caminho")
            signature = evidence.get("signature_id")
            key = (module["module"], finding["description"], path, signature, evidence.get("domain"), finding["time"])
            reason = None
            if key in seen:
                reason = "Observação repetida da mesma fonte."
            seen.add(key)
            if module["module"] == "M3" and path in observed and signature and trusted and ctx.consent.get("files"):
                digest = evidence.get("sha256")
                if not digest:
                    try:
                        digest = bounded_hash(observed[path], ctx.storage, deadline)
                    except (OSError, ValueError, TimeoutError):
                        pass
                if digest in trusted:
                    reason = "O mesmo arquivo corresponde a uma referência oficial verificada em M10."
            if reason:
                finding.update(level="INFORMATIVO", weight=0, review=reason)
    return modules
