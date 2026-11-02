"""Localização de achados já autorizados, sem pesquisar o restante do aparelho."""
from pathlib import PurePosixPath


def add_locations(ctx, modules):
    # Só atribuir caminho absoluto a objetos observados pela caminhada permitida.
    observed = {}
    for path in ctx.files:
        try:
            relative = path.relative_to(ctx.storage).as_posix()
        except ValueError:
            continue
        observed[relative] = path.as_posix()
    for module in modules:
        for finding in module.get("findings", []):
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                continue
            name = evidence.get("caminho") or evidence.get("path")
            if not isinstance(name, str) or "[REDIGIDO]" in name:
                continue
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts:
                continue
            if name in observed:
                evidence["caminho_android"] = observed[name]
            elif module.get("module") == "M4" and name == "Download":
                evidence["caminho_android"] = (ctx.storage / "Download").as_posix()
