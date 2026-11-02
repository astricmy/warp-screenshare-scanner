"""M4: rastros acessíveis; não recupera dados apagados nem copia bancos privados."""
import datetime as dt
import os
import re
from pathlib import Path
from .cheats import contextual_match, metadata
from .roblox import PACKAGE_RE, package_info, query, requirements


def collect(ctx):
    findings, checks = [], []
    checked = 0
    entries = ctx.signatures.get("entries", [])
    if ctx.privilege.get("root") or ctx.privilege.get("adb"):
        for entry in entries:
            for package in entry.get("pacotes", [])[:16]:
                if checked >= 64 or not PACKAGE_RE.fullmatch(package):
                    continue
                info = package_info(ctx, package)
                if not info.get("verified") or info.get("present"):
                    continue
                result, cap, failures = query(ctx, ["pm", "list", "packages", "-u", package], max_bytes=16384)
                if result and result.ok:
                    checked += 1
                    if re.search(r"(?m)^package:" + re.escape(package) + r"\s*$", result.text):
                        findings.append(ctx.finding("M4", "remoção", "Registro residual de pacote da base sem instalação ativa", {"package": package, "signature_id": entry.get("id"), "signature_verified": entry.get("verificado") is True,
                            "limite": "pm -u pode incluir apps de sistema/perfis desativados; não informa uso nem data de remoção."}, "PROVÁVEL" if entry.get("verificado") else "INDÍCIO", "removed" if entry.get("verificado") else "hint", cap))
    checks.append({"name": "Registros residuais de pacotes da base", "requires": "adb", "status": "OK" if checked else "NÃO VERIFICADO", "reason": f"Consultas direcionadas concluídas: {checked}; não equivale a histórico de execução."})
    for value in getattr(ctx, "files", []):
        path = Path(value)
        if not path.name.lower().startswith(".trashed-"):
            continue
        for entry in entries:
            if contextual_match(path.name.replace("_", " ").replace("-", " ").replace(".", " "), entry):
                try:
                    detail = metadata(path, ctx)
                    findings.append(ctx.finding("M4", "lixeira", "Arquivo com marca/contexto em entrada .trashed", {**detail, "signature_id": entry.get("id"), "limite": "Não demonstra quem removeu o arquivo nem que foi executado."}, "INDÍCIO", "hint", time=detail["mtime"]))
                except OSError:
                    pass
                break
    # A ausência de arquivos não prova limpeza; registrar só a condição técnica.
    empty = None
    download = ctx.storage / "Download"
    try:
        if not download.is_symlink():
            with os.scandir(download) as items:
                empty = next(items, None) is None
            changed = dt.datetime.fromtimestamp(download.stat().st_mtime, dt.timezone.utc)
            recent = 0 <= (dt.datetime.now(dt.timezone.utc) - changed).total_seconds() <= 24 * 3600
            if empty and recent:
                findings.append(ctx.finding("M4", "limpeza", "Download vazio com modificação nas últimas 24 horas", {"path": "Download", "mtime": changed.isoformat(), "limite": "Pasta vazia e mtime recente não comprovam limpeza nem ocultação."}, "INDÍCIO", "hint", time=changed.isoformat()))
    except OSError:
        pass
    checks.extend([
        {"name": "Uso anterior, UIDs órfãos e remoções em logs", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Usagestats, notificações, batterystats, netstats, logcat e bugreport globais não são lidos: podem conter atividade pessoal não relacionada."},
        {"name": "SQLite/WAL/freelist e ABX", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Não copia bancos nem recupera registros apagados: a leitura bruta pode incluir mensagens, cookies e credenciais."},
        {"name": "Lixeiras de fabricantes/apps", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Apenas nomes .trashed em caminhos já autorizados; lixeiras privadas e pastas de mídia não são abertas."},
    ])
    return {"module": "M4", "requires": "none", "status": "PARCIAL", "reason": "Somente rastros observáveis e minimizados; não há recuperação de arquivos apagados.", "findings": findings, "data": {"download_empty": empty, "residual_queries": checked}, "checks": checks}
