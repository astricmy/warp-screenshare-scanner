"""M8: reconhecimento estático local; nunca baixa ou executa scripts."""
from __future__ import annotations

import hashlib
import io
import math
import re
import shutil
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .safety import contains_credential, read_bounded_file, redact, safe_url, normalize_domain

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]\}]+", re.I)
_TEXT_EXT = {".txt", ".lua", ".luau", ".json"}


def _token(text: str, name: str) -> bool:
    escaped = re.escape(name).replace(r"\.", r"\s*\.\s*").replace(":", r"\s*:\s*")
    return bool(re.search(r"(?<![\w])" + escaped + r"(?![\w])", text, re.I))


def _verified_matches(values: list, candidate: str) -> bool:
    # Strings simples da base não são promovidas silenciosamente a verificadas.
    return any(isinstance(item, dict) and item.get("verificado") is True
               and str(item.get("value", item.get("hash", item.get("repo", "")))).casefold() == candidate.casefold()
               for item in values)


def analyze_text(text: str, signatures: dict, *, source: str = "arquivo", digest: str = "") -> dict | None:
    """Retorna só padrões conhecidos e URLs sanitizadas, nunca o texto original."""
    cfg = signatures.get("scripts", {})
    functions = [name for name in cfg.get("funcoes_executor", []) if _token(text, name)]
    libraries = [name for name in cfg.get("bibliotecas_gui", []) if _token(text, name)]
    obfuscators = [name for name in cfg.get("ofuscadores", []) if _token(text, name)]
    general = [name for name in ("LocalPlayer", "GetService", "Instance.new", "RunService", "workspace") if _token(text, name)]
    has_load = any(x.casefold() == "loadstring" for x in functions)
    has_http = any("httpget" in x.casefold() for x in functions)
    urls = list(dict.fromkeys(safe_url(m.group(0)) for m in _URL_RE.finditer(text)))[:8] if functions else []
    urls = [url for url in urls if url != "[REDIGIDO]"]
    repos = []
    for url in urls:
        if normalize_domain(url) == "raw.githubusercontent.com":
            parts = url.split("/", 3)[-1].split("/")
            if len(parts) >= 3:
                repos.append({"dono": redact(parts[0], 80), "repositorio": redact(parts[1], 80),
                              "arquivo": redact("/".join(parts[3:]), 160)})
    obfuscation = list(obfuscators)
    if len(re.findall(r"\\(?:\d{3}|x[0-9a-fA-F]{2})", text)) >= 30:
        obfuscation.append("sequências de bytes escapados")
    if sum(len(re.findall(r"string\s*\.\s*" + func, text)) for func in ("char", "byte", "gsub")) >= 20:
        obfuscation.append("transformações repetidas de strings")
    if len(text) >= 2000 and max(map(len, text.splitlines()), default=0) >= 2000:
        counts = Counter(text)
        entropy = -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())
        if entropy >= 5.7:
            obfuscation.append("linha longa com alta entropia")
    known = bool(digest and _verified_matches(cfg.get("hashes_script", []), digest))
    known = known or any(_verified_matches(cfg.get("repos_bloqueados", []), r["dono"] + "/" + r["repositorio"]) for r in repos)
    if not functions and not obfuscation and not known:
        return None
    if known:
        level, weight = "CONFIRMADO", "confirmed"
    elif has_load and (has_http or urls):
        level = "PROVÁVEL"
        weight = "script_executor" if len(functions) > 2 else "script_loader"
    elif functions:
        level, weight = "INDÍCIO", "hint"
    else:
        level, weight = "INDÍCIO", "obfuscation"
    if source == "clipboard":
        # Conteúdo copiado pode ser apenas uma mensagem recebida: não prova uso.
        level = "PROVÁVEL" if level in {"PROVÁVEL", "CONFIRMADO"} else "INDÍCIO"
        weight = "script_clipboard" if has_load else "hint"
    credential = contains_credential(text)
    patterns = functions + libraries + obfuscation + (general if functions or libraries else [])
    excerpt = "[REDIGIDO]" if credential else redact("Padrões: " + ", ".join(patterns) + ("; " + urls[0] if urls else ""), 160)
    # Credenciais invalidam qualquer recorte/URL derivado do mesmo conteúdo.
    return {"level": level, "weight_key": weight, "padroes": patterns[:40],
            "trecho": excerpt, "urls": [] if credential else urls,
            "repositorios": [] if credential else repos, "credential_warning": credential,
            "correspondencia_validada": known}


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _check(name: str, status: str, reason: str, requires: str = "none") -> dict:
    return {"name": name, "requires": requires, "status": status, "reason": reason}


def collect(ctx) -> dict:
    findings, checks = [], []
    data = {"credential_warning": False, "arquivos_analisados": 0,
            "arquivos_pulados": 0, "clipboard_leituras": 0,
            "observacao": "Padrões estáticos não demonstram execução. ctime é alteração de metadados, não criação."}
    max_bytes = min(max(int(getattr(ctx.args, "max_file_kb", 512)), 1), 8192) * 1024
    max_files = max(1, int(getattr(ctx.args, "max_files", 2000)))
    deadline = time.monotonic() + max(1, float(getattr(ctx.args, "max_seconds", 30)))
    if ctx.consent.get("files"):
        for index, path in enumerate(ctx.files):
            if index >= max_files or time.monotonic() > deadline:
                data["arquivos_pulados"] += len(ctx.files) - index
                break
            path = Path(path)
            if path.suffix.lower() not in _TEXT_EXT | {".zip", ".apks"}:
                continue
            try:
                raw, meta = read_bounded_file(path, ctx.storage, max_bytes)
                relative = redact(path.relative_to(ctx.storage).as_posix(), 300)
                if path.suffix.lower() in {".zip", ".apks"}:
                    _archive_names(ctx, raw, relative, meta, findings, data)
                    continue
                if b"\x00" in raw:
                    data["arquivos_pulados"] += 1
                    continue
                text = raw.decode("utf-8-sig", errors="strict")
                if sum(ord(c) < 32 and c not in "\r\n\t" for c in text) > max(2, len(text) // 100):
                    data["arquivos_pulados"] += 1
                    continue
                digest = hashlib.sha256(raw).hexdigest()
                result = analyze_text(text, ctx.signatures, digest=digest)
                data["credential_warning"] |= contains_credential(text)
                data["arquivos_analisados"] += 1
                del raw, text
                if result:
                    evidence = {"caminho": relative, "tamanho": meta.st_size,
                                "mtime": _iso(meta.st_mtime), "ctime_metadados": _iso(meta.st_ctime),
                                "sha256": digest, "padroes": result["padroes"], "trecho": result["trecho"],
                                "urls": result["urls"], "repositorios": result["repositorios"],
                                "origem_download": "NÃO VERIFICADO"}
                    findings.append(ctx.finding("M8", "scripts", "Padrões de script em arquivo autorizado",
                                                evidence, result["level"], result["weight_key"], time=_iso(meta.st_mtime)))
            except (OSError, ValueError, UnicodeError, zipfile.BadZipFile, OverflowError):
                data["arquivos_pulados"] += 1
        stats = getattr(ctx, "file_stats", {})
        skipped = data["arquivos_pulados"] or stats.get("limited") or stats.get("errors", 0)
        status = "PARCIAL" if skipped else "OK"
        if not data["arquivos_analisados"] and stats.get("errors", 0):
            status = "NÃO VERIFICADO"
        checks.append(_check("arquivos_autorizados", status,
                             "Arquivos inacessíveis, binários ou limites atingidos." if skipped else "Análise estática de arquivos elegíveis concluída."))
    else:
        checks.append(_check("arquivos_autorizados", "NÃO VERIFICADO", "Leitura de conteúdo recusada pelo jogador."))
    if ctx.consent.get("clipboard"):
        # Exatamente uma chamada: não tenta outro backend nem acompanha mudanças.
        clip_requires = "none"
        command = ["termux-clipboard-get"]
        if shutil.which("termux-clipboard-get") is None and ctx.privilege.get("adb"):
            command, clip_requires = ["dumpsys", "clipboard"], "adb"
        clip = ctx.run(command, requires=clip_requires, timeout=15, max_bytes=max_bytes)
        data["clipboard_leituras"] = 1
        if clip.ok and clip.text.strip():
            text = clip.text
            result = analyze_text(text, ctx.signatures, source="clipboard")
            data["credential_warning"] |= contains_credential(text)
            adb_opaque = clip_requires == "adb" and (result is None or bool(re.search(r"\b(?:redacted|permission denied|access denied)\b", text, re.I)))
            if adb_opaque:
                result = None
            if result:
                findings.append(ctx.finding("M8", "clipboard", "Padrões de script na área de transferência; cópia não comprova uso",
                                            {"trecho": result["trecho"], "padroes": result["padroes"],
                                             "urls": result["urls"], "repositorios": result["repositorios"]},
                                            result["level"], result["weight_key"]))
            del text, clip
            checks.append(_check("clipboard_atual", "NÃO VERIFICADO" if adb_opaque else "OK",
                                 "ADB retornou dados redigidos ou um formato sem conteúdo confirmável; conferir na call."
                                 if adb_opaque else "Uma leitura consentida; conteúdo não relacionado descartado.", clip_requires))
        else:
            checks.append(_check("clipboard_atual", "NÃO VERIFICADO", "Termux:API ausente, permissão negada ou área de transferência vazia. Instale o app Termux:API da mesma fonte do Termux e mantenha o Termux em primeiro plano.", clip_requires))
    else:
        checks.append(_check("clipboard_atual", "NÃO VERIFICADO", "Leitura recusada pelo jogador."))
    checks.append(_check("historico_clipboard", "NÃO VERIFICADO", "Históricos de teclados podem conter dados pessoais e não são abertos; conferir visualmente na call.", "root"))
    checks.append(_check("scripts_privados", "NÃO VERIFICADO", "Diretórios privados não são lidos; a base pública não contém pacotes validados.", "root"))
    status = "PARCIAL" if any(c["status"] != "OK" for c in checks) else "OK"
    if not any(c["status"] in {"OK", "PARCIAL"} for c in checks):
        status = "NÃO VERIFICADO"
    return {"module": "M8", "requires": "none", "status": status,
            "reason": "Análise local, estática, limitada e com consentimentos independentes.",
            "findings": findings, "data": data, "checks": checks}


def _archive_names(ctx, raw: bytes, relative: str, meta, findings: list, data: dict):
    """Lê somente o diretório central; não abre nenhum membro do arquivo ZIP."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > 2000:
            data["arquivos_pulados"] += 1
            return
        names = []
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            # O nome de um .lua sozinho não significa executor.
            if re.search(r"(?:^|/)(?:autoexec|executor)[^/]*/.*\.(?:lua|luau|txt)$", name, re.I):
                names.append(redact(name, 160))
            if len(names) >= 10:
                break
        data["arquivos_analisados"] += 1
        if names:
            findings.append(ctx.finding("M8", "scripts", "Nomes de entradas de arquivo sugerem contexto de executor",
                                        {"caminho": relative, "tamanho": meta.st_size, "mtime": _iso(meta.st_mtime),
                                         "sha256": hashlib.sha256(raw).hexdigest(), "entradas": names,
                                         "observacao": "Apenas nomes; nenhum conteúdo extraído."},
                                        "INDÍCIO", "hint", time=_iso(meta.st_mtime)))
