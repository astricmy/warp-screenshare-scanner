"""M3: compara alvos da base; nomes genéricos nunca bastam."""
import datetime as dt
import hashlib
import os
import re
import stat
import time
from pathlib import Path
from .roblox import PACKAGE_RE, package_info
from .safety import _open_beneath

NON_CHEAT_CATEGORIES = {"root", "gerenciador_root", "root_manager", "acessibilidade", "macro", "autoclicker", "automacao", "adb", "clonador", "virtualização", "patcher"}


def contextual_match(name, entry):
    """Uma marca ambígua precisa de um segundo token contextual independente."""
    text = name.casefold()
    labels = [entry.get("nome", ""), entry.get("id", "")] + entry.get("rotulos", []) + entry.get("pastas", [])
    brands = [label.casefold().replace("-", " ").replace("_", " ") for label in labels if isinstance(label, str) and len(label) >= 3]
    context = [token.casefold() for token in entry.get("tokens_contextuais", []) if isinstance(token, str) and len(token) >= 3]
    for brand in brands:
        pattern = r"(?<![\w])" + re.escape(brand).replace(r"\ ", r"[\s_-]+") + r"(?![\w])"
        if re.search(pattern, text) and any(token != brand and re.search(r"(?<![\w])" + re.escape(token) + r"(?![\w])", text) for token in context):
            return True
    # Nomes compostos ('Delta Executor') têm o contexto incorporado.
    return any(len(brand.split()) >= 2 and brand in text and any(token in brand for token in context) for brand in brands)


def relative(path, storage):
    try:
        return path.relative_to(storage).as_posix()
    except ValueError:
        return "[caminho fora da raiz omitido]"


def metadata(path, ctx):
    stat = path.stat()
    return {"path": relative(path, ctx.storage), "size": stat.st_size,
            "mtime": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
            "ctime": dt.datetime.fromtimestamp(stat.st_ctime, dt.timezone.utc).isoformat(),
            "ctime_note": "ctime é alteração de metadados no Android/Linux, não data de criação."}


def bounded_hash(path, storage, deadline):
    """Hash em streaming, com abertura sem seguir links no Android."""
    if os.name == "nt":
        if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.resolve().is_relative_to(storage.resolve()):
            raise ValueError("Link ou caminho externo recusado")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    else:
        fd = _open_beneath(path, storage)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 128 * 1024 * 1024:
            raise ValueError("Arquivo não regular ou acima do limite")
        digest, count = hashlib.sha256(), 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError()
            chunk = handle.read(65536)
            if not chunk:
                break
            count += len(chunk)
            if count > 128 * 1024 * 1024:
                raise ValueError("Arquivo cresceu além do limite")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Arquivo mudou durante leitura")
        return digest.hexdigest()


def collect(ctx):
    findings, checks = [], []
    entries = ctx.signatures.get("entries", [])
    checked = matched = 0
    packages = [(package, entry) for entry in entries for package in entry.get("pacotes", []) if PACKAGE_RE.fullmatch(package)]
    for package, entry in packages[:64]:
        info = package_info(ctx, package)
        checked += bool(info.get("verified"))
        if info.get("present"):
            matched += 1
            category = entry.get("categoria", "aplicativo")
            confirmed = entry.get("verificado") is True and category not in NON_CHEAT_CATEGORIES
            findings.append(ctx.finding("M3", category, "Pacote da base instalado: " + entry.get("nome", entry.get("id", "assinatura")),
                {"package": package, "signature_id": entry.get("id"), "signature_verified": entry.get("verificado") is True,
                 "installer": info.get("installerPackageName", "não informado"), "firstInstallTime": info.get("firstInstallTime", "não informado"),
                 "limite": "Presença de ferramenta auxiliar ou referência não validada requer revisão humana."},
                "CONFIRMADO" if confirmed else "INDÍCIO", "confirmed" if confirmed else "hint", info.get("requires", "none")))
    checks.append({"name": "Pacotes da base", "requires": "none", "status": "OK" if packages and checked == len(packages) else "NÃO VERIFICADO" if not checked else "PARCIAL",
                   "reason": "Base sem pacotes validados: preencher em aparelho de teste." if not packages else f"Consultas verificáveis: {checked}/{len(packages)}; limite 64 alvos."})
    checks.append({"name": "Apps renomeados/certificados/hashes de APKs instalados", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Não há inventário irrestrito de apps; pacote renomeado pode escapar da base. Certificado/hash de APK instalado exige referência validada e acesso ao APK."})
    start = time.monotonic()
    observed = 0
    error = False
    known_hashes = {value.lower(): entry for entry in entries if entry.get("verificado") for value in entry.get("hashes_apk", []) if re.fullmatch(r"[a-fA-F0-9]{64}", value)}
    hashed = 0
    for value in getattr(ctx, "files", []):
        if time.monotonic() - start > 20:
            error = True
            break
        path = Path(value)
        if path.suffix.lower() not in (".apk", ".xapk", ".apks", ".zip", ".so", ".obb", ".crdownload"):
            continue
        try:
            if path.is_symlink() or not path.is_file():
                continue
            observed += 1
            detail = metadata(path, ctx)
            # Não lê arquivos só para gerar hashes quando a base não contém hashes úteis.
            if known_hashes and detail["size"] <= 128 * 1024 * 1024 and hashed < 8:
                digest = bounded_hash(path, ctx.storage, start + 20)
                hashed += 1
                if digest in known_hashes:
                    findings.append(ctx.finding("M3", "arquivo", "Hash de arquivo coincide com assinatura validada", {**detail, "sha256": digest, "signature_id": known_hashes[digest]["id"]}, "CONFIRMADO", "confirmed", time=detail["mtime"]))
                    continue
            for entry in entries:
                if contextual_match(path.name.replace("_", " ").replace("-", " ").replace(".", " "), entry):
                    findings.append(ctx.finding("M3", "arquivo", "Nome de arquivo com marca e contexto de executor", {**detail, "signature_id": entry.get("id"), "signature_verified": entry.get("verificado") is True, "limite": "Nome pode ser alterado; não comprova conteúdo nem execução."}, "PROVÁVEL" if entry.get("verificado") else "INDÍCIO", "probable" if entry.get("verificado") else "hint", time=detail["mtime"]))
                    break
        except (OSError, ValueError, TimeoutError):
            error = True
    stats = getattr(ctx, "file_stats", {}) or {}
    checks.append({"name": "Arquivos em diretórios permitidos", "requires": "none", "status": "PARCIAL" if error or stats.get("limited") or stats.get("errors") else "OK", "reason": f"Arquivos de instalação examinados: {observed}; hashes calculados: {hashed}. Links simbólicos não seguidos; limite de 20 segundos e 8 hashes."})
    return {"module": "M3", "requires": "none", "status": "PARCIAL", "reason": "Pacotes e hashes dependem de referências validadas; inventário de apps não é irrestrito.", "findings": findings, "data": {"target_packages": len(packages), "checked_packages": checked, "matched_packages": matched, "candidate_files": observed}, "checks": checks}
