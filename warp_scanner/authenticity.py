"""M10. Inspeção local do APK/manifesto e comparação com referências validadas."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import time

from .roblox import PACKAGE, PACKAGE_RE, package_info, query
from .safety import _open_beneath

HEX = re.compile(r"[a-f0-9]{64}")
MAX_APK_BYTES = 256 * 1024 * 1024


def _hex(value):
    value = value.replace(":", "").lower() if isinstance(value, str) else ""
    return value if HEX.fullmatch(value) else ""


def _refs(rows):
    return [r for r in rows if isinstance(r, dict) and r.get("verificado") is True and r.get("fonte")]


def signer_hashes(text, lineage=False):
    prefix = r"Signer #(\d+) in lineage" if lineage else r"Signer #(\d+)"
    rows = re.findall(r"(?im)^" + prefix + r" certificate SHA-256 digest:\s*([a-f0-9]{64})[ \t]*$", text)
    return [v.lower() for _, v in sorted(rows, key=lambda item: int(item[0]))]


def manifest_identity(text):
    pkg = re.search(r"(?m)^package: name='([^']+)' versionCode='([0-9]{1,15})'", text)
    if not pkg or not PACKAGE_RE.fullmatch(pkg[1]):
        return None
    looks_roblox = bool(re.search(r"(?im)^(?:application-label(?:-[\w-]+)?:'|application: label=')roblox(?: beta)?'", text))
    return {"package": pkg[1], "version_code": pkg[2], "rotulo_roblox": looks_roblox}


def classify(signatures, package, version, digest, current, lineage):
    """Um certificado desconhecido ou uma atualização sem referência não é confirmação."""
    official = signatures.get("roblox", {})
    good_hashes = {v for r in _refs(official.get("arquivos_oficiais", [])) if (v := _hex(r.get("sha256")))}
    accepted = {v for h in official.get("official_certificates_sha256", []) if (v := _hex(h))}
    exact = []
    for row in _refs(official.get("conjuntos_signatarios", [])):
        if str(row.get("version_code", "")) != version or not row.get("canal_completo"):
            continue
        items = row.get("sha256", [])
        if isinstance(items, list) and items and all(_hex(v) for v in items):
            exact.append({_hex(v) for v in items})
    current = {_hex(v) for v in current if _hex(v)}
    bad_hash = bad_cert = False
    for entry in signatures.get("entries", []):
        if entry.get("verificado") is not True or entry.get("categoria") not in {"executor_mobile", "executor_pc", "cheat", "injecao"}:
            continue
        bad_hash |= bool(digest and digest in {_hex(v) for v in entry.get("hashes_apk", [])})
        bad_cert |= bool(current & {_hex(v) for v in entry.get("certificados_sha256", [])})
    # Uma linhagem só é aplicada ao APK verificado com um único signatário atual.
    rotated = bool(len(current) == 1 and lineage and lineage[-1] in current and set(lineage) & accepted)
    trusted = bool(package == PACKAGE and (
        (digest and digest in good_hashes) or (current and current in exact) or
        (len(current) == 1 and current <= accepted) or rotated))
    if trusted and (bad_hash or bad_cert):
        return "CONFLITO DE REFERÊNCIAS"
    if bad_hash:
        return "HASH BLOQUEADO VALIDADO"
    if bad_cert:
        return "CERTIFICADO BLOQUEADO VALIDADO"
    if trusted:
        return "COMPATÍVEL COM REFERÊNCIA"
    if package == PACKAGE and current and exact:
        return "DIVERGÊNCIA DA VERSÃO REFERENCIADA"
    return "INCONCLUSIVO"


def _run(ctx, args, deadline, *, output=32768):
    remain = deadline - time.monotonic()
    if remain <= 0:
        return None
    result = ctx.run(args, timeout=min(12, max(1, int(remain))), max_bytes=output)
    return result.text if result.ok else None


def _inspect(ctx, path, *, installed, deadline):
    """Usa o mesmo descritor para hash, manifesto e signatários no Android."""
    if installed:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    else:
        fd = _open_beneath(path, ctx.storage)
    with os.fdopen(fd, "rb") as handle:
        initial = os.fstat(handle.fileno())
        if not stat.S_ISREG(initial.st_mode) or not 0 < initial.st_size <= MAX_APK_BYTES:
            raise ValueError("APK fora dos limites")
        proc_path = f"/proc/{os.getpid()}/fd/{handle.fileno()}"
        digest = hashlib.sha256()
        count = 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError()
            block = handle.read(131072)
            if not block:
                break
            count += len(block)
            if count > MAX_APK_BYTES:
                raise ValueError("Arquivo alterado")
            digest.update(block)
        manifest = None
        badging = shutil.which("aapt") or shutil.which("aapt2")
        if badging:
            manifest = manifest_identity(_run(ctx, [badging, "dump", "badging", proc_path], deadline, output=131072) or "")
        current, history = [], []
        signer = shutil.which("apksigner")
        if signer:
            verified = _run(ctx, [signer, "verify", "--print-certs", proc_path], deadline)
            if verified:
                current = signer_hashes(verified)
                if len(current) == 1:
                    history = signer_hashes(_run(ctx, [signer, "lineage", "--in", proc_path, "--print-certs"], deadline) or "", lineage=True)
        final = os.fstat(handle.fileno())
        if (initial.st_mtime_ns, initial.st_size) != (final.st_mtime_ns, final.st_size):
            raise ValueError("APK alterado durante a leitura")
    package = manifest["package"] if manifest else (PACKAGE if installed else "")
    # Confere a identidade do caminho instalado com o manifesto, se disponível.
    if installed and manifest and package != PACKAGE:
        raise ValueError("Pacote instalador inconsistente com o manifesto")
    hex_digest = digest.hexdigest()
    version = manifest["version_code"] if manifest else ""
    outcome = classify(ctx.signatures, package, version, hex_digest, current, history)
    return {"package": package, "version_code": version, "rotulo_roblox": bool(manifest and manifest["rotulo_roblox"]),
            "sha256": hex_digest, "signatarios": current, "linhagem": history, "manifesto_lido": manifest is not None,
            "assinatura_verificada": bool(current), "resultado": outcome}


def _installed_base(ctx):
    result, _, _ = query(ctx, ["pm", "path", PACKAGE], timeout=4, max_bytes=16384)
    if not result.ok:
        return None
    for line in result.text.splitlines():
        if re.fullmatch(r"package:/(?:data/app|system/(?:priv-)?app|product/(?:priv-)?app|system_ext/(?:priv-)?app)/[A-Za-z0-9._~+=/-]+/base\.apk", line):
            path = Path(line.removeprefix("package:"))
            if ".." not in path.parts:
                return path
    return None


def collect(ctx):
    checks, findings = [], []
    data = {"referencia_instalada": "INCONCLUSIVO", "apks_examinados": 0,
            "apks_desconhecidos": 0, "base_apenas": True,
            "limite": "APK base e arquivos .apk elegíveis. Splits e apps fora dos alvos podem escapar."}
    deadline = time.monotonic() + 36
    trusted = set()
    ctx.review_trusted_hashes = trusted
    def record(result, target, installed):
        outcome = result["resultado"]
        if outcome == "COMPATÍVEL COM REFERÊNCIA":
            trusted.add(result["sha256"])
        if installed:
            data["referencia_instalada"] = outcome
            data["apk_base"] = result
        blocked = outcome in {"HASH BLOQUEADO VALIDADO", "CERTIFICADO BLOQUEADO VALIDADO", "DIVERGÊNCIA DA VERSÃO REFERENCIADA"}
        disguise = result["rotulo_roblox"] and result["package"] != PACKAGE
        if blocked or disguise or outcome == "CONFLITO DE REFERÊNCIAS":
            evidence = {"target": target, "package": result["package"], "sha256": result["sha256"],
                        "resultado": outcome, "version_code": result["version_code"], "rotulo_roblox": result["rotulo_roblox"]}
            if not installed:
                evidence["path"] = target
            findings.append(ctx.finding("M10", "autenticidade", outcome if blocked else
                                        "Referências conflitantes" if outcome == "CONFLITO DE REFERÊNCIAS" else
                                        "Rótulo Roblox em APK com outro identificador de pacote",
                                        evidence, "CONFIRMADO" if blocked else "INDÍCIO", "confirmed" if blocked else "hint"))
        if outcome == "INCONCLUSIVO":
            data["apks_desconhecidos"] += 1

    base = _installed_base(ctx)
    if base:
        try:
            result = _inspect(ctx, base, installed=True, deadline=deadline)
            record(result, PACKAGE, True)
        except (OSError, ValueError, TimeoutError):
            pass
    checks.append({"name": "Autenticidade do APK base do Roblox", "requires": "none",
                   "status": "OK" if data["referencia_instalada"] not in {"INCONCLUSIVO", "CONFLITO DE REFERÊNCIAS"} else "NÃO VERIFICADO",
                   "reason": data["referencia_instalada"] + ". Uma assinatura válida isolada não identifica o editor oficial."})
    candidates = [Path(p) for p in ctx.files if Path(p).suffix.lower() == ".apk"]
    if ctx.consent.get("files"):
        for path in candidates[:6]:
            if time.monotonic() >= deadline:
                break
            try:
                relative = path.relative_to(ctx.storage).as_posix()
                result = _inspect(ctx, path, installed=False, deadline=deadline)
                data["apks_examinados"] += 1
                record(result, relative, False)
            except (OSError, ValueError, TimeoutError):
                continue
    complete = ctx.consent.get("files") and data["apks_examinados"] == len(candidates) and not any(getattr(ctx, "file_stats", {}).get(k) for k in ("limited", "errors"))
    checks.append({"name": "APK de armazenamento autorizado", "requires": "none", "status": "OK" if complete else "PARCIAL" if data["apks_examinados"] else "NÃO VERIFICADO",
                   "reason": "Até seis APKs, 256 MiB por arquivo e 36 s no módulo. O hash e o certificado são comparados no aparelho. Referências sem procedência têm cobertura inconclusiva." if ctx.consent.get("files") else "Leitura de conteúdo recusada."})
    checks.append({"name": "Cobertura de disfarces", "requires": "none", "status": "PARCIAL" if data["apks_examinados"] else "NÃO VERIFICADO",
                   "reason": "Com aapt/aapt2 compara rótulo e ID do manifesto. Um nome diferente não atesta fraude. Não há inventário de apps pessoais."})
    return {"module": "M10", "requires": "none", "status": "PARCIAL" if data.get("apk_base") or data["apks_examinados"] else "NÃO VERIFICADO",
            "reason": "Verificação estática local baseada em referências auditadas.", "data": data, "checks": checks, "findings": findings}
