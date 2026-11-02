"""M1: metadados do pacote oficial, sem ler dados da conta."""
import datetime as dt
import os
import re
import shutil
from pathlib import Path
from .core import CommandResult

PACKAGE = "com.roblox.client"
PACKAGE_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+\Z")


def requirements(ctx):
    return "root" if ctx.privilege.get("root") else ("adb" if ctx.privilege.get("adb") else "none")


def query(ctx, argv, timeout=8, max_bytes=262144):
    """Tenta capacidades fortes primeiro e registra fallback para o chamador."""
    attempts = []
    if ctx.privilege.get("root"):
        attempts.append("root")
    if ctx.privilege.get("adb"):
        attempts.append("adb")
    attempts.append("none")
    failures = []
    last = None
    for required in attempts:
        last = ctx.run(argv, requires=required, timeout=timeout, max_bytes=max_bytes)
        # Alguns serviços retornam código zero mesmo para SecurityException.
        denied = bool(re.search(r"(?i)(permission denial|permission denied|securityexception|not allowed|can't find service)", last.text))
        if last.ok and not denied:
            return last, required, failures
        failures.append(required)
    return CommandResult(False, reason="Consultas indisponíveis ou negadas em todas as capacidades"), "none", failures


def package_info(ctx, package):
    if not PACKAGE_RE.fullmatch(package):
        return {"verified": False, "reason": "Identificador de pacote inválido na base."}
    cache = getattr(ctx, "installed", None)
    if cache is None:
        ctx.installed = cache = {}
    if package in cache:
        return cache[package]
    result, required, fallback = query(ctx, ["dumpsys", "package", package])
    data = {"verified": False, "requires": required, "fallback": fallback}
    if not result or not result.ok or re.search(r"(?i)(permission den|securityexception)", result.text):
        data["reason"] = "O Android não permitiu consultar os metadados deste pacote."
        cache[package] = data
        return data
    text = result.text
    if re.search(r"(?i)(unable to find package|unknown package|package .* not found)", text):
        data.update(verified=True, present=False)
    elif re.search(r"Package\s*\[" + re.escape(package) + r"\]", text):
        data.update(verified=True, present=True)
        for field in ("versionName", "firstInstallTime", "lastUpdateTime", "installerPackageName"):
            match = re.search(r"(?m)^\s*" + field + r"=([^\r\n]+)", text)
            if match:
                data[field] = match.group(1).strip()[:128]
        users = re.findall(r"User\s+(\d+):[^\n]*?installed=(true|false)", text)
        if users:
            data["installed_profiles"] = sum(flag == "true" for _, flag in users)
            data["present"] = any(flag == "true" for _, flag in users)
        installer = re.search(r"installerPackageName=([a-zA-Z0-9_.]+)", text)
        if installer:
            data["installerPackageName"] = installer.group(1)
    else:
        data["reason"] = "Resposta de pacote indisponível ou formato não reconhecido."
    del text
    cache[package] = data
    return data


def parse_install_time(value):
    try:
        # O dumpsys fornece horário local do aparelho; não inventar UTC.
        return dt.datetime.fromisoformat(value).astimezone()
    except (ValueError, TypeError):
        return None


def collect(ctx):
    info = package_info(ctx, PACKAGE)
    findings, checks = [], []
    data = {"package": PACKAGE, **info, "reinstallation": "indeterminado", "certificate": "NÃO VERIFICADO"}
    checks.append({"name": "Metadados do Roblox", "requires": info.get("requires", "none"), "status": "OK" if info.get("verified") else "NÃO VERIFICADO", "reason": info.get("reason", "Consulta direcionada ao pacote com.roblox.client.")})
    if info.get("fallback"):
        checks.append({"name": "Fallback de capacidade", "requires": info["fallback"][0], "status": "PARCIAL", "reason": "Falharam: " + ", ".join(info["fallback"]) + "; usada a capacidade disponível."})
    if info.get("present"):
        installer = info.get("installerPackageName", "não informado")
        if installer not in ("com.android.vending", "não informado", "null", "None"):
            findings.append(ctx.finding("M1", "instalação", "Roblox com instalador diferente da Play Store", {"installer": installer}, "INDÍCIO", "hint", info.get("requires", "none")))
        installed = parse_install_time(info.get("firstInstallTime"))
        if installed and 0 <= (dt.datetime.now().astimezone() - installed).total_seconds() <= 72 * 3600:
            findings.append(ctx.finding("M1", "instalação", "Instalação inicial registrada há menos de 72 horas", {"firstInstallTime": info["firstInstallTime"], "limite": "A data sozinha não comprova reinstalação."}, "INDÍCIO", "reinstall", info.get("requires", "none"), time=installed.isoformat()))
        if info.get("installed_profiles", 0) > 1:
            findings.append(ctx.finding("M1", "múltiplos perfis", "Roblox instalado em mais de um perfil Android", {"profiles": info["installed_profiles"], "limite": "Perfil de trabalho/usuário adicional não comprova clonagem ou cheat."}, "INDÍCIO", "hint", info.get("requires", "none")))

        official = {value.lower().replace(":", "") for value in ctx.signatures.get("roblox", {}).get("official_certificates_sha256", []) if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value.replace(":", ""))}
        certificate_reason = "Certificado oficial validado não foi configurado na base."
        if official:
            if shutil.which("apksigner"):
                paths, cap, _ = query(ctx, ["pm", "path", PACKAGE], max_bytes=8192)
                if paths and paths.ok:
                    apk_paths = re.findall(r"(?m)^package:(/[^\r\n]+\.apk)$", paths.text)
                    base = next((p for p in apk_paths if p.endswith("/base.apk")), None)
                    if base and base.startswith(("/data/app/", "/system/", "/product/")) and os.path.isfile(base):
                        cert = ctx.run(["apksigner", "verify", "--print-certs", base], timeout=20, max_bytes=16384)
                        found = set(re.findall(r"(?i)certificate SHA-256 digest:\s*([0-9a-f]{64})", cert.text)) if cert.ok else set()
                        found = {value.lower() for value in found}
                        if found:
                            data["certificate"] = sorted(found)
                            certificate_reason = "SHA-256 obtido por apksigner verify; comparação com base local."
                            if not (found & official):
                                certificate_reason = "Signatário não listado entre os vínculos publicados. Conferir versão, canal e rotação em M10."
                                findings.append(ctx.finding("M1", "integridade", "Signatário fora das referências conhecidas", {"sha256": sorted(found), "limite": certificate_reason}, "INDÍCIO", "hint"))
                        else:
                            certificate_reason = "Não foi possível validar o APK/certificado com apksigner."
                    else:
                        certificate_reason = "APK oficial não ficou acessível para validação local."
            else:
                certificate_reason = "apksigner indisponível; não foi inventado um certificado de referência."
        checks.append({"name": "Certificado SHA-256", "requires": "none", "status": "OK" if isinstance(data["certificate"], list) else "NÃO VERIFICADO", "reason": certificate_reason})

    # Somente stat em caminhos conhecidos; sem enumerar conteúdo privado.
    remnants = []
    for area in ("data", "obb", "media"):
        path = ctx.storage / "Android" / area / PACKAGE
        try:
            if path.is_symlink():
                continue
            stat = path.stat()
            remnants.append({"path": "Android/" + area + "/" + PACKAGE, "mtime": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat()})
        except OSError:
            pass
    data["directory_metadata"] = remnants
    checks.append({"name": "Reinstalação e eventos anteriores", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Dumps globais de uso/logcat/bugreport são omitidos para não ler dados de outros apps; datas isoladas não provam reinstalação."})
    if ctx.privilege.get("root"):
        meta = []
        for suffix in ("", "/files", "/cache"):
            target = "/data/user/0/" + PACKAGE + suffix
            result = ctx.run(["stat", "-c", "%Y %s", target], requires="root", timeout=3, max_bytes=1024)
            if result.ok and re.fullmatch(r"\d+ \d+\s*", result.text):
                mtime, size = result.text.split()
                meta.append({"path": target, "mtime_unix": int(mtime), "directory_size": int(size)})
        data["private_directory_metadata"] = meta
        checks.append({"name": "Metadados de diretórios privados conhecidos", "requires": "root", "status": "OK" if meta else "NÃO VERIFICADO", "reason": "Somente stat da raiz/files/cache; nenhum conteúdo, cookies, WebView ou Keystore."})
    else:
        checks.append({"name": "Metadados privados", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Root local não confirmado."})
    return {"module": "M1", "requires": "none", "status": "PARCIAL" if info.get("verified") else "NÃO VERIFICADO", "reason": "Integridade, reinstalação e visibilidade de outros perfis dependem de capacidades adicionais.", "findings": findings, "data": data, "checks": checks}
