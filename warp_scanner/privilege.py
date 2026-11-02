"""Sonda de privilégios: indicadores não são prova de uso de cheats."""
import errno
import os
import re
import shutil
from pathlib import Path


def _indicator(name, value, source, status="OK"):
    return {"name": name, "value": value, "source": source, "status": status}


def _exists(path):
    try:
        os.stat(path)
        return "existe"
    except PermissionError:
        # EACCES pode vir de um ancestral: não prova a existência do alvo.
        return "acesso negado; existência do alvo indeterminada"
    except FileNotFoundError:
        return "não encontrado"
    except OSError as exc:
        return "não verificável" if exc.errno != errno.ENOENT else "não encontrado"


def privilege_probe(ctx):
    indicators = []
    suspects = []
    su_paths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/debug_ramdisk/su"]
    located = shutil.which("su")
    if located and located not in su_paths:
        su_paths.append(located)
    for path in su_paths:
        value = _exists(path)
        system_path = path != located or path.startswith(("/system/", "/sbin/", "/su/", "/debug_ramdisk/"))
        indicators.append(_indicator("binário su", value, path if system_path else "PATH do shell"))
        if value == "existe" and system_path:
            suspects.append("binário su em caminho do sistema")

    direct = ctx.run(["id"], timeout=3, max_bytes=4096)
    uid = re.match(r"^uid=(\d+)(?:\(|\s|$)", direct.text.strip()) if direct.ok else None
    active = ctx.run(["su", "-c", "id"], timeout=5, max_bytes=4096)
    su_root = active.ok and bool(re.match(r"^uid=0(?:\(|\s|$)", active.text.strip()))
    root = bool(su_root or (uid and uid[1] == "0"))
    indicators.append(_indicator("teste ativo su", "uid=0" if su_root else "não confirmado (negado, indisponível ou sem resposta)", "su -c id"))
    # Consultas exatas dos IDs de distribuição pública definidos pelos respectivos projetos.
    for pkg, manager in (("com.topjohnwu.magisk", "Magisk"), ("me.weishu.kernelsu", "KernelSU")):
        result = ctx.run(["pm", "path", pkg], timeout=3, max_bytes=1024)
        if result.ok and re.search(r"(?m)^package:/[^\r\n]+\.apk\s*$", result.text):
            suspects.append("pacote do " + manager + " presente")
            indicators.append(_indicator(manager, "pacote presente", "pm path"))
    for path in ("/data/adb", "/data/adb/modules"):
        value = _exists(path)
        indicators.append(_indicator("artefato de gerenciador", value, path))
        if value == "existe":
            suspects.append("artefato em /data/adb")

    properties = {
        "ro.build.tags": lambda value: "test-keys" in value,
        "ro.debuggable": lambda value: value == "1",
        "ro.secure": lambda value: value == "0",
        "ro.boot.verifiedbootstate": lambda value: value in ("orange", "red", "yellow"),
        "ro.boot.flash.locked": lambda value: value == "0",
    }
    for prop, predicate in properties.items():
        result = ctx.run(["getprop", prop], timeout=3, max_bytes=1024)
        value = result.text.strip()[:80] if result.ok else "não verificável"
        indicators.append(_indicator(prop, value or "não exposto", "getprop " + prop, "OK" if result.ok and value else "NÃO VERIFICADO"))
        if result.ok and predicate(value):
            suspects.append("build com test-keys" if prop == "ro.build.tags" else "indicador em " + prop)
    se = ctx.run(["getenforce"], timeout=3, max_bytes=1024)
    state = se.text.strip()
    indicators.append(_indicator("SELinux", state if state in ("Enforcing", "Permissive", "Disabled") else "não verificável", "getenforce"))
    if state in ("Permissive", "Disabled"):
        suspects.append("SELinux " + state)
    try:
        with Path("/proc/self/mountinfo").open(encoding="utf-8") as handle:
            text = handle.read(262144)
        markers = sorted({marker for marker in ("/data/adb/", "magisk", "kernelsu", "apatch", "zygisk", "overlay") if marker in text.lower()})
        # Somente nomes dos indicadores; caminhos e montagens não relacionados são descartados.
        indicators.append(_indicator("montagens", markers or "sem marcadores conhecidos", "/proc/self/mountinfo"))
        suspects.extend("marca de " + marker + " nas montagens" for marker in markers if marker != "overlay")
        del text
    except (OSError, UnicodeError):
        indicators.append(_indicator("montagens", "não verificável", "/proc/self/mountinfo", "NÃO VERIFICADO"))
    indicators.append(_indicator("gerenciadores renomeados/ocultação", "não verificável de forma conclusiva", "DenyList, Shamiko e renomeação podem ocultar indicadores", "NÃO VERIFICADO"))

    adb = False
    serial = getattr(ctx.args, "adb_serial", "") or ""
    if re.fullmatch(r"(?:localhost|127\.0\.0\.1):[0-9]{1,5}", serial) and 1 <= int(serial.rsplit(":", 1)[1]) <= 65535:
        probe = ctx.run(["adb", "-s", serial, "shell", "id"], timeout=5, max_bytes=4096)
        adb = probe.ok and bool(re.search(r"\buid=(?:2000|0)(?:\(|\s|$)", probe.text))
        if adb and re.search(r"\buid=0(?:\(|\s|$)", probe.text):
            # ADB root é capacidade ADB, não autoriza presumir su local.
            indicators.append(_indicator("ADB privilegiado", "uid=0 via ADB; su local separado", "adb shell id"))
    indicators.append(_indicator("ADB local", "disponível" if adb else "não pareado ou indisponível", "adb shell id (somente endpoint local informado)"))
    if root:
        root_result = {"value": True, "reason": "confirmado: su com uid=0" if su_root else "confirmado: processo com uid=0"}
    elif suspects:
        root_result = {"value": True, "reason": "suspeito: " + suspects[0]}
    elif uid:
        root_result = {"value": False, "reason": "não detectado (não garante ausência)"}
    else:
        root_result = {"value": None, "reason": "sonda de privilégios indisponível"}
    classification = "ROOT_CONFIRMADO" if root else ("ROOT_SUSPEITO" if suspects else ("ADB_SHELL" if adb else "SEM_ROOT" if uid else "NÃO VERIFICADO"))
    mode = "AVANÇADO" if root else ("PADRÃO+" if adb else "PADRÃO")
    return {"classification": classification, "mode": mode, "root": bool(root), "root_result": root_result, "adb": bool(adb), "indicators": indicators,
            "note": "Ausência de indícios significa root não detectado; não garante ausência de root."}


def collect(ctx):
    state = ctx.privilege
    findings = []
    if state.get("classification") in ("ROOT_CONFIRMADO", "ROOT_SUSPEITO"):
        findings.append(ctx.finding("PRIV", "ambiente", "Root confirmado" if state.get("root") else "Indicadores de ambiente com privilégios alterados", "Root não comprova uso de cheat.", "INDÍCIO", "root" if state.get("root") else "hint"))
    return {"module": "PRIV", "requires": "none", "status": "PARCIAL", "reason": state.get("note", ""), "findings": findings, "data": state,
            "checks": [{"name": "Ocultação de root", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Não é possível excluir root oculto."}]}
