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
    suspicious = False
    su_paths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/debug_ramdisk/su"]
    located = shutil.which("su")
    if located and located not in su_paths:
        su_paths.append(located)
    for path in su_paths:
        value = _exists(path)
        indicators.append(_indicator("binário su", value, path))
        suspicious |= value == "existe"

    direct = ctx.run(["id"], timeout=3, max_bytes=4096)
    root = direct.ok and bool(re.search(r"\buid=0(?:\(|\s|$)", direct.text))
    active = ctx.run(["su", "-c", "id"], timeout=5, max_bytes=4096)
    root |= active.ok and bool(re.search(r"\buid=0(?:\(|\s|$)", active.text))
    indicators.append(_indicator("teste ativo su", "uid=0" if root else "não confirmado (negado, indisponível ou sem resposta)", "su -c id"))
    for path in ("/data/adb", "/data/adb/modules"):
        value = _exists(path)
        indicators.append(_indicator("artefato de gerenciador", value, path))
        suspicious |= value == "existe"

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
        suspicious |= result.ok and predicate(value)
    se = ctx.run(["getenforce"], timeout=3, max_bytes=1024)
    state = se.text.strip()
    indicators.append(_indicator("SELinux", state if state in ("Enforcing", "Permissive", "Disabled") else "não verificável", "getenforce"))
    suspicious |= state in ("Permissive", "Disabled")
    try:
        with Path("/proc/self/mountinfo").open(encoding="utf-8") as handle:
            text = handle.read(262144)
        markers = sorted({marker for marker in ("/data/adb/", "magisk", "kernelsu", "apatch", "zygisk", "overlay") if marker in text.lower()})
        # Somente nomes dos indicadores; caminhos e montagens não relacionados são descartados.
        indicators.append(_indicator("montagens", markers or "sem marcadores conhecidos", "/proc/self/mountinfo"))
        suspicious |= any(marker != "overlay" for marker in markers)
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
    classification = "ROOT_CONFIRMADO" if root else ("ROOT_SUSPEITO" if suspicious else ("ADB_SHELL" if adb else "SEM_ROOT"))
    mode = "AVANÇADO" if root else ("PADRÃO+" if adb else "PADRÃO")
    return {"classification": classification, "mode": mode, "root": bool(root), "adb": bool(adb), "indicators": indicators,
            "note": "Ausência de indícios significa root não detectado; não garante ausência de root."}


def collect(ctx):
    state = ctx.privilege
    findings = []
    if state.get("classification") in ("ROOT_CONFIRMADO", "ROOT_SUSPEITO"):
        findings.append(ctx.finding("PRIV", "ambiente", "Root confirmado" if state.get("root") else "Indicadores de ambiente com privilégios alterados", "Root não comprova uso de cheat.", "INDÍCIO", "root" if state.get("root") else "hint"))
    return {"module": "PRIV", "requires": "none", "status": "PARCIAL", "reason": state.get("note", ""), "findings": findings, "data": state,
            "checks": [{"name": "Ocultação de root", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Não é possível excluir root oculto."}]}
