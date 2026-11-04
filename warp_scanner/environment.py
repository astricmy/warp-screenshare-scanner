"""M6: configuração técnica, sem armazenar servidores, contas ou IDs do aparelho."""
from datetime import date
import re
from .roblox import PACKAGE_RE, package_info, query


def device_info(ctx):
    """Lê somente propriedades públicas de produto, individualmente (nunca getprop sem filtro)."""
    props = {"brand": "ro.product.brand", "model": "ro.product.model",
             "android": "ro.build.version.release", "security_patch": "ro.build.version.security_patch",
             "api_level": "ro.build.version.sdk"}
    device = {}
    for field, prop in props.items():
        result = ctx.run(["getprop", prop], timeout=3, max_bytes=1024)
        value = result.text.strip()
        if not result.ok or not value or value.casefold() in {"null", "unknown", "none"}:
            continue
        if field == "api_level":
            if re.fullmatch(r"[1-9][0-9]{0,2}", value):
                device[field] = int(value)
        elif field == "security_patch":
            try:
                if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
                    device[field] = date.fromisoformat(value).isoformat()
            except ValueError:
                continue
        elif field == "android":
            if re.fullmatch(r"[0-9]{1,2}(?:\.[0-9]{1,2}){0,2}[A-Za-z]?", value):
                device[field] = value
        elif len(value) <= 96 and all(ch.isprintable() for ch in value):
            device[field] = value
    return device


def collect(ctx):
    findings, checks = [], []
    device = device_info(ctx)
    complete = all(key in device for key in ("brand", "model", "android", "security_patch"))
    checks.append({"name": "Modelo e versão Android", "requires": "none",
                   "status": "OK" if complete else "PARCIAL" if device else "NÃO VERIFICADO",
                   "reason": "Propriedades públicas de marca, modelo, versão, nível da API e patch de segurança."})
    emulator = []
    for prop, values in (("ro.kernel.qemu", {"1"}), ("ro.hardware", {"goldfish", "ranchu"})):
        result = ctx.run(["getprop", prop], timeout=3, max_bytes=1024)
        if result.ok and result.text.strip().lower() in values:
            emulator.append(prop)
    if emulator:
        findings.append(ctx.finding("M6", "emulador", "Propriedades compatíveis com emulação Android", {"properties": emulator, "limite": "Emulador é ambiente legítimo de desenvolvimento; propriedades podem ser alteradas."}, "INDÍCIO", "hint"))
    checks.append({"name": "Indicadores de emulador", "requires": "none", "status": "PARCIAL", "reason": "Somente ro.kernel.qemu/ro.hardware; ausência desses indicadores não exclui emulação."})
    # Guardar apenas um booleano/estado público, nunca o valor literal de proxy/DNS/VPN.
    rules = [
        ("global", "development_settings_enabled", "opções de desenvolvedor", lambda value: value == "1"),
        ("global", "adb_enabled", "depuração USB", lambda value: value == "1"),
        ("global", "adb_wifi_enabled", "depuração sem fio", lambda value: value == "1"),
        ("global", "auto_time", "hora automática desativada", lambda value: value == "0"),
        ("global", "auto_time_zone", "fuso automático desativado", lambda value: value == "0"),
    ]
    states = {}
    observed = {}
    for namespace, key, label, predicate in rules:
        result, cap, failures = query(ctx, ["settings", "get", namespace, key], timeout=3, max_bytes=4096)
        if result and result.ok and not re.search(r"(?i)(exception|permission|error)", result.text):
            value = result.text.strip()
            if value in ("0", "1"):
                observed[key] = value == "1"
                active = bool(predicate(value))
                states[label] = active
                if active:
                    # Depuração iniciada pela própria verificação não soma ao risco.
                    from_scan = key in {"adb_wifi_enabled", "development_settings_enabled"} and getattr(ctx.args, "adb_connected", False)
                    if not from_scan:
                        findings.append(ctx.finding("M6", "configuração", label[0].upper() + label[1:], {"state": "ativo", "limite": "Configuração legítima em muitos aparelhos; não comprova cheat."}, "INDÍCIO", "hint", cap))
    checks.append({"name": "Configurações selecionadas", "requires": "none", "status": "OK" if len(states) == len(rules) else "PARCIAL" if states else "NÃO VERIFICADO", "reason": f"Estados acessíveis: {len(states)}/{len(rules)}. Valores de servidores, pacotes VPN e IDs são descartados."})
    known_packages = {package for entry in ctx.signatures.get("entries", []) for package in entry.get("pacotes", []) if PACKAGE_RE.fullmatch(package)}
    overlay_checked = 0
    for package in sorted(known_packages)[:64]:
        info = package_info(ctx, package)
        if not info.get("present"):
            continue
        result, cap, failures = query(ctx, ["cmd", "appops", "get", package, "SYSTEM_ALERT_WINDOW"], timeout=4, max_bytes=8192)
        if not result or not result.ok or re.search(r"(?i)(exception|permission|error)", result.text):
            continue
        overlay_checked += 1
        if re.search(r"SYSTEM_ALERT_WINDOW:\s*allow\b", result.text):
            source = info.get("installerPackageName", "não informado")
            findings.append(ctx.finding("M6", "overlay", "App da base autorizado a sobrepor outras janelas", {"package": package, "installer": source, "limite": "Permissão não comprova que a sobreposição foi usada no Roblox."}, "INDÍCIO", "overlay" if source not in ("com.android.vending", "não informado") else "hint", cap))
    checks.append({"name": "Overlay de apps presentes na base", "requires": "adb", "status": "OK" if overlay_checked else "NÃO VERIFICADO", "reason": f"Consultas direcionadas: {overlay_checked}; não inventaria todos os aplicativos."})
    # O valor de accessibility contém somente componentes. Retém apenas pacotes da base.
    result, cap, failures = query(ctx, ["settings", "get", "secure", "enabled_accessibility_services"], timeout=4, max_bytes=16384)
    accessibility_ok = bool(result and result.ok and not re.search(r"(?i)(exception|permission|error)", result.text))
    if accessibility_ok:
        for component in result.text.strip().split(":"):
            package = component.split("/", 1)[0]
            if package in known_packages:
                info = package_info(ctx, package)
                source = info.get("installerPackageName", "não informado")
                findings.append(ctx.finding("M6", "acessibilidade", "Serviço de acessibilidade de app da base está habilitado", {"package": package, "installer": source, "limite": "Acessibilidade também atende usos legítimos."}, "INDÍCIO", "overlay" if source not in ("com.android.vending", "não informado") else "hint", cap))
    checks.append({"name": "Acessibilidade filtrada pela base", "requires": "adb", "status": "OK" if accessibility_ok else "NÃO VERIFICADO", "reason": "Descarta componentes de apps fora da base imediatamente."})
    checks.extend([
        {"name": "Device admin e fontes desconhecidas", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Interfaces variam por fabricante. VPN, DNS e proxy são cobertos em M11."},
        {"name": "Bootloader e SELinux", "requires": "none", "status": "PARCIAL", "reason": "Indicadores aparecem na sonda de privilégios; propriedades podem ser ocultadas/adulteradas."},
    ])
    return {"module": "M6", "requires": "none", "status": "PARCIAL", "reason": "Configurações são contexto técnico, não prova de uso de cheats.", "findings": findings,
            "data": {"device": device, "settings": states, "usb_debug": observed.get("adb_enabled"),
                     "auto_time": observed.get("auto_time")}, "checks": checks}
