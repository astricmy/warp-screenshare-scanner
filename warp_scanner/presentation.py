"""Resumo compartilhado entre a embed e o TXT. Dados do aparelho ficam em spans inertes."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import re
import config
from .report_privacy import clean_span

LEVELS = ("CONFIRMADO", "PROVÁVEL", "INDÍCIO")
BADGE = dict(zip(LEVELS, ("🔴", "🟠", "🟡")))
BAR = "-" * 41
BR = timezone(timedelta(hours=-3))
TICK = chr(96)
LABELS = {
    "M1": "Instalação do Roblox", "M2": "Perfil público", "M3": "Pacotes e arquivos",
    "M4": "Rastros e lixeira", "M5": "Downloads", "M6": "Dispositivo e configurações",
    "M7": "Processos", "M8": "Scripts e clipboard", "M9": "Uso e reinstalação",
    "M10": "Autenticidade do APK", "M11": "Rede e proxy",
}

def units(v):
    return len(v.encode("utf-16-le")) // 2

def fit(v, limit):
    if units(v) <= limit:
        return v
    return v.encode("utf-16-le")[:max(0, limit-1)*2].decode("utf-16-le", "ignore") + "…"

def span(value, limit=80):
    return TICK + fit(clean_span(value).strip() or "N/A", limit) + TICK

def fixed(value):
    """Exclusivo para dados estruturados já validados (UUID, data, ID, sessão)."""
    return TICK + str(value) + TICK

def when(stamp, fmt="%d/%m/%Y %H:%M"):
    try:
        event = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if event.tzinfo is not None:
            return event.astimezone(BR).strftime(fmt)
    except (ValueError, AttributeError, OverflowError):
        pass
    return "N/A"

def module(report, name):
    return next((m for m in report["modules"] if m["module"] == name), {})

def check(report, name, part):
    return next((c["status"] for c in module(report, name).get("checks", []) if c["name"] == part), None)

def toggle(value):
    return "**ON**" if value is True else "**OFF**" if value is False else "**N/A**"

def boolean(value, reason):
    label = "🚨 **True**" if value is True else "✅ **False**" if value is False else "➖ **N/A**"
    return label + " — " + fit(reason, 78)

def profile_url(identity):
    uid = identity.get("userId")
    if type(uid) is int and 0 < uid < 2**63 and re.fullmatch(r"[A-Za-z0-9_]{3,20}", str(identity.get("nick", ""))):
        return f"https://www.roblox.com/users/{uid}/profile"
    return None

def facts(findings):
    """Guardar totais antes do corte de detalhes. A cobertura nunca parece limpa por truncamento."""
    counts = Counter(f.get("level") for f in findings)
    clipboard = [f for f in findings if f.get("category") == "clipboard" and f["level"] in LEVELS]
    patterns = {p for f in clipboard for p in f["evidence"].get("padroes", []) if isinstance(p, str)}
    downloads = [f for f in findings if f.get("module") == "M5" and f.get("category") == "download"]
    signals = [f for f in findings if f.get("module") == "M11" and f.get("level") in LEVELS[:2]]
    return {
        "counts": {level: counts[level] for level in LEVELS},
        "clipboard": len(patterns) or len(clipboard),
        "excerpt": clipboard[0]["evidence"].get("trecho", "") if clipboard else "",
        "downloads": len(downloads),
        "domains": [{"domain": f["evidence"].get("domain", ""), "time": f["time"]} for f in downloads[:4]],
        "network_alert": signals[0]["description"] if signals else None,
        "network_place": signals[0]["evidence"].get("local", "") if signals else "",
    }

def location(f):
    e = f.get("evidence")
    e = e if isinstance(e, dict) else {}
    path = e.get("caminho_android") or e.get("caminho") or e.get("path")
    if path:
        shown = path.removeprefix("/storage/emulated/0/").replace("/", " › ")
        exact = bool(e.get("caminho_android"))
        state = "na lixeira" if f.get("category") == "lixeira" else "existe" if exact else "citado"
        suffix = f" ({state} • {'exato' if exact else 'local informado'})"
    elif e.get("local"):
        shown, suffix = e["local"], " (configuração observada)"
    elif e.get("package"):
        shown = "Apps › " + e["package"]
        suffix = " (registro residual)" if f.get("category") == "remoção" else " (pacote)"
    else:
        shown = {"clipboard": "Área de transferência atual", "download": "Gerenciador de downloads"}.get(
            f.get("category"), LABELS.get(f["module"], "Local não identificado"))
        suffix = " (sem caminho de arquivo)"
    prefix = "└ 📍 "
    return prefix + span(shown, 90 - units(prefix + suffix) - 2) + suffix

def finding_lines(f):
    level = f["level"]
    return [f"{BADGE[level]} **[{level}]** " + span(f["description"], 78), location(f)]

def replace_result(m10, m1):
    result = m10.get("referencia_instalada")
    source = m1.get("installerPackageName")
    installers = {"com.android.vending": "Play Store", "com.android.packageinstaller": "instalador de pacotes",
                  "com.google.android.packageinstaller": "instalador de pacotes", "com.android.shell": "ADB"}
    via = " • instalador: " + installers.get(source, "não identificado" if not source or source == "null" else "outra origem")
    if result == "COMPATÍVEL COM REFERÊNCIA":
        return boolean(False, "APK base compatível com referência oficial" + via)
    bad = {"DIVERGÊNCIA DA VERSÃO REFERENCIADA": "certificado diferente da referência da versão",
           "HASH BLOQUEADO VALIDADO": "APK base com hash bloqueado validado",
           "CERTIFICADO BLOQUEADO VALIDADO": "APK base com certificado bloqueado validado"}
    if result in bad:
        return boolean(True, bad[result] + via)
    return boolean(None, "referências conflitantes" if result == "CONFLITO DE REFERÊNCIAS" else "autenticidade do APK instalado não verificada")

def usage_result(history, privilege):
    usage = history.get("uso_roblox") or {}
    seconds = usage.get("segundos_pareados_observados")
    if type(seconds) is not int or seconds < 0:
        return boolean(None, "eventos de uso indisponíveis" if privilege.get("root") or privilege.get("adb") else "requer ADB")
    if not usage.get("intervalos_pareados") and usage.get("transicoes_incompletas"):
        return boolean(None, "transições sem uma sessão completa observável")
    return f"**{seconds // 3600}h {(seconds // 60) % 60}m** — nas últimas 72 h (observado; pode estar parcial)"

def proxy_result(report, s):
    if s["network_alert"]:
        place = re.search(r"rede salva #([0-9]{1,4})", s.get("network_place", ""))
        note = f" (rede salva #{place[1]})" if place else ""
        return "🚨 **True** — " + span(s["network_alert"], 74-units(note)) + note
    net = module(report, "M11")
    # Conexões/sites inacessíveis, CAs ocultas ou sondas recusadas não são um negativo verificado.
    observation = net.get("data", {})
    notes = []
    if observation.get("vpn", {}).get("interfaces_ativas"):
        notes.append("VPN ativa")
    if observation.get("dns", {}).get("modo_privado") == "hostname":
        notes.append("DNS privado")
    if net.get("status") == "OK":
        return boolean(False, "nenhum sinal forte em proxy, VPN, DNS e certificados" + ("; " + ", ".join(notes) if notes else ""))
    return boolean(None, "cobertura de rede incompleta" + ("; observado: " + ", ".join(notes) if notes else ""))

def overview(report, top=4):
    data = {m["module"]: m.get("data", {}) for m in report["modules"]}
    identity, env, hist = (data.get(k, {}) for k in ("M2", "M6", "M9"))
    url = profile_url(identity)
    privilege = report["privilege"]
    device = env.get("device", {})
    lines = []
    if url:
        name = span(identity["nick"])
        lines.append(f"👤 **Roblox User:** {name} • [🔗 Perfil]({url}) (ID {fixed(identity['userId'])})")
    else:
        lines.append("👤 **Roblox User:** ➖ **N/A** — não identificado")
    ownership = {"verificada":"✅ **verificada**", "não confere":"⚠️ **não confere**"}
    lines.append("└ Posse do perfil: " + ownership.get(identity.get("ownership_status") if url else None, "➖ não verificada"))
    discord = report.get("discord_identity", {})
    if discord.get("username"):
        did = str(discord.get("id", ""))
        tag = " (ID " + fixed(did) + ")" if re.fullmatch(r"[1-9][0-9]{16,19}", did) else ""
        lines.append(f"💬 **Discord User:** {span(discord['username'],32)}{tag} • 📝 informado (não verificado)")
    else:
        lines.append("💬 **Discord User:** ➖ **N/A** — não informado")
    model = " ".join(str(device[k]) for k in ("brand", "model") if device.get(k))
    patch = device.get("security_patch", "")
    patch = fixed(patch) if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", patch) else "N/A"
    lines.append(f"📱 **Device:** **{span(model or 'N/A',64)}** | Android {span(device.get('android', 'N/A'),16)} (patch {patch})")
    mode = privilege.get("mode")
    mode = mode if mode in ("PADRÃO", "PADRÃO+", "AVANÇADO") else "N/A"
    lines.append(f"⚙️ **System Info:** **{mode}** | Scanner {fixed('v'+report['version'])}" + (" • simulação" if report["synthetic"] else ""))
    session = report["session_code"] or "N/A"
    lines.append(f"└ Scan {fixed(report['scan_id'])} | Sessão {fixed(session)}")
    lines.append(f"└ {when(report['timestamp'])} (UTC-3) | USB debug {toggle(env.get('usb_debug'))} | Data auto {toggle(env.get('auto_time'))}")
    root = privilege.get("root_result", {})
    lines.append("🔓 **Root:** " + boolean(root.get("value"), root.get("reason") or "sonda não verificada"))
    lines.append(BAR)
    s = report.get("summary_facts") or facts(report["findings"])
    counts = s["counts"]
    total = sum(counts.values())
    counts_line = " • ".join(f"{BADGE[k]} {counts[k]} {words[counts[k] != 1]}" for k, words in
                             zip(LEVELS, (("confirmado","confirmados"),("provável","prováveis"),("indício","indícios"))))
    verdict = report["verdict"].split(" (")[0]
    emoji = {"ALTO RISCO":"🚨", "SUSPEITO":"⚠️", "LIMPO":"✅"}.get(verdict, "➖")
    partial = " (cobertura parcial)" if report["partial_coverage"] else ""
    lines.append(f"📊 **General Result:** {emoji} **{verdict}**{partial} — {total} {'achado' if total == 1 else 'achados'} ({counts_line})")
    findings = [f for f in report["findings"] if f["level"] in LEVELS][:top]
    for f in findings:
        lines.extend(finding_lines(f))
    if total > len(findings):
        lines.append(f"➕ {total-len(findings)} outros achados; veja os detalhes e os limites nos anexos")
    if s["clipboard"]:
        n = s["clipboard"]
        clip = f"⚠️ **{n} {'padrão suspeito' if n == 1 else 'padrões suspeitos'}** (leitura única)"
    elif check(report, "M8", "clipboard_atual") == "OK":
        clip = "✅ **nenhum padrão suspeito** (leitura única)"
    elif report["consent"].get("clipboard") is False and not report["synthetic"]:
        clip = "➖ **N/A — recusado pelo jogador**"
    else:
        clip = "➖ **N/A** — leitura não verificada"
    lines.append("📋 **Clipboard Results:** " + clip)
    if s["excerpt"]:
        lines.append("└ " + span(s["excerpt"], 80))
    lines.append("└ ℹ️ Histórico: N/A — " + ("não coletado" if privilege.get("root") else "não verificável sem root"))
    if s["downloads"]:
        n = s["downloads"]
        browser = f"⚠️ **{n} {'download de domínio' if n == 1 else 'downloads de domínios'} da blocklist**"
    elif check(report, "M5", "Origens de download filtradas pelo provedor") == "OK":
        browser = "✅ **nenhum domínio da blocklist** (downloads verificados)"
    else:
        browser = "➖ **N/A** — verificação de downloads incompleta"
    lines.append("🧭 **Browser History Result:** " + browser)
    lines.extend("└ " + span(row["domain"], 60) + " (" + when(row["time"], "%d/%m %H:%M") + ")" for row in s["domains"][:4])
    lines.append("└ ℹ️ Histórico do navegador: N/A — " + ("não coletado" if privilege.get("root") else "não verificável sem root"))
    lines.append("🌐 **Proxy Bypass Detection:** " + proxy_result(report, s))
    lines.append(BAR)
    lines.append("🔁 **Roblox Replace Check:** " + replace_result(data.get("M10", {}), data.get("M1", {})))
    lines.append("⏱️ **Roblox Total Time on 3d:** " + usage_result(hist, privilege))
    reinst = hist.get("reinstall", {})
    reason = reinst.get("reason") or "indeterminado"
    installed = when(reinst.get("firstInstallTime"))
    if reinst.get("value") is True and installed != "N/A":
        reason = f"instalado em {installed} (< 72 h) • com uso anterior"
    lines.append("♻️ **Roblox Reinstall:** " + boolean(reinst.get("value"), reason))
    return "\n".join(lines)

def message(report, avatar=False):
    desc = overview(report)
    for top in (3, 2, 1, 0):
        if units(desc) <= 3800:
            break
        desc = overview(report, top)
    profile = profile_url(module(report, "M2").get("data", {}))
    main = {"title":"🛡️ Relatório de Verificação | WARP SCREENSHARE", "description":desc,
            "color":0xFFFFFF, "timestamp":report["timestamp"],
            "footer":{"text":f"🛡️ {config.BRAND} • {config.DISCORD_INVITE} • Scan {report['scan_id']} • Sessão {report['session_code'] or 'N/A'}"}}
    if profile:
        main["url"] = profile
        if avatar:
            main["thumbnail"] = {"url":"attachment://avatar.png"}
    budget = 6000 - sum(units(v) for v in (main["title"], desc, main["footer"]["text"]))
    embeds = [main]
    def add(title, lines, allocation):
        nonlocal budget
        remaining = min(allocation, budget-units(title), 4096)
        selected = []
        for line in lines:
            size = units(line) + int(bool(selected))
            if size > remaining:
                break
            selected.append(line)
            remaining -= size
        if selected:
            body = "\n".join(selected)
            embeds.append({"title":title, "description":body, "color":0x010101})
            budget -= units(title)+units(body)
    ranked = [f for f in report["findings"] if f["level"] in LEVELS]
    extra = ["\n".join(finding_lines(f)) for f in ranked[4:]]
    timeline = ["Horários em UTC-3; podem indicar a coleta.",
                *(f"{when(f['time'])} • {span(f['description'], 58)}" for f in report["timeline"][:3])]
    add("Achados e linha do tempo", [*extra[:3], *timeline, "Lista completa dos registros retidos nos anexos."], min(850, budget//2))
    critical = [f"{m['module']} • {LABELS.get(m['module'], 'Verificação')}: {m['status']}" for m in report["modules"]]
    add("Cobertura e integridade", [report["notice"], "Integridade: " + span(report["integrity"].get("status", "NÃO VERIFICADO")), *critical], budget)
    return {"embeds": embeds, "allowed_mentions": {"parse": []}}
