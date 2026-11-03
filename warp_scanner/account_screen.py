"""Extrai somente um campo de usuário da tela de conta aberta pelo participante."""
import re
import time
from xml.etree import ElementTree

PACKAGES = {"Roblox": "com.roblox.client", "Discord": "com.discord"}
LABELS = ("username", "nome de usuário", "nome de utilizador")
HEADINGS = {"my account", "account info", "account information", "conta", "minha conta",
            "informações da conta", "informações de conta", "account", "edit username", "editar nome de usuário"}


def username(xml, app):
    start, end = xml.find("<hierarchy"), xml.rfind("</hierarchy>")
    if start < 0 or end <= start:
        return None
    try:
        root = ElementTree.fromstring(xml[start:end + len("</hierarchy>")])
    except ElementTree.ParseError:
        return None
    def labels(node):
        if node.get("package") != PACKAGES[app] or node.get("password") == "true":
            return []
        return [v.strip() for v in (node.get("text", ""), node.get("content-desc", "")) if v.strip()]
    nodes = list(root.iter("node"))
    if not any(v.casefold() in HEADINGS for n in nodes for v in labels(n)):
        return None
    pattern = r"[A-Za-z0-9_]{3,20}" if app == "Roblox" else r"[a-z0-9_.]{2,32}"
    def valid(v):
        v = v.removeprefix("@")
        return v if re.fullmatch(pattern, v) and v.casefold() not in set(LABELS)|HEADINGS|{"everyone","here","password","email","edit","editar"} else None
    candidates = set()
    for n in nodes:
        for value in labels(n):
            match = re.fullmatch(r"(?:username|nome de usuário|nome de utilizador)\s*[:,\n]\s*(@?[^\s]+)", value, re.I)
            if match:
                candidates.add(valid(match[1]))
        # Apenas rótulo e valor no mesmo grupo de dois controles.
        pair = list(n)
        if len(pair) == 2 and any(v.casefold() in LABELS for v in labels(pair[0])):
            for value in labels(pair[1]):
                candidates.add(valid(value))
    candidates.discard(None)
    return candidates.pop() if len(candidates) == 1 else None


def observe(ctx, app, ask, sleep=time.sleep):
    if not ctx.privilege.get("adb"):
        return None
    if not ask(f"Ler apenas o nick visível na tela Minha conta do {app} via ADB?"):
        return None
    print(f"Abra agora o {app} em Configurações > Conta e deixe o nome de usuário visível. Leitura única em 12 segundos. Depois volte ao Termux.", flush=True)
    sleep(12)
    def foreground():
        r = ctx.run(["sh", "-c", "dumpsys activity activities | grep -m1 -E 'topResumedActivity=|mResumedActivity:'"],
                    requires="adb", timeout=4, max_bytes=2048)
        return r.ok and re.search(r"\s"+re.escape(PACKAGES[app])+r"/", r.text)
    if not foreground():
        return None
    result = ctx.run(["uiautomator", "dump", "/dev/fd/1"], requires="adb", timeout=10, max_bytes=256*1024)
    return username(result.text, app) if result.ok and foreground() else None
