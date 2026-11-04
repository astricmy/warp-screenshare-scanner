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
    parents = {child: parent for parent in root.iter() for child in parent}
    def labels(node):
        current = node
        package = None
        while current is not None:
            if current.get("password") == "true":
                return []
            package = package or current.get("package")
            current = parents.get(current)
        if package != PACKAGES[app]:
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
        if 2 <= len(pair) <= 3 and any(v.casefold().rstrip(":") in LABELS for v in labels(pair[0])):
            # O terceiro controle costuma ser o botão Editar. Apenas o segundo
            # controle, dentro da mesma linha rotulada, fornece o valor.
            for child in pair[1].iter():
                for value in labels(child):
                    candidates.add(valid(value))
    candidates.discard(None)
    return candidates.pop() if len(candidates) == 1 else None


def observe(ctx, app, ask, sleep=time.sleep):
    def status(value, reason):
        args = getattr(ctx, "args", ctx)
        observations = getattr(args, "account_observations", {})
        observations[app] = {"status": value, "reason": reason}
        args.account_observations = observations
        print(f"{app}: {reason}", flush=True)
    if not ctx.privilege.get("adb"):
        status("NÃO VERIFICADO", "ADB indisponível. Autorizar a leitura exige também conectar o ADB local.")
        return None
    if not ask(f"Ler apenas o nick visível na tela Minha conta do {app} via ADB?"):
        status("RECUSADO", "Leitura da tela recusada.")
        return None
    print(f"Abra agora o {app} em Configurações > Conta e deixe o nome de usuário visível. Serão feitas até 6 tentativas enquanto você abre a tela. Volte ao Termux em até 2 minutos para conferir o resultado.", flush=True)
    def foreground():
        r = ctx.run(["sh", "-c", "dumpsys activity activities | grep -m1 -E 'topResumedActivity=|mResumedActivity:'"],
                    requires="adb", timeout=4, max_bytes=2048)
        return r.ok and re.search(r"\s"+re.escape(PACKAGES[app])+r"/", r.text)
    reason = "A tela do aplicativo não ficou em primeiro plano durante a leitura."
    for _ in range(6):
        sleep(5)
        if not foreground():
            continue
        result = ctx.run(["uiautomator", "dump", "/dev/fd/1"], requires="adb", timeout=5, max_bytes=256*1024)
        if not result.ok:
            reason = "O Android não disponibilizou a leitura da tela pelo ADB."
            continue
        nick = username(result.text, app)
        if nick and foreground():
            status("OBSERVADO", "Nome de usuário identificado na tela da conta.")
            return nick
        reason = "Campo Nome de usuário não reconhecido. Abra a tela da conta com esse campo visível."
    status("NÃO VERIFICADO", reason)
    return None
