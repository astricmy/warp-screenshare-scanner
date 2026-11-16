"""Identidade pública, sem autenticação e sem ler dados privados do aplicativo."""
import re
from .net import get_json
from .core import unavailable
from .safety import redact


def discord_id(value):
    value = str(value)
    if re.fullmatch(r"[1-9][0-9]{16,19}", value) and int(value) < 2**64:
        return value
    return ""


def discord_identity(username, user_id=""):
    """O próprio jogador informa o nome. O scanner não acessa o app Discord."""
    handle = (username or "").strip().removeprefix("@")
    if not re.fullmatch(r"[a-z0-9_.]{2,32}", handle) or ".." in handle or handle in {"here", "everyone"}:
        return {"status": "NÃO VERIFICADO", "source": "Ausente ou formato inválido"}
    data = {"status": "AUTODECLARADO", "username": handle, "ownership_verified": False}
    did = discord_id(user_id)
    if did:
        data.update(id=did, profile_url=f"https://discord.com/users/{did}")
    return data


def ask_profiles(args, include_discord, ask):
    def read(initial, prompt, validate, correction):
        value = initial or ask(prompt)
        while value:
            normalized = validate(value.strip())
            if normalized:
                return normalized
            print(correction)
            value = ask(prompt)
        return ""

    def roblox_name(value):
        value = value.removeprefix("@")
        return value if re.fullmatch(r"[A-Za-z0-9_]{3,20}", value) else ""

    args.nick = read(args.nick, "Informe seu nome de usuário do Roblox (Enter para pular): ",
                     roblox_name, "Use o nome de usuário de 3 a 20 caracteres que aparece após @ no perfil.")
    if not include_discord:
        args.discord_user = args.discord_id = ""
        return
    args.discord_user = read(args.discord_user, "Informe seu nome de usuário do Discord (Enter para pular): ",
                             lambda value: discord_identity(value).get("username"),
                             "Use o @nome de usuário do Discord, com letras minúsculas, números, ponto ou sublinhado.")
    if args.discord_user:
        args.discord_id = read(args.discord_id, "Para incluir o link do Discord, cole o ID de usuário (opcional; Enter para pular): ",
                               discord_id, "Copie o ID numérico em seu perfil do Discord, no menu de três pontos.")


def collect(ctx):
    nick = ctx.args.nick
    if not nick or not re.fullmatch(r"[A-Za-z0-9_]{3,20}", nick):
        return unavailable("M2", "Nome de usuário do Roblox ausente ou inválido")
    def failed(reason):
        return {"module":"M2", "requires":"none", "status":"PARCIAL", "reason":reason,
                "data":{"nick":nick, "source":"informado", "ownership_verified":False},
                "findings":[], "checks":[{"name":"Perfil público", "requires":"none", "status":"NÃO VERIFICADO", "reason":reason}]}
    try:
        lookup = get_json("https://users.roblox.com/v1/usernames/users",
                          {"usernames":[nick],"excludeBannedUsers":False})
        users = lookup.get("data",[])
        if len(users)!=1 or type(users[0].get("id")) is not int or not 0 < users[0]["id"] < 10**19:
            return failed("Usuário não encontrado na API pública")
        uid = users[0]["id"]
        profile = get_json(f"https://users.roblox.com/v1/users/{uid}")
        name = profile.get("name", "")
        if profile.get("id") != uid or not re.fullmatch(r"[A-Za-z0-9_]{3,20}", name) or name.casefold() != nick.casefold():
            raise ValueError()
        description = profile.pop("description", None)
        checked = bool(getattr(ctx.args, "verify_ownership", True) and ctx.args.session_code and isinstance(description, str))
        owned = bool(checked and re.search(r"(?<![A-Za-z0-9-])"+re.escape(ctx.args.session_code)+r"(?![A-Za-z0-9-])",description))
        del description
        data = {"nick":name,"displayName":redact(profile.get("displayName",""),80),
                "userId":uid,"profile_url":f"https://www.roblox.com/users/{uid}/profile",
                "created":profile.get("created"),"isBanned":profile.get("isBanned"),"ownership_verified":owned,
                "ownership_status":"verificada" if owned else "não confere" if checked else "não verificada"}
        data["source"] = "informado"
        findings=[]
        if ctx.args.expected_nick and ctx.args.expected_nick.casefold()!=data["nick"].casefold():
            findings.append(ctx.finding("M2","identidade","Nickname diferente do esperado pela staff",
                                        {"informado":data["nick"],"esperado":ctx.args.expected_nick},"PROVÁVEL","identity_mismatch"))
        return {"module":"M2","requires":"none","status":"PARCIAL","reason":"Somente identidade pública; identidade privada do app não lida",
                "data":data,"findings":findings,"checks":[
                    {"name":"API pública e posse","requires":"none","status":"OK","reason":"Descrição descartada após comparar código" if checked else "Perfil público consultado; posse não verificada"},
                    {"name":"Identidade privada do aplicativo","requires":"root","status":"NÃO VERIFICADO","reason":"Sem formato isolado de identidade validado; credenciais não são acessadas"}]}
    except Exception:
        return failed("API pública indisponível ou resposta inválida; nome informado preservado")
