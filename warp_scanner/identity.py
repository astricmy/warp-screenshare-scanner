"""Identidade pública, sem autenticação e sem ler dados privados do aplicativo."""
import re
from .net import get_json
from .core import unavailable
from .safety import redact


def discord_identity(username, user_id=""):
    """O próprio jogador informa o nome. O scanner não acessa o app Discord."""
    handle = (username or "").strip().removeprefix("@")
    if not re.fullmatch(r"[a-z0-9_.]{2,32}", handle) or ".." in handle or handle in {"here", "everyone"}:
        return {"status": "NÃO VERIFICADO", "source": "Ausente ou formato inválido"}
    data = {"status": "AUTODECLARADO", "username": handle, "ownership_verified": False}
    if re.fullmatch(r"[1-9][0-9]{16,19}", str(user_id)) and int(user_id) < 2**64:
        data["id"] = str(user_id)
    return data


def collect(ctx):
    nick = ctx.args.nick
    if not nick or not re.fullmatch(r"[A-Za-z0-9_]{3,20}",nick):
        return unavailable("M2","Nickname ausente ou inválido")
    try:
        lookup = get_json("https://users.roblox.com/v1/usernames/users",
                          {"usernames":[nick],"excludeBannedUsers":False})
        users = lookup.get("data",[])
        if len(users)!=1 or type(users[0].get("id")) is not int or not 0 < users[0]["id"] < 10**19:
            return unavailable("M2","Usuário não encontrado na API pública")
        uid = users[0]["id"]
        profile = get_json(f"https://users.roblox.com/v1/users/{uid}")
        name = profile.get("name", "")
        if profile.get("id") != uid or not re.fullmatch(r"[A-Za-z0-9_]{3,20}", name):
            raise ValueError()
        description = profile.pop("description", None)
        checked = bool(ctx.args.session_code and isinstance(description, str))
        owned = bool(checked and re.search(r"(?<![A-Za-z0-9-])"+re.escape(ctx.args.session_code)+r"(?![A-Za-z0-9-])",description))
        del description
        data = {"nick":name,"displayName":redact(profile.get("displayName",""),80),
                "userId":uid,"profile_url":f"https://www.roblox.com/users/{uid}/profile",
                "created":profile.get("created"),"isBanned":profile.get("isBanned"),"ownership_verified":owned,
                "ownership_status":"verificada" if owned else "não confere" if checked else "não verificada"}
        findings=[]
        if ctx.args.expected_nick and ctx.args.expected_nick.casefold()!=data["nick"].casefold():
            findings.append(ctx.finding("M2","identidade","Nickname diferente do esperado pela staff",
                                        {"informado":data["nick"],"esperado":ctx.args.expected_nick},"PROVÁVEL","identity_mismatch"))
        return {"module":"M2","requires":"none","status":"PARCIAL","reason":"Somente identidade pública; identidade privada do app não lida",
                "data":data,"findings":findings,"checks":[
                    {"name":"API pública e posse","requires":"none","status":"OK","reason":"Descrição descartada após comparar código"},
                    {"name":"Identidade privada do aplicativo","requires":"root","status":"NÃO VERIFICADO","reason":"Sem formato isolado de identidade validado; credenciais não são acessadas"}]}
    except Exception:
        return unavailable("M2","API pública indisponível ou resposta inválida; nenhuma credencial utilizada")
