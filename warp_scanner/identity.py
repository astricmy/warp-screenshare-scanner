"""Identidade pública, sem autenticação e sem ler dados privados do aplicativo."""
import re
from .net import get_json
from .core import unavailable
from .safety import redact


def discord_identity(username):
    """O próprio jogador informa o nome. O scanner não acessa o app Discord."""
    handle = (username or "").strip().removeprefix("@")
    if not re.fullmatch(r"[a-z0-9_.]{2,32}", handle) or ".." in handle or handle in {"here", "everyone"}:
        return {"status": "NÃO VERIFICADO", "source": "Ausente ou formato inválido"}
    return {"status": "AUTODECLARADO", "username": handle, "ownership_verified": False}


def collect(ctx):
    nick = ctx.args.nick
    if not nick or not re.fullmatch(r"[A-Za-z0-9_]{3,20}",nick):
        return unavailable("M2","Nickname ausente ou inválido")
    try:
        lookup = get_json("https://users.roblox.com/v1/usernames/users",
                          {"usernames":[nick],"excludeBannedUsers":False})
        users = lookup.get("data",[])
        if len(users)!=1 or not isinstance(users[0].get("id"),int):
            return unavailable("M2","Usuário não encontrado na API pública")
        uid = users[0]["id"]
        profile = get_json(f"https://users.roblox.com/v1/users/{uid}")
        if profile.get("id") != uid:
            raise ValueError()
        description = profile.pop("description","")
        owned = bool(ctx.args.session_code and re.search(r"(?<![A-Za-z0-9-])"+re.escape(ctx.args.session_code)+r"(?![A-Za-z0-9-])",description))
        del description
        data = {"nick":redact(profile.get("name",nick),60),"displayName":redact(profile.get("displayName",""),80),
                "userId":uid,"profile_url":f"https://www.roblox.com/users/{uid}/profile",
                "created":profile.get("created"),"isBanned":profile.get("isBanned"),"ownership_verified":owned}
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
