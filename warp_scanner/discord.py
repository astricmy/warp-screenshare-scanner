"""Envio exclusivamente após confirmação; erros não exibem URLs nem segredos."""
import base64
import json
import math
import os
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
import uuid
import config
from .net import request


def saved_invite():
    from pathlib import Path
    # O convite da staff só pode ser usado na origem definida nesta versão.
    if os.environ.get("WARP_RELAY_URL", config.RELAY_URL).rstrip("/") != config.RELAY_URL:
        return ""
    try:
        return (Path.home() / ".config/warp/report-invite").read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return ""


def cloud_token(invite, code, sleep=time.sleep):
    body = json.dumps({"code": code}).encode()
    headers = {"Authorization": "Invite " + invite, "Content-Type": "application/json"}
    for attempt in range(3):
        try:
            raw = request(config.RELAY_URL + "/session", body, headers, max_bytes=2048)
            token = json.loads(raw)["token"]
            if not isinstance(token, str) or not token.startswith("auto."):
                raise ValueError("Resposta inválida")
            return token
        except HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
            delay = 2 ** attempt
            if error.code == 429:
                try:
                    delay = float(json.loads(error.read(2048)).get("retry_after", delay))
                except (ValueError, TypeError, AttributeError):
                    raise ValueError("Limite de sessão inválido") from None
                if not math.isfinite(delay) or not 0 < delay <= 60:
                    raise ValueError("Limite de sessão ativo") from None
            sleep(delay)
        except OSError:
            if attempt == 2:
                raise
            sleep(2 ** attempt)


def multipart(envelope):
    boundary="warp"+uuid.uuid4().hex
    payload={**envelope["payload"],"username":config.BRAND,"allowed_mentions":{"parse":[]}}
    chunks=[]
    chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="payload_json"\r\nContent-Type: application/json\r\n\r\n'.encode()+json.dumps(payload,ensure_ascii=False).encode()+b"\r\n")
    for i,item in enumerate(envelope["attachments"]):
        is_png = item["content_type"] == "image/png"
        content = base64.b64decode(item["content"],validate=True) if is_png else item["content"].encode()
        content_type = "image/png" if is_png else item["content_type"]+"; charset=utf-8"
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="files[{i}]"; filename="{item["filename"]}"\r\nContent-Type: {content_type}\r\n\r\n'.encode()+content+b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks),f"multipart/form-data; boundary={boundary}"


def send(envelope, token="", direct=False, sleep=time.sleep):
    if direct:
        # Modo deliberadamente explícito para bancada da staff.
        url=os.environ.get("WARP_WEBHOOK_URL","")
        parsed=urlsplit(url)
        if parsed.scheme!="https" or parsed.hostname!="discord.com" or not parsed.path.startswith("/api/webhooks/") or parsed.username:
            return False,"Webhook de teste não configurado ou inválido"
        url=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,"wait=true",""))
        body,content_type=multipart(envelope)
        headers={"Content-Type":content_type}
    else:
        url=os.environ.get("WARP_RELAY_URL",config.RELAY_URL).rstrip("/")
        if not url or not token:
            return False,"Relay ou token de sessão não configurado"
        parsed=urlsplit(url)
        if parsed.scheme!="https" or parsed.username or parsed.query or parsed.fragment:
            return False,"Relay inválido; HTTPS obrigatório"
        url+="/report"
        body=json.dumps(envelope,ensure_ascii=False).encode()
        headers={"Content-Type":"application/json","Authorization":"Bearer "+token}
    with_image = any(f.get("content_type") == "image/png" for f in envelope.get("attachments",[]))
    if with_image and not direct:
        headers["X-Warp-Evidence"]="png"
    if len(body)>(6553604 if with_image else 262144):
        return False,"Relatório excedeu limite de envio; salve localmente para revisão"
    for attempt in range(3):
        try:
            raw=request(url,body,headers,max_bytes=65536 if direct else 4096,timeout=20)
            response=json.loads(raw) if raw else {}
            if not direct and response.get("ok") is not True:
                return False,"Relay não confirmou o recebimento"
            return True,"Relatório entregue ao Discord" if direct else "Relay confirmou o envio"
        except HTTPError as error:
            if not direct and error.code != 429:
                try:
                    info = json.loads(error.read(2048))
                except (ValueError, OSError):
                    info = {}
                if not isinstance(info, dict):
                    info = {}
                if info.get("uncertain"):
                    return False, "Entrega incerta. Confira o canal antes de repetir."
                if error.code < 500 or error.code == 502:
                    reason = info.get("message") if url == config.RELAY_URL + "/report" else None
                    if not isinstance(reason, str) or not reason.isprintable():
                        reason = "Confira a configuração com a staff."
                    return False, f"O envio foi autorizado, mas o servidor respondeu HTTP {error.code}. {reason[:180]}"
            if error.code==429:
                try:
                    delay=float(json.loads(error.read(1024)).get("retry_after",2**attempt))
                    if not math.isfinite(delay) or delay>60:
                        return False,"Limite de envio ativo; aguarde a janela indicada pela staff e preserve o relatório local"
                    delay=max(1,delay)
                except Exception:
                    delay=2**attempt
            elif error.code>=500:
                delay=2**attempt
            else:
                return False,"Envio rejeitado; confira sessão e configuração com a staff"
        except Exception:
            if direct:
                return False,"Entrega direta incerta. Confira o canal antes de tentar novamente"
            delay=2**attempt
        if attempt<2:
            sleep(delay)
    return False,"Envio não confirmado após 3 tentativas; nenhum erro bruto foi registrado"
