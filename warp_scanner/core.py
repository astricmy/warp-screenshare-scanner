"""Contratos comuns e execução limitada de comandos somente leitura."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
import re
import shlex
import subprocess
import threading
import uuid

from .safety import redact


def now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CommandResult:
    ok: bool
    text: str = ""
    reason: str = ""
    code: int = -1


def run_command(argv, timeout=8, max_bytes=262144):
    """Sem shell local, sem arquivos temporários e sem vazar stderr em erros."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, shell=False)
    except (OSError, ValueError):
        return CommandResult(False, reason="Comando indisponível ou acesso negado")
    result = bytearray()
    overflow = threading.Event()

    def read():
        try:
            while True:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                if len(result) + len(chunk) > max_bytes:
                    overflow.set()
                    proc.kill()
                    break
                result.extend(chunk)
        except (OSError, ValueError):
            overflow.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        proc.wait(timeout=timeout)
        reader.join(timeout=1)
        if reader.is_alive() or overflow.is_set():
            return CommandResult(False, reason="Limite de saída excedido")
        if proc.returncode != 0:
            return CommandResult(False, reason="Consulta negada ou não suportada", code=proc.returncode)
        return CommandResult(True, bytes(result).decode("utf-8", "replace"), code=0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
        return CommandResult(False, reason="Tempo limite excedido")
    finally:
        reader.join(timeout=1)
        proc.stdout.close()


class Context:
    def __init__(self, args, signatures, settings, consent, storage):
        self.args, self.signatures, self.settings = args, signatures, settings
        self.consent, self.storage = consent, storage
        self.privilege = {"root":False,"adb":False,"mode":"PADRÃO","classification":"SEM_ROOT","indicators":[]}
        self.files, self.file_stats, self.installed = [], {}, {}

    def run(self, argv, requires="none", timeout=8, max_bytes=262144):
        if requires == "root":
            if not self.privilege.get("root"):
                return CommandResult(False, reason="Root não confirmado")
            argv = ["su", "-c", shlex.join([str(x) for x in argv])]
        elif requires == "adb":
            if not self.privilege.get("adb") or not getattr(self.args, "adb_serial", None):
                return CommandResult(False, reason="ADB local não conectado")
            argv = ["adb", "-s", self.args.adb_serial, "shell", shlex.join([str(x) for x in argv])]
        return run_command([str(x) for x in argv], timeout, max_bytes)

    def finding(self, module, category, description, evidence, level, weight_key,
                requires="none", time=None):
        return {"id":str(uuid.uuid4()),"module":module,"category":redact(str(category),80),
                "description":redact(str(description),200),"evidence":sanitize(evidence),
                "level":level,"weight":int(self.settings["weights"].get(weight_key,10)),
                "time":time or now(),"requires":requires}


def sanitize(value, key=""):
    """Barreira final: nada de tokens, credenciais ou dados arbitrários em logs."""
    if isinstance(value, dict):
        return {str(k):sanitize(v,str(k)) for k,v in value.items()
                if str(k).lower() not in {"token","password","cookie","authorization","secret","description_raw"}}
    if isinstance(value, (list,tuple)):
        return [sanitize(v,key) for v in value]
    if isinstance(value,str):
        if key == "profile_url" and re.fullmatch(r"https://www\.roblox\.com/users/[1-9][0-9]{0,18}/profile",value):
            return value
        # Identificadores técnicos gerados pelo scanner não são conteúdo do aparelho.
        if key in {"sha256","scanner_sha256","signatures_sha256","active_base_sha256","hash"} and re.fullmatch(r"[a-fA-F0-9]{64}",value):
            return value
        if key in {"id","scan_id"} and re.fullmatch(r"[a-fA-F0-9-]{36}",value):
            return value
        if key == "session_code" and re.fullmatch(r"WARP-[A-Z0-9]{4,24}",value):
            return value
        if key in {"timestamp","time","mtime","ctime","ctime_metadados","firstInstallTime","lastUpdateTime","created"} and re.fullmatch(r"[0-9TZ +:.\-]{10,40}",value):
            return value[:256]
        return redact(value,1000)
    return value if isinstance(value,(bool,int,float,type(None))) else redact(str(value),160)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path,"rb") as stream:
        for block in iter(lambda:stream.read(65536),b""):
            digest.update(block)
    return digest.hexdigest()


def unavailable(module, reason, requires="none"):
    return {"module":module,"requires":requires,"status":"NÃO VERIFICADO", "reason":reason,
            "findings":[],"data":{},"checks":[{"name":module,"requires":requires,"status":"NÃO VERIFICADO","reason":reason}]}
