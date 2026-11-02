"""Integridade de distribuição e atualização da base com pin SHA-256."""
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit
import config
from .core import sha256_file
from .net import request


def verify_manifest(base, manifest):
    mismatches=[]
    checked=0
    for line in manifest.splitlines():
        if not line.strip():
            continue
        match=re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.\-/]+)",line)
        if not match:
            raise ValueError("Manifesto inválido")
        digest, name=match.groups()
        relative=Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Caminho inválido")
        path=base / relative
        if path.is_symlink() or not path.is_file() or sha256_file(path)!=digest:
            mismatches.append(name)
        checked+=1
    if not checked:
        raise ValueError("Manifesto vazio")
    return checked,mismatches


def collect_integrity(base):
    result={"scanner_sha256":sha256_file(base/"scan.py"),"signatures_sha256":sha256_file(base/"signatures.json"),
            "status":"NÃO VERIFICADO","source":"checksums.txt local; pode ser adulterado junto do código"}
    manifest_path=base/"checksums.txt"
    if manifest_path.exists():
        try:
            count,mismatches=verify_manifest(base,manifest_path.read_text(encoding="utf-8"))
            result.update(status="DIVERGENTE" if mismatches else "OK LOCAL",checked=count,mismatches=mismatches)
        except (OSError,ValueError):
            result["status"]="MANIFESTO INVÁLIDO"
    # Nunca requisitar endereço placeholder. HTTPS remoto somente em instalação configurada.
    if "SEU_USUARIO" not in config.REPO_URL:
        try:
            manifest=request(f"{config.REPO_URL}/releases/download/{config.RELEASE_TAG}/checksums.txt",release=True).decode("utf-8")
            count,mismatches=verify_manifest(base,manifest)
            result.update(status="DIVERGENTE" if mismatches else "OK RELEASE",checked=count,mismatches=mismatches,source="manifesto do release HTTPS")
        except Exception:
            result["remote_status"]="NÃO VERIFICADO: manifesto do release indisponível"
    else:
        result["remote_status"]="NÃO VERIFICADO: repositório ainda não configurado"
    return result


def load_signatures(base, local_only=False):
    public_bytes=(base/"signatures.json").read_bytes()
    public=json.loads(public_bytes)
    active_hash=hashlib.sha256(public_bytes).hexdigest()
    url="" if local_only else os.environ.get("WARP_SIGNATURES_URL",config.SIGNATURES_URL)
    pin=os.environ.get("WARP_SIGNATURES_SHA256","").lower()
    status="Base pública local"
    if url:
        try:
            if not re.fullmatch(r"[a-f0-9]{64}",pin):
                raise ValueError()
            headers={}
            relay=urlsplit(os.environ.get("WARP_RELAY_URL",config.RELAY_URL))
            target=urlsplit(url)
            if os.environ.get("WARP_SESSION_TOKEN") and target.scheme == "https" and target.netloc == relay.netloc and target.path == "/signatures" and not target.query:
                headers["Authorization"]="Bearer "+os.environ["WARP_SESSION_TOKEN"]
            raw=request(url,headers=headers)
            if hashlib.sha256(raw).hexdigest()!=pin:
                raise ValueError()
            remote=json.loads(raw)
            if not isinstance(remote.get("entries"),list) or not isinstance(remote.get("scripts"),dict):
                raise ValueError()
            public=remote
            active_hash=pin
            status="Base HTTPS com SHA-256 fixado pela staff"
        except Exception:
            status="Atualização não verificada; fallback para base pública local"
    return public,status,active_hash
