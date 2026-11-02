"""Minimização final dos dados que deixam os coletores (inclui os anexos locais)."""
import ipaddress
import re
import unicodedata
from .safety import contains_credential, redact

_IPV4 = re.compile(r"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")
_IPV6 = re.compile(r"(?<![a-fA-F0-9:])[a-fA-F0-9:]*:[a-fA-F0-9:]+(?:%[a-zA-Z0-9_.-]+)?(?![a-fA-F0-9:])")
_MAC = re.compile(r"(?i)(?<![a-z0-9])(?:[a-f0-9]{2}[:-]){5}[a-f0-9]{2}(?![a-z0-9])")
_PRIVATE_KEYS = {"ssid", "bssid", "imei", "serial", "serialno", "android_id", "mac", "phone", "google_account"}

def hide_address(m):
    try:
        ipaddress.ip_address(m[0])
    except ValueError:
        return m[0]
    return "[REDIGIDO:ip]"

def scrub(value, key=""):
    if isinstance(value, dict):
        return {k: scrub(v, k) for k, v in value.items() if k.lower() not in _PRIVATE_KEYS}
    if isinstance(value, list):
        return [scrub(v, key) for v in value]
    if not isinstance(value, str):
        return value
    value = "".join(" " if unicodedata.category(c).startswith("C") or c in "\u2028\u2029" else c for c in value)
    value = _MAC.sub("[REDIGIDO:mac]", value)
    return _IPV6.sub(hide_address, _IPV4.sub(hide_address, value))

def clean_span(value):
    """Conteúdo de um único span. Nunca fecha a crase nem cria nova linha no Discord."""
    value = " ".join("".join(" " if unicodedata.category(c).startswith("C") else c for c in str(value)).split())
    value = value.replace(chr(96), "")
    if contains_credential(value):
        return "[REDIGIDO:credencial]"
    value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[REDIGIDO:email]", value)
    value = re.sub(r"(?<!\w)\+?\d[\d ()-]{6,}\d(?!\w)", "[REDIGIDO:número]", value)
    value = str(scrub(redact(value))).replace("[REDIGIDO]", "[REDIGIDO:dado]")
    # Não deixar o aparelho construir menções, comandos ou escapar o fim do span.
    return value.replace("@", "＠").replace("<", "‹").replace(">", "›").replace(chr(92), "/")
