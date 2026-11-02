"""Fronteira de privacidade: caminhos permitidos, leitura limitada e redação."""
from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

REDACTED = "[REDIGIDO]"
_CREDENTIAL = re.compile(
    r"(?i)(?:\.ROBLOSECURITY|_\|WARNING:|DO-NOT-SHARE-THIS|"
    r"discord(?:app)?\.com/api(?:/v\d+)?/webhooks/|"
    r"\b(?:authorization|bearer|password|passwd|senha|secret|api[_ -]?key|"
    r"access[_ -]?token|refresh[_ -]?token|session[_ -]?(?:id|token)|cookie|"
    r"c[oó]digo\s+(?:de\s+)?verifica[cç][aã]o|verification[_ -]?code)\b|"
    r"\b(?:token|otp|2fa)\s*[:=]|-----BEGIN [A-Z ]*PRIVATE KEY|"
    r"\b(?:gh[pousr]_|github_pat_|sk_live_|sk-proj-)[A-Za-z0-9_-]+|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)
_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
_LONG_NUMBER = re.compile(r"(?<!\w)\+?\d[\d ()-]{6,}\d(?!\w)")
_URL = re.compile(r"https?://[^\s\"'<>\)\]\}]+", re.I)
FORBIDDEN_DIRS = frozenset({
    "dcim", "pictures", "movies", "music", "documents", "documentos",
    "whatsapp", "telegram", "signal", "messenger", "wechat", "line",
    "com.whatsapp", "org.telegram.messenger", "org.thoughtcrime.securesms",
    "com.facebook.orca", "camera", "screenshots", "recordings", "podcasts",
})
_SUFFIXES = frozenset({".txt", ".lua", ".luau", ".json", ".zip", ".apks", ".apk", ".xapk", ".so", ".obb", ".crdownload", ".pac", ".ovpn", ".conf", ".crt", ".pem", ".cer", ".p12"})


def contains_credential(text: str) -> bool:
    return bool(_CREDENTIAL.search(unquote(str(text))))


def normalize_domain(value: str) -> str:
    """Normaliza um host sem aceitar credenciais, portas inválidas ou curingas."""
    try:
        value = str(value).strip()
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host) or ".." in host:
            return ""
        return host[4:] if host.startswith("www.") else host
    except (ValueError, UnicodeError):
        return ""


def domain_matches(host: str, domain: str) -> bool:
    host, domain = normalize_domain(host), normalize_domain(domain)
    return bool(host and domain and (host == domain or host.endswith("." + domain)))


def match_domains(value: str, signatures: dict) -> list[dict]:
    matches = []
    for entry in signatures.get("entries", []):
        for domain in entry.get("dominios", []):
            if domain_matches(value, domain):
                matches.append({"id": entry["id"], "nome": entry["nome"],
                                "domain": normalize_domain(domain),
                                "verificado": bool(entry.get("verificado")),
                                "confianca": entry.get("confianca", "baixa")})
                break
    return matches


def safe_url(url: str) -> str:
    """Retém host/caminho público; elimina autenticação, query e fragmento."""
    try:
        parsed = urlsplit(str(url))
        host = normalize_domain(url)
        if not host or parsed.scheme.lower() not in {"http", "https"}:
            return REDACTED
        path = parsed.path
        if contains_credential(path) or _EMAIL.search(unquote(path)):
            path = "/" + REDACTED
        else:
            path = re.sub(r"(?<=/)[A-Za-z0-9_-]{40,}(?=/|$)", REDACTED, path)
            path = _LONG_NUMBER.sub(REDACTED, path)
        return urlunsplit((parsed.scheme.lower(), host, path, "", ""))
    except (ValueError, UnicodeError):
        return REDACTED


def redact(text: str, max_length: int | None = None) -> str:
    """Ao detectar credencial, descarta o texto inteiro, inclusive o contexto."""
    if max_length is not None and max_length <= 0:
        return ""
    text = str(text)
    if contains_credential(text):
        return REDACTED
    text = _URL.sub(lambda m: safe_url(m.group(0)), text)
    text = _EMAIL.sub(REDACTED, text)
    text = _LONG_NUMBER.sub(REDACTED, text)
    # Escapes ANSI, controles bidi e caracteres de controle nunca vão ao terminal.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(c for c in text if (c >= " " or c in "\n\t") and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
    if max_length is not None and len(text) > max_length:
        text = text[:max(0, max_length - 1)] + "…"
    return text


def _forbidden(name: str) -> bool:
    lower = name.casefold()
    return lower in FORBIDDEN_DIRS or any(word in lower for word in ("whatsapp", "telegram", "messenger", "signal", "dcim"))


def _executor_folders(signatures: dict) -> set[str]:
    folders = {"autoexec", "workspace", "scripts"}
    for entry in signatures.get("entries", []):
        for folder in entry.get("pastas", []):
            if "/" not in folder and "\\" not in folder and folder not in {".", ".."} and not _forbidden(folder):
                folders.add(folder.casefold())
    return folders


def iter_allowed_files(storage: Path, signatures: dict, max_files: int = 2000,
                       max_seconds: float = 30, stats: dict | None = None):
    """Varre somente raízes explícitas; não segue links nem busca diretórios privados.

    O limite de entradas evita árvores enormes mesmo que não contenham arquivos
    candidatos. stats sinaliza qualquer corte, para nunca transformar limite em OK.
    """
    stats = stats if stats is not None else {}
    stats.update(files=0, entries=0, directories=0, errors=0, limited=False)
    root = Path(os.path.abspath(storage))
    deadline = time.monotonic() + max(0.01, max_seconds)
    folders = _executor_folders(signatures)
    packages = {p for e in signatures.get("entries", []) for p in e.get("pacotes", [])
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", p)}
    pending = [(root, 0, "root")]
    max_entries = max(100, max_files * 8)
    seen = set()
    while pending:
        if time.monotonic() > deadline or stats["files"] >= max_files or stats["entries"] >= max_entries:
            stats["limited"] = True
            return
        directory, depth, branch = pending.pop()
        try:
            if directory.is_symlink() or any(p.is_symlink() for p in directory.parents if p.is_relative_to(root)):
                stats["errors"] += 1
                continue
            if not directory.resolve().is_relative_to(root.resolve()):
                stats["errors"] += 1
                continue
            # O_NOFOLLOW protege a abertura final de diretórios no Android.
            fd = None
            if os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
                fd = _open_beneath(directory, root, directory=True)
            try:
                with os.scandir(fd if fd is not None else directory) as entries:
                    stats["directories"] += 1
                    for item in entries:
                        stats["entries"] += 1
                        if time.monotonic() > deadline or stats["entries"] > max_entries or stats["files"] >= max_files:
                            stats["limited"] = True
                            return
                        name = item.name
                        if _forbidden(name) or item.is_symlink():
                            continue
                        path = directory / name
                        if item.is_dir(follow_symlinks=False):
                            low = name.casefold()
                            if depth == 0:
                                if low == "download" or low in folders:
                                    pending.append((path, 1, "allowed"))
                                elif low == "android":
                                    # Acesso direcionado por pacote: nunca lista todos
                                    # os apps de Android/data ou Android/obb.
                                    for package in sorted(packages):
                                        for area in ("data", "obb"):
                                            target = path / area / package
                                            if target.exists():
                                                pending.append((target, 3, "allowed"))
                            elif branch == "allowed" and depth < 8:
                                pending.append((path, depth + 1, "allowed"))
                            elif branch == "allowed":
                                stats["limited"] = True
                        elif item.is_file(follow_symlinks=False) and (branch in {"root", "allowed"}) and path.suffix.lower() in _SUFFIXES:
                            key = str(path)
                            if key not in seen:
                                seen.add(key)
                                stats["files"] += 1
                                yield path
            finally:
                if fd is not None:
                    os.close(fd)
        except (OSError, ValueError):
            stats["errors"] += 1


def _open_beneath(path: Path, root: Path, directory: bool = False) -> int:
    """Abre todos os componentes com dir_fd/O_NOFOLLOW em Android/Linux."""
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    parts = path.relative_to(root).parts
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.open(root, root_flags)
    try:
        for index, part in enumerate(parts):
            if part in {".", ".."} or (index < len(parts) - 1 and _forbidden(part)):
                raise ValueError("Caminho recusado")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            if index < len(parts) - 1 or directory:
                flags |= getattr(os, "O_DIRECTORY", 0)
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
        result, current = current, None
        return result
    finally:
        if current is not None:
            os.close(current)


def read_bounded_file(path: Path, root: Path, max_bytes: int) -> tuple[bytes, os.stat_result]:
    path, root = Path(path), Path(root)
    relative = Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    if any(_forbidden(part) for part in relative.parts[:-1]):
        raise ValueError("Diretório pessoal recusado")
    if os.name == "nt":
        if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Link ou caminho externo recusado")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    else:
        fd = _open_beneath(path, root)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError("Arquivo não regular ou acima do limite")
        chunks, count = [], 0
        while True:
            chunk = handle.read(min(65536, max_bytes + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > max_bytes:
                raise ValueError("Arquivo acima do limite")
        after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Arquivo mudou durante leitura")
        return b"".join(chunks), after
