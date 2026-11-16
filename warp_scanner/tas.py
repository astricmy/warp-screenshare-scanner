"""Inventário por extensão na memória compartilhada primária. Apenas metadados."""
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import time

from .safety import redact


@contextmanager
def _entries(path, parent_fd):
    if os.name == "nt":
        if path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Diretório redirecionado")
        with os.scandir(path) as entries:
            yield entries, None
        return
    # Cada abertura fica ancorada no descritor pai. Uma troca de pasta por
    # link entre a enumeração e a abertura não redireciona a busca.
    fd = os.open(path if parent_fd is None else path.name,
                 os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        with os.scandir(fd) as entries:
            yield entries, fd
    finally:
        os.close(fd)


def collect(ctx, max_files, max_seconds):
    root = Path(ctx.storage)
    deadline = time.monotonic() + max_seconds
    entry_limit = max(256, max_files * 32)
    matches = []
    seen_directories = set()
    visited = 0
    opened = 0
    errors = 0
    limited = False
    depth_limited = False

    def walk(path, parent_fd, depth):
        nonlocal opened, errors, visited, limited, depth_limited
        try:
            with _entries(path, parent_fd) as (entries, fd):
                directory = os.fstat(fd) if fd is not None else path.stat(follow_symlinks=False)
                identity = (directory.st_dev, directory.st_ino)
                if directory.st_ino:
                    if identity in seen_directories:
                        return
                    seen_directories.add(identity)
                opened += 1
                for entry in entries:
                    if limited or visited >= entry_limit or len(matches) >= max_files or time.monotonic() >= deadline:
                        limited = True
                        return
                    visited += 1
                    try:
                        child = path / entry.name
                        if entry.is_dir(follow_symlinks=False):
                            if depth >= 64:
                                depth_limited = True
                            else:
                                walk(child, fd, depth + 1)
                        elif entry.name.casefold().endswith(".tas"):
                            meta = entry.stat(follow_symlinks=False)
                            if stat.S_ISREG(meta.st_mode):
                                stamp = datetime.fromtimestamp(meta.st_mtime, timezone.utc).isoformat()
                                matches.append(ctx.finding(
                                    "M8", "arquivo TAS", "Arquivo solto com extensão .tas",
                                    {"caminho": redact(child.relative_to(root).as_posix(), 1024),
                                     "caminho_android": redact(child.as_posix(), 1024),
                                     "tamanho": meta.st_size, "mtime": stamp,
                                     "limite": "Extensão observada. Conteúdo e uso não verificados."},
                                    "INFORMATIVO", "artifact", time=stamp))
                    except (OSError, OverflowError, ValueError):
                        errors += 1
        except (OSError, ValueError):
            errors += 1

    walk(root, None, 0)
    status = "OK" if opened else "NÃO VERIFICADO"
    if opened and (limited or depth_limited or errors):
        status = "PARCIAL"
    reason = f"{len(matches)} arquivos .tas soltos encontrados em {opened} pastas do armazenamento compartilhado primário."
    if errors:
        reason += f" Leituras indisponíveis: {errors}."
    if limited or depth_limited:
        reason += " Limite de busca atingido."
    return matches, {"name": "arquivos_tas", "requires": "none", "status": status, "reason": reason}
