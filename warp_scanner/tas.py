"""Inventário de arquivos .tas soltos por área de armazenamento e capacidade disponível."""
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import time

from . import tas_android, tas_roots
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


def _walk_local(area, timeout):
    deadline = time.monotonic() + timeout
    pruned = set(map(Path, area.prune))
    seen = set()
    paths = []
    opened = errors = 0
    limited = False

    def walk(path, parent_fd, depth):
        nonlocal opened, errors, limited
        if path in pruned:
            return
        if time.monotonic() >= deadline or depth > 256:
            limited = True
            return
        try:
            with _entries(path, parent_fd) as (entries, fd):
                directory = os.fstat(fd) if fd is not None else path.stat(follow_symlinks=False)
                key = directory.st_dev, directory.st_ino
                if directory.st_ino and key in seen:
                    return
                seen.add(key)
                opened += 1
                for entry in entries:
                    if time.monotonic() >= deadline:
                        limited = True
                        break
                    try:
                        child = path / entry.name
                        if entry.is_dir(follow_symlinks=False):
                            walk(child, fd, depth + 1)
                        elif entry.name.casefold().endswith(".tas") and stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                            paths.append(child)
                    except OSError:
                        errors += 1
        except (OSError, ValueError):
            errors += 1

    walk(Path(area.path), None, 0)
    status = "NÃO VERIFICADO" if not opened else "PARCIAL" if errors or limited else "OK"
    reason = f"{opened} pastas percorridas. {errors} falhas de leitura."
    if limited:
        reason += " Um limite de tempo ou profundidade foi atingido."
    return paths, status, reason


def collect(ctx, max_seconds):
    areas, notes = tas_roots.discover(ctx)
    matches, checks = {}, []
    android = Path("/system/bin/getprop").is_file()
    for area in areas:
        caps = ["none"]
        if android:
            print(f"Procurando .tas — {area.label}…", flush=True)
            if area.privileged:
                caps = [cap for cap in ("root", "adb") if ctx.privilege.get(cap)] + caps
        results = []
        keys = set()
        for cap in caps:
            if android:
                paths, status, reason = tas_android.scan_area(ctx, area, cap, max_seconds)
            else:
                paths, status, reason = _walk_local(area, max_seconds)
            results.append((status, cap, reason))
            for value in paths:
                path = Path(value)
                if not path.is_absolute() or not path.is_relative_to(area.path) or ".." in path.parts:
                    continue
                if not path.name.casefold().endswith(".tas"):
                    continue
                key = area.key(path)
                keys.add(key)
                if key not in matches:
                    display = redact(str(area.display_path(path)), 1024)
                    evidence = {"caminho": display, "caminho_android": display, "área": area.label,
                                "limite": "Identificação por extensão. Conteúdo e uso não verificados."}
                    try:
                        metadata = path.stat(follow_symlinks=False)
                        if stat.S_ISREG(metadata.st_mode):
                            evidence.update(tamanho=metadata.st_size,
                                            mtime=datetime.fromtimestamp(metadata.st_mtime, timezone.utc).isoformat())
                    except (OSError, OverflowError, ValueError):
                        pass
                    matches[key] = ctx.finding(
                        "M8", "arquivo TAS", "Arquivo solto com extensão .tas",
                        evidence, "INFORMATIVO", "artifact", requires=cap, time=evidence.get("mtime"))
            if status == "OK":
                break
        # A shell menos privilegiada pode ver uma árvore menor em seu próprio
        # namespace. Uma leitura parcial nessa área permanece registrada.
        order = {"PARCIAL": 2, "OK": 1, "NÃO VERIFICADO": 0}
        status, cap, reason = max(results, key=lambda item: order[item[0]])
        checks.append({"name": "Busca .tas — " + area.label, "requires": cap, "status": status,
                       "reason": f"{len(keys)} arquivo(s) .tas observado(s). {reason}"})
    complete = sum(c["status"] == "OK" for c in checks)
    status = "NÃO VERIFICADO"
    if matches or any(c["status"] != "NÃO VERIFICADO" for c in checks):
        status = "OK" if complete == len(checks) and not notes else "PARCIAL"
    reason = f"{len(matches)} arquivo(s) .tas solto(s). Áreas com leitura completa: {complete}/{len(checks)}."
    if notes:
        reason += " " + " ".join(notes)
    overall = {"name": "arquivos_tas", "requires": "none", "status": status, "reason": reason}
    return list(matches.values()), overall, checks
