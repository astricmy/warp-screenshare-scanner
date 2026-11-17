"""Busca nativa por nomes .tas em uma área, com limites por processo e saída."""
import math
import os
from pathlib import PurePosixPath
import re
import selectors
import shlex
import subprocess
import time


_TOYBOX = "/system/bin/toybox"
_MAX_OUTPUT = 4 * 1024 * 1024
_MAX_PATHS = 12000
_ROOT = re.compile(
    r"/(?:data|storage/emulated/[0-9]+|(?:storage|mnt/media_rw)/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}|mnt/expand/[a-zA-Z0-9-]+"
    r"|data/(?:data|user/[0-9]+)/com\.termux/files(?:/home)?|system|product|vendor|odm"
    r"|system_ext|vendor_dlkm|odm_dlkm|system_dlkm|oem|metadata|cache|cust|preload)\Z"
)

_ROOT_EXCLUDES = {"/proc", "/sys", "/dev", "/mnt", "/storage", "/data", "/apex",
                  "/data_mirror", "/linkerconfig", "/debug_ramdisk", "/second_stage_resources"}

# pwd pode revelar o alias /data/user/0 usado pelo Android para o Termux.
# O find não segue links. Dentro de uma área, montagens de disco e volumes
# FUSE podem ser atravessados, e as demais montagens são podadas antes.
_FIND = r"""
base=$1
cd -P "$base" && [ -r . ] && [ -x . ] || exit 3
actual=$(pwd -P) || exit 3
if [ "$base" != "$actual" ]; then
    case "$base:$actual" in
        /data/data/com.termux/files:/data/user/0/com.termux/files|/data/user/0/com.termux/files:/data/data/com.termux/files) ;;
        *) exit 3 ;;
    esac
fi
shift
if [ "$base" = / ]; then
    set -- -xdev "$@"
elif [ -r /proc/self/mountinfo ]; then
    while IFS=' ' read -r id parent dev sub target flags tail; do
        case "$target" in "$actual"/*) ;; *) continue ;; esac
        fs=" $tail"; fs=${fs#* - }; fs=${fs%% *}
        case "$fs" in ext[234]|f2fs|erofs|squashfs|vfat|exfat|ntfs|ntfs3|fuse*|sdcardfs|overlay|ubifs|yaffs2) continue ;; esac
        case "$target" in
            *'\'*|*'*'*|*'?'*|*'['*) printf 'restrita\000'; set -- -xdev "$@"; break ;;
        esac
        set -- -path ".${target#"$actual"}" -prune -o "$@"
    done < /proc/self/mountinfo
else
    printf 'restrita\000'
    set -- -xdev "$@"
fi
exec /system/bin/toybox find . "$@" 2>/dev/null
"""


def _argv(ctx, area, capability, seconds):
    root = PurePosixPath(area.path.as_posix())
    system = (getattr(area, "kind", "") == "system" and len(root.parts) >= 2
              and re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]*", root.parts[1])
              and ("/" + root.parts[1] not in _ROOT_EXCLUDES or root.parts[1] == "apex"))
    accepted = any(_ROOT.fullmatch(str(base)) and str(base) not in {"/storage/emulated", "/storage/self"}
                   for base in (root, *root.parents))
    if (not (accepted or system or str(root) == "/") or not root.is_absolute()
            or not all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}", part) for part in root.parts[1:])):
        raise ValueError("Área Android desconhecida")
    expression = ["(", "-path", ".", "-print0", ")", "-o"]
    exclusions = {PurePosixPath(skip.as_posix()) for skip in area.prune}
    if str(root) == "/":
        exclusions.update(map(PurePosixPath, _ROOT_EXCLUDES))
    for skip in sorted(exclusions):
        relative = skip.relative_to(root)
        if not relative.parts or ".." in relative.parts:
            raise ValueError("Exclusão inválida")
        # -path interpreta padrões mesmo quando o argumento já está entre aspas.
        literal = re.sub(r"([*?\[\\])", r"\\\1", "./" + relative.as_posix())
        expression.extend(["-path", literal, "-prune", "-o"])
    expression.extend(["-type", "f", "-iname", "*.tas", "-print0"])
    command = [_TOYBOX, "timeout", "-s", "KILL", str(seconds), "/system/bin/sh", "-c",
               _FIND, "tas-find", str(root), *expression]
    if capability == "none":
        return command
    if capability == "root" and ctx.privilege.get("root"):
        return ["su", "-c", shlex.join(command)]
    serial = getattr(ctx.args, "adb_serial", "") or ""
    if (capability == "adb" and ctx.privilege.get("adb")
            and re.fullmatch(r"(?:127\.0\.0\.1|localhost):[0-9]{1,5}", serial)
            and 0 < int(serial.rsplit(":", 1)[1]) <= 65535):
        return ["adb", "-s", serial, "shell", "-T", shlex.join(command)]
    raise ValueError("Acesso indisponível")


def _capture(argv, timeout):
    # Termux é POSIX. Ler por blocos e NUL permite preservar todos os registros
    # completos recebidos antes de uma interrupção, inclusive nomes com quebras.
    output = bytearray()
    deadline = time.monotonic() + timeout
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, bufsize=0) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        return bytes(output), "tempo"
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    capacity = _MAX_OUTPUT - len(output)
                    output.extend(chunk[:capacity])
                    if len(chunk) > capacity:
                        return bytes(output), "saída"
            code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            return bytes(output), ("ok" if code == 0 else "tempo" if code in (124, 137, -9) else "acesso")
        except subprocess.TimeoutExpired:
            return bytes(output), "tempo"
        finally:
            if proc.poll() is None:
                proc.kill()


def scan_area(ctx, area, capability, timeout):
    """Retorna caminhos absolutos observados, cobertura e motivo sem stderr."""
    if timeout <= 0:
        return [], "NÃO VERIFICADO", "Sem tempo restante para esta área."
    try:
        argv = _argv(ctx, area, capability, max(1, math.ceil(timeout)))
        output, outcome = _capture(argv, timeout)
    except (OSError, ValueError):
        return [], "NÃO VERIFICADO", "Área ou ferramenta de busca indisponível."
    paths = []
    root_seen = False
    malformed = bool(output and not output.endswith(b"\x00"))
    records = output.split(b"\x00")
    for item in records[:-1]:
        if item == b"restrita":
            malformed = True
            continue
        if item == b".":
            root_seen = True
            continue
        try:
            name = item.decode("utf-8")
        except UnicodeError:
            malformed = True
            continue
        parts = name[2:].split("/")
        if not name.startswith("./") or not name.casefold().endswith(".tas") or any(p in ("", ".", "..") for p in parts):
            malformed = True
            continue
        if len(paths) == _MAX_PATHS:
            outcome = "quantidade"
            break
        paths.append((PurePosixPath(area.path.as_posix()) / name[2:]).as_posix())
    if outcome == "ok" and root_seen and not malformed:
        return paths, "OK", "Busca por nome concluída nesta área."
    reasons = {"tempo": "Tempo de busca atingido.", "saída": "Limite de dados da busca atingido.",
               "quantidade": "Limite de correspondências desta área atingido.",
               "acesso": "Área inacessível, leitura parcial ou erro do Android."}
    return paths, "PARCIAL" if paths or root_seen else "NÃO VERIFICADO", reasons.get(outcome, "Resposta incompleta da busca.")
