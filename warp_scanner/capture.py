"""Uma captura manual da tela, sob consentimento e revisão do jogador."""
import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid

from .core import now
from .ui import yes_no, choice

MAX_PNG_BYTES = 4 * 1024 * 1024
MAX_PIXELS = 16_777_216
MAX_WIRE_BYTES = 262144 + 4 * ((MAX_PNG_BYTES + 2) // 3)
_PNG = b"\x89PNG\r\n\x1a\n"
_COLOR_CHUNKS = {b"sRGB", b"sBIT", b"gAMA", b"cHRM", b"pHYs", b"cICP", b"mDCV", b"cLLI", b"iCCP"}


def png_dimensions(data):
    """Valida estrutura PNG RGB/RGBA de screencap, sem decodificar pixels."""
    if not 45 <= len(data) <= MAX_PNG_BYTES or not data.startswith(_PNG):
        raise ValueError("PNG ausente ou grande demais")
    offset = 8
    dimensions = None
    has_pixels = False
    for _ in range(8192):
        if offset + 12 > len(data):
            break
        size, tag = struct.unpack_from(">I4s", data, offset)
        end = offset + 8 + size
        if end + 4 > len(data):
            break
        if binascii.crc32(memoryview(data)[offset + 4:end]) != struct.unpack_from(">I", data, end)[0]:
            break
        if dimensions is None:
            if tag != b"IHDR" or size != 13:
                break
            width, height, depth, color, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", data, offset + 8)
            if not (0 < width <= 8192 and 0 < height <= 8192 and width * height <= MAX_PIXELS):
                break
            if depth != 8 or color not in (2, 6) or (compression, filtering, interlace) != (0, 0, 0):
                break
            dimensions = (width, height)
        elif tag == b"IDAT":
            has_pixels |= size > 0
        elif tag == b"IEND" and size == 0 and end + 4 == len(data) and has_pixels:
            return dimensions
        elif tag not in _COLOR_CHUNKS or has_pixels:
            break
        offset = end + 4
    raise ValueError("PNG de captura inválido ou formato não suportado")


def capture_command(ctx):
    """Restringe ADB ao par local selecionado pelo guia, sem descoberta de aparelhos."""
    serial = getattr(ctx.args, "adb_serial", "") or ""
    port = re.fullmatch(r"(?:127\.0\.0\.1|localhost):(\d{1,5})", serial)
    if ctx.privilege.get("adb") and port and 0 < int(port.group(1)) <= 65535:
        return ["adb", "-s", serial, "exec-out", "/system/bin/screencap", "-p"]
    if ctx.privilege.get("root"):
        return ["su", "-c", "/system/bin/screencap -p"]
    return None


def _capture(argv):
    # exec-out entrega os bytes originais; nunca usar uma API que decodifica stdout como texto.
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, shell=False, bufsize=0)
    deadline = time.monotonic() + 12
    image = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                if left <= 0 or not selector.select(left):
                    raise TimeoutError
                chunk = os.read(proc.stdout.fileno(), min(65536, MAX_PNG_BYTES + 1 - len(image)))
                if not chunk:
                    break
                image.extend(chunk)
                if len(image) > MAX_PNG_BYTES:
                    raise ValueError("Captura excede o limite")
        if proc.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
            raise OSError("Captura recusada")
        return bytes(image)
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)


def _preview(data, tmpdir):
    """O arquivo 0600 existe só entre a abertura da prévia e a decisão do jogador."""
    if not choice("Digite VER para abrir a prévia local. Enter descarta: ", {"ver"}, {""}):
        return False
    fd, name = tempfile.mkstemp(dir=tmpdir, prefix="warp-previa-", suffix=".png")
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as temporary:
            temporary.write(data)
        viewer = subprocess.run(["termux-open", "--chooser", "--view", "--content-type", "image/png", str(path)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10, check=False)
        if viewer.returncode:
            return False
        print("Use um visualizador local. Verifique a tela inteira e retorne ao Termux.")
        return yes_no("Você VIU a imagem, confirmou a pasta correta e autoriza anexar este PNG integral ao relatório?")
    finally:
        path.unlink(missing_ok=True)


def _paths(report):
    result = []
    for finding in report.get("findings", []):
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            continue
        path = evidence.get("caminho_android") or evidence.get("caminho") or evidence.get("path") or evidence.get("arquivo")
        if isinstance(path, str) and path and not any(ord(c) < 32 or ord(c) == 127 for c in path):
            identifier = finding.get("id")
            try:
                uuid.UUID(identifier)
            except (AttributeError, TypeError, ValueError):
                continue
            result.append((identifier, path))
    return result


def review(ctx, report):
    """Atualiza report['capture'] só com metadados. Retorna zero ou um anexo de transporte."""
    def skip(reason):
        report["capture"] = {"status": "NÃO VERIFICADO", "reason": reason, "reviewed": False}
        print("Captura opcional — " + reason)
        return []

    if (report.get("synthetic") or getattr(ctx.args, "dry_run", False) or getattr(ctx.args, "test", False)
            or not ctx.consent.get("screenshot")):
        return skip("Etapa de captura desativada ou recusada.")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return skip("Revisão requer terminal interativo no aparelho.")
    command = capture_command(ctx)
    prefix = os.environ.get("PREFIX")
    if not command or not prefix or not shutil.which("termux-open"):
        return skip("É necessário ADB local pareado ou root e um visualizador via Termux.")
    tmpdir = Path(prefix) / "tmp"
    if not tmpdir.is_absolute() or not tmpdir.is_dir() or tmpdir.is_symlink():
        return skip("Diretório privado de prévia indisponível.")
    choices = _paths(report)
    if not choices:
        return skip("Sem achado de arquivo com caminho para conferir.")
    print("Escolha o achado cuja pasta você quer mostrar. Enter cancela.")
    for index, (_, path) in enumerate(choices, 1):
        print(f"{index}. {path}")
    try:
        number = input("Número do achado: ").strip()
        if not re.fullmatch(r"[0-9]{1,5}", number) or not 1 <= int(number) <= len(choices):
            return skip("Nenhum achado selecionado.")
        finding_id, path = choices[int(number) - 1]
        if not getattr(ctx.args, "plain", False) and os.environ.get("TERM") != "dumb":
            print("\033[2J\033[H", end="")
        finding = next(item for item in report.get("findings", []) if item.get("id") == finding_id)
        print("WARP SCREENSHARE • REVISÃO DO ACHADO")
        print(finding.get("description", "Arquivo selecionado"))
        print(path)
        print(f"Prepare o gerenciador de arquivos na pasta de {path} e volte ao Termux.")
        print("A imagem incluirá a tela INTEIRA exatamente como estiver, inclusive notificações.")
        print("Oculte dados pessoais. Após confirmar, terá 10 segundos para voltar à pasta.")
        if not yes_no("Autoriza UMA captura integral após a contagem e sua abertura em um visualizador local?"):
            return skip("Captura recusada pelo jogador.")
        for seconds in range(10, 0, -1):
            print(f"Captura em {seconds} s. Ctrl+C cancela.", flush=True)
            time.sleep(1)
        data = _capture(command)
        captured_at = now()
        width, height = png_dimensions(data)
        if not _preview(data, tmpdir):
            return skip("Prévia indisponível ou anexo recusado pelo jogador.")
        filename = f"prova_{report['scan_id']}.png"
        report["capture"] = {
            "status": "REVISADA", "reviewed": True, "finding_id": finding_id, "filename": filename,
            "width": width, "height": height, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "timestamp": captured_at, "source": "screencap Android", "caminho": path,
        }
        return [{"filename": filename, "content_type": "image/png",
                 "content": base64.b64encode(data).decode("ascii")}]
    except KeyboardInterrupt:
        return skip("Captura cancelada pelo jogador.")
    except (EOFError, OSError, ValueError, subprocess.SubprocessError):
        return skip("Captura ou revisão local indisponível.")
