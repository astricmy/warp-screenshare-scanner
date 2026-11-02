"""Avatar público opcional. Só um userId obtido do Roblox chega a esta consulta."""
import binascii
import json
import re
import struct
from urllib.parse import urlsplit
import zlib

from .net import request

SIZE = 150
MAX_BYTES = 128 * 1024
MAGIC = b"\x89PNG\r\n\x1a\n"


def _image_url(url):
    if not isinstance(url, str) or not url.isascii() or len(url) > 2048:
        return False
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname is not None
                and re.fullmatch(r"(?:[a-z0-9-]+\.)*rbxcdn\.com", parsed.hostname) is not None
                and parsed.netloc == parsed.hostname and not parsed.query and not parsed.fragment
                and re.fullmatch(r"/[A-Za-z0-9_./%-]+", parsed.path) is not None)
    except ValueError:
        return False


def _chunk(kind, payload):
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", binascii.crc32(kind + payload)))


def _palette_to_rgba(pixels, stride, depth, palette, alpha):
    """Expande uma miniatura indexada para o mesmo RGBA aceito pelo relay."""
    if not palette or len(palette) % 3 or len(palette) > 3 * (1 << depth) or len(alpha) > len(palette) // 3:
        return None
    previous = bytes(stride - 1)
    mask = (1 << depth) - 1
    output = bytearray()
    for pos in range(0, len(pixels), stride):
        mode = pixels[pos]
        row = bytearray(pixels[pos + 1:pos + stride])
        for i in range(len(row)):
            left = row[i - 1] if i else 0
            up = previous[i]
            corner = previous[i - 1] if i else 0
            if mode == 4:
                p = left + up - corner
                prediction = min((left, up, corner), key=lambda value: abs(p - value))
            else:
                prediction = (0, left, up, (left + up) // 2)[mode]
            row[i] = (row[i] + prediction) & 255
        output.append(0)
        for x in range(SIZE):
            bit = x * depth
            index = (row[bit // 8] >> (8 - depth - bit % 8)) & mask
            if 3 * index + 2 >= len(palette):
                return None
            output.extend(palette[3 * index:3 * index + 3])
            output.append(alpha[index] if index < len(alpha) else 255)
        previous = row
    return bytes(output)


def clean_png(raw):
    """Valida dimensões, CRC e pixels. Recria o PNG sem texto, perfis ou metadados."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES or not raw.startswith(MAGIC):
        return None
    cursor = len(MAGIC)
    header = None
    palette, alpha = b"", b""
    image_data = bytearray()
    while cursor + 12 <= len(raw):
        size, kind = struct.unpack_from(">I4s", raw, cursor)
        end = cursor + 8 + size
        if end + 4 > len(raw):
            return None
        value = raw[cursor + 8:end]
        if binascii.crc32(kind + value) != struct.unpack_from(">I", raw, end)[0]:
            return None
        cursor = end + 4
        if header is None:
            if kind != b"IHDR" or len(value) != 13:
                return None
            width, height, depth, color, method, filtering, interlace = struct.unpack(">IIBBBBB", value)
            supported = (color in {2, 6} and depth == 8) or (color == 3 and depth in {1, 2, 4, 8})
            if (width, height) != (SIZE, SIZE) or not supported or (method, filtering, interlace) != (0, 0, 0):
                return None
            header = value
        elif kind == b"PLTE" and color == 3 and not palette and not image_data:
            palette = value
        elif kind == b"tRNS" and color == 3 and not alpha and not image_data:
            alpha = value
        elif kind == b"IDAT":
            image_data.extend(value)
        elif kind == b"IEND":
            if value or cursor != len(raw) or not image_data:
                return None
            stride = 1 + ((SIZE * depth + 7) // 8 if color == 3 else SIZE * (4 if color == 6 else 3))
            expected = SIZE * stride
            inflater = zlib.decompressobj()
            try:
                pixels = inflater.decompress(image_data, expected + 1)
            except zlib.error:
                return None
            if (not inflater.eof or inflater.unused_data or len(pixels) != expected
                    or any(pixels[i] > 4 for i in range(0, expected, stride))):
                return None
            if color == 3:
                pixels = _palette_to_rgba(pixels, stride, depth, palette, alpha)
                if pixels is None:
                    return None
                header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
            # Recompactação determinística deixa apenas os dados de pixels.
            return MAGIC + _chunk(b"IHDR", header) + _chunk(b"IDAT", zlib.compress(pixels)) + _chunk(b"IEND", b"")
        elif not (kind[0] & 32):
            return None
    return None


def fetch_headshot(user_id):
    """Qualquer falha de rede, imagem bloqueada ou resposta inesperada omite o avatar."""
    if type(user_id) is not int or not 1 <= user_id <= 2**63 - 1:
        return None
    api = f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size={SIZE}x{SIZE}&format=Png&isCircular=false"
    try:
        answer = json.loads(request(api, max_bytes=8192, timeout=4))
        rows = answer["data"]
        if not isinstance(rows, list) or len(rows) != 1:
            return None
        row = rows[0]
        if type(row.get("targetId")) is not int or row["targetId"] != user_id or row.get("state") != "Completed":
            return None
        url = row.get("imageUrl")
        if not _image_url(url):
            return None
        return clean_png(request(url, max_bytes=MAX_BYTES, timeout=4))
    except Exception:
        # Avatar é decorativo. Nunca expor URL de CDN, resposta, erro ou dados brutos.
        return None
