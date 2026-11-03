"""Configuração pública. Segredos são recebidos exclusivamente pelo ambiente."""
from pathlib import Path

BRAND = "WARP SCREENSHARE"
DISCORD_INVITE = "https://discord.gg/pthFZGupmH"
VERSION = "0.2.1"
REPO_URL = "https://github.com/astricmy/warp-screenshare-scanner"
RELEASE_TAG = "v0.2.1"
RELAY_URL = ""  # Defina WARP_RELAY_URL no ambiente após publicar o Worker.
SIGNATURES_URL = ""  # HTTPS; requer SHA-256 independente em WARP_SIGNATURES_SHA256.
BASE_DIR = Path(__file__).resolve().parent
STORAGE_ROOT = Path("/storage/emulated/0")
CRITICAL_MODULES = ("M1", "M3", "M5", "M8")
