"""Configuração pública. Segredos são recebidos exclusivamente pelo ambiente."""
from pathlib import Path

BRAND = "WARP SCREENSHARE"
DISCORD_INVITE = "https://discord.gg/pthFZGupmH"
VERSION = "0.2.4"
REPO_URL = "https://github.com/astricmy/warp-screenshare-scanner"
RELEASE_TAG = "v0.2.4"
RELAY_URL = "https://warp-screenshare-relay.ffcontapraff0.workers.dev"
SIGNATURES_URL = ""  # HTTPS; requer SHA-256 independente em WARP_SIGNATURES_SHA256.
BASE_DIR = Path(__file__).resolve().parent
STORAGE_ROOT = Path("/storage/emulated/0")
CRITICAL_MODULES = ("M1", "M3", "M5", "M8")
