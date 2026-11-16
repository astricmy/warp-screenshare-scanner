"""Verifica a permissão Android antes da varredura autorizada."""
from .core import run_command
from .roblox import query


def accessible(storage):
    import os
    try:
        with os.scandir(storage):
            return True
    except OSError:
        return False


def prepare(storage, ask, wait=input):
    if accessible(storage):
        return True
    print("O Termux ainda não consegue ler o armazenamento compartilhado.")
    if ask("Abrir a solicitação do Android para permitir acesso aos arquivos?"):
        result = run_command(["termux-setup-storage"], timeout=20, max_bytes=4096)
        if result.ok:
            wait("Aceite a permissão do Android, volte ao Termux e pressione Enter: ")
            if accessible(storage):
                print("Acesso ao armazenamento confirmado.")
                return True
    print("Arquivos não verificáveis. Confira a permissão de arquivos do Termux nas configurações do Android.")
    return False


def offer_zarchiver(ctx, ask, wait=input):
    if not ctx.consent.get("files"):
        return
    for package in ("ru.zdevs.zarchiver", "ru.zdevs.zarchiver.pro"):
        path, _, _ = query(ctx, ["pm", "path", package], timeout=3, max_bytes=4096)
        if path.ok and any(line.startswith("package:/") for line in path.text.splitlines()):
            break
    else:
        return
    if not ask("Quer abrir o ZArchiver para selecionar arquivos extras para esta verificação?"):
        return
    print("No ZArchiver, copie ou extraia só os arquivos escolhidos para Download/WARP. O relatório usará o caminho da cópia.")
    result = ctx.run(["am", "start", "-a", "android.intent.action.MAIN", "-c",
                      "android.intent.category.LAUNCHER", "-p", package],
                     timeout=6, max_bytes=1024)
    if not result.ok or "error" in result.text.lower() or "exception" in result.text.lower():
        print("Abra o ZArchiver pelo ícone no celular.")
    wait("Após selecionar os arquivos ou se quiser pular, volte ao Termux e pressione Enter: ")
