"""Verifica a permissão Android antes da varredura autorizada."""
from .core import run_command


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
