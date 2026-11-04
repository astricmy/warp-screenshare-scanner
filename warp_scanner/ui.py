"""Interface PT-BR; nenhum dado bruto de coleta é impresso."""
import os
import re
import shutil
import sys
import textwrap
from .core import run_command

UNICODE_BANNER = "╔══════════════════════════════════╗\n║         WARP SCREENSHARE         ║\n╚══════════════════════════════════╝\n   https://discord.gg/pthFZGupmH"
ASCII_BANNER = "+----------------------------------+\n|         WARP SCREENSHARE         |\n+----------------------------------+\n   https://discord.gg/pthFZGupmH"


def banner(plain=False):
    ascii_only = plain or "NO_COLOR" in os.environ or "utf" not in (sys.stdout.encoding or "").lower()
    lines = (ASCII_BANNER if ascii_only else UNICODE_BANNER).splitlines()
    width = max(1,shutil.get_terminal_size((40,20)).columns)
    padding = " " * max(0,(width-36)//2)
    for i,line in enumerate(lines):
        color = "" if ascii_only or not sys.stdout.isatty() else ("\033[90m" if i==3 else "\033[96m")
        print(padding + color + line + ("\033[0m" if color else ""))


def step(number, title):
    print(f"[{number}/10] [{'#'*number}{'.'*(10-number)}] {title}")


PLAIN = False


def question(prompt):
    if not PLAIN and sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb":
        prompt = "\033[1;93m" + prompt + "\033[0m"
    return input(prompt).strip().casefold()


def choice(prompt, positive, negative):
    while True:
        answer = question(prompt)
        if answer in positive:
            return True
        if answer in negative:
            return False
        print("Resposta não reconhecida. Tente novamente.")


def yes_no(prompt):
    return choice(prompt + " (s/n): ", {"s", "sim"}, {"n", "não", "nao"})


def consent_screen():
    step(1,"Consentimento")
    print(textwrap.dedent("""\
    Esta verificação ocorre uma vez, acompanhada pela staff.
    Serão consultados: indicadores de root (incluindo su -c id), marca/modelo,
    Android/patch, metadados do Roblox e de pacotes presentes na base de
    assinaturas; configurações de risco, metadados de processos do Roblox;
    nomes, tamanho, datas e hashes de arquivos relevantes em Download,
    raiz do armazenamento e pastas explicitamente autorizadas da base.
    Nomes dentro de ZIP/APKS podem ser analisados, sem extração.
    Também serão examinados o certificado do Roblox, os sinais de instalação do
    Android e o tempo de uso do Roblox nas últimas 72 horas, quando disponível.
    Proxy, VPN, DNS, perfis de rede e certificados acessíveis serão verificados.
    Com ADB pareado, você pode autorizar uma leitura da tela Minha conta de
    cada app. Só o campo de nome de usuário é retido. Não é preciso digitar o nick.
    O nickname informado será consultado na API pública oficial do Roblox;
    a descrição pública será usada apenas para verificar o código da sessão.
    Após autorizações separadas, texto/Lua e o clipboard atual serão
    analisados localmente. Apenas correspondências redigidas, metadados,
    cobertura, perfil público e pontuação irão ao relatório.
    Você revisará o relatório e confirmará antes de enviá-lo ao relay da staff,
    que o encaminhará ao Discord. O relay recebe seu IP para limitar abusos.
    Uma foto da tela inteira pode conter notificações. A captura é opcional,
    exige nova autorização no momento e a imagem será aberta para sua revisão.
    Não acessamos credenciais, conversas, contatos, mídia, documentos pessoais,
    histórico de teclado, bancos privados ou identificadores do aparelho.
    Não recuperamos arquivos apagados. Nenhum script encontrado é executado.
    Ao concluir, o scanner salva os relatórios JSON e TXT na pasta privada
    ~/.local/share/warp-screenshare/relatorios ou na pasta escolhida com --output.
    Só após a confirmação do envio, o scanner tenta anexar ao Discord a imagem
    pública do avatar do Roblox. O avatar não é salvo no aparelho.
    Recusar qualquer etapa será registrado como NÃO VERIFICADO.
    """))
    if not choice("Digite ACEITO para continuar ou RECUSO para sair: ", {"aceito", "s", "sim"}, {"recuso", "n", "não", "nao"}):
        return None
    return {"clipboard":yes_no("Autoriza uma leitura do clipboard atual?"),
            "files":yes_no("Autoriza ler texto/Lua nas pastas permitidas para análise local?"),
            "discord":yes_no("Autoriza incluir seu nick do Discord se identificável?"),
            "network_tests":yes_no("Autoriza testes de DNS do sistema, DNS sobre HTTPS público e TLS com servidores públicos do Roblox?"),
            "screenshot":yes_no("Quer a opção de revisar e anexar uma captura real de um achado?")}


def _adb_port(value):
    return bool(re.fullmatch(r"[0-9]{1,5}", value) and 1 <= int(value) <= 65535)


def _adb_ready(args, serial):
    # Só endpoints do próprio aparelho; não selecionar celulares da rede.
    if not re.fullmatch(r"(?:127\.0\.0\.1|localhost):[0-9]{1,5}", serial):
        return False
    if not _adb_port(serial.rsplit(":", 1)[1]):
        return False
    result = run_command(["adb", "-s", serial, "shell", "id"], timeout=5, max_bytes=4096)
    if not result.ok or not re.match(r"^uid=(?:2000|0)(?:\(|\s|$)", result.text.strip()):
        return False
    args.adb_serial, args.adb_connected = serial, True
    print("ADB local conectado e verificado.")
    return True


def _adb_auto(args):
    devices = run_command(["adb", "devices"], timeout=5, max_bytes=8192)
    if devices.ok:
        for row in devices.text.splitlines():
            fields = row.split()
            if len(fields) >= 2 and fields[1] == "device" and _adb_ready(args, fields[0]):
                return True
    # Esta propriedade é lida localmente no Android e não exige ADB pareado.
    port = run_command(["/system/bin/getprop", "service.adb.tls.port"], timeout=3, max_bytes=64)
    value = port.text.strip() if port.ok else ""
    if _adb_port(value):
        serial = "127.0.0.1:" + value
        connection = run_command(["adb", "connect", serial], timeout=6, max_bytes=1024)
        if connection.ok and _adb_ready(args, serial):
            return True
    return False


def _ask_adb_port(prompt):
    while True:
        port = question(prompt + " (Enter para seguir sem ADB): ")
        if not port or _adb_port(port):
            return port
        print("Porta inválida. Digite um número de 1 a 65535.")


def adb_guide(args):
    import subprocess
    args.adb_serial, args.adb_connected = None, False
    print("Verificando conexão ADB local e porta de depuração sem fio…")
    if _adb_auto(args):
        return
    print("Ative Opções do desenvolvedor > Depuração sem fio no Android 11 ou superior.")
    print("Se já pareou este Termux, mantenha a depuração sem fio ligada.")
    input("Pressione Enter após ativar para tentar conectar automaticamente: ")
    if _adb_auto(args):
        return
    print("Abra Depuração sem fio > Parear com código. Mantenha essa tela aberta em tela dividida.")
    print("O Android exige a confirmação do código na primeira conexão.")
    port = _ask_adb_port("Porta de pareamento")
    if not port:
        print("ADB indisponível. As leituras que exigem ADB aparecerão como NÃO VERIFICADO.")
        return
    try:
        # O adb recebe o código diretamente, sem salvar no relatório ou arquivo.
        result = subprocess.run(["adb", "pair", f"127.0.0.1:{port}"], timeout=90)
        if result.returncode:
            print("Pareamento recusado ou expirado. Abra um novo código e execute warp-scan --adb.")
            return
        if _adb_auto(args):
            return
        port = _ask_adb_port("Porta de conexão na tela principal de Depuração sem fio (diferente da porta de pareamento)")
        if port:
            serial = f"127.0.0.1:{port}"
            result = run_command(["adb", "connect", serial], timeout=6, max_bytes=1024)
            if result.ok and _adb_ready(args, serial):
                return
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    print("ADB indisponível. As leituras que exigem ADB aparecerão como NÃO VERIFICADO.")
