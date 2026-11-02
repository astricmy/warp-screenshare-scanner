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


def yes_no(prompt):
    return input(prompt + " (s/n): ").strip().lower() == "s"


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
    Os achados incluem o caminho Android dos arquivos autorizados. Você pode
    informar seu usuário do Discord ou seguir sem incluí-lo.
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
    O aparelho não é alterado pelo scan. Salvar um relatório exige sua escolha.
    Recusar qualquer etapa será registrado como NÃO VERIFICADO.
    """))
    if input("Digite ACEITO para continuar: ").strip() != "ACEITO":
        return None
    return {"clipboard":yes_no("Autoriza uma leitura do clipboard atual?"),
            "files":yes_no("Autoriza ler texto/Lua nas pastas permitidas para análise local?"),
            "discord":yes_no("Quer incluir seu usuário do Discord no relatório?"),
            "network_tests":yes_no("Autoriza testes de DNS do sistema, DNS sobre HTTPS público e TLS com servidores públicos do Roblox?"),
            "screenshot":yes_no("Quer a opção de revisar e anexar uma captura real de um achado?")}


def adb_guide(args):
    print("ADB opcional: Android 11+, Wi-Fi, Termux no próprio aparelho.")
    print("Ative Opções do desenvolvedor > Depuração sem fio > Parear com código.")
    print("Digite apenas as portas; a conexão será restrita a 127.0.0.1.")
    port = input("Porta de pareamento (Enter para seguir sem ADB): ").strip()
    if not port:
        return
    if not re.fullmatch(r"\d{1,5}",port) or not 1 <= int(port) <= 65535:
        print("Porta inválida. Continuando no modo PADRÃO.")
        return
    # O código é digitado diretamente no adb, não capturado nem registrado.
    import subprocess
    try:
        result = subprocess.run(["adb","pair",f"127.0.0.1:{port}"],timeout=90)
        if result.returncode:
            raise ValueError()
        port = input("Porta de conexão mostrada em Depuração sem fio: ").strip()
        if not re.fullmatch(r"\d{1,5}",port) or not 1 <= int(port) <= 65535:
            raise ValueError()
        serial = f"127.0.0.1:{port}"
        result = run_command(["adb","connect",serial])
        if not result.ok or "connected" not in result.text.lower():
            raise ValueError()
        args.adb_serial, args.adb_connected = serial, True
    except (OSError,ValueError,subprocess.TimeoutExpired):
        print("Pareamento indisponível. Continuando no modo PADRÃO.")
