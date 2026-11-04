#!/usr/bin/env python3
"""Ponto de entrada WARP. Nenhuma coleta antecede ACEITO."""
import argparse
import base64
import secrets
import getpass
import json
import os
from pathlib import Path
import re
import sys

import config
from warp_scanner.core import Context, unavailable
from warp_scanner import ui
from warp_scanner.safety import iter_allowed_files
from warp_scanner.integrity import collect_integrity, load_signatures
from warp_scanner.report import build, render_text, envelope
from warp_scanner.discord import send, saved_invite, cloud_token
from warp_scanner.locations import add_locations
from warp_scanner.avatar import fetch_headshot


def positive(value):
    number=int(value)
    if not 1 <= number <= 100000:
        raise argparse.ArgumentTypeError("Informe um número entre 1 e 100000")
    return number


def arguments(argv=None):
    parser=argparse.ArgumentParser(description="WARP SCREENSHARE — análise estática com consentimento")
    for flag,help_text in [("test","Dados fictícios em memória; sem coleta nem rede"),("dry-run","Coleta consentida; mostra relatório sem enviar"),("plain","Terminal em ASCII e sem cores"),("adb","Guia de pareamento ADB no próprio celular"),("direct","Envio direto explícito para bancada da staff")]:
        parser.add_argument("--"+flag,action="store_true",help=help_text)
    parser.add_argument("--window-days",type=positive,default=14)
    parser.add_argument("--max-file-kb",type=positive,default=512)
    parser.add_argument("--max-files",type=positive,default=2000)
    parser.add_argument("--max-seconds",type=positive,default=30)
    parser.add_argument("--session-code",default="")
    parser.add_argument("--nick",default="")
    parser.add_argument("--expected-nick",default="")
    parser.add_argument("--discord", "--discord-user", dest="discord_user", default="",
                        help="Nome do Discord informado pelo jogador, incluído apenas com consentimento")
    parser.add_argument("--discord-id", default="", help="ID público do Discord informado pelo jogador ou pela staff (opcional)")
    parser.add_argument("--output",type=Path,help="Diretório explícito para salvar os relatórios minimizados")
    parser.add_argument("--version",action="version",version=config.VERSION)
    args=parser.parse_args(argv)
    args.adb_serial=None
    args.adb_connected=False
    if args.session_code and not re.fullmatch(r"WARP-[A-Z0-9]{4,24}",args.session_code):
        parser.error("Código deve seguir WARP- seguido por 4 a 24 letras maiúsculas/números")
    if args.max_file_kb>8192 or args.max_seconds>300 or args.max_files>20000 or args.window_days>365:
        parser.error("Limites máximos: 8192 KB, 300 segundos, 20000 arquivos e 365 dias")
    return args


def synthetic_modules(ctx):
    from warp_scanner.scripts_clipboard import analyze_text
    specimen='loadstring(game:HttpGet("https://raw.githubusercontent.com/warp-fixture/demo/main/test.lua?discard=1"))() getgenv()'
    result=analyze_text(specimen,ctx.signatures)
    if not result:
        raise RuntimeError("Amostra sintética não detectada")
    finding=ctx.finding("M8","scripts","DEMONSTRAÇÃO: padrão em amostra fictícia",{"caminho":"Download/exemplo.lua","padroes":result["padroes"],"trecho":result["trecho"],"urls":result["urls"]},result["level"],result["weight_key"])
    modules=[unavailable(f"M{i}","Simulação: aparelho não consultado") for i in range(1,8)]
    modules[1]["data"]={"nick":"JogadorExemplo","displayName":"Exemplo fictício","ownership_verified":False}
    modules[5].update(status="PARCIAL", reason="Exemplo fictício; nenhuma propriedade foi consultada.",
                      data={"device":{"brand":"Marca Exemplo","model":"Modelo X","android":"14",
                                      "api_level":34,"security_patch":"2026-09-01"},
                            "usb_debug":True,"auto_time":True})
    modules.append({"module":"M8","requires":"none","status":"PARCIAL","reason":"Fixture em memória, sem arquivos reais nem clipboard","data":{},"findings":[finding],"checks":[{"name":"Fixture Lua","requires":"none","status":"OK","reason":"Análise estática em memória"}]})
    modules.extend(unavailable(m,"Simulação: aparelho e rede não consultados") for m in ("M9","M10","M11"))
    modules[8].update(status="PARCIAL", reason="Sessões de uso fictícias para demonstração.",
                      data={"uso_roblox":{"segundos_pareados_observados":4320,"intervalos_pareados":2,
                                          "total_exato_72h":None}})
    return modules


def default_output():
    return Path.home() / ".local" / "share" / "warp-screenshare" / "relatorios"


def _write_private(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # Apenas o arquivo exclusivo recém-criado pode ficar incompleto.
        path.unlink(missing_ok=True)
        raise


def save_report(report, destination=None, captures=None):
    """Salva cada formato independentemente. A cópia local independe do envelope do Discord."""
    private = destination is None
    try:
        destination = default_output() if private else Path(destination).expanduser()
        if destination.is_symlink():
            raise ValueError("Destino simbólico")
        if private and not destination.resolve().is_relative_to(Path.home().resolve()):
            raise ValueError("Destino privado redirecionado para fora da pasta pessoal")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        if private and os.name == "posix":
            os.chmod(destination, 0o700)
        destination = destination.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        print("Falha ao abrir a pasta de relatórios. O envio opcional continua disponível.")
        return False

    scan_id = report["scan_id"]
    if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", scan_id):
        print("ID do scan inválido para gravação local.")
        return False
    files = [
        (f"relatorio_{scan_id}.json", lambda: json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")),
        (f"relatorio_{scan_id}.txt", lambda: render_text(report).encode("utf-8")),
    ]
    # O --output explícito conserva o comportamento de salvar a captura aprovada.
    for item in (captures or []) if not private else ():
        if item.get("filename") == f"prova_{scan_id}.png" and item.get("content_type") == "image/png":
            files.append((item["filename"], lambda image=item: base64.b64decode(image["content"], validate=True)))
    success = True
    for filename, encode in files:
        path = destination / filename
        try:
            _write_private(path, encode())
            print(f"Salvo neste aparelho: {path}")
        except (OSError, KeyError, TypeError, ValueError):
            success = False
            print(f"Falha ao salvar {filename}. Confira espaço e permissão da pasta.")
    return success


def deliver(report, captures, direct):
    """Obtém a imagem pública somente após a confirmação de envio."""
    if not direct and not os.environ.get("WARP_RELAY_URL", config.RELAY_URL):
        print("Discord indisponível: a staff ainda precisa configurar o endereço de entrega (WARP_RELAY_URL).")
        return False
    if not direct and not report.get("session_code"):
        print("Discord indisponível: inicie com --session-code e o código WARP fornecido pela staff.")
        return False
    identity = next((m.get("data", {}) for m in report.get("modules", [])
                     if m.get("module") == "M2" and m.get("status") in {"OK", "PARCIAL"}), {})
    uid = identity.get("userId")
    avatar = None
    if type(uid) is int and identity.get("profile_url") == f"https://www.roblox.com/users/{uid}/profile":
        avatar = fetch_headshot(uid)
    token = os.environ.get("WARP_SESSION_TOKEN", "") if not direct else ""
    if not direct and not token:
        invite = saved_invite()
        if invite:
            try:
                token = cloud_token(invite, report["session_code"])
            except (OSError, ValueError, KeyError, TypeError):
                print("A nuvem não autorizou o envio. Confira o convite e a conexão. O relatório continua no aparelho.")
                return False
        else:
            token = getpass.getpass("Token privado da sessão: ")
    try:
        if avatar:
            try:
                message_body = envelope(report, captures, avatar)
            except ValueError:
                message_body = envelope(report, captures)
        else:
            message_body = envelope(report, captures)
        success, message = send(message_body, token=token, direct=direct)
        print(message)
        return success
    except (OSError, ValueError, TypeError):
        print("O envio não foi confirmado. Confira a configuração com a staff.")
        return False


def finish_report(report, captures, args):
    saved = True
    if not args.test or args.output:
        saved = save_report(report, args.output, captures)
    delivered = True
    if args.test or args.dry_run:
        print("Sem envio: modo de teste ou dry-run.")
        if args.dry_run:
            print(json.dumps(envelope(report), ensure_ascii=False, indent=2))
    else:
        ui.step(10, "Envio opcional")
        if ui.yes_no("Confirma enviar este relatório minimizado ao Discord da staff?"):
            print("Envio autorizado. Enviando ao Discord…")
            delivered = deliver(report, captures, args.direct)
        else:
            print("Você escolheu não enviar. Nenhum relatório foi enviado ao Discord.")
    return 0 if saved and delivered else 1


def main(argv=None):
    args=arguments(argv)
    ui.PLAIN = args.plain
    if hasattr(sys.stdout,"reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ui.banner(args.plain)
    if args.test:
        print("DEMONSTRAÇÃO com dados fictícios. Para verificar o aparelho, execute warp-scan --adb sem --test.")
    elif not args.dry_run and not args.direct and not os.environ.get("WARP_RELAY_URL", config.RELAY_URL):
        print("Verificação local disponível. Envio ao Discord indisponível: o endereço de entrega da staff não está configurado.")
    if not args.test and os.name!="posix":
        print("Coleta disponível somente no Android/Termux. Use --test neste computador.")
        return 2
    consent=dict.fromkeys(("clipboard","files","discord","screenshot","network_tests"),False) if args.test else ui.consent_screen()
    if consent is None:
        print("Consentimento recusado. Nenhum dado foi coletado.")
        ui.banner(args.plain)
        return 0
    if not args.test and not Path("/system/bin/getprop").is_file():
        print("A coleta real requer Android/Termux. Use --test para a demonstração.")
        return 2
    settings=json.loads((config.BASE_DIR/"settings.json").read_text(encoding="utf-8"))
    if args.test:
        signatures=json.loads((config.BASE_DIR/"signatures.json").read_text(encoding="utf-8"))
        signatures_status="Base local; teste sem rede"
        signatures_digest=""
    else:
        # A sonda deve ocorrer antes da atualização ou qualquer outra coleta.
        signatures=json.loads((config.BASE_DIR/"signatures.json").read_text(encoding="utf-8"))
    ctx=Context(args,signatures,settings,consent,config.STORAGE_ROOT)
    if args.test:
        args.session_code=args.session_code or "WARP-TESTE"
        modules=synthetic_modules(ctx)
        integrity={"status":"SIMULAÇÃO — sem verificação remota"}
    else:
        from warp_scanner import privilege, roblox, identity, cheats, traces, downloads_browser, environment, processes, scripts_clipboard, device_history, authenticity, network
        if args.adb:
            ui.adb_guide(args)
        ui.step(2,"Privilégios")
        try:
            ctx.privilege=privilege.privilege_probe(ctx)
        except Exception:
            ctx.privilege.update(classification="NÃO VERIFICADO", mode="PADRÃO")
        print(f"{ctx.privilege['classification']} | {ctx.privilege['mode']}")
        if ctx.privilege.get("root"):
            print("ALERTA: root confirmado; consultas privilegiadas restritas a metadados autorizados.")
        signatures,signatures_status,signatures_digest=load_signatures(config.BASE_DIR,local_only=args.dry_run)
        ctx.signatures=signatures
        from warp_scanner.account_screen import observe
        args.visible_roblox = None if args.nick else observe(ctx, "Roblox", ui.yes_no)
        args.visible_discord = observe(ctx, "Discord", ui.yes_no) if consent.get("discord") and not args.discord_user else None
        if ctx.privilege.get("adb") and getattr(args, "account_observations", {}):
            input("Volte ao Termux e pressione Enter para continuar a coleta: ")
        if not ctx.privilege.get("adb") and not args.nick:
            print("Leitura automática do nick indisponível sem ADB local. Para tentar, use warp-scan --adb.")
        if not args.session_code and saved_invite():
            args.session_code = "WARP-" + secrets.token_hex(8).upper()
        if not args.session_code:
            code=input("Código público da sessão fornecido pela staff (WARP-...): ").strip()
            args.session_code=code if re.fullmatch(r"WARP-[A-Z0-9]{4,24}",code) else ""
        if args.session_code and args.nick:
            print("Coloque o código da sessão temporariamente na descrição pública do perfil.")
            input("Pressione Enter quando estiver pronto para consultar o perfil: ")
        ui.step(3,"Arquivos e integridade")
        from warp_scanner.storage_access import prepare
        prepare(ctx.storage, ui.yes_no)
        try:
            ctx.files=list(iter_allowed_files(ctx.storage,signatures,args.max_files,args.max_seconds,ctx.file_stats))
        except (OSError, ValueError):
            ctx.file_stats["errors"]=True
        integrity=collect_integrity(config.BASE_DIR)
        integrity.update(base_source=signatures_status,active_base_sha256=signatures_digest)
        modules=[]
        for step_no,title,collectors in [(4,"Roblox e perfis",[(roblox,"M1"),(identity,"M2")]),(5,"Executores e rastros",[(cheats,"M3"),(traces,"M4")]),(6,"Downloads e ambiente",[(downloads_browser,"M5"),(environment,"M6")]),(7,"Processos, histórico e autenticidade",[(processes,"M7"),(device_history,"M9"),(authenticity,"M10")]),(8,"Scripts, clipboard e rede",[(scripts_clipboard,"M8"),(network,"M11")])]:
            ui.step(step_no,title)
            for collector,module_id in collectors:
                try:
                    result=collector.collect(ctx)
                except Exception:
                    result=unavailable(module_id,"Coleta falhou; detalhes brutos descartados para preservar privacidade")
                modules.append(result)
                print(f"{module_id}: {result['status']}")
        if ctx.privilege.get("classification") in {"ROOT_CONFIRMADO","ROOT_SUSPEITO"}:
            root_finding=ctx.finding("M6","privilégio","Root confirmado" if ctx.privilege.get("root") else "Indicadores de root sem confirmação",{"status":ctx.privilege["classification"],"observacao":"Root não comprova uso de cheat"},"INDÍCIO","root" if ctx.privilege.get("root") else "hint")
            next(m for m in modules if m["module"]=="M6")["findings"].append(root_finding)
        if any(m.get("data",{}).get("credential_warning") for m in modules):
            print("Possível credencial encontrada no conteúdo autorizado. Conteúdo redigido; troque a senha e encerre sessões se houve exposição.")
    ui.step(9,"Resumo e revisão")
    from warp_scanner import review
    from warp_scanner.identity import discord_identity
    add_locations(ctx,modules)
    modules=review.apply(modules,ctx)
    report=build(ctx,modules,integrity,synthetic=args.test)
    report["discord_identity"]=discord_identity(args.discord_user, args.discord_id) if consent.get("discord") else {"status":"NÃO VERIFICADO"}
    if not consent.get("discord") and not args.test:
        report["discord_identity"]["reason"] = "Inclusão do Discord recusada."
    elif not args.discord_user and not args.test:
        report["discord_identity"].update(getattr(args, "account_observations", {}).get("Discord", {}))
    if getattr(args, "visible_discord", None):
        report["discord_identity"]={"status":"OBSERVADO", "username":args.visible_discord}
    captures=[]
    if not (args.test or args.dry_run) and consent.get("screenshot"):
        from warp_scanner import capture
        try:
            captures=capture.review(ctx,report)
        except (OSError, ValueError):
            report["capture"]={"status":"NÃO VERIFICADO","reason":"Captura ou revisão indisponível"}
    console_report=render_text(report)
    if args.plain or "NO_COLOR" in os.environ or "utf" not in (sys.stdout.encoding or "").lower():
        console_report=console_report.replace(ui.UNICODE_BANNER,ui.ASCII_BANNER)
    print(console_report)
    exit_code = finish_report(report, captures, args)
    print("Remova o código do perfil. Desative a depuração sem fio após a call.")
    ui.banner(args.plain)
    return exit_code


if __name__=="__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt,EOFError):
        print("\nOperação encerrada. Nenhum envio adicional. Desative a depuração sem fio.")
        sys.exit(130)
    except Exception:
        print("Falha de configuração ou gravação. Nenhum detalhe sensível foi exibido.")
        sys.exit(1)
