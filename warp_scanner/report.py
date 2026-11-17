"""Relatórios limitados e minimizados, sem vereditos automáticos de punição."""
import base64
import re
from .presentation import LEVELS, LABELS, facts, overview, message, profile_url, module, when
from .report_privacy import scrub
from .text_model import HIGH
import json
import uuid
import config
from .core import now, sanitize
from .ui import UNICODE_BANNER


def build(ctx, modules, integrity, synthetic=False):
    findings=[]
    for result in modules:
        findings.extend(result.get("findings",[]))
    def review_order(finding):
        level = finding.get("level")
        evidence = finding.get("evidence")
        priority = isinstance(evidence, dict) and evidence.get("prioridade_ia") == HIGH
        return (len(LEVELS) - LEVELS.index(level) if level in LEVELS else 0,
                finding.get("weight", 0), priority)
    findings.sort(key=review_order, reverse=True)
    score=sum(max(0,f.get("weight",0)) for f in findings)
    partial=any(not any(m["module"]==critical and m["status"]=="OK" for m in modules) for critical in config.CRITICAL_MODULES)
    limits=ctx.settings["thresholds"]
    if score>=limits["high_risk"] or any(f.get("level")=="CONFIRMADO" for f in findings):
        verdict="ALTO RISCO"
    elif score>=limits["suspect"]:
        verdict="SUSPEITO"
    else:
        verdict="INCONCLUSIVO" if partial else "LIMPO"
    if partial:
        verdict+=" (cobertura parcial)"
    cutoff=ctx.settings.get("max_findings",100)
    report={"scan_id":str(uuid.uuid4()),"session_code":ctx.args.session_code,"timestamp":now(),"version":config.VERSION,
            "synthetic":synthetic,"verdict":verdict,"score":score,"partial_coverage":partial,
            "notice":"Evidências técnicas não comprovam uso de cheat. Decisão final da staff; sem punição automática.",
            "consent":ctx.consent,"privilege":ctx.privilege,"integrity":integrity,
            "summary_facts":facts(findings), "findings":findings[:cutoff],"findings_omitted":max(0,len(findings)-cutoff),
            "modules":[{k:v for k,v in m.items() if k!="findings"} for m in modules],
            "timeline":[{"time":f.get("time"),"module":f.get("module"),"description":f.get("description")} for f in sorted(findings[:cutoff],key=lambda f:f.get("time") or "")],
            "timeline_note":"Horário da coleta quando a fonte não fornece data do evento; proximidade temporal não implica causalidade."}
    extra_paths = [
        f["evidence"]["caminho_android"] for f in findings[cutoff:]
        if f.get("module") == "M8" and f.get("category") == "arquivo TAS"
        and isinstance(f.get("evidence"), dict) and f["evidence"].get("caminho_android")
    ]
    if extra_paths:
        report["caminhos_tas_adicionais_locais"] = extra_paths
    return scrub(sanitize(report))


def plain_summary(report):
    # Preserva pontuação legítima de nomes/caminhos: só remove decoração do modelo.
    def convert(line):
        pieces = line.split(chr(96))
        for index in range(0, len(pieces), 2):
            pieces[index] = pieces[index].replace("**", "")
            pieces[index] = re.sub(r"\[🔗 Perfil\]\((https://www\.roblox\.com/users/[0-9]+/profile)\)", r"Perfil: \1", pieces[index])
            pieces[index] = re.sub(r"\[🔗 Discord\]\((https://discord\.com/users/[0-9]+)\)", r"Perfil: \1", pieces[index])
        return "".join(pieces)
    return "\n".join(convert(line) for line in overview(report).splitlines())


def render_text(report, *, include_extra_tas=False):
    lines = [UNICODE_BANNER, "", "RELATÓRIO SINTÉTICO — TESTE" if report["synthetic"] else "RELATÓRIO DE VERIFICAÇÃO",
             "", plain_summary(report), "", report["notice"], "", "ACHADOS E LOCALIZAÇÕES"]
    for number, f in enumerate(report["findings"], 1):
        lines.append(f"{number}. [{f['level']}] {f['description']}")
        lines.append(f"   Fonte: {f['module']} • {when(f['time'])} (UTC-3)")
        e = f.get("evidence")
        if isinstance(e, dict):
            for key, label in (("caminho_android","Caminho Android"), ("path","Caminho"), ("caminho","Caminho"),
                               ("local","Local"), ("domain","Domínio"), ("package","Pacote"), ("trecho","Trecho"),
                               ("sha256","SHA-256"), ("prioridade_ia","Triagem local de IA"),
                               ("motivo_ia","Motivo da sugestão"), ("limite","Limite da evidência")):
                if key in e:
                    lines.append(f"   {label}: {e[key]}")
        if f.get("review"):
            lines.append("   Revisão: " + f["review"])
    if not report["findings"]:
        lines.append("Nenhuma correspondência entre as verificações executadas.")
    if report.get("findings_omitted"):
        lines.append(f"{report['findings_omitted']} registros excederam o limite de detalhes; totais preservados no resumo.")
    extra_paths = report.get("caminhos_tas_adicionais_locais", [])
    local_count = len(extra_paths) or report.get("outros_tas_no_relatorio_local", 0)
    if local_count:
        lines.append(f"{local_count} caminhos .tas adicionais no relatório local do celular.")
        if include_extra_tas:
            lines.extend(extra_paths)
    lines.extend(["", "COBERTURA POR MÓDULO"])
    for m in report["modules"]:
        lines.append(f"{m['module']} • {LABELS.get(m['module'], 'Verificação')} — {m['status']}")
        for c in m.get("checks", []):
            lines.append(f"  {c['name']}: {c['status']} • {c.get('reason', '')}")
    lines.extend(["", "LINHA DO TEMPO (UTC-3)", report["timeline_note"]])
    lines.extend(f"{when(e['time'])} | {e['module']} | {e['description']}" for e in report["timeline"])
    lines.extend(["", "INTEGRIDADE: " + str(report["integrity"].get("status", "NÃO VERIFICADO")),
                  "Consulte o arquivo JSON deste scan para as evidências estruturadas, consentimentos e hashes."])
    if report.get("capture"):
        lines.append("Captura da tela: " + str(report["capture"].get("status", "NÃO VERIFICADO")))
    return "\n".join(lines) + "\n"


def discord_payload(report):
    return message(report)


def envelope(report, captures=None, avatar=None):
    # O limite geral de achados não limita a lista de caminhos disponível no celular.
    local_paths = report.get("caminhos_tas_adicionais_locais")
    if local_paths:
        report = {k: v for k, v in report.items() if k != "caminhos_tas_adicionais_locais"}
        report["outros_tas_no_relatorio_local"] = len(local_paths)
    result = _envelope(report, captures, avatar)
    if not any(f.get("category") == "arquivo TAS" for f in report.get("findings", [])):
        return result
    # Mede somente a porção textual; imagens possuem limite separado no relay.
    # Reserva espaço para metadados das imagens e delimitação do JSON.
    wire_text = {**result, "attachments": result["attachments"][:2]}
    if len(json.dumps(wire_text, ensure_ascii=False).encode("utf-8")) <= 255 * 1024:
        return result
    keep, removed = [], 0
    sample = 0
    reviewed = report.get("capture", {}).get("finding_id")
    for finding in report["findings"]:
        if finding.get("category") == "arquivo TAS":
            if sample >= 3 and finding.get("id") != reviewed:
                removed += 1
                continue
            sample += 1
        keep.append(finding)
    if removed:
        reduced = {**report, "findings": keep, "findings_omitted": report.get("findings_omitted", 0) + removed,
                   "outros_tas_no_relatorio_local": report.get("outros_tas_no_relatorio_local", 0) + removed}
        return _envelope(reduced, captures, avatar)
    return result


def _envelope(report, captures, avatar):
    attachments = [{"filename": f"relatorio_{report['scan_id']}.json", "content_type": "application/json",
                    "content": json.dumps(report, ensure_ascii=False, indent=2)},
                   {"filename": f"relatorio_{report['scan_id']}.txt", "content_type": "text/plain",
                    "content": render_text(report)}, *(captures or [])]
    with_avatar = bool(avatar and profile_url(module(report, "M2").get("data", {})))
    if with_avatar:
        attachments.append({"filename":"avatar.png", "content_type":"image/png",
                            "content":base64.b64encode(avatar).decode("ascii")})
    return {"session_code":report["session_code"], "scan_id":report["scan_id"],
            "payload":message(report, avatar=with_avatar), "attachments":attachments}
