"""Relatórios limitados e minimizados, sem vereditos automáticos de punição."""
from collections import Counter
import json
import uuid
import config
from .core import now, sanitize
from .ui import UNICODE_BANNER


def build(ctx, modules, integrity, synthetic=False):
    findings=[]
    for result in modules:
        findings.extend(result.get("findings",[]))
    findings.sort(key=lambda f:(f.get("level")=="CONFIRMADO",f.get("weight",0)),reverse=True)
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
            "findings":findings[:cutoff],"findings_omitted":max(0,len(findings)-cutoff),
            "modules":[{k:v for k,v in m.items() if k!="findings"} for m in modules],
            "timeline":[{"time":f.get("time"),"module":f.get("module"),"description":f.get("description")} for f in sorted(findings[:cutoff],key=lambda f:f.get("time") or "")],
            "timeline_note":"Horário da coleta quando a fonte não fornece data do evento; proximidade temporal não implica causalidade."}
    return sanitize(report)


def module_data(report, module):
    return next((m.get("data",{}) for m in report["modules"] if m["module"]==module),{})


def render_text(report):
    lines=[UNICODE_BANNER,"", "RELATÓRIO SINTÉTICO — TESTE" if report["synthetic"] else "RELATÓRIO DE VERIFICAÇÃO",
           f"ID: {report['scan_id']}",f"Sessão: {report['session_code']}",f"Data UTC: {report['timestamp']}",
           f"Resultado: {report['verdict']} | Pontuação: {report['score']}",report["notice"],
           "", "CONSENTIMENTO",json.dumps(report["consent"],ensure_ascii=False),
           "", "PRIVILÉGIOS",json.dumps(report["privilege"],ensure_ascii=False,indent=2),
           "", "INTEGRIDADE",json.dumps(report["integrity"],ensure_ascii=False,indent=2),"", "ACHADOS"]
    for finding in report["findings"]:
        lines.append(f"[{finding['level']}] {finding['module']} +{finding['weight']} {finding['description']}")
        lines.append(json.dumps(finding["evidence"],ensure_ascii=False))
        lines.append(f"Horário: {finding['time']} | requires: {finding['requires']}")
    if not report["findings"]:
        lines.append("Nenhuma correspondência nas verificações executadas; consulte a cobertura.")
    lines.extend(["", "COBERTURA E METADADOS"])
    for m in report["modules"]:
        lines.append(f"{m['module']} [{m['status']}] requires={m['requires']}: {m.get('reason','')}")
        for check in m.get("checks",[]):
            lines.append(f"  {check['name']}: {check['status']} | {check['requires']} | {check.get('reason','')}")
        if m.get("data"):
            lines.append(json.dumps(m["data"],ensure_ascii=False,indent=2))
    lines.extend(["", "LINHA DO TEMPO",report["timeline_note"]])
    lines.extend(f"{e['time']} | {e['module']} | {e['description']}" for e in report["timeline"])
    if report.get("discord_identity"):
        lines.extend(["", "DISCORD INFORMADO PELO JOGADOR", json.dumps(report["discord_identity"],ensure_ascii=False)])
    if report.get("capture"):
        lines.extend(["", "CAPTURA REVISADA", json.dumps(report["capture"],ensure_ascii=False)])
    lines.extend(["", "Remova o código do perfil e desative a depuração sem fio."])
    return "\n".join(lines)+"\n"


def compact(value, limit):
    value=str(value)
    return value if len(value)<=limit else value[:limit-12]+" … ver anexo"


def discord_payload(report):
    identity=module_data(report,"M2")
    roblox=module_data(report,"M1")
    environment=module_data(report,"M6")
    color=0x808080 if report["partial_coverage"] else (0xD83C3E if "ALTO RISCO" in report["verdict"] else 0xF0B232 if "SUSPEITO" in report["verdict"] else 0x2ECC71)
    profile=identity.get("profile_url")
    summary={"title":"WARP SCREENSHARE • Relatório de Verificação","color":color,"timestamp":report["timestamp"],
             "description":compact(f"{report['verdict']} | {report['score']} pontos\n{report['privilege'].get('mode')} | {report['privilege'].get('classification')}\n"+report["notice"],400),
             "fields":[{"name":"Jogador","value":compact(f"{identity.get('nick','NÃO VERIFICADO')} | {identity.get('displayName','')} | userId={identity.get('userId','—')}",180)},
                       {"name":"Perfil no Roblox","value":f"[Abrir perfil]({profile})" if profile else "NÃO VERIFICADO"},
                       {"name":"Posse verificada","value":"Sim" if identity.get("ownership_verified") else "Não"},
                       {"name":"Dispositivo","value":compact(json.dumps(environment.get("device",{}),ensure_ascii=False),240) or "NÃO VERIFICADO"},
                       {"name":"Roblox","value":compact(json.dumps(roblox,ensure_ascii=False),320)},
                       {"name":"Achados por severidade","value":compact(str(dict(Counter(f["level"] for f in report["findings"]))),160)}],
             "footer":{"text":f"{config.BRAND} • {config.DISCORD_INVITE}"}}
    if profile:
        summary["url"]=profile
    discord_user = report.get("discord_identity", {})
    summary["fields"].extend([
        {"name":"Discord", "value":compact(discord_user.get("username","NÃO VERIFICADO") + (" (informado pelo jogador)" if discord_user.get("username") else ""),100)},
        {"name":"🌐 Rede", "value":compact(module_data(report,"M11").get("resumo","NÃO VERIFICADO"),210)},
    ])
    items=report["findings"][:10]
    evidence={"title":"Achados (até 10; detalhes nos anexos)","description":"\n".join(compact(f"{f['level']} • {f['description']} • {f['time']}\n{json.dumps(f['evidence'],ensure_ascii=False)}",200) for f in items) or "Sem correspondências; consulte a cobertura."}
    coverage={"title":"Cobertura e integridade","description":compact("\n".join(f"{m['module']}: {m['status']} ({m['requires']})" for m in report["modules"]),700),
              "fields":[{"name":"Identificação","value":f"Scan: {report['scan_id']}\nSessão: {report['session_code']}\nVersão: {report['version']}"},
                        {"name":"Consentimentos","value":str(report["consent"])},
                        {"name":"Integridade","value":compact(json.dumps(report["integrity"],ensure_ascii=False),650)}]}
    payload={"embeds":[summary,evidence,coverage]}
    return payload


def envelope(report, captures=None):
    doc=json.dumps(report,ensure_ascii=False,indent=2)
    return {"session_code":report["session_code"],"scan_id":report["scan_id"],"payload":discord_payload(report),"attachments":[
        {"filename":f"relatorio_{report['scan_id']}.json","content":doc,"content_type":"application/json"},
        {"filename":f"relatorio_{report['scan_id']}.txt","content":render_text(report),"content_type":"text/plain"},*(captures or [])]}
