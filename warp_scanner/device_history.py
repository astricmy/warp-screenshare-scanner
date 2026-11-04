"""M9. Marcos do Android e uso observado do Roblox em uma janela móvel de 72 h."""
import datetime as dt
import re
import time

from .roblox import PACKAGE, package_info, parse_install_time, query

HOUR_MS = 3_600_000
WINDOW_MS = 72 * HOUR_MS
# Programa fixo, sem interpolação. O Android filtra pelo pacote. O sh projeta
# somente datas, transições e instanceId do perfil principal (mesmo armazenamento do scanner).
# Não persiste ID de atividade, classe, nomes de outros apps nem linhas brutas.
EVENT_PROJECTION = r'''PATH=/system/bin:/system/xbin; set -o pipefail; set -f
dumpsys usagestats -c com.roblox.client | while IFS= read -r line; do
  [ "$finished" = 1 ] && continue
  case "$line" in
    *"Permission Denial"*|*"Permission denied"*|*"SecurityException"*) exit 2;;
    *user=*)
      if [ "$active" = 1 ]; then finished=1; continue; fi
      set -- $line
      owner=0
      [ "$1" = user=0 ] && owner=1
      ;;
    *"hour events ("*"beginTime="*"endTime="*)
      [ "$owner" = 1 ] || continue
      if [ "$active" = 1 ]; then finished=1; continue; fi
      active=1
      b= e=
      range=${line#*beginTime=}
      set -- $range
      b=$1
      for f in $range; do case "$f" in endTime=*) e=$f;; esac; done
      printf 'R %s %s\n' "$b" "${e#endTime=}" | tr -d ')'
      ;;
    *"In-memory "*) if [ "$active" = 1 ]; then finished=1; continue; fi ;;
    *"package=com.roblox.client "*)
      [ "$active" = 1 ] || continue
      t= k= i= p=
      for f in $line; do case "$f" in time=*) t=${f#time=};; type=*) k=${f#type=};; package=*) p=${f#package=};; instanceId=*) i=${f#instanceId=};; esac; done
      [ "$p" = com.roblox.client ] || continue
      case "$k" in MOVE_TO_FOREGROUND|MOVE_TO_BACKGROUND) [ -n "$i" ] || i=0;; esac
      case "$k" in ACTIVITY_RESUMED|ACTIVITY_PAUSED|ACTIVITY_STOPPED|MOVE_TO_FOREGROUND|MOVE_TO_BACKGROUND) printf 'E %s %s %s\n' "$t" "$k" "$i";; esac
      ;;
  esac
done'''


def _check(name, status, reason, requires="none"):
    return dict(name=name, status=status, reason=reason, requires=requires)


def _utc(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat()


def marker(value, source, now, milliseconds=False):
    """Rejeita datas futuras, sentinelas e formatos não canônicos de fabricante."""
    if not re.fullmatch(r"[0-9]{10,13}", value.strip()):
        return None
    stamp = int(value.strip()) / (1000 if milliseconds else 1)
    if not 1_230_768_000 <= stamp <= now:
        return None
    return {"fonte": source, "timestamp": _utc(stamp), "segundos_ate_coleta": int(now - stamp)}


def observed_usage(projected, now_ms):
    """Une intervalos por atividade no mesmo pacote. Pontas abertas não são estimadas."""
    rows = projected.splitlines()
    if not rows:
        return None
    span = re.fullmatch(r"R (\d{13}) (\d{13})", rows[0].strip())
    if not span:
        return None
    first, last = map(int, span.groups())
    if first >= last or last > now_ms + 60_000 or last < now_ms - WINDOW_MS:
        return None
    start, end = max(first, now_ms - WINDOW_MS), min(last, now_ms)
    if start >= end:
        return None
    events = []
    gaps = 0
    for line in rows[1:]:
        match = re.fullmatch(r"E (\d{13}) (ACTIVITY_RESUMED|ACTIVITY_PAUSED|ACTIVITY_STOPPED|MOVE_TO_FOREGROUND|MOVE_TO_BACKGROUND) (-?\d{1,10})", line.strip())
        if not match:
            gaps += 1
            continue
        stamp, kind, instance = match.groups()
        if first <= int(stamp) <= last:
            events.append((int(stamp), kind, instance))
    opened, intervals = {}, []
    # Ordem estável no mesmo milissegundo é a ordem do histórico do Android.
    for stamp, kind, instance in sorted(events, key=lambda event: event[0]):
        if kind in {"ACTIVITY_RESUMED", "MOVE_TO_FOREGROUND"}:
            if instance in opened:
                # Uma retomada sem pausa intermediária é ambígua.
                gaps += 1
            opened[instance] = stamp
        else:
            if instance not in opened:
                if kind != "ACTIVITY_STOPPED":
                    gaps += 1
                continue
            a, b = max(start, opened.pop(instance)), min(stamp, end)
            if a < b:
                intervals.append((a, b))
    gaps += len(opened)
    elapsed, current_end = 0, start
    for a, b in sorted(intervals):
        elapsed += max(0, b - max(a, current_end))
        current_end = max(current_end, b)
    # Eventos pareados não permitem provar retenção integral nem observar
    # sessões abertas nas bordas. O total solicitado permanece inconclusivo.
    return {"janela_solicitada_h": 72, "inicio_janela_ms": now_ms - WINDOW_MS,
            "fim_janela_ms": now_ms, "inicio_observado_ms": start, "fim_observado_ms": end,
            "segundos_pareados_observados": elapsed // 1000, "intervalos_pareados": len(intervals),
            "primeiro_inicio_pareado_ms": min((a for a, _ in intervals), default=None),
            "transicoes_incompletas": gaps, "total_exato_72h": None,
            "interpretacao": "Tempo das sessões completas observáveis, limitado à janela. Nenhuma extrapolação para os dias ausentes."}


def reinstall_status(info, usage, now):
    installed = parse_install_time(info.get("owner_first_install"))
    if not info.get("present") or not installed or not 1_230_768_000 <= installed.timestamp() <= now:
        return {"value": None, "reason": "data de instalação do perfil principal indisponível"}
    result = {"value": None, "reason": "instalação recente; uso anterior indeterminado",
              "firstInstallTime": installed.isoformat()}
    if now - installed.timestamp() >= WINDOW_MS / 1000:
        result.update(value=False, reason="instalação registrada há pelo menos 72 h")
    elif usage:
        first = usage.get("primeiro_inicio_pareado_ms")
        if first is not None and first < int(installed.timestamp() * 1000):
            result.update(value=True, reason="reinstalação provável: uso anterior no mesmo perfil")
    return result


def collect(ctx):
    now = time.time()
    checks, data = [], {"formatacao_exata": "INDETERMINADO", "marcos": [], "uso_roblox": None}
    sources = [
        (["stat", "-c", "%Y", "/data/misc/bootstat/factory_reset"], "bootstat/factory_reset", False,
         "Marco de inicialização do registro de reset da partição de dados. Relógio alterado ou registro recriado muda a estimativa."),
        (["getprop", "ro.runtime.firstboot"], "ro.runtime.firstboot", True,
         "Indicador auxiliar de primeira inicialização do runtime. Pode refletir reinício ou atualização."),
        (["getprop", "ro.build.date.utc"], "ro.build.date.utc", False,
         "Data de compilação da imagem. É apenas contexto da versão instalada."),
    ]
    for command, source, millis, meaning in sources:
        result, cap, _ = query(ctx, command, timeout=3, max_bytes=160)
        value = marker(result.text, source, now, millis) if result.ok else None
        if value:
            value["interpretacao"] = meaning
            value["confianca"] = "moderada para o marco local" if source.startswith("bootstat/") else "contextual"
            data["marcos"].append(value)
        checks.append(_check(source, "OK" if value else "NÃO VERIFICADO", meaning if value else "Registro não disponível ou horário inválido.", cap))
    data["limite"] = "O aparelho pode restaurar, alterar ou perder os marcos. A data real da última formatação e reinstalação permanece indeterminada."
    usage = None
    cap = "adb"
    if ctx.privilege.get("root") or ctx.privilege.get("adb"):
        for cap in ("root", "adb"):
            if ctx.privilege.get(cap):
                result = ctx.run(["/system/bin/sh", "-c", EVENT_PROJECTION], requires=cap, timeout=10, max_bytes=256_000)
                if result.ok:
                    usage = observed_usage(result.text, int(time.time() * 1000))
                    if usage:
                        break
    data["uso_roblox"] = usage
    data["reinstall"] = reinstall_status(package_info(ctx, PACKAGE), usage, now)
    checks.append(_check("Uso do Roblox nas últimas 72 h", "PARCIAL" if usage else "NÃO VERIFICADO",
                         "Tempo de atividade no perfil principal. AOSP normalmente expõe até 24 h; períodos ausentes ficam desconhecidos."
                         if usage else "Eventos específicos com intervalo e instâncias verificáveis indisponíveis.", cap))
    return {"module": "M9", "requires": "none", "status": "PARCIAL" if data["marcos"] or usage else "NÃO VERIFICADO",
            "reason": "Marcos e uso observado contextualizam a análise e não geram pontos.",
            "data": data, "findings": [], "checks": checks}
