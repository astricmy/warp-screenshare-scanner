"""M7: metadados do processo e diagnósticos recentes do carregador do Roblox."""
import re
from collections import Counter
from .exit_history import collect_exit_history
from .roblox import PACKAGE, query, requirements


_MAP = re.compile(r"^[0-9a-fA-F]+-[0-9a-fA-F]+\s+([r-][w-][x-][ps])\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+:[0-9a-fA-F]+\s+\d+\s*(.*)$")
_MAP_LIMIT = 8192


def inspect_maps(text):
    counts = Counter()
    paths = set()
    lines = text.splitlines()
    for line in lines[:_MAP_LIMIT]:
        match = _MAP.fullmatch(line)
        if not match:
            counts["linhas_ilegíveis"] += 1
            continue
        flags, name = match.groups()
        counts["regiões"] += 1
        path = name.removesuffix(" (deleted)")
        if flags[2] == "x":
            counts["executáveis"] += 1
            jit_name = path.removeprefix("/memfd:").removeprefix("/dev/ashmem/").removeprefix("[anon:").removesuffix("]")
            if jit_name in {"jit-cache", "jit-code-cache", "jit-zygote-cache", "dalvik-jit-code-cache"}:
                counts["jit_reconhecido"] += 1
            elif path.startswith("/memfd:"):
                counts["memfd_executável"] += 1
            elif path.endswith(".so") and name.endswith(" (deleted)"):
                counts["biblioteca_executável_removida"] += 1
            elif flags[1] == "w" and (not path or path.startswith(("[anon:", "[anon_shmem:"))):
                counts["anônima_gravável_executável"] += 1
        if path.startswith("/") and not path.startswith("/memfd:") and path.endswith(".so"):
            # /data/app contém bibliotecas legítimas, inclusive splits; sem cert não acusar.
            if not path.startswith(("/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/data/app/")) and not path.startswith(("/data/user/0/" + PACKAGE + "/", "/data/data/" + PACKAGE + "/")):
                paths.add(path)
    incomplete = len(lines) > _MAP_LIMIT or bool(counts["linhas_ilegíveis"]) or len(paths) > 64
    return sorted(paths)[:64], counts, incomplete


def parse_maps(text):
    return inspect_maps(text)[0]


def _proc_metadata(ctx, pid, name, max_bytes):
    # Mantém o diretório do processo aberto e confere o pacote antes da leitura.
    # Se o PID for reutilizado, o diretório antigo deixa de fornecer os metadados.
    script = ('cd "/proc/$1" && [ "$(tr \'\\000\' \'\\n\' <cmdline | head -n 1)" = "$2" ] && '
              f'head -n {_MAP_LIMIT + 1} "$3"')
    return query(ctx, ["sh", "-c", script, "warp-proc", pid, PACKAGE, name], timeout=5, max_bytes=max_bytes)


_TOOL_LIBRARY = re.compile(r"(?<![\w.-])(libfrida-gadget(?:-[a-z0-9_-]+)?\.so|libxposed_art\.so)(?![\w.-])", re.I)
_LINKER_LINE = re.compile(r"^[WEF]/(?:linker|linker64)\s*:\s*(.*)$")


def linker_diagnostics(ctx, pids):
    check = {"name": "Log recente do carregador de bibliotecas do Roblox",
             "requires": "adb", "status": "NÃO VERIFICADO"}
    if not ctx.consent.get("runtime_logs"):
        return [], dict(check, reason="Leitura opcional do log desativada.")
    if not pids:
        return [], dict(check, reason="Processo do Roblox indisponível.")
    result, _, _ = query(ctx, ["pm", "list", "packages", "-U", PACKAGE], timeout=4, max_bytes=4096)
    uid = re.search(r"(?m)^package:com\.roblox\.client\s+uid:([0-9]+)[ \t]*$", result.text) if result.ok else None
    if not uid:
        return [], dict(check, reason="O Android não expôs o UID do Roblox para filtrar o log.")
    observed = {}
    visible = 0
    for pid in pids:
        argv = ["logcat", "-b", "main", "-d", "-t", "400", "--uid=" + uid[1], "--pid=" + pid,
                "-v", "tag", "linker:W", "linker64:W", "*:S"]
        # Fallback para Termux comum não teria visibilidade do log de outro UID.
        for capability in ("root", "adb"):
            if not ctx.privilege.get(capability):
                continue
            sample = ctx.run(argv, requires=capability, timeout=4, max_bytes=65536)
            if not sample.ok:
                continue
            for line in sample.text.splitlines():
                diagnostic = _LINKER_LINE.match(line)
                if diagnostic:
                    visible += 1
                    for match in _TOOL_LIBRARY.finditer(diagnostic[1]):
                        observed[match[1].lower()] = capability
            break
    findings = [ctx.finding("M7", "log do Roblox", "Carregador do Roblox mencionou biblioteca de instrumentação",
                            {"biblioteca": lib, "local": "Android › logcat › Roblox › linker",
                             "limite": "Um aviso pode indicar tentativa de carga que falhou."},
                            "INFORMATIVO", "artifact", capability) for lib, capability in sorted(observed.items())]
    check["status"] = "PARCIAL" if visible else "NÃO VERIFICADO"
    check["reason"] = (f"{visible} linhas de diagnóstico visíveis na amostra recente." if visible else
                       "Sem diagnósticos visíveis na amostra ou acesso indisponível.")
    return findings, check


def collect(ctx):
    required = requirements(ctx)
    findings, checks = [], []
    if required == "none":
        return {"module": "M7", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Requer ADB local pareado ou root; deixe o Roblox aberto em segundo plano.", "findings": [], "data": {}, "checks": [{"name": "Processos Roblox", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Capacidade indisponível."}]}
    exit_events, exit_check = collect_exit_history(ctx)
    checks.append(exit_check)
    result, cap, failures = query(ctx, ["pidof", PACKAGE], timeout=4, max_bytes=4096)
    pids = result.text.split() if result and result.ok else []
    all_pids = list(dict.fromkeys(pid for pid in pids if re.fullmatch(r"[0-9]{1,7}", pid) and 0 < int(pid) <= 4194304))
    pids = all_pids[:4]
    completed = 0
    resident_kib = []
    memory_totals = []
    map_counts = Counter()
    maps_read = 0
    maps_incomplete = False
    for pid in pids:
        status, status_cap, failed = _proc_metadata(ctx, pid, "status", 16384)
        if status and status.ok:
            rss = re.search(r"(?m)^VmRSS:[ \t]+(\d+)[ \t]+kB$", status.text)
            if rss:
                resident_kib.append(int(rss[1]))
            tracer = re.search(r"(?m)^TracerPid:\s*(\d+)", status.text)
            if tracer:
                completed += 1
                if int(tracer.group(1)):
                    findings.append(ctx.finding("M7", "instrumentação", "Roblox tem um processo rastreador conectado", {"TracerPid": int(tracer.group(1)), "limite": "Pode ser depuração legítima; não é prova de cheat."}, "INDÍCIO", "hint", status_cap))
        rollup, _, _ = _proc_metadata(ctx, pid, "smaps_rollup", 16384)
        if rollup.ok:
            values = {key: int(value) for key, value in re.findall(
                r"(?m)^(Rss|Pss|Anonymous|Swap):[ \t]+(\d+)[ \t]+kB$", rollup.text)}
            if values:
                memory_totals.append(values)
        maps, maps_cap, failed = _proc_metadata(ctx, pid, "maps", 2 * 1024 * 1024)
        if maps and maps.ok:
            paths, observed, incomplete = inspect_maps(maps.text)
            maps_incomplete |= incomplete
            if observed["regiões"]:
                completed += 1
                maps_read += 1
            map_counts.update(observed)
            for path in paths:
                findings.append(ctx.finding("M7", "biblioteca", "Biblioteca carregada fora dos diretórios usuais", {"path": path, "limite": "Caminho incomum exige validação; não identifica conteúdo nem origem."}, "INDÍCIO", "hint", maps_cap))
            for key, label in (("memfd_executável", "Região executável em arquivo de memória"),
                               ("biblioteca_executável_removida", "Biblioteca executável mapeada após remoção do arquivo"),
                               ("anônima_gravável_executável", "Região anônima gravável e executável")):
                if observed[key]:
                    findings.append(ctx.finding("M7", "mapa de memória", label,
                        {"local": "Android › Roblox › mapa de memória", "regiões": observed[key],
                         "limite": "Fotografia dos mapeamentos. Compilação dinâmica e atualizações também podem gerar essas regiões."},
                        "INFORMATIVO", "artifact", maps_cap))
    maps_status = "NÃO VERIFICADO"
    if maps_read:
        maps_status = "OK" if maps_read == len(all_pids) and not maps_incomplete else "PARCIAL"
    checks.append({"name": "Mapas de memória do Roblox", "requires": required, "status": maps_status,
                   "reason": f"{maps_read}/{len(all_pids)} processos com mapas legíveis; {map_counts['regiões']} regiões interpretadas. Limite de 4 processos, {_MAP_LIMIT} linhas e 2 MiB por processo."})
    checks.append({"name": "Memória proporcional e anônima do Roblox", "requires": required,
                   "status": "OK" if memory_totals and len(memory_totals) == len(all_pids) and all(len(v) == 4 for v in memory_totals) else "PARCIAL" if memory_totals else "NÃO VERIFICADO",
                   "reason": f"smaps_rollup de {len(memory_totals)}/{len(all_pids)} processos observado; métricas disponíveis em KiB no JSON."})
    checks.append({"name": "TracerPid e bibliotecas do Roblox", "requires": "adb", "status": "PARCIAL" if completed else "NÃO VERIFICADO", "reason": "Leitura limitada a metadados; caminhos incomuns não comprovam injeção." if pids else "Roblox fechado ou pidof indisponível; abrir em segundo plano e repetir."})
    diagnostics, coverage = linker_diagnostics(ctx, pids)
    findings.extend(diagnostics)
    checks.append(coverage)
    checks.append({"name": "RAM residente dos processos Roblox", "requires": required,
                   "status": "OK" if pids and len(resident_kib) == len(pids) else "PARCIAL" if resident_kib else "NÃO VERIFICADO",
                   "reason": "VmRSS por processo em KiB: " + ", ".join(map(str, resident_kib)) if resident_kib else "VmRSS indisponível."})
    for process in ("frida-server", "gdbserver"):
        result, cap, failures = query(ctx, ["pidof", process], timeout=3, max_bytes=4096)
        if result and result.ok and re.fullmatch(r"\d+(?:\s+\d+)*\s*", result.text):
            findings.append(ctx.finding("M7", "instrumentação", "Processo de instrumentação em execução", {"name": process, "limite": "Nome do processo não comprova instrumentação do Roblox; pode ser alterado."}, "INDÍCIO", "hint", cap))
    checks.append({"name": "Portas e processos renomeados", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Não varre conexões nem lista todos os processos; nomes podem ser ocultados."})
    partial = completed or resident_kib or memory_totals or coverage["status"] == "PARCIAL" or exit_check["status"] in ("OK", "PARCIAL") or findings
    return {"module": "M7", "requires": "adb", "status": "PARCIAL" if partial else "NÃO VERIFICADO", "reason": "Metadados e diagnósticos limitados ao alvo.", "findings": findings, "data": {"roblox_running": bool(pids), "completed_queries": completed, "ram_residente_kib": resident_kib, "smaps_rollup_kib": memory_totals, "mapas_observados": dict(map_counts), "encerramentos_android": exit_events}, "checks": checks}
