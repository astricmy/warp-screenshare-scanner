"""M7: metadados de processo; não lê memória nem dados de outros apps."""
import re
from .roblox import PACKAGE, query, requirements


def parse_maps(text):
    paths = set()
    for line in text.splitlines():
        columns = line.split(None, 5)
        if len(columns) != 6:
            continue
        path = columns[5].removesuffix(" (deleted)")
        if path.startswith("/") and path.endswith(".so"):
            # /data/app contém bibliotecas legítimas, inclusive splits; sem cert não acusar.
            if not path.startswith(("/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/data/app/")) and not path.startswith(("/data/user/0/" + PACKAGE + "/", "/data/data/" + PACKAGE + "/")):
                paths.add(path)
    return sorted(paths)[:64]


def collect(ctx):
    required = requirements(ctx)
    findings, checks = [], []
    if required == "none":
        return {"module": "M7", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Requer ADB local pareado ou root; deixe o Roblox aberto em segundo plano.", "findings": [], "data": {}, "checks": [{"name": "Processos Roblox", "requires": "adb", "status": "NÃO VERIFICADO", "reason": "Capacidade indisponível."}]}
    result, cap, failures = query(ctx, ["pidof", PACKAGE], timeout=4, max_bytes=4096)
    pids = result.text.split() if result and result.ok else []
    pids = [pid for pid in pids if pid.isdecimal() and 0 < int(pid) <= 4194304][:4]
    completed = 0
    for pid in pids:
        status, status_cap, failed = query(ctx, ["cat", "/proc/" + pid + "/status"], timeout=3, max_bytes=16384)
        if status and status.ok:
            tracer = re.search(r"(?m)^TracerPid:\s*(\d+)", status.text)
            if tracer:
                completed += 1
                if int(tracer.group(1)):
                    findings.append(ctx.finding("M7", "instrumentação", "Roblox tem um processo rastreador conectado", {"TracerPid": int(tracer.group(1)), "limite": "Pode ser depuração legítima; não é prova de cheat."}, "INDÍCIO", "hint", status_cap))
        maps, maps_cap, failed = query(ctx, ["cat", "/proc/" + pid + "/maps"], timeout=4, max_bytes=262144)
        if maps and maps.ok:
            completed += 1
            for path in parse_maps(maps.text):
                findings.append(ctx.finding("M7", "biblioteca", "Biblioteca carregada fora dos diretórios usuais", {"path": path, "limite": "Caminho incomum exige validação; não identifica conteúdo nem origem."}, "INDÍCIO", "hint", maps_cap))
    checks.append({"name": "TracerPid e bibliotecas do Roblox", "requires": "adb", "status": "PARCIAL" if completed else "NÃO VERIFICADO", "reason": "Leitura limitada a metadados; caminhos incomuns não comprovam injeção." if pids else "Roblox fechado ou pidof indisponível; abrir em segundo plano e repetir."})
    for process in ("frida-server", "gdbserver"):
        result, cap, failures = query(ctx, ["pidof", process], timeout=3, max_bytes=4096)
        if result and result.ok and re.fullmatch(r"\d+(?:\s+\d+)*\s*", result.text):
            findings.append(ctx.finding("M7", "instrumentação", "Processo de instrumentação em execução", {"name": process, "limite": "Nome do processo não comprova instrumentação do Roblox; pode ser alterado."}, "INDÍCIO", "hint", cap))
    checks.append({"name": "Portas e processos renomeados", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Não varre conexões nem lista todos os processos; nomes podem ser ocultados."})
    return {"module": "M7", "requires": "adb", "status": "PARCIAL" if completed else "NÃO VERIFICADO", "reason": "Somente metadados dos alvos; nunca dump de memória.", "findings": findings, "data": {"roblox_running": bool(pids), "completed_queries": completed}, "checks": checks}
