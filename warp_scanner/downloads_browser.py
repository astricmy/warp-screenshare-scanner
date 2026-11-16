"""M5: downloads filtrados e contagem local em histórico exportado pelo jogador."""
import datetime as dt
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from .roblox import query, requirements
from .safety import domain_matches, normalize_domain, read_bounded_file


HISTORY_LIMIT = 8 * 1024 * 1024
HISTORY_DOMAINS = {"pastebin.com": "Pastebin", "mediafire.com": "MediaFire"}


def is_history_export(path, storage, selected=None):
    path = Path(path)
    if path.name.casefold() in {"history.json", "browserhistory.json", "browser history.json"}:
        return True
    return bool(selected and path == Path(storage) / "Download" / selected)


def browser_history(ctx, since_ms, now_ms):
    check = {"name": "Histórico exportado do Chrome", "requires": "none", "status": "NÃO VERIFICADO"}
    selected = getattr(ctx.args, "history_export", None)
    if not getattr(ctx, "consent", {}).get("browser_history") or not selected:
        check["reason"] = "Exportação não autorizada ou não selecionada."
        return check, {}
    try:
        root = Path(ctx.storage) / "Download"
        path = root / selected
        if not path.is_relative_to(root) or ".." in path.parts or path.suffix.casefold() != ".json":
            raise ValueError("Caminho fora de Download ou tipo incompatível")
        raw, _ = read_bounded_file(path, root, HISTORY_LIMIT)
        records = json.loads(raw)
        if not isinstance(records, dict) or not isinstance(records.get("Browser History"), list):
            raise ValueError("Formato desconhecido")
    except (OSError, ValueError, RecursionError):
        check["reason"] = "Arquivo inacessível ou inválido. Selecione o histórico JSON do Chrome/Takeout em Download (até 8 MiB)."
        return check, {}

    counts = dict.fromkeys(HISTORY_DOMAINS.values(), 0)
    incomplete = False
    for visit in records["Browser History"]:
        if not isinstance(visit, dict) or not isinstance(visit.get("url"), str):
            incomplete = True
            continue
        try:
            link = urlsplit(visit["url"])
            if link.scheme not in {"http", "https"}:
                continue
            if not link.hostname or "\\" in link.netloc:
                incomplete = True
                continue
            host = link.hostname.lower().rstrip(".")
        except ValueError:
            incomplete = True
            continue
        service = next((name for domain, name in HISTORY_DOMAINS.items()
                        if host == domain or host.endswith("." + domain)), None)
        if not service:
            continue
        stamp = str(visit.get("time_usec", ""))
        if not re.fullmatch(r"[0-9]{1,18}", stamp):
            incomplete = True
            continue
        if since_ms <= int(stamp) // 1000 <= now_ms:
            counts[service] += 1
    check["status"] = "PARCIAL" if incomplete else "OK"
    check["reason"] = "Contagem das visitas no arquivo selecionado e na janela do scan. O histórico sincronizado pode incluir outros aparelhos."
    if incomplete:
        check["reason"] += " Há registros ilegíveis."
    return check, counts


def _domains(signatures):
    entries = {}
    for entry in signatures.get("entries", []):
        for domain in entry.get("dominios", []):
            domain = normalize_domain(domain)
            if domain and re.fullmatch(r"[a-z0-9.-]{1,253}", domain) and "." in domain:
                entries[domain] = entry
    return entries


def parse_download_rows(text, domains, since_ms):
    """Reduz imediatamente cada linha a domínio da blocklist + horário."""
    rows = []
    # O CLI content imprime os valores solicitados como uri=..., lastmod=...
    for line in text.splitlines():
        match = re.search(r"\buri=(https?://.*?),\s*lastmod=(\d+)\s*$", line)
        if not match:
            continue
        uri, stamp = match.group(1), int(match.group(2))
        host = normalize_domain(uri)
        if stamp < since_ms or stamp > int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000) + 300000:
            continue
        signature_domain = next((domain for domain in domains if domain_matches(host, domain)), None)
        if signature_domain:
            rows.append({"domain": host, "timestamp_ms": stamp, "signature_domain": signature_domain})
    return rows


def collect(ctx):
    findings, checks = [], []
    domains = _domains(ctx.signatures)
    since = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=ctx.args.window_days)).timestamp() * 1000)
    tested = 0
    completed = 0
    required = requirements(ctx)
    if required in ("root", "adb") and domains:
        # Filtragem no provedor, ANTES do retorno. Falhas de schema são cobertura parcial.
        # Uma lista grande é dividida; limite impede consultas e outputs ilimitados.
        selected = list(domains)[:80]
        seen = set()
        for start in range(0, len(selected), 10):
            group = selected[start:start + 10]
            clauses = []
            for domain in group:
                for scheme in ("https", "http"):
                    clauses.extend([f"uri LIKE '{scheme}://{domain}/%'", f"uri LIKE '{scheme}://%.{domain}/%'"])
            where = f"lastmod >= {since} AND (" + " OR ".join(clauses) + ")"
            result, cap, failures = query(ctx, ["content", "query", "--uri", "content://downloads/all_downloads", "--projection", "uri:lastmod", "--where", where], timeout=6, max_bytes=65536)
            tested += 1
            if not result or not result.ok or re.search(r"(?i)(error|exception|permission|unknown column|not found)", result.text):
                break
            completed += 1
            for row in parse_download_rows(result.text, domains, since):
                key = row["domain"], row["timestamp_ms"]
                if key in seen:
                    continue
                seen.add(key)
                entry = domains[row.pop("signature_domain")]
                stamp = dt.datetime.fromtimestamp(row["timestamp_ms"] / 1000, dt.timezone.utc).isoformat()
                findings.append(ctx.finding("M5", "download", "Origem de download coincide com domínio da base", {"domain": row["domain"], "time": stamp, "signature_id": entry.get("id"), "signature_verified": entry.get("verificado") is True,
                    "limite": "Domínio não validado é apenas indício; download não comprova execução."}, "PROVÁVEL" if entry.get("verificado") else "INDÍCIO", "probable" if entry.get("verificado") else "hint", cap, time=stamp))
    all_queried = bool(domains) and len(domains) <= 80 and completed == (len(domains) + 9) // 10
    checks.append({"name": "Origens de download filtradas pelo provedor", "requires": "adb", "status": "OK" if all_queried else "PARCIAL" if completed else "NÃO VERIFICADO", "reason": "Consultas filtradas por domínio e janela, somente domínio e data retidos. Colunas/permissões variam por fabricante; limite de 80 domínios." if completed else "Provedor indisponível, acesso negado ou base sem domínios. Nenhum dump completo foi feito."})
    history_check, visits = browser_history(ctx, since, int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000))
    checks.append(history_check)
    status = "OK" if all_queried and history_check["status"] == "OK" else "PARCIAL" if completed or visits else "NÃO VERIFICADO"
    return {"module": "M5", "requires": "none", "status": status, "reason": "Origens de download e visitas na exportação são verificadas separadamente.",
            "findings": findings, "data": {"window_days": ctx.args.window_days, "provider_queries": tested, "history_visits": visits}, "checks": checks}
