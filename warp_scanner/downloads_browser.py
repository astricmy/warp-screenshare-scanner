"""M5: consulta filtrada ao gerenciador de downloads; nenhum histórico completo."""
import datetime as dt
import re
from urllib.parse import urlsplit
from .roblox import query, requirements
from .safety import domain_matches, normalize_domain


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
    completed = False
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
            completed = True
            for row in parse_download_rows(result.text, domains, since):
                key = row["domain"], row["timestamp_ms"]
                if key in seen:
                    continue
                seen.add(key)
                entry = domains[row.pop("signature_domain")]
                stamp = dt.datetime.fromtimestamp(row["timestamp_ms"] / 1000, dt.timezone.utc).isoformat()
                findings.append(ctx.finding("M5", "download", "Origem de download coincide com domínio da base", {"domain": row["domain"], "time": stamp, "signature_id": entry.get("id"), "signature_verified": entry.get("verificado") is True,
                    "limite": "Domínio não validado é apenas indício; download não comprova execução."}, "PROVÁVEL" if entry.get("verificado") else "INDÍCIO", "probable" if entry.get("verificado") else "hint", cap, time=stamp))
    checks.append({"name": "Origens de download filtradas pelo provedor", "requires": "adb", "status": "PARCIAL" if completed else "NÃO VERIFICADO", "reason": "Consultas filtradas por domínio e janela, somente domínio e data retidos. Colunas/permissões variam por fabricante; limite de 80 domínios." if completed else "Provedor indisponível, acesso negado ou sem capacidade ADB/root. Nenhum dump completo foi feito."})
    checks.extend([
        {"name": "Histórico do navegador", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Conferir manualmente na call. Bancos de histórico não são copiados, pois podem conter dados pessoais fora da blocklist."},
        {"name": "Typosquatting e títulos de páginas", "requires": "root", "status": "NÃO VERIFICADO", "reason": "Sem histórico completo; correspondências aproximadas não são prova e não ampliam a coleta."},
    ])
    return {"module": "M5", "requires": "none", "status": "PARCIAL" if completed else "NÃO VERIFICADO", "reason": "Histórico não verificável: conferir manualmente na call.", "findings": findings, "data": {"window_days": ctx.args.window_days, "provider_queries": tested}, "checks": checks}
