"""M11. Metadados de rede com filtros na origem e consentimento para DNS/TLS."""
import base64
import binascii
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import urlsplit

from . import net
from .roblox import PACKAGE, PACKAGE_RE, package_info, query, requirements
from .safety import read_bounded_file, redact

UNKNOWN = "NÃO VERIFICADO"
GAME_HOSTS = ("www.roblox.com", "games.roblox.com")
PROXY_PORTS = {3128, 8080, 8888, 1080, 9090}
PROFILE_TYPES = {".pac", ".ovpn", ".conf", ".crt", ".pem", ".cer", ".p12"}
SYSTEM_SH = "/system/bin/sh"
LIMIT_NOTE = ("O Python do Termux usa seu próprio conjunto de CAs e abre conexões diretas. "
              "O proxy do Wi-Fi e a política de confiança do aplicativo podem diferir. "
              "O proxy do roteador não é visível do aparelho.")

# As saídas de dumpsys nunca entram no Python. Filtros fixos exportam apenas
# configuração de proxy e propriedades de conexão. Ausência de formato reconhecido
# é diferente de uma configuração explicitamente NONE.
WIFI_FILTER = """PATH=/system/bin:/system/xbin; set -o pipefail
dumpsys wifi | awk '
/Permission Denial|Permission denied|SecurityException|Can.t find service/ {print "UNAVAILABLE"; exit}
/^[[:space:]]*Proxy settings:[[:space:]]*(STATIC|PAC|NONE|UNASSIGNED)[[:space:]]*$/ {
  mode=$NF; print "MODE " mode; next
}
(mode=="STATIC" || mode=="PAC") && /^[[:space:]]*HTTP proxy:[[:space:]]*/ {
  sub(/^[[:space:]]*HTTP proxy:[[:space:]]*/, ""); print "PROXY " substr($0,1,512); mode=""
}'"""
LINK_FILTER = """PATH=/system/bin:/system/xbin; set -o pipefail
dumpsys connectivity | awk '
/Permission Denial|Permission denied|SecurityException|Can.t find service/ {print "UNAVAILABLE"; exit}
/Active default network:[[:space:]]*[0-9]+/ {net=$NF; next}
/NetworkAgentInfo/ {chosen=(net ~ /^[0-9]+$/ && index($0,"network{" net "}")>0)}
chosen && /DnsAddresses:/ {
  dns=$0; sub(/^.*DnsAddresses:[[:space:]]*\\[/,"",dns); sub(/\\].*$/,"",dns);
  if(length(dns)<512 && dns ~ /^[0-9a-fA-F.:,\\/ \\t]*$/) print "DNS " dns
}
chosen && /HttpProxy:[[:space:]]*/ {
  p=$0; sub(/^.*HttpProxy:[[:space:]]*/,"",p); sub(/[[:space:]]+(TcpBufferSizes|Routes|Domains|MTU|CaptivePortalApiUrl|PrivateDnsActive|Nat64Prefix):.*/, "",p);
  print "PROXY " substr(p,1,350)
}'"""
ROUTE_FILTER = """PATH=/system/bin:/system/xbin; set -o pipefail
ip route show default | awk '$1=="default" && $2=="via" {print $3}'"""
LINKS_UP = """PATH=/system/bin:/system/xbin; set -o pipefail
ip -o link show up | awk -F ': ' '{n=$2; sub(/@.*/,"",n); if(n ~ /^(tun|tap|wg|ppp)[0-9]+$/) print n}'"""
TCP_FILTER = """PATH=/system/bin:/system/xbin
seen=0
for p in /proc/net/tcp /proc/net/tcp6; do
  if [ -r "$p" ]; then
    awk -v u="$1" '$8==u && $4=="01" {print $3}' "$p" || exit 2
    seen=$((seen+1))
  fi
done
[ "$seen" -gt 0 ] && echo "TABLES=$seen" """
USAGE_FILTER = """PATH=/system/bin:/system/xbin; set -o pipefail
dumpsys usagestats | awk -v p="$1" '
/Permission Denial|Permission denied|SecurityException|Can.t find service/ {denied=1; exit}
/type=(ACTIVITY_RESUMED|MOVE_TO_FOREGROUND)/ {
 found=0; for(i=1;i<=NF;i++) if($i=="package=" p) found=1;
 if(found) hit=1
} END {if(denied) print "UNAVAILABLE"; else if(hit) print "HIT"}'"""


def check(name, requires, status, reason):
    return {"name": name, "requires": requires, "status": status, "reason": reason}


def _read(ctx, argv, max_bytes=4096):
    result, cap, _ = query(ctx, argv, timeout=4, max_bytes=max_bytes)
    return (result.text.strip() if result.ok else None), cap


def _setting(ctx, namespace, key):
    value, _ = _read(ctx, ["settings", "get", namespace, key])
    if value in ("null", "None", ""):
        return ""
    return value


def _filtered(ctx, script, *args, max_bytes=8192):
    # Les données variables entrent exclusivement comme arguments positionnels.
    value, cap = _read(ctx, [SYSTEM_SH, "-c", script, "warp", *args], max_bytes)
    if value is not None and "UNAVAILABLE" in value.splitlines():
        return None, cap
    return value, cap


def _ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _hostname(host):
    if not host or any(c in host for c in "@?#/\\%") or len(host) > 253:
        return None
    address = _ip(host)
    if address:
        return str(address)
    try:
        canonical = host.rstrip(".").encode("idna").decode().lower()
    except (ValueError, UnicodeError):
        return None
    if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in canonical.split(".")):
        return canonical
    return None


def parse_proxy(raw, mode="STATIC", port=None):
    """Só a origem do proxy/PAC é serializada. Descartar caminho evita tokens em URLs."""
    if not raw or raw in (":0", "null", "None", "[null]", "0", "[]"):
        return None
    raw = raw.strip()
    # Formato ProxyInfo.toString: [host] port xl=... ou PAC Script: URL.
    pac = re.match(r"(?i)PAC Script:\s*(https?://\S+)", raw)
    wrapped = re.match(r"^\[([^\]]+)\]\s*(?::|\s)\s*(\d+)(?:\s|$)", raw)
    if pac:
        raw, mode = pac.group(1), "PAC"
    elif wrapped:
        raw, port = wrapped.group(1), wrapped.group(2)
    try:
        if "://" not in raw and _ip(raw) and ":" in raw:
            raw = "[" + raw + "]"
        parsed = urlsplit(raw if "://" in raw else "//" + raw)
        if parsed.scheme not in ("", "http", "https", "socks", "socks5"):
            return None
        host = _hostname(parsed.hostname)
        number = parsed.port or (int(port) if port else None)
        if not host or (number is not None and not 1 <= number <= 65535):
            return None
    except (UnicodeError, ValueError):
        return None
    address = _ip(host)
    scope = ("público" if address.is_global else "local ou reservado") if address else "hostname; alcance não verificado"
    return {"modo": mode, "host": host, "porta": number, "alcance": scope}


def _proxy_config(ctx):
    fields = ("http_proxy", "global_http_proxy_host", "global_http_proxy_port",
              "global_http_proxy_exclusion_list", "global_proxy_pac_url")
    values = {key: _setting(ctx, "global", key) for key in fields}
    record = (parse_proxy(values["global_proxy_pac_url"], "PAC")
              or parse_proxy(values["global_http_proxy_host"], port=values["global_http_proxy_port"])
              or parse_proxy(values["http_proxy"]))
    raw_forms = [values[key] for key in ("global_proxy_pac_url", "global_http_proxy_host", "http_proxy")]
    malformed = not record and any(raw and raw not in (":0", "0", "[]") for raw in raw_forms)
    specific = sum(value is not None for value in values.values())
    status = "OK" if specific == len(fields) and not malformed else ("PARCIAL" if specific else UNKNOWN)
    count = len([item for item in (values["global_http_proxy_exclusion_list"] or "").split(",") if item.strip()])
    return {"configuracao": record, "exclusoes": count if values["global_http_proxy_exclusion_list"] is not None else None}, status


def parse_wifi(text):
    records, mode, known = [], None, False
    for line in (text or "").splitlines():
        if line.startswith("MODE ") and line[5:] in ("PAC", "STATIC", "NONE", "UNASSIGNED"):
            known, mode = True, line[5:]
            if mode in ("PAC", "STATIC"):
                records.append({"local": f"Configurações › Wi-Fi › rede salva #{len(records) + 1} › Proxy", "modo": mode})
        elif mode in ("STATIC", "PAC") and line.startswith("PROXY "):
            detail = parse_proxy(line[6:], mode)
            if detail:
                records[-1].update(detail)
            mode = None
    return records, known


def _net_config(ctx, data, checks):
    data["proxy_global"], proxy_status = _proxy_config(ctx)
    checks.append(check("Proxy global e PAC", "none", proxy_status, "Cinco chaves consultadas. Exclusões são representadas apenas pela quantidade."))
    wifi, _ = _filtered(ctx, WIFI_FILTER)
    saved, known = parse_wifi(wifi)
    data["proxy_wifi"] = saved
    full = known and all(item.get("host") for item in saved)
    checks.append(check("Proxy de redes Wi-Fi salvas", "adb", "OK" if full else "PARCIAL" if known else UNKNOWN,
                        "Somente registros STATIC/PAC. Ausência de campos ou dump redigido limita a cobertura."))
    link, _ = _filtered(ctx, LINK_FILTER)
    dns, active_proxy = [], None
    for line in (link or "").splitlines():
        if line.startswith("DNS "):
            for word in re.split(r"[,/ \t]+", line[4:]):
                if _ip(word) and word not in dns:
                    dns.append(word)
        if line.startswith("PROXY "):
            active_proxy = parse_proxy(line[6:])
    data["proxy_conexao_ativa"] = active_proxy
    dns_mode = _setting(ctx, "global", "private_dns_mode")
    specifier = _setting(ctx, "global", "private_dns_specifier") if dns_mode == "hostname" else ""
    data["dns"] = {"modo_privado": dns_mode if dns_mode in ("off", "opportunistic", "hostname") else "padrão" if dns_mode == "" else UNKNOWN,
                   "hostname": _hostname(specifier), "servidores_atuais": dns[:8]}
    route, _ = _filtered(ctx, ROUTE_FILTER)
    data["gateway"] = next((str(_ip(line)) for line in (route or "").splitlines() if _ip(line)), None)
    checks.append(check("DNS privado", "none", "OK" if dns_mode is not None and (dns_mode != "hostname" or _hostname(specifier)) else UNKNOWN,
                        "Modo e hostname de settings global."))
    checks.append(check("DNS e gateway da conexão atual", "adb", "OK" if dns and data["gateway"] else ("PARCIAL" if dns or data["gateway"] else UNKNOWN),
                        "DNS somente da rede padrão identificada pelo Android e gateway da rota default visível."))
    iface, _ = _filtered(ctx, LINKS_UP)
    names = sorted({v for v in (iface or "").splitlines() if re.fullmatch(r"(?:tun|tap|wg|ppp)\d+", v)})
    owner = _setting(ctx, "secure", "always_on_vpn_app")
    data["vpn"] = {"interfaces_ativas": names[:12], "sempre_ativa": bool(owner) if owner is not None else None,
                   "pacote_sempre_ativa": owner if owner and PACKAGE_RE.fullmatch(owner) else None}
    checks.append(check("Túneis ativos e VPN permanente", "none", "OK" if iface is not None and owner is not None else ("PARCIAL" if iface is not None or owner is not None else UNKNOWN),
                        "A configuração permanente informa o pacote configurado. Uma interface UP evidencia o estado no instante da consulta."))


def decode_endpoint(value):
    try:
        host, raw_port = value.split(":")
        if not re.fullmatch(r"(?:[A-Fa-f0-9]{8}|[A-Fa-f0-9]{32})", host) or not re.fullmatch(r"[A-Fa-f0-9]{4}", raw_port):
            return None
        # tcp6 apresenta quatro palavras de 32 bits na ordem nativa do kernel.
        packed = b"".join(int(host[i:i+8], 16).to_bytes(4, sys.byteorder) for i in range(0, len(host), 8))
        address = ipaddress.ip_address(packed)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address, int(raw_port, 16)
    except (TypeError, ValueError):
        return None


def _validated(config, key):
    return [row for row in config.get(key, []) if isinstance(row, dict) and row.get("verificado") is True
            and isinstance(row.get("fonte"), str) and row["fonte"].startswith("https://")][:64]


def _game_endpoints(ctx, config):
    required = requirements(ctx)
    if required == "none":
        return [], UNKNOWN, "Requer ADB local ou root."
    pids, _ = _read(ctx, ["pidof", PACKAGE])
    if not re.fullmatch(r"\d+(?:\s+\d+)*", pids or ""):
        return [], UNKNOWN, "Roblox fechado ou PID indisponível. Abra o jogo antes do scan."
    output, _ = _read(ctx, ["pm", "list", "packages", "-U", PACKAGE])
    match = re.search(r"(?m)^package:com\.roblox\.client\s+uid:([0-9]{1,9})\s*$", output or "")
    if not match:
        return [], UNKNOWN, "Android não expôs o UID do pacote."
    uid = match.group(1)
    packages, _ = _read(ctx, ["cmd", "package", "list", "packages", "--uid", uid])
    if (packages or "").strip() != "package:" + PACKAGE:
        return [], UNKNOWN, "Não foi possível comprovar que o UID pertence exclusivamente ao Roblox."
    text, _ = _filtered(ctx, TCP_FILTER, uid, max_bytes=16384)
    if text is None or "TABLES=" not in text:
        return [], UNKNOWN, "As tabelas TCP por UID ficaram inacessíveis."
    endpoints = [endpoint for line in text.splitlines() if (endpoint := decode_endpoint(line))]
    counts = Counter(address for address, _ in endpoints)
    ranges = []
    for row in _validated(config, "intervalos_roblox"):
        try:
            ranges.append(ipaddress.ip_network(row.get("valor", "")))
        except ValueError:
            pass
    found = []
    stamp = datetime.now(timezone.utc).isoformat()
    for address, port in sorted(set(endpoints), key=lambda x: (str(x[0]), x[1])):
        reasons = []
        if not address.is_global:
            reasons.append("endereço local/reservado")
        if port in PROXY_PORTS:
            reasons.append("porta também usada por proxies")
        if counts[address] > 1 and ranges and not any(address.version == subnet.version and address in subnet for subnet in ranges):
            reasons.append("destino repetido fora da referência validada")
        if reasons:
            found.append({"ip": str(address), "porta": port, "time": stamp, "motivos": reasons})
    note = "Somente sockets TCP estabelecidos com UID exclusivo do Roblox. UDP/QUIC não é observado."
    if not ranges:
        note += " Não há intervalos oficiais validados para afirmar desvios por faixa."
    return found[:16], ("OK" if "TABLES=2" in text else "PARCIAL"), note

def _certificate_meta(contents):
    """Lê somente certificados públicos e reduz o resultado a emissor + início."""
    if not contents or len(contents) > 65536:
        return None
    form = "PEM" if contents.startswith(b"-----BEGIN CERTIFICATE-----") else "DER"
    if form == "PEM" and not re.fullmatch(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*", contents):
        return None
    if form == "DER":
        # Exigir uma única estrutura ASN.1 de comprimento definido, sem bytes anexos.
        if len(contents) < 4 or contents[0] != 48:
            return None
        length = contents[1]
        if length < 128:
            size, offset = length, 2
        else:
            octets = length & 127
            if not 1 <= octets <= 3:
                return None
            size, offset = int.from_bytes(contents[2:2+octets], "big"), 2+octets
        if offset + size != len(contents):
            return None
    try:
        proc = subprocess.run(["openssl", "x509", "-inform", form, "-noout", "-issuer", "-startdate", "-nameopt", "RFC2253"],
                              input=contents, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode or len(proc.stdout) > 8192:
        return None
    text = proc.stdout.decode("utf-8", "replace")
    issuer = re.search(r"(?:^issuer=\s*|,)(?:CN)=([^,\r\n]{1,200})", text, re.M)
    if not issuer:
        issuer = re.search(r"(?:^issuer=\s*|,)O=([^,\r\n]{1,200})", text, re.M)
    date = re.search(r"(?m)^notBefore=([A-Za-z0-9 :+-]{8,40})$", text)
    if not issuer:
        return None
    return {"emissor": redact(issuer.group(1), 100), "valida_desde": date.group(1) if date else None}


def _user_ca(ctx):
    required = requirements(ctx)
    if required == "none":
        return [], UNKNOWN
    user, _ = _read(ctx, ["am", "get-current-user"])
    if not re.fullmatch(r"[0-9]{1,5}", user or ""):
        return [], UNKNOWN
    # Ambos os locais são trust stores do Android, nunca o Keystore do usuário.
    locations = ["/data/misc/user/" + user + "/cacerts-added"]
    if user == "0":
        locations.append("/data/misc/keychain/cacerts-added")
    read_names = r"""PATH=/system/bin:/system/xbin
d="$1"; [ ! -L "$d" ] && [ -d "$d" ] && [ -r "$d" ] && [ -x "$d" ] || exit 2
for f in "$d"/*; do [ -f "$f" ] && [ ! -L "$f" ] && basename "$f"; done
exit 0"""
    read_cert = r"""PATH=/system/bin:/system/xbin
f="$1"; [ ! -L "$f" ] && [ -f "$f" ] && [ "$(stat -c %s "$f")" -le 32768 ] || exit 2
base64 "$f" """
    observed, result, errors = False, [], False
    for directory in locations:
        names, _ = _filtered(ctx, read_names, directory)
        if names is None:
            continue
        observed = True
        paths = [name for name in names.splitlines() if re.fullmatch(r"[a-fA-F0-9]{8}\.[0-9]{1,3}", name)]
        errors |= len(paths) > 16
        for name in paths[:16]:
            encoded, _ = _filtered(ctx, read_cert, directory + "/" + name, max_bytes=49152)
            try:
                cert = base64.b64decode("".join((encoded or "").split()), validate=True)
                detail = _certificate_meta(cert)
            except (ValueError, binascii.Error):
                detail = None
            if detail and detail not in result:
                result.append(detail)
            errors |= detail is None
        break
    return result, ("PARCIAL" if errors else "OK") if observed else UNKNOWN


def _apps(ctx, config):
    output = []
    targets = _validated(config, "apps")[:8]
    tested, complete = 0, 0
    for row in targets:
        package = row.get("pacote")
        if not isinstance(package, str) or not PACKAGE_RE.fullmatch(package):
            continue
        info = package_info(ctx, package)
        if not info.get("verified"):
            continue
        tested += 1
        base = {"ferramenta": str(row.get("nome", package))[:80], "pacote": package}
        if info.get("present"):
            output.append({**base, "estado": "instalado", "fonte": "dumpsys package"})
            complete += 1
            continue
        if requirements(ctx) != "none":
            result, _ = _filtered(ctx, USAGE_FILTER, package)
            if result == "HIT":
                output.append({**base, "estado": "ausente com atividade registrada", "fonte": "evento de primeiro plano filtrado por pacote"})
                complete += 1
                continue
            residual, _ = _read(ctx, ["pm", "list", "packages", "-u", package])
            if f"package:{package}" in (residual or "").splitlines():
                output.append({**base, "estado": "registro residual sem instalação ativa", "fonte": "pm -u; remoção não comprovada"})
            if result is not None:
                complete += 1
    status = "OK" if targets and complete == len(targets) else "PARCIAL" if tested else UNKNOWN
    return output, status


def _profiles(ctx):
    rows, errors = [], False
    for item in ctx.files:
        path = Path(item)
        suffix = path.suffix.lower()
        if suffix not in PROFILE_TYPES:
            continue
        # .conf é uma extensão genérica: requer contexto WireGuard no nome/caminho.
        if suffix == ".conf" and not (re.fullmatch(r"wg[0-9]+\.conf", path.name, re.I) or "wireguard" in str(path.relative_to(ctx.storage)).casefold()):
            continue
        try:
            relative = path.relative_to(ctx.storage).as_posix()
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != ctx.storage.parent):
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            row = {"path": redact(relative, 350), "tipo": suffix, "tamanho": info.st_size,
                   "mtime": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
                   "ctime": datetime.fromtimestamp(info.st_ctime, timezone.utc).isoformat()}
            # Perfis VPN podem conter chaves privadas. Só hashear certificados
            # públicos .crt/.cer reconhecidos, de tamanho limitado.
            if suffix in (".crt", ".cer") and info.st_size <= 65536 and ctx.consent.get("files"):
                raw, _ = read_bounded_file(path, ctx.storage, 65536)
                if _certificate_meta(raw):
                    row["sha256"] = hashlib.sha256(raw).hexdigest()
            rows.append(row)
        except (OSError, ValueError, OverflowError):
            errors = True
        if len(rows) >= 25:
            errors = True
            break
    stats = getattr(ctx, "file_stats", {})
    return rows, "PARCIAL" if errors or stats.get("limited") or stats.get("errors") else "OK"


def _system_addresses(ctx, host):
    # getaddrinfo não oferece timeout no Python. O subprocesso limitado garante o prazo.
    script = ("import socket,sys; print('\\n'.join(sorted({str(r[4][0]) for r in "
              "socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)})))")
    result = ctx.run([sys.executable, "-I", "-B", "-c", script, host], timeout=5, max_bytes=2048)
    return {_ip(v) for v in result.text.splitlines() if _ip(v)} if result.ok else set()


def _doh_addresses(host, family):
    # Google recebe exclusivamente o domínio predefinido, sem conta e sem ECS.
    url = "https://dns.google/resolve?name=" + host + "&type=" + family + "&edns_client_subnet=0.0.0.0%2F0"
    reply = json.loads(net.request(url, max_bytes=32768, timeout=4))
    if reply.get("Status") != 0:
        raise ValueError("Resposta DoH indisponível")
    return {a for item in reply.get("Answer", []) if item.get("type") == (1 if family == "A" else 28)
            and (a := _ip(item.get("data", "")))}


def _tls(address, host):
    def handshake(context):
        with socket.create_connection((str(address), 443), timeout=4) as tcp:
            with context.wrap_socket(tcp, server_hostname=host) as channel:
                return channel.getpeercert(), channel.getpeercert(binary_form=True)
    try:
        cert, _ = handshake(ssl.create_default_context())
        fields = dict(pair for group in cert.get("issuer", ()) for pair in group)
        issuer = fields.get("commonName") or fields.get("organizationName")
        return {"confianca": "validada", "emissor": redact(issuer, 100) if issuer else None}
    except ssl.SSLCertVerificationError as err:
        # Nova conexão sem transmitir dados de aplicação, exclusivamente para
        # identificar o emissor público do certificado que não passou na validação.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        meta = {}
        try:
            _, der = handshake(context)
            meta = _certificate_meta(der) or {}
        except (OSError, ssl.SSLError):
            pass
        return {"confianca": "falha na validação", "codigo_verificacao": err.verify_code, "emissor": meta.get("emissor")}


def _active_tests(ctx, config):
    if not ctx.consent.get("network_tests"):
        return [], UNKNOWN, []
    rows, issues = [], []
    issuers = {v["valor"].strip().casefold() for v in _validated(config, "emissores") if isinstance(v.get("valor"), str)}
    done = 0
    for host in GAME_HOSTS:
        system = _system_addresses(ctx, host)
        doh, complete = set(), True
        for family in ("A", "AAAA"):
            try:
                doh.update(_doh_addresses(host, family))
            except (OSError, ValueError, TypeError, AttributeError):
                complete = False
        row = {"dominio": host, "dns_sistema": [str(v) for v in sorted(system, key=str)][:12],
               "dns_doh": [str(v) for v in sorted(doh, key=str)][:12], "doh_completo": complete}
        if any(not ip.is_global for ip in system):
            issues.append(("DNS retornou endereço local/reservado para domínio público", {"dominio": host}, "INDÍCIO", "network_dns"))
        if system and doh and complete and system.isdisjoint(doh):
            issues.append(("Conjuntos DNS sem endereço em comum", {"dominio": host, "limite": "CDNs e resolvedores regionais podem retornar respostas legítimas diferentes."}, "INDÍCIO", "network_dns"))
        destination = next((ip for ip in sorted(system, key=lambda v: (v.version, str(v))) if ip.is_global), None)
        if destination:
            try:
                row["tls"] = _tls(destination, host)
            except (OSError, ssl.SSLError):
                pass
        tls = row.get("tls", {})
        issuer = tls.get("emissor")
        if issuer and issuer.casefold() in issuers:
            issues.append(("Nome do emissor TLS coincide com ferramenta de interceptação", {"dominio": host, "emissor": issuer, "limite": "Correspondência de nome na sonda do Termux; não atesta o fluxo do jogo."}, "CONFIRMADO", "network_known"))
        elif tls.get("confianca") == "falha na validação":
            issues.append(("Cadeia TLS não foi validada pelo Termux", {"dominio": host, "emissor": issuer, "limite": "CA privada, certificado expirado ou cadeia incompleta são explicações possíveis."}, "INDÍCIO", "hint"))
        if system and doh and complete and issuer:
            done += 1
        rows.append(row)
    return rows, "OK" if done == len(GAME_HOSTS) else ("PARCIAL" if any(r["dns_sistema"] or r["dns_doh"] or r.get("tls") for r in rows) else UNKNOWN), issues


def _known_proxy(host, config):
    for item in _validated(config, "infraestrutura"):
        value = item.get("valor")
        if not isinstance(value, str):
            continue
        if item.get("tipo") == "host" and _hostname(value) == host:
            return True
        if item.get("tipo") == "ip" and _ip(value) and _ip(host) == _ip(value):
            return True
    return False


def collect(ctx):
    data, checks, findings = {}, [], []
    config = ctx.signatures.get("proxy_mitm", {})
    _net_config(ctx, data, checks)
    data["ca_usuario"], ca_status = _user_ca(ctx)
    checks.append(check("CAs do usuário Android atual", "adb", ca_status, "Somente emissor e início de validade, até 16 certificados. Na call, confira Configurações › Segurança › Credenciais."))
    data["apps_de_rede"], app_status = _apps(ctx, config)
    checks.append(check("Apps e uso anterior de ferramentas de rede", "none", app_status, "Apenas pacotes validados pela base. Registros residuais isolados não comprovam remoção."))
    data["perfis_rede"], file_status = _profiles(ctx)
    checks.append(check("Perfis nas pastas autorizadas", "none", file_status, "Somente metadados. SHA-256 disponível para .cer/.crt públicos reconhecidos com permissão de arquivos."))
    data["endpoints_roblox"], socket_status, socket_note = _game_endpoints(ctx, config)
    checks.append(check("Conexões TCP com UID exclusivo do Roblox", "adb", socket_status, socket_note))
    data["validacao_ativa"], active_status, active_issues = _active_tests(ctx, config)
    checks.append(check("Comparação DNS/DoH e emissor TLS", "none", active_status, LIMIT_NOTE if ctx.consent.get("network_tests") else "Testes ativos recusados. " + LIMIT_NOTE))
    data["limites"] = LIMIT_NOTE

    def add(title, evidence, level="INDÍCIO", weight="hint", required="none"):
        findings.append(ctx.finding("M11", "rede", title, evidence, level, weight, required))

    global_proxy = data["proxy_global"]["configuracao"]
    proxies = [(global_proxy, "Configurações › Rede › Proxy global"), (data["proxy_conexao_ativa"], "Configurações › Conexão atual › Proxy")]
    proxies.extend((row, row["local"]) for row in data["proxy_wifi"])
    seen = set()
    for proxy, where in proxies:
        if not proxy:
            continue
        host = proxy.get("host", "")
        key = (host, proxy.get("porta"), proxy.get("modo"))
        if key in seen:
            continue
        seen.add(key)
        evidence = {**proxy, "local": where}
        if host and _known_proxy(host, config):
            add("Origem de proxy/PAC coincide com infraestrutura validada", evidence, "CONFIRMADO", "network_known")
        elif proxy.get("alcance") == "público":
            add("Proxy/PAC configurado para IP público", evidence, "PROVÁVEL", "network_proxy")
        else:
            add("Proxy/PAC configurado", evidence)
    vpn = data["vpn"]
    if vpn["interfaces_ativas"]:
        add("Interface de túnel ativa", {**vpn, "local": "Configurações › Rede › VPN"}, weight="network_vpn")
    if data["dns"]["modo_privado"] == "hostname":
        add("DNS privado personalizado", {"hostname": data["dns"]["hostname"], "local": "Configurações › Rede › DNS privado"}, weight="network_dns")
    has_active_proxy = bool(global_proxy or data["proxy_conexao_ativa"])
    if data["ca_usuario"] and (has_active_proxy or vpn["interfaces_ativas"]):
        add("CA de usuário junto de proxy ou túnel ativo", {"certificados": len(data["ca_usuario"]), "local": "Configurações › Segurança › Credenciais", "limite": "Uma CA instalada pode não participar da conexão."}, "PROVÁVEL", "network_ca_proxy")
    for app in data["apps_de_rede"]:
        residual = app["estado"].startswith("registro residual")
        add("Ferramenta de rede na consulta de pacotes", {**app, "local": "Configurações › Apps"}, level="INDÍCIO" if residual else "PROVÁVEL", weight="hint" if residual else "network_app")
    for title, evidence, level, weight in active_issues:
        add(title, evidence, level, weight)
    if data["endpoints_roblox"]:
        add("Destino TCP do Roblox com característica de proxy ou rede local", {"endpoints": data["endpoints_roblox"], "local": "Sockets TCP › UID exclusivo do Roblox"}, required=requirements(ctx))
    profiles = [p for p in data["perfis_rede"] if p["tipo"] in (".pac", ".ovpn")]
    if profiles and findings:
        add("Perfil PAC/VPN junto de outro indicador de rede", {"perfis": profiles[:5]}, weight="network_profile")
    vpn_state = "túnel ativo" if vpn["interfaces_ativas"] else "permanente configurada" if vpn["sempre_ativa"] else "sem túnel observado"
    data["resumo"] = (f"Proxy/PAC: {len(seen)} configuração(ões) observada(s) • VPN: {vpn_state} • "
                      f"DNS: {data['dns']['modo_privado']} • CAs: {len(data['ca_usuario']) if ca_status == 'OK' else ca_status}")
    status = "OK" if all(row["status"] == "OK" for row in checks) else ("PARCIAL" if any(row["status"] != UNKNOWN for row in checks) else UNKNOWN)
    return {"module": "M11", "requires": "none", "status": status, "reason": "Metadados de configuração e conexão. Ferramentas de rede também têm usos legítimos.",
            "data": data, "checks": checks, "findings": findings}
