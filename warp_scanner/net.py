"""HTTP limitado: TLS validado, sem cookies, proxy do ambiente ou redirects."""
import json
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ReleaseRedirect(NoRedirect):
    """O GitHub entrega arquivos de release por um CDN HTTPS dedicado."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        if (req.get_method() == "GET" and target.scheme == "https"
                and target.hostname in {"release-assets.githubusercontent.com","objects.githubusercontent.com"}
                and not target.username and not target.password):
            return urllib.request.Request(newurl,headers={"User-Agent":"WARP-Scanner/0.2.3"})
        return None


def request(url, data=None, headers=None, max_bytes=262144, timeout=12, release=False):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("HTTPS sem credenciais obrigatório")
    handler = ReleaseRedirect() if release and parsed.hostname=="github.com" and not headers and data is None else NoRedirect()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),handler)
    req = urllib.request.Request(url,data=data,headers={"User-Agent":"WARP-Scanner/0.2.3",**(headers or {})})
    with opener.open(req,timeout=timeout) as response:
        body = response.read(max_bytes+1)
        if len(body)>max_bytes:
            raise ValueError("Resposta excedeu limite")
        return body


def get_json(url, body=None):
    raw = request(url, None if body is None else json.dumps(body).encode(),
                  {"Content-Type":"application/json"})
    return json.loads(raw)
