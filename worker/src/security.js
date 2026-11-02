// Validações não dependem do runtime Cloudflare e são testadas com Node.
import { MAX_BASE64, MAX_AVATAR_BASE64 } from "./evidence.js";
export const MAX_BYTES = 256 * 1024;
export const BRAND = "WARP SCREENSHARE";
export const CODE = /^WARP-[A-Z0-9]{4,24}$/;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const encoder = new TextEncoder();

export class PublicError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export function reply(status, message, extra = {}) {
  const headers = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (status === 429) headers["Retry-After"] = String(Math.ceil(extra.retry_after || 60));
  return new Response(JSON.stringify({ ok: status === 200, message, ...extra }), { status, headers });
}

export function base64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function unbase64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Formato inválido");
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const result = Uint8Array.from(binary, c => c.charCodeAt(0));
  if (base64url(result) !== value) throw new Error("Formato não canônico");
  return result;
}

async function key(secret) {
  if (typeof secret !== "string" || encoder.encode(secret).length < 32) throw new PublicError(503, "Relay não configurado.");
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function digest(value) {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

export async function opaqueKey(secret, value) {
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", await key(secret), encoder.encode(value))));
}

export async function createToken(secret, claims) {
  const body = base64url(encoder.encode(JSON.stringify(claims)));
  return `${body}.${await opaqueKey(secret, body)}`;
}

function object(value, allowed, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new PublicError(400, "Estrutura inválida.");
  const keys = Object.keys(value);
  if (keys.some(k => !allowed.includes(k)) || required.some(k => !keys.includes(k))) throw new PublicError(400, "Campos inválidos.");
}

export async function verifyToken(secret, auth, now = Math.floor(Date.now() / 1000)) {
  try {
    if (typeof auth !== "string" || auth.length > 1024 || !auth.startsWith("Bearer ")) throw new Error();
    const parts = auth.slice(7).split(".");
    if (parts.length !== 2) throw new Error();
    const valid = await crypto.subtle.verify("HMAC", await key(secret), unbase64url(parts[1]), encoder.encode(parts[0]));
    if (!valid) throw new Error();
    const claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(unbase64url(parts[0])));
    object(claims, ["v", "code", "iat", "exp", "nonce"]);
    if (claims.v !== 1 || typeof claims.code !== "string" || !CODE.test(claims.code) || typeof claims.nonce !== "string" || !UUID.test(claims.nonce) || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.iat > now + 30 || claims.exp <= now || claims.exp - claims.iat < 60 || claims.exp - claims.iat > 3600) throw new Error();
    return claims;
  } catch (error) {
    if (error instanceof PublicError && error.status === 503) throw error;
    throw new PublicError(401, "Token ausente, inválido ou expirado.");
  }
}

export async function readBoundedJSON(request, limit = MAX_BYTES, stats = {}) {
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) throw new PublicError(413, "Relatório excede o limite.");
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get("content-type") || "")) throw new PublicError(415, "Envie application/json.");
  if (request.headers.get("content-encoding")) throw new PublicError(415, "Corpo comprimido não permitido.");
  if (!request.body) throw new PublicError(400, "Relatório ausente.");
  const reader = request.body.getReader();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new PublicError(413, "Relatório excede o limite."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  stats.bytes = size;
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new PublicError(400, "JSON inválido."); }
}

function text(value, max, empty = false) {
  if (typeof value !== "string" || value.length > max || (!empty && !value.length) || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) throw new PublicError(400, "Texto inválido.");
  return value;
}

function profileURL(value) {
  if (!/^https:\/\/www\.roblox\.com\/users\/[1-9]\d{0,19}\/profile$/.test(value)) throw new PublicError(400, "Perfil inválido.");
}

function richText(value, max, profile = "", footer = false) {
  text(value, max);
  if (/@(?:everyone|here)\b|<[@#][!&]?\d+>|<\/(?:[^:>]+):\d+>/i.test(value)) throw new PublicError(400, "Menção não permitida.");
  // Remover somente spans de uma linha delimitados por crases literais.
  // Nunca tratar uma crase escapada ou cerca Markdown como proteção de URL.
  if (/\\`|``/.test(value)) throw new PublicError(400, "Delimitador de código inválido.");
  let outside = value;
  if (profile) {
    outside = outside.replace(`[🔗 Perfil](${profile})`, "");
    outside = outside.replace(`[Abrir perfil](${profile})`, "");
  }
  if (footer) outside = outside.replace(/^(?:🛡️ )?WARP SCREENSHARE • https:\/\/discord\.gg\/pthFZGupmH(?= • |$)/, "");
  outside = outside.replace(/`[^`\r\n]*`/g, "");
  if (outside.includes("`")) throw new PublicError(400, "Span de código incompleto.");
  if (/[a-z][\w+.-]*:\/\/|\b(?:javascript|mailto|tel):|\bdata:[\w-]+\/|\bwww\.|\bdiscord\.gg\/|\]\s*\(/i.test(outside)) throw new PublicError(400, "Link não permitido.");
  return value.length;
}

export function validateReport(value, claims) {
  object(value, ["session_code", "scan_id", "payload", "attachments"]);
  if (value.session_code !== claims.code || typeof value.scan_id !== "string" || !UUID.test(value.scan_id)) throw new PublicError(400, "Sessão ou scan inválido.");
  object(value.payload, ["embeds", "username", "allowed_mentions"], ["embeds"]);
  if ("username" in value.payload && value.payload.username !== BRAND) throw new PublicError(400, "Marca inválida.");
  if ("allowed_mentions" in value.payload) {
    object(value.payload.allowed_mentions, ["parse"]);
    if (!Array.isArray(value.payload.allowed_mentions.parse) || value.payload.allowed_mentions.parse.length) throw new PublicError(400, "Menções não permitidas.");
  }
  if (!Array.isArray(value.payload.embeds) || value.payload.embeds.length < 1 || value.payload.embeds.length > 10) throw new PublicError(400, "Embeds inválidos.");
  let total = 0;
  const summary = value.payload.embeds[0];
  for (const embed of value.payload.embeds) {
    object(embed, ["title", "description", "url", "color", "fields", "footer", "timestamp", "thumbnail"], []);
    if ("url" in embed) {
      if (embed !== summary || typeof embed.url !== "string") throw new PublicError(400, "Perfil fora do resumo.");
      profileURL(embed.url);
    }
    if ("title" in embed) total += richText(embed.title, 256);
    if ("description" in embed) total += richText(embed.description, embed === summary ? 3800 : 4096, embed === summary ? summary.url : "");
    if ("color" in embed && (!Number.isInteger(embed.color) || embed.color < 0 || embed.color > 0xffffff)) throw new PublicError(400, "Cor inválida.");
    if ("timestamp" in embed && (typeof embed.timestamp !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(embed.timestamp) || !Number.isFinite(Date.parse(embed.timestamp)))) throw new PublicError(400, "Data inválida.");
    if ("fields" in embed) {
      if (!Array.isArray(embed.fields) || embed.fields.length > 25) throw new PublicError(400, "Campos do embed inválidos.");
      for (const field of embed.fields) {
        object(field, ["name", "value", "inline"], ["name", "value"]);
        total += richText(field.name, 256) + richText(field.value, 1024, embed === summary ? summary.url : "");
        if ("inline" in field && typeof field.inline !== "boolean") throw new PublicError(400, "Campo inline inválido.");
      }
    }
    if ("footer" in embed) { object(embed.footer, ["text"]); total += richText(embed.footer.text, 2048, "", true); }
    if ("thumbnail" in embed) {
      object(embed.thumbnail, ["url"]);
      if (embed !== summary || embed.thumbnail.url !== "attachment://avatar.png" || !summary.url) throw new PublicError(400, "Miniatura inválida.");
    }
    if (!embed.title && !embed.description && !embed.fields?.length) throw new PublicError(400, "Embed vazio.");
  }
  if (total > 6000) throw new PublicError(400, "Embeds excedem 6000 caracteres; use anexos.");
  if (!Array.isArray(value.attachments) || value.attachments.length < 2 || value.attachments.length > 4) throw new PublicError(400, "Anexos inválidos.");
  const seen = new Set();
  for (const file of value.attachments) {
    object(file, ["filename", "content", "content_type"]);
    if (file.content_type === "image/png") {
      const kind = file.filename === "avatar.png" ? "avatar" : "prova";
      if (!value.attachments.slice(2).includes(file) || seen.has(kind) ||
          (kind === "prova" && file.filename !== `prova_${value.scan_id}.png`) ||
          typeof file.content !== "string" || !file.content.length ||
          file.content.length > (kind === "avatar" ? MAX_AVATAR_BASE64 : MAX_BASE64)) throw new PublicError(400, "Anexo PNG inválido.");
      seen.add(kind);
      continue;
    }
    const extension = file.content_type === "application/json" ? "json" : file.content_type === "text/plain" ? "txt" : null;
    if (!extension || seen.has(extension) || file.filename !== `relatorio_${value.scan_id}.${extension}`) throw new PublicError(400, "Anexo inválido.");
    seen.add(extension); text(file.content, MAX_BYTES);
    if (extension === "json") {
      let report;
      try { report = JSON.parse(file.content); } catch { throw new PublicError(400, "Anexo JSON inválido."); }
      if (!report || typeof report !== "object" || Array.isArray(report) || report.scan_id !== value.scan_id || report.session_code !== value.session_code) throw new PublicError(400, "Anexo não corresponde ao scan.");
    }
  }
  if (!seen.has("json") || !seen.has("txt") || Boolean(summary.thumbnail) !== seen.has("avatar")) throw new PublicError(400, "Anexo obrigatório ou referência de avatar divergente.");
  // Defesa adicional; a minimização e redação detalhada ocorrem no scanner.
  const serialized = JSON.stringify({ ...value, attachments: value.attachments.filter(f => f.content_type !== "image/png") });
  if (/(?:_|\\u005f)\|WARNING:-DO-NOT-SHARE-THIS|https?:\/?\/?(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d+\/|Bearer\s+[A-Za-z0-9._-]{16,}|[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}/i.test(serialized)) throw new PublicError(400, "Possível segredo ou dado pessoal: revise a redação local.");
  return { session_code: value.session_code, scan_id: value.scan_id, payload: { embeds: value.payload.embeds, username: BRAND, allowed_mentions: { parse: [] } }, attachments: value.attachments };
}

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function webhookURL(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.hostname !== "discord.com" || url.port || url.username || url.password || !/^\/api\/(?:v10\/)?webhooks\/\d{10,22}\/[A-Za-z0-9_-]{20,200}$/.test(url.pathname) || url.hash || (url.search && url.search !== "?wait=true")) throw new Error();
    url.search = "?wait=true"; return url.toString();
  } catch { throw new PublicError(503, "Destino do relay não configurado."); }
}

export async function sensitiveSignatures(env) {
  const source = env.SENSITIVE_SIGNATURES_JSON;
  if (!source) return reply(404, "Base sensível não configurada.");
  try {
    if (typeof source !== "string" || encoder.encode(source).length > MAX_BYTES) throw new Error();
    const base = JSON.parse(source);
    object(base, ["schema_version", "version", "updated_at", "notice", "roblox", "proxy_mitm", "entries", "scripts"], ["schema_version", "version", "entries", "scripts"]);
    if (base.schema_version !== 1 || typeof base.version !== "string" || base.version.length > 100 || !Array.isArray(base.entries) || base.entries.length > 2000) throw new Error();
    const stringList = (values, pattern = null) => {
      if (!Array.isArray(values) || values.length > 2000 || values.some(v => typeof v !== "string" || !v.length || v.length > 1024 || (pattern && !pattern.test(v)))) throw new Error();
    };
    for (const entry of base.entries) {
      object(entry, ["id", "nome", "categoria", "plataformas", "pacotes", "rotulos", "dominios", "pastas", "arquivos", "hashes_apk", "certificados_sha256", "tokens_contextuais", "confianca", "verificado", "fonte", "atualizado_em"]);
      for (const k of ["id", "nome", "categoria", "fonte", "atualizado_em"]) text(entry[k], 1024);
      if (typeof entry.verificado !== "boolean" || !["alta", "media", "baixa"].includes(entry.confianca)) throw new Error();
      for (const k of ["plataformas", "rotulos", "dominios", "tokens_contextuais"]) stringList(entry[k]);
      stringList(entry.pacotes, /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/);
      for (const k of ["hashes_apk", "certificados_sha256"]) stringList(entry[k], /^[a-f0-9]{64}$/i);
      for (const k of ["pastas", "arquivos"]) {
        stringList(entry[k]);
        if (entry[k].some(v => v === "." || v === ".." || /[\\/\x00-\x1f]/.test(v))) throw new Error();
      }
    }
    object(base.scripts, ["funcoes_executor", "bibliotecas_gui", "ofuscadores", "hosts_script", "repos_bloqueados", "hashes_script", "urls_bloqueadas", "note"], ["funcoes_executor", "bibliotecas_gui", "ofuscadores", "hosts_script", "repos_bloqueados", "hashes_script"]);
    for (const k of ["funcoes_executor", "bibliotecas_gui", "ofuscadores", "hosts_script"]) stringList(base.scripts[k]);
    for (const k of ["repos_bloqueados", "hashes_script", "urls_bloqueadas"]) {
      if (!(k in base.scripts)) continue;
      if (!Array.isArray(base.scripts[k]) || base.scripts[k].length > 2000) throw new Error();
      for (const item of base.scripts[k]) {
        object(item, ["value", "verificado", "fonte", "atualizado_em"]);
        text(item.value, 1024); text(item.fonte, 1024); text(item.atualizado_em, 100);
        if (typeof item.verificado !== "boolean" || (k === "hashes_script" && !/^[a-f0-9]{64}$/i.test(item.value))) throw new Error();
      }
    }
    if (base.proxy_mitm !== undefined) {
      const proxy = base.proxy_mitm;
      object(proxy, ["versao", "apps", "emissores", "infraestrutura", "intervalos_roblox", "nota"], ["versao", "apps", "emissores", "infraestrutura", "intervalos_roblox"]);
      if (proxy.versao !== 1) throw new Error();
      if ("nota" in proxy) text(proxy.nota, 1024);
      for (const field of ["apps", "emissores", "infraestrutura", "intervalos_roblox"]) {
        if (!Array.isArray(proxy[field]) || proxy[field].length > 256) throw new Error();
        for (const entry of proxy[field]) {
          const key = field === "apps" ? "pacote" : "valor";
          object(entry, ["nome", key, "verificado", "fonte", "atualizado_em"]);
          text(entry.nome, 128); text(entry[key], 256); text(entry.atualizado_em, 32);
          if (typeof entry.verificado !== "boolean" || !/^https:\/\//.test(text(entry.fonte, 1024))) throw new Error();
        }
      }
    }
    if (base.roblox !== undefined) {
      object(base.roblox, ["package", "official_certificates_sha256", "source"]);
      if (base.roblox.package !== "com.roblox.client") throw new Error();
      stringList(base.roblox.official_certificates_sha256, /^[a-f0-9]{64}$/i); text(base.roblox.source, 1024);
    }
    const bytes = encoder.encode(source);
    const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(x => x.toString(16).padStart(2, "0")).join("");
    if (env.SENSITIVE_SIGNATURES_SHA256 && env.SENSITIVE_SIGNATURES_SHA256 !== hash) throw new Error();
    return new Response(bytes, { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Signatures-SHA256": hash } });
  } catch {
    return reply(503, "Base sensível indisponível ou inválida; use o fallback público.");
  }
}
