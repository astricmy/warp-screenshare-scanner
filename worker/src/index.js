import { CODE, createToken, MAX_BYTES, PublicError, reply, opaqueKey, verifyToken, readBoundedJSON, validateReport, webhookURL, sensitiveSignatures } from "./security.js";
export { Quota, Delivery } from "./state.js";
import { MAX_WIRE_BYTES, verifyEvidence } from "./evidence.js";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return reply(400, "HTTPS obrigatório.");
      if (!["/report", "/signatures", "/session"].includes(url.pathname) || url.search) return reply(404, "Rota inexistente.");
      const signatureRequest = url.pathname === "/signatures";
      if (request.method !== (signatureRequest ? "GET" : "POST")) return reply(405, signatureRequest ? "Use GET." : "Use POST.");
      // Verificar configuração antes de abrir contadores persistentes.
      if (!signatureRequest) webhookURL(env.DISCORD_WEBHOOK_URL);
      const ip = request.headers.get("CF-Connecting-IP");
      if (!ip) return reply(400, "Origem indisponível.");
      const ipKey = await opaqueKey(env.SESSION_SECRET, `ip:${ip}`);
      const quota = env.QUOTAS.get(env.QUOTAS.idFromName(`ip:${ipKey}`));
      const allowed = await quota.fetch("https://internal/consume", { method: "POST", body: JSON.stringify({ limit: 30, seconds: 60 }) });
      if (!allowed.ok) return reply(429, "Aguarde antes de tentar novamente.", { retry_after: 60 });
      const auth = request.headers.get("Authorization") || "";
      if (url.pathname === "/session") {
        const invite = await opaqueKey(env.SESSION_SECRET, "warp:report-invite:v1");
        // Compara HMACs de comprimento fixo sem expor o convite.
        const supplied = auth.startsWith("Invite ") ? auth.slice(7) : "";
        if (supplied.length !== invite.length ||
            await opaqueKey(env.SESSION_SECRET, supplied) !== await opaqueKey(env.SESSION_SECRET, invite))
          return reply(401, "Convite inválido.");
        const body = await readBoundedJSON(request, 256);
        if (typeof body?.code !== "string" || !CODE.test(body.code)) return reply(400, "Código inválido.");
        const shared = env.QUOTAS.get(env.QUOTAS.idFromName("auto:issuance"));
        if (!(await shared.fetch("https://internal/consume", { method: "POST", body: JSON.stringify({ limit: 10, seconds: 60 }) })).ok)
          return reply(429, "Aguarde antes de enviar.", { retry_after: 60 });
        const iat = Math.floor(Date.now() / 1000);
        const claims = { v: 1, code: body.code, iat, exp: iat + 900, nonce: crypto.randomUUID() };
        const key = await opaqueKey(env.SESSION_SECRET, "warp:report-signing:v1");
        return reply(200, "Sessão pronta.", { token: "auto." + await createToken(key, claims) });
      }
      const automatic = !signatureRequest && auth.startsWith("Bearer auto.");
      const signingKey = automatic ? await opaqueKey(env.SESSION_SECRET, "warp:report-signing:v1") : env.SESSION_SECRET;
      const claims = await verifyToken(signingKey, automatic ? auth.replace("Bearer auto.", "Bearer ") : auth);
      const codeKey = await opaqueKey(env.SESSION_SECRET, `${automatic ? "auto" : "code"}:${claims.code}`);
      const codeQuota = env.QUOTAS.get(env.QUOTAS.idFromName(`code:${codeKey}`));
      if (!(await codeQuota.fetch("https://internal/consume", { method: "POST", body: JSON.stringify({ limit: 10, seconds: 60 }) })).ok) return reply(429, "Limite da sessão atingido.", { retry_after: 60 });
      if (signatureRequest) return await sensitiveSignatures(env);
      const header = request.headers.get("X-Warp-Evidence");
      if (header !== null && header !== "png") return reply(400, "Tipo de evidência inválido.");
      const stats = {};
      const value = await readBoundedJSON(request, header ? MAX_WIRE_BYTES : MAX_BYTES, stats);
      const files = Array.isArray(value?.attachments) ? value.attachments : [];
      const imageChars = files.slice(2, 4).reduce((n, f) => n + (f?.content_type === "image/png" && typeof f.content === "string" ? f.content.length : 0), 0);
      if (stats.bytes - imageChars > MAX_BYTES) return reply(413, "Relatório textual excede 256 KiB.");
      const report = validateReport(value, claims);
      const png = report.attachments[2];
      if (Boolean(header) !== Boolean(png)) return reply(400, "Cabeçalho e anexo PNG divergentes.");
      if (png) {
        try { await verifyEvidence(report); }
        catch { return reply(400, "Imagem inválida ou divergente da prévia confirmada."); }
      }
      const delivery = env.DELIVERIES.get(env.DELIVERIES.idFromName(codeKey));
      return await delivery.fetch("https://internal/deliver", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ report, expires: claims.exp }) });
    } catch (error) {
      // Não serializar exceções: erros de fetch podem conter a URL do webhook.
      if (error instanceof PublicError) return reply(error.status, error.message);
      return reply(503, "Relay temporariamente indisponível. O relatório permanece no aparelho.");
    }
  }
};
