import { reply, digest, canonical, webhookURL } from "./security.js";
import { decodePNG } from "./evidence.js";

// API fetch de Durable Objects: classes tradicionais permitem testes sem
// importar cloudflare:workers. O namespace é privado ao Worker.
export class Quota {
  constructor(ctx) { this.ctx = ctx; }
  async fetch(request) {
    const { limit, seconds } = await request.json();
    if (![10, 30].includes(limit) || seconds !== 60) return reply(400, "Limite inválido.");
    const now = Date.now();
    const accepted = await this.ctx.storage.transaction(async tx => {
      let state = await tx.get("quota");
      if (!state || state.until <= now) state = { count: 0, until: now + seconds * 1000 };
      if (state.count >= limit) return false;
      state.count += 1;
      await tx.put("quota", state);
      await this.ctx.storage.setAlarm(state.until + 1000);
      return true;
    });
    return reply(accepted ? 200 : 429, accepted ? "Permitido." : "Limite atingido.", accepted ? {} : { retry_after: seconds });
  }
  async alarm() {
    // Não apagar uma janela nova quando um alarme antigo vence.
    await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get("quota");
      if (state && state.until > Date.now()) await this.ctx.storage.setAlarm(state.until + 1000);
      else await this.ctx.storage.deleteAll();
    });
  }
}

export class Delivery {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
  async fetch(request) {
    const { report, expires } = await request.json();
    const fingerprint = await digest(canonical(report));
    const now = Date.now();
    const status = await this.ctx.storage.transaction(async tx => {
      const record = await tx.get("delivery");
      if (record) {
        if (record.id !== report.scan_id || record.fingerprint !== fingerprint) return "conflict";
        if (record.state === "sent") return "sent";
        if (record.state === "unknown" || (record.state === "sending" && now - record.started > 30000)) return "unknown";
        if (record.state === "sending") return "busy";
      }
      await tx.put("delivery", { id: report.scan_id, fingerprint, state: "sending", started: now, expires });
      await this.ctx.storage.setAlarm(Math.max(expires * 1000 + 600000, now + 600000));
      return "send";
    });
    if (status === "sent") return reply(200, "Relatório já recebido.", { duplicate: true });
    if (status === "conflict") return reply(409, "A sessão já está vinculada a outro relatório.");
    if (status === "busy") return reply(409, "Envio em andamento. Aguarde e repita o mesmo relatório.", { retry_after: 5 });
    if (status === "unknown") return reply(409, "Entrega incerta: confira o canal da staff antes de gerar outra sessão.", { uncertain: true });

    // O relatório e anexos existem só em memória; armazenamento guarda apenas
    // hash, ID, estado e prazo. Nunca guardamos IP, token nem conteúdo coletado.
    const form = new FormData();
    form.append("payload_json", JSON.stringify(report.payload));
    report.attachments.forEach((file, i) => {
      const content = file.content_type === "image/png" ? decodePNG(file.content) : file.content;
      form.append(`files[${i}]`, new Blob([content], { type: file.content_type }), file.filename);
    });
    let response;
    try {
      response = await fetch(webhookURL(this.env.DISCORD_WEBHOOK_URL), { method: "POST", body: form, redirect: "error", signal: AbortSignal.timeout(15000) });
    } catch {
      await this.setState("unknown");
      return reply(502, "Entrega incerta: confira o canal da staff.", { uncertain: true });
    }
    if (response.ok) {
      // Não repassar nem registrar a resposta Discord (contém dados do webhook).
      await response.body?.cancel();
      await this.setState("sent");
      return reply(200, "Relatório entregue.");
    }
    if (response.status === 429) {
      let seconds = Number(response.headers.get("Retry-After"));
      try {
        const reader = response.body?.getReader();
        if (reader) {
          const { value } = await reader.read();
          await reader.cancel();
          if (value && value.length < 4096) {
            const data = JSON.parse(new TextDecoder().decode(value));
            seconds = Number(data.retry_after) || seconds;
          }
        }
      } catch { /* Corpo remoto não é diagnóstico público. */ }
      if (!Number.isFinite(seconds) || seconds <= 0) seconds = 5;
      await this.setState("retry");
      return reply(429, "Discord solicitou uma pausa.", { retry_after: Math.min(3600, Math.max(1, seconds)) });
    }
    await response.body?.cancel();
    // Em erros de rede/5xx, não é possível garantir se o Discord aceitou.
    // Uma repetição automática poderia publicar a mesma evidência duas vezes.
    await this.setState(response.status >= 500 ? "unknown" : "retry");
    return reply(502, response.status >= 500 ? "Entrega incerta: confira o canal da staff." : "Discord recusou o envio. Verifique a configuração do relay.", { uncertain: response.status >= 500 });
  }
  async setState(state) {
    await this.ctx.storage.transaction(async tx => {
      const record = await tx.get("delivery");
      if (record) { record.state = state; await tx.put("delivery", record); }
    });
  }
  async alarm() {
    await this.ctx.blockConcurrencyWhile(async () => {
      const record = await this.ctx.storage.get("delivery");
      if (record && record.expires * 1000 + 600000 > Date.now()) await this.ctx.storage.setAlarm(record.expires * 1000 + 600000);
      else await this.ctx.storage.deleteAll();
    });
  }
}
