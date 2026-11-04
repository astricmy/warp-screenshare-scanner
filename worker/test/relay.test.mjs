import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto, createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createToken, verifyToken, validateReport, readBoundedJSON, webhookURL, sensitiveSignatures, MAX_BYTES, PublicError } from "../src/security.js";
import { Quota, Delivery } from "../src/state.js";
import worker from "../src/index.js";
globalThis.crypto ??= webcrypto;

// Valores sintéticos: não são credenciais de nenhum serviço real.
const secret = "TESTE-LOCAL-SEM-ACESSO-A-SERVICOS-0000000000";
const code = "WARP-TESTE";
const id = "12345678-1234-4123-8123-123456789abc";
const claims = () => ({ v: 1, code, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 900, nonce: id });
const webhook = () => "https://discord.com/api/" + "webhooks/" + "123456789012345678/" + "X".repeat(30);
function report() {
  return {
    scan_id: id, session_code: code,
    payload: { embeds: [{ title: "WARP SCREENSHARE", description: "Dados fictícios", url: "https://www.roblox.com/users/123/profile", footer: { text: "WARP SCREENSHARE" }, fields: [{ name: "Cobertura", value: "Parcial", inline: false }], timestamp: new Date().toISOString() }] },
    attachments: [
      { filename: `relatorio_${id}.json`, content_type: "application/json", content: JSON.stringify({ scan_id: id, session_code: code }) },
      { filename: `relatorio_${id}.txt`, content_type: "text/plain", content: "WARP SCREENSHARE\nDados fictícios" }
    ]
  };
}

class Storage {
  constructor() { this.data = new Map(); this.queue = Promise.resolve(); this.alarm = null; }
  async get(k) { return structuredClone(this.data.get(k)); }
  async put(k, v) { this.data.set(k, structuredClone(v)); }
  async setAlarm(v) { this.alarm = v; }
  async deleteAll() { this.data.clear(); this.alarm = null; }
  transaction(fn) {
    const run = this.queue.then(() => fn({ get: this.get.bind(this), put: this.put.bind(this) }));
    this.queue = run.catch(() => {}); return run;
  }
}
function context() { const storage = new Storage(); return { storage, blockConcurrencyWhile: fn => storage.transaction(fn) }; }
function namespace(Class, env) {
  const objects = new Map();
  return {
    objects, idFromName: name => name,
    get(name) {
      if (!objects.has(name)) objects.set(name, new Class(context(), env));
      return { fetch: (url, init) => objects.get(name).fetch(new Request(url, init)) };
    }
  };
}
function environment() {
  const env = { SESSION_SECRET: secret, DISCORD_WEBHOOK_URL: webhook() };
  env.QUOTAS = namespace(Quota, env); env.DELIVERIES = namespace(Delivery, env);
  return env;
}
function deliveryRequest(data = report(), exp = claims().exp) { return new Request("https://internal/deliver", { method: "POST", body: JSON.stringify({ report: validateReport(data, claims()), expires: exp }) }); }
async function request(data = report(), options = {}) {
  return new Request("https://relay.invalid/report", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "192.0.2.1", Authorization: `Bearer ${await createToken(secret, claims())}`, ...options.headers }, body: JSON.stringify(data) });
}

test("token HMAC válido vincula código e expiração", async () => {
  const c = claims(); const token = await createToken(secret, c);
  assert.deepEqual(await verifyToken(secret, `Bearer ${token}`), c);
});
test("token adulterado é rejeitado", async () => {
  const token = await createToken(secret, claims());
  await assert.rejects(verifyToken(secret, `Bearer x${token}`), e => e.status === 401);
});
test("token expirado e validade excessiva são rejeitados", async () => {
  for (const c of [{ ...claims(), iat: 100, exp: 1000 }, { ...claims(), exp: claims().iat + 3601 }]) {
    await assert.rejects(verifyToken(secret, `Bearer ${await createToken(secret, c)}`), e => e.status === 401);
  }
});
test("código público sozinho não autoriza envio", async () => {
  await assert.rejects(verifyToken(secret, `Bearer ${code}`), e => e.status === 401);
});
test("secreto curto falha fechado", async () => {
  await assert.rejects(createToken("curto", claims()), e => e.status === 503);
});
test("payload válido fixa marca e bloqueia menções", () => {
  const result = validateReport(report(), claims());
  assert.equal(result.payload.username, "WARP SCREENSHARE");
  assert.deepEqual(result.payload.allowed_mentions, { parse: [] });
});
test("rejeita campos desconhecidos, menções e conteúdo arbitrário no payload", () => {
  for (const modify of [r => r.extra = true, r => r.payload.content = "@everyone", r => r.payload.allowed_mentions = { parse: ["everyone"] }, r => r.payload.embeds[0].author = { name: "x" }]) {
    const r = report(); modify(r); assert.throws(() => validateReport(r, claims()), PublicError);
  }
});
test("rejeita anexos de outro scan, traversal e duplicação", () => {
  for (const modify of [r => r.attachments[0].filename = "../secret.json", r => r.attachments[0].content = "{}", r => r.attachments[1] = r.attachments[0], r => r.session_code = "WARP-OUTRO"]) {
    const r = report(); modify(r); assert.throws(() => validateReport(r, claims()), PublicError);
  }
});
test("rejeita limite individual e agregado Discord", () => {
  const a = report(); a.payload.embeds[0].fields[0].value = "x".repeat(1025);
  assert.throws(() => validateReport(a, claims()), PublicError);
  const b = report(); b.payload.embeds = [{ description: "x".repeat(4000) }, { description: "x".repeat(2001) }];
  assert.throws(() => validateReport(b, claims()), PublicError);
});
test("URL de perfil e miniatura não permitem hosts arbitrários", () => {
  for (const url of ["https://evil.invalid/", "https://www.roblox.com.evil.invalid/users/1/profile", "javascript:alert(1)"]) {
    const r = report(); r.payload.embeds[0].url = url; assert.throws(() => validateReport(r, claims()));
  }
  const r = report(); r.payload.embeds[0].thumbnail = { url: "https://tr.rbxcdn.com/avatar.png" };
  assert.throws(() => validateReport(r, claims()));
  r.payload.embeds[0].thumbnail.url = "https://rbxcdn.com.evil.invalid/a";
  assert.throws(() => validateReport(r, claims()));
});
test("defesa adicional rejeita possíveis credenciais e e-mail", () => {
  for (const sample of ["nome@example.invalid", "_|WARNING:-DO-NOT-SHARE-THIS" + "-fake", "Bearer " + "A".repeat(30), webhook()]) {
    const r = report(); r.attachments[1].content = sample; assert.throws(() => validateReport(r, claims()));
  }
});
test("leitura limitada não confia no Content-Length", async () => {
  const req = new Request("https://relay.invalid", { method: "POST", headers: { "content-type": "application/json" }, body: new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(MAX_BYTES)); controller.enqueue(new Uint8Array(1)); controller.close(); } }), duplex: "half" });
  await assert.rejects(readBoundedJSON(req), e => e.status === 413);
});
test("UTF-8 inválido e tipo de corpo inválido são recusados", async () => {
  await assert.rejects(readBoundedJSON(new Request("https://x.invalid", { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([0xff]) })), e => e.status === 400);
  await assert.rejects(readBoundedJSON(new Request("https://x.invalid", { method: "POST", body: "{}" })), e => e.status === 415);
});
test("webhook aceita apenas HTTPS Discord canônico com wait=true", () => {
  assert.ok(webhookURL(webhook()).endsWith("?wait=true"));
  for (const url of [webhook().replace("https:", "http:"), webhook().replace("discord.com", "discord.com.evil.invalid"), webhook() + "?thread_id=1", webhook().replace("discord.com", "evil@discord.com")]) assert.throws(() => webhookURL(url));
});
test("quota atômica limita chamadas concorrentes", async () => {
  const q = new Quota(context());
  const responses = await Promise.all(Array.from({ length: 50 }, () => q.fetch(new Request("https://internal/consume", { method: "POST", body: JSON.stringify({ limit: 10, seconds: 60 }) }))));
  assert.equal(responses.filter(r => r.status === 200).length, 10);
});
test("entrega repetida do mesmo scan é idempotente", async t => {
  let calls = 0; t.mock.method(globalThis, "fetch", async (_url, init) => { calls++; assert.equal(init.redirect, "manual"); const payload = JSON.parse(init.body.get("payload_json")); assert.deepEqual(payload.allowed_mentions, { parse: [] }); return new Response("{}", { status: 200 }); });
  const d = new Delivery(context(), environment()); const data = report();
  assert.equal((await d.fetch(deliveryRequest(data))).status, 200);
  const second = await d.fetch(deliveryRequest(data)); assert.equal(second.status, 200); assert.equal((await second.json()).duplicate, true); assert.equal(calls, 1);
  data.payload.embeds[0].description = "outro";
  assert.equal((await d.fetch(deliveryRequest(data))).status, 409);
});
test("corrida de entregas não duplica postagem", async t => {
  let calls = 0, release;
  t.mock.method(globalThis, "fetch", () => { calls++; return new Promise(resolve => { release = () => resolve(new Response("{}")); }); });
  const d = new Delivery(context(), environment()); const data = report();
  const first = d.fetch(deliveryRequest(data));
  while (!release) await new Promise(resolve => setImmediate(resolve));
  assert.equal((await d.fetch(deliveryRequest(data))).status, 409);
  release(); assert.equal((await first).status, 200); assert.equal(calls, 1);
});
test("429 permite nova tentativa e respeita retry_after", async t => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => ++calls === 1 ? new Response(JSON.stringify({ retry_after: 2.5 }), { status: 429 }) : new Response("{}"));
  const d = new Delivery(context(), environment()); const data = report();
  const first = await d.fetch(deliveryRequest(data)); assert.equal(first.status, 429); assert.equal((await first.json()).retry_after, 2.5);
  assert.equal((await d.fetch(deliveryRequest(data))).status, 200);
});
test("timeout não produz repetição cega nem revela segredo no erro", async t => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => { calls++; throw new Error(webhook()); });
  const ctx = context(), d = new Delivery(ctx, environment()), data = report();
  const first = await d.fetch(deliveryRequest(data)); assert.equal(first.status, 502); assert.ok(!(await first.text()).includes(webhook()));
  assert.equal((await d.fetch(deliveryRequest(data))).status, 409); assert.equal(calls, 1);
  assert.ok(!JSON.stringify([...ctx.storage.data]).includes("Dados fictícios"));
});
test("alarmes removem metadados expirados", async () => {
  const ctx = context(), d = new Delivery(ctx, environment());
  await ctx.storage.put("delivery", { expires: 1 }); await d.alarm(); assert.equal(ctx.storage.data.size, 0);
  const qctx = context(), q = new Quota(qctx); await qctx.storage.put("quota", { until: 1 }); await q.alarm(); assert.equal(qctx.storage.data.size, 0);
});
test("Worker integra autenticação, limites e envio", async t => {
  let calls = 0; t.mock.method(globalThis, "fetch", async () => { calls++; return new Response("{}"); });
  const env = environment(); const r = await worker.fetch(await request(), env);
  assert.equal(r.status, 200); assert.equal(calls, 1);
});
test("Worker recusa HTTP e token inválido antes do envio", async t => {
  let calls = 0; t.mock.method(globalThis, "fetch", async () => { calls++; return new Response("{}"); });
  assert.equal((await worker.fetch(new Request("http://relay.invalid/report"), environment())).status, 400);
  assert.equal((await worker.fetch(await request(report(), { headers: { Authorization: "Bearer invalid" } }), environment())).status, 401);
  assert.equal(calls, 0);
});

const signatureBase = () => ({ schema_version: 1, version: "teste", entries: [], scripts: { funcoes_executor: ["loadstring", "game:HttpGet"], bibliotecas_gui: [], ofuscadores: [], hosts_script: ["raw.githubusercontent.com"], repos_bloqueados: [], hashes_script: [] } });
test("base sensível retorna bytes exatos e hash, sem cache", async () => {
  const source = JSON.stringify(signatureBase());
  const sha = createHash("sha256").update(source).digest("hex");
  const response = await sensitiveSignatures({ SENSITIVE_SIGNATURES_JSON: source, SENSITIVE_SIGNATURES_SHA256: sha });
  assert.equal(response.status, 200); assert.equal(response.headers.get("X-Signatures-SHA256"), sha);
  assert.equal(response.headers.get("Cache-Control"), "no-store"); assert.equal(await response.text(), source);
});
test("base ausente, inválida, divergente e excessiva falham fechado", async () => {
  assert.equal((await sensitiveSignatures({})).status, 404);
  for (const env of [{ SENSITIVE_SIGNATURES_JSON: "{}" }, { SENSITIVE_SIGNATURES_JSON: JSON.stringify(signatureBase()), SENSITIVE_SIGNATURES_SHA256: "bad" }, { SENSITIVE_SIGNATURES_JSON: "x".repeat(MAX_BYTES + 1) }]) assert.equal((await sensitiveSignatures(env)).status, 503);
});
test("base pública completa também atende schema sensível", async () => {
  const source = await readFile(new URL("../../signatures.json", import.meta.url), "utf8");
  assert.equal((await sensitiveSignatures({ SENSITIVE_SIGNATURES_JSON: source })).status, 200);
});
test("GET signatures usa token e quotas sem consumir entrega", async () => {
  const env = environment(); env.SENSITIVE_SIGNATURES_JSON = JSON.stringify(signatureBase());
  const headers = { "CF-Connecting-IP": "192.0.2.1", Authorization: `Bearer ${await createToken(secret, claims())}` };
  const response = await worker.fetch(new Request("https://relay.invalid/signatures", { headers }), env);
  assert.equal(response.status, 200); assert.equal(env.DELIVERIES.objects.size, 0);
  assert.equal((await worker.fetch(new Request("https://relay.invalid/signatures", { headers: { "CF-Connecting-IP": "192.0.2.1" } }), env)).status, 401);
  for (let i = 0; i < 9; i++) assert.equal((await worker.fetch(new Request("https://relay.invalid/signatures", { headers }), env)).status, 200);
  assert.equal((await worker.fetch(new Request("https://relay.invalid/signatures", { headers }), env)).status, 429);
});
test("envelope do formatador Python com perfil e avatar sintéticos chega intacto ao multipart", async t => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/synthetic-envelope.json", import.meta.url), "utf8"));
  const value = validateReport(fixture, { code: fixture.session_code });
  assert.equal(value.payload.embeds.length, 3);
  assert.ok(Buffer.byteLength(JSON.stringify(value)) < MAX_BYTES);
  const attached = JSON.parse(value.attachments.find(a => a.content_type === "application/json").content);
  assert.equal(attached.synthetic, true);
  const summary = value.payload.embeds[0];
  assert.equal(summary.title, "🛡️ Relatório de Verificação | WARP SCREENSHARE");
  assert.equal(summary.color, 0xffffff);
  assert.match(summary.description, /\*\*Roblox User:\*\* `JogadorExemplo`/);
  assert.ok(summary.description.includes(`[🔗 Perfil](${summary.url})`));
  assert.equal(summary.thumbnail.url, "attachment://avatar.png");
  let received = false;
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    const sent = JSON.parse(init.body.get("payload_json"));
    const file = init.body.get("files[2]");
    assert.equal(sent.embeds.length, 5);
    assert.deepEqual(sent.embeds.slice(0, 3).map(e => e.fields.length), [5, 4, 3]);
    assert.deepEqual(sent.embeds.slice(3), value.payload.embeds.slice(1));
    assert.equal(file.name, "avatar.png");
    assert.deepEqual(Buffer.from(await file.arrayBuffer()), Buffer.from(fixture.attachments[2].content, "base64"));
    received = true;
    return new Response("{}");
  });
  const response = await worker.fetch(await request(fixture, { headers: { "X-Warp-Evidence": "png" } }), environment());
  assert.equal(response.status, 200);
  assert.equal(received, true);
});

// PNG sintético de 1 × 1 para exercitar o protocolo. O scanner nunca oferece esta imagem ao jogador.
function reviewedReport() {
  const data = report();
  const content = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC";
  const bytes = Buffer.from(content, "base64");
  const filename = `prova_${data.scan_id}.png`;
  const finding = { id: "12345678-1234-4123-8123-123456789abd", evidence: { caminho: "Download/exemplo.lua" } };
  const manifest = { reviewed: true, status: "REVISADA", finding_id: finding.id, filename, width: 1, height: 1,
    bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
  data.attachments[0].content = JSON.stringify({ session_code: data.session_code, scan_id: data.scan_id, synthetic: false,
    consent: { screenshot: true }, findings: [finding], capture: manifest });
  data.attachments.push({ filename, content, content_type: "image/png" });
  return data;
}
test("PNG revisado é encaminhado ao Discord como os mesmos bytes binários", async t => {
  const data = reviewedReport();
  const expected = Buffer.from(data.attachments[2].content, "base64");
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    calls++;
    const file = init.body.get("files[2]");
    assert.equal(file.type, "image/png");
    assert.equal(file.name, data.attachments[2].filename);
    assert.deepEqual(Buffer.from(await file.arrayBuffer()), expected);
    return new Response("{}");
  });
  const env = environment();
  const options = { headers: { "X-Warp-Evidence": "png" } };
  assert.equal((await worker.fetch(await request(data, options), env)).status, 200);
  assert.equal((await worker.fetch(await request(data, options), env)).status, 200);
  assert.equal(calls, 1);
});
test("imagem divergente, não revisada ou de scan sintético não é enviada", async t => {
  let calls = 0; t.mock.method(globalThis, "fetch", async () => { calls++; return new Response("{}"); });
  for (const change of [
    (r, m) => { m.capture.sha256 = "0".repeat(64); },
    (r, m) => { m.capture.width = 70000; },
    (r, m) => { m.capture.reviewed = false; },
    (r, m) => { m.consent.screenshot = false; },
    (r, m) => { m.synthetic = true; },
    (r, m) => { m.findings = []; },
    r => { r.attachments[2].content = Buffer.from("not a png").toString("base64"); },
    r => { r.attachments[2].content = "junk!"; },
    r => { r.attachments[2].filename = "outra.png"; },
  ]) {
    const data = reviewedReport();
    const manifest = JSON.parse(data.attachments[0].content);
    change(data, manifest);
    data.attachments[0].content = JSON.stringify(manifest);
    assert.equal((await worker.fetch(await request(data, { headers: { "X-Warp-Evidence": "png" } }), environment())).status, 400);
  }
  assert.equal(calls, 0);
});
test("cabeçalho de PNG e imagem são exigidos juntos", async () => {
  assert.equal((await worker.fetch(await request(reviewedReport()), environment())).status, 400);
  assert.equal((await worker.fetch(await request(report(), { headers: { "X-Warp-Evidence": "png" } }), environment())).status, 400);
});
test("limite textual segue em 256 KiB mesmo com captura", async () => {
  const data = reviewedReport();
  data.attachments[1].content = "x".repeat(MAX_BYTES);
  assert.equal((await worker.fetch(await request(data, { headers: { "X-Warp-Evidence": "png" } }), environment())).status, 413);
});
test("PNG com CRC inválido é recusado mesmo com hash atualizado", async () => {
  const data = reviewedReport(), bytes = Buffer.from(data.attachments[2].content, "base64");
  bytes[bytes.length - 1] ^= 1;
  const info = JSON.parse(data.attachments[0].content);
  info.capture.sha256 = createHash("sha256").update(bytes).digest("hex");
  data.attachments[0].content = JSON.stringify(info);
  data.attachments[2].content = bytes.toString("base64");
  assert.equal((await worker.fetch(await request(data, { headers: { "X-Warp-Evidence": "png" } }), environment())).status, 400);
});

function withAvatar(data = report()) {
  data.attachments.push({ filename: "avatar.png", content_type: "image/png", content: reviewedReport().attachments[2].content });
  data.payload.embeds[0].thumbnail = { url: "attachment://avatar.png" };
  return data;
}

test("avatar e captura coexistem com JSON/TXT e thumbnail local em multipart", async t => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    const payload = JSON.parse(init.body.get("payload_json"));
    assert.equal(payload.embeds[0].thumbnail.url, "attachment://avatar.png");
    assert.deepEqual(payload.allowed_mentions, { parse: [] });
    const file = init.body.get(`files[${calls === 0 ? 2 : 3}]`);
    assert.equal(file.name, "avatar.png");
    assert.equal(file.type, "image/png");
    assert.deepEqual(Buffer.from(await file.arrayBuffer()), Buffer.from(reviewedReport().attachments[2].content, "base64"));
    calls++;
    return new Response("{}");
  });
  for (const data of [withAvatar(), withAvatar(reviewedReport())]) {
    assert.equal((await worker.fetch(await request(data, { headers: { "X-Warp-Evidence": "png" } }), environment())).status, 200);
  }
  assert.equal(calls, 2);
});

test("avatar exige PNG válido, tamanho limitado, perfil e referência na primeira embed", async () => {
  for (const change of [
    d => { delete d.payload.embeds[0].thumbnail; },
    d => { delete d.payload.embeds[0].url; },
    d => { d.payload.embeds.push({ title: "Detalhes", thumbnail: d.payload.embeds[0].thumbnail }); },
    d => { d.attachments.pop(); },
    d => { d.attachments.push({ ...d.attachments[2] }); },
    d => { d.attachments[2].content = Buffer.from("Arquivo que não é PNG").toString("base64"); },
    d => { d.attachments[2].content = Buffer.alloc(512 * 1024 + 1).toString("base64"); },
  ]) {
    const d = withAvatar();
    change(d);
    const res = await worker.fetch(await request(d, { headers: { "X-Warp-Evidence": "png" } }), environment());
    assert.equal(res.status, 400);
  }
});

test("permite só o perfil numérico coerente e URLs de conteúdo dentro de spans", () => {
  function tryDescription(description) {
    const d = report(); d.payload.embeds[0].description = description;
    return () => validateReport(d, claims());
  }
  assert.doesNotThrow(tryDescription("👤 **Roblox User:** `Exemplo` • [🔗 Perfil](https://www.roblox.com/users/123/profile)\n└ `https://origem.invalid/x`"));
  for (const text of [
    "Acesse https://origem.invalid/", "[perfil](https://origem.invalid/)", "[🔗 Perfil](https://www.roblox.com/users/456/profile)",
    "<@123456>", "<#123456>", "@everyone", "www.origemdados.invalid", "discord.gg/nascimentos",
    "\\`https://origem.invalid/\\`", "texto `aberto https://origem.invalid/", "[perfil](//origem.invalid)",
  ]) assert.throws(tryDescription(text), PublicError);
});

test("resumo mede UTF-16 até 3800 e detalhes respeitam o total de 6000", () => {
  const d = report(); d.payload.embeds[0].description = "🛡".repeat(1900);
  assert.doesNotThrow(() => validateReport(d, claims()));
  d.payload.embeds[0].description += "x"; assert.throws(() => validateReport(d, claims()));
  d.payload.embeds[0].description = "a".repeat(3000); d.payload.embeds.push({ title: "Detalhes", description: "a".repeat(3000) });
  assert.throws(() => validateReport(d, claims()));
});
import { opaqueKey } from "../src/security.js";

test("convite permite somente sessões para relatórios, sem acesso às assinaturas", async () => {
  const env = environment();
  const headers = {"Content-Type":"application/json","CF-Connecting-IP":"192.0.2.1"};
  const issue = auth => worker.fetch(new Request("https://relay.invalid/session", {
    method:"POST", headers:{...headers, Authorization:auth}, body:JSON.stringify({code})
  }), env);
  assert.equal((await issue("Invite invalid")).status,401);
  const issued = await issue("Invite " + await opaqueKey(secret,"warp:report-invite:v1"));
  assert.equal(issued.status,200);
  const {token} = await issued.json();
  const auth = "Bearer " + token;
  const denied = await worker.fetch(new Request("https://relay.invalid/signatures",{headers:{...headers,Authorization:auth}}),env);
  assert.equal(denied.status,401);
  env.DELIVERIES = {idFromName:n=>n,get:()=>({fetch:()=>new Response("ok")})};
  assert.equal((await worker.fetch(await request(report(),{headers:{Authorization:auth}}),env)).status,200);
});
