#!/usr/bin/env node
// Somente na máquina da staff. Não instalar no telefone do jogador.
import { randomUUID, randomBytes, webcrypto } from "node:crypto";
import { createToken, CODE } from "./src/security.js";
globalThis.crypto ??= webcrypto;

const code = process.argv[2] || `WARP-${randomBytes(5).toString("hex").toUpperCase()}`;
const minutes = Number(process.argv[3] || 15);
const secret = process.env.SESSION_SECRET;
if (!CODE.test(code) || !Number.isInteger(minutes) || minutes < 1 || minutes > 60 || !secret || Buffer.byteLength(secret) < 32) {
  process.stderr.write("Uso: SESSION_SECRET no ambiente; node generate-session.mjs [WARP-CODIGO] [1-60 minutos]. Segredo de ao menos 32 bytes.\n");
  process.exitCode = 1;
} else {
  const iat = Math.floor(Date.now() / 1000);
  const token = await createToken(secret, { v: 1, code, iat, exp: iat + minutes * 60, nonce: randomUUID() });
  process.stdout.write(`Código público para o perfil: ${code}\nToken privado para o scanner (não colocar no perfil):\n${token}\nExpira em ${minutes} minuto(s). Não reutilize o código em outras verificações.\n`);
}
