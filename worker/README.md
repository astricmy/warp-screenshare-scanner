# Relay WARP SCREENSHARE

Worker Cloudflare que recebe um relatório já minimizado, autentica a sessão e o encaminha ao webhook Discord. O endereço real do webhook fica apenas no segredo `DISCORD_WEBHOOK_URL` do Worker. O código público `WARP-...`, colocado no perfil Roblox, **não é** a credencial de envio. O token privado assinado é inserido no scanner e nunca deve ser colocado na descrição do perfil.

## Preparar e publicar pela staff

Requer Node.js 22 ou mais recente, uma conta Cloudflare e Wrangler. A hospedagem não é criada automaticamente pelo scanner. Confira as condições e limites da conta Cloudflare antes do deploy.

```sh
cd worker
node --test test/*.test.mjs
npx wrangler login
npx wrangler secret put DISCORD_WEBHOOK_URL
npx wrangler secret put SESSION_SECRET
npx wrangler deploy
```

Os dois comandos `secret put` pedem os valores interativamente. Use um segredo `SESSION_SECRET` aleatório com no mínimo 32 bytes; mantenha a cópia da staff em um gerenciador de segredos. Não cole valores no código, em arquivos versionados, em argumentos de comandos ou em chats públicos. A URL Discord deve ser HTTPS, host `discord.com` e caminho `/api/webhooks/<id>/<token>` (também aceito `/api/v10/webhooks/...`). O relay fixa `?wait=true`, desabilita menções e impede redirecionamentos.

`wrangler.toml` define dois namespaces Durable Objects com armazenamento SQLite. `Quota` é particionado por IP e código; `Delivery` é particionado por código de sessão. Os identificadores usam HMAC e não contêm o IP original. Não é usado um contador global único nem um `Map` volátil como limite de produção.

Configure a origem HTTPS retornada pelo deploy no scanner como `WARP_RELAY_URL` (por exemplo `https://warp-screenshare-relay.<sua-conta>.workers.dev`), **sem** `/report`: o cliente acrescenta essa rota. Nenhum webhook precisa ir ao aparelho do jogador. Rotacione `SESSION_SECRET` periodicamente (os tokens anteriores deixam de funcionar) e troque o webhook se suspeitar de exposição. Os nomes de sessão devem ser novos a cada verificação.

## Gerar uma sessão

Na máquina da staff, carregue `SESSION_SECRET` no ambiente por seu gerenciador de segredos, com o mesmo valor cadastrado no Worker. Depois:

```sh
node generate-session.mjs WARP-7K3Q 15
```

Sem argumentos, a ferramenta gera um código aleatório. O prazo padrão é 15 minutos; são aceitos 1–60 minutos. A saída contém o código público e o token privado destinado ao jogador durante a call. Não publique essa saída, não a cole na descrição Roblox e não a salve em logs. O gerador não imprime o segredo mestre. Remova `SESSION_SECRET` do ambiente após o uso conforme os procedimentos da staff.

O jogador informa `--session-code WARP-7K3Q` no scanner e fornece o token privado no prompt protegido ou em `WARP_SESSION_TOKEN`. O token autoriza apenas um relatório por código, com expiração. O relay não aceita o código público como autenticação e não possui rota pública de emissão de tokens.

## Protocolo do cliente

`POST https://<worker>/report` recebe JSON com o cabeçalho `Authorization: Bearer <token>`. Relatórios sem imagens têm limite de 256 KiB para o corpo inteiro. Quando houver PNGs, envie também `X-Warp-Evidence: png`. O limite passa a 6.553.604 bytes e a parte textual continua limitada a 256 KiB. O Worker conta os bytes durante a leitura mesmo quando a requisição não declara o tamanho.

```json
{
  "session_code": "WARP-7K3Q",
  "scan_id": "12345678-1234-4123-8123-123456789abc",
  "payload": {
    "embeds": [{ "title": "WARP SCREENSHARE", "description": "Resumo redigido" }]
  },
  "attachments": [
    {
      "filename": "relatorio_12345678-1234-4123-8123-123456789abc.json",
      "content_type": "application/json",
      "content": "{\"scan_id\":\"12345678-1234-4123-8123-123456789abc\",\"session_code\":\"WARP-7K3Q\"}"
    },
    {
      "filename": "relatorio_12345678-1234-4123-8123-123456789abc.txt",
      "content_type": "text/plain",
      "content": "WARP SCREENSHARE\nResumo redigido"
    }
  ]
}
```

O exemplo mostra a estrutura mínima do envelope. O scanner produz a apresentação completa e os relatórios legíveis nos dois primeiros anexos, JSON e TXT. O JSON deve repetir o UUID v4 do scan e o código público da sessão.

O resumo admite 3800 caracteres na descrição. Cada embed de detalhes admite 4096. O Worker confere o máximo de 10 embeds, 6000 caracteres no conjunto, 25 campos por embed e 1024 caracteres no valor de cada campo. A contagem usa unidades UTF-16. O link de perfil precisa apontar para o mesmo ID numérico no título e na descrição da primeira embed. URLs de origem no texto de achados devem ficar em spans de código. O rodapé admite o convite fixo da marca. O relay rejeita menções e fixa `allowed_mentions = {"parse":[]}` e `username = "WARP SCREENSHARE"`.

Após JSON e TXT podem vir os seguintes anexos opcionais, em qualquer ordem. Cada objeto usa `filename`, `content_type: "image/png"` e `content` em base64 padrão.

- **Avatar público.** O scanner obtém a imagem de perfil do Roblox e inclui `avatar.png`. A primeira embed deve ter `url` do perfil e `thumbnail.url = "attachment://avatar.png"`. A miniatura pode ter até 512 KiB e 512 × 512 px. O Worker verifica estrutura, dimensões, CRCs e a quantidade de dados descomprimidos do PNG. Quando a consulta do avatar falha, o scanner omite tanto a miniatura quanto o anexo.
- **Evidência revisada.** Uma captura de tela de até 4 MiB usa o nome `prova_<scan_id>.png`. O Worker confere o consentimento e a revisão registrados no JSON, o ID do achado, as dimensões, o tamanho e o SHA-256 da imagem. O jogador precisa conferir a tela inteira no visualizador antes de autorizar o anexo, inclusive notificações ou outros dados visíveis.

O encaminhamento ao Discord usa `multipart/form-data` com `payload_json` e um campo `files[n]` por arquivo. Os PNGs seguem como bytes binários. As mesmas cotas, prazo de sessão e regra de idempotência valem para envios com e sem imagens.

## Limites, repetição e falhas

- Máximo de 30 requisições por IP e 10 por código a cada janela de 60 segundos. A cota por IP também cobre tokens inválidos. IPs compartilhados podem precisar aguardar.
- Um código fica vinculado ao primeiro `scan_id` e ao hash canônico do relatório. Repetir o mesmo relatório já enviado retorna 200 e `duplicate: true`, sem publicar novamente. Um conteúdo diferente para o mesmo código recebe 409.
- Discord 429 retorna `retry_after` e libera repetição do mesmo conteúdo. O cliente deve respeitar a pausa e limitar as tentativas a três.
- Falha de rede, timeout ou erro 5xx pode ocorrer depois que o Discord recebeu a mensagem. O relay registra **entrega incerta** e evita repetir a publicação automaticamente. A staff precisa conferir o canal antes de emitir outra sessão. Não existe garantia de exatamente uma entrega entre serviços independentes sem uma chave de idempotência aceita pelo Discord.
- Erros e respostas não incluem URL secreta, exceção bruta, resposta Discord ou corpo do relatório. O cliente deve conservar a cópia local redigida quando o envio falhar.

## Privacidade e limites da proteção

Conteúdo de relatórios permanece em memória durante o encaminhamento; o relay não grava anexos, IP bruto, tokens, nomes de jogadores ou payloads no armazenamento Durable Objects. Guarda somente contadores e metadados de idempotência (hash, UUID, estado, prazos). Um alarme remove contadores expirados e os metadados de entrega dez minutos depois da expiração da sessão. Cloudflare recebe o tráfego e Discord recebe os anexos; a staff deve definir retenção e acesso ao canal. Os provedores podem aplicar retenção técnica própria.

A observabilidade do Worker está desativada no exemplo. Não habilite logs de corpo/cabeçalhos nem use `console.log(request)`; ferramentas de diagnóstico também podem expor tokens. A defesa extra rejeita padrões evidentes de credenciais/e-mail, mas não substitui a minimização e redação realizadas no scanner. Um token roubado pode enviar um relatório adulterado dentro da sessão; ele **não comprova** execução legítima do scanner ou consentimento. A call e a revisão humana continuam necessárias.

## Base sensível opcional

`GET /signatures` exige o mesmo token e compartilha as cotas por IP e código, mas não consome a entrega do relatório. Se o segredo `SENSITIVE_SIGNATURES_JSON` não estiver configurado, retorna 404 e o scanner usa a base pública. O segredo deve conter uma base **completa**, com `schema_version: 1`, `version`, `entries` e `scripts`; o scanner a usa em substituição à pública, sem mescla. Mantenha as funções gerais de detecção na seção `scripts`. O esquema segue `signatures.json` da raiz, incluindo proveniência e `verificado` nas entradas. JSON ou esquema inválido resulta em 503 sem expor o conteúdo.

```sh
npx wrangler secret put SENSITIVE_SIGNATURES_JSON
npx wrangler secret put SENSITIVE_SIGNATURES_SHA256
```

`SENSITIVE_SIGNATURES_SHA256` é opcional no servidor; quando definido, precisa ser o SHA-256 hexadecimal minúsculo dos bytes UTF-8 exatos do JSON armazenado. Espaços, ordem dos campos e quebra final de linha alteram esse hash. O endpoint retorna esses mesmos bytes, `Cache-Control: no-store` e o cabeçalho `X-Signatures-SHA256`. O hash esperado do cliente (`WARP_SIGNATURES_SHA256`) deve ser distribuído previamente pela staff, não aprendido da própria resposta.

Configure `WARP_SIGNATURES_URL` como a mesma origem de `WARP_RELAY_URL`, com `/signatures`, e forneça `WARP_SESSION_TOKEN` no ambiente antes de iniciar o scan. O token nunca deve ser encaminhado para um servidor externo de assinaturas. A base recebida não é gravada pelo scanner nem pelo relay. Ela pode ser extraída da memória do aparelho: autenticação reduz a distribuição pública, mas não torna a base inacessível ao jogador.

O limite defensivo do endpoint é 256 KiB. Entretanto, [Cloudflare limita cada variável/segredo a 5 KB](https://developers.cloudflare.com/workers/platform/limits/#environment-variables), portanto esta opção comporta apenas uma base compacta. Bases maiores precisam de um binding privado de armazenamento adicional, como R2, que **não faz parte deste exemplo**. Não publique uma base sensível como arquivo estático nem a inclua em `wrangler.toml`.

## Validação

`node --test test/*.test.mjs` cobre assinatura e prazo do token, rejeição de esquemas/URLs, leitura limitada em streaming, redirecionamentos, quotas concorrentes, idempotência, corrida de envios, 429, entrega incerta, expiração de metadados, base sensível autenticada e um envelope produzido por `scan.py --test`. São testes com armazenamento e Discord simulados; não equivalem a deploy Cloudflare nem envio real. Valide em uma conta de teste da staff antes do uso operacional.

Referências primárias: [armazenamento Durable Objects](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/), [limitação de taxa e suas garantias](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/), [segredos Workers](https://developers.cloudflare.com/workers/configuration/secrets/), [webhooks Discord](https://discord.com/developers/docs/resources/webhook#execute-webhook) e [limites de embeds](https://discord.com/developers/docs/resources/message#embed-object-embed-limits).
