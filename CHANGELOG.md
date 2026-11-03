# Histórico

## 0.2.1 — sessão real no Termux

- A demonstração indica como iniciar uma verificação real. A falta de endereço de entrega é informada antes do scan e não gera pedido de token.
- O fluxo padrão tenta ler somente o nick visível em Minha conta do Roblox e do Discord com ADB e autorização. Fontes indisponíveis ficam sem identificação.

## 0.2.0 — relatório e cópia no aparelho

- Embed em português, com os rótulos do modelo WARP, link de perfil numérico, avatar público opcional, quatro achados principais e detalhes de cobertura. A pontuação fica no JSON.
- Cópia local automática em TXT e JSON, inclusive quando o jogador recusa o envio ou o relay está indisponível. A captura da tela continua opcional e exige revisão.
- Marca, modelo, Android, patch, nível de API, depuração USB e hora automática quando acessíveis. Campos não verificáveis mostram N/A; sinais de uso anterior e instalação recente são cruzados no mesmo perfil.
- O relay aceita o avatar junto da captura aprovada, restringe links e menções e verifica os limites de texto e de imagem.

## 0.1.0 — versão preliminar

- Scanner modular com consentimento e cobertura explícita.
- Análise estática de scripts, leitura única opcional do clipboard e redação.
- Consultas Android direcionadas e fallback de privilégio.
- Relatório JSON/TXT e relay Discord com sessão privada, quotas e idempotência.
- Instalador de release fixo com conferência SHA-256.
- Testes automatizados com dados sintéticos. Validação em aparelhos ainda pendente.
- Captura opcional da tela inteira com prévia local e autorização por imagem.
- Caminho Android dos arquivos sinalizados e identificação Discord autodeclarada.
- M9, M10 e M11 acrescentam marcos do sistema, uso observável do Roblox, revisão de autenticidade do APK e sinais de proxy/VPN/DNS.
- Revisão local da força das evidências antes da pontuação.
