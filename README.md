# WARP SCREENSHARE SCANNER

Ferramenta de linha de comando em português para verificações consentidas do Roblox no Android. O jogador acompanha a coleta no Termux, revisa o relatório e decide se autoriza o envio ao Discord da staff.

**Versão preliminar para validação em bancada.** Os testes automatizados usam amostras sintéticas. A validação em Android 11 a 15, Samsung, Xiaomi e Motorola está pendente. A staff precisa publicar o relay e cadastrar referências confiáveis antes de usar resultados em verificações reais.

## Primeira execução

Para ver um relatório de demonstração em um computador com Python 3.10 ou posterior, abra o diretório do projeto e execute:

```sh
python scan.py --test --plain
```

No celular, instale o Termux e o aplicativo complementar Termux:API pela mesma fonte. O pacote de terminal `termux-api` e o aplicativo Android correspondente são necessários para usar o clipboard pelo Termux. [Instalação oficial do Termux](https://github.com/termux/termux-app#installation) · [Termux:API](https://github.com/termux/termux-api)

Com o release `v0.2.3` disponível, esta linha instala o comando `warp-scan` no Termux:

```sh
pkg install -y curl && curl -fsSL https://raw.githubusercontent.com/astricmy/warp-screenshare-scanner/v0.2.3/install.sh | bash
```

Para inspecionar o instalador primeiro:

```sh
pkg install -y curl
curl -fsSLo install.sh https://raw.githubusercontent.com/astricmy/warp-screenshare-scanner/v0.2.3/install.sh
less install.sh
bash install.sh
warp-scan --test
```

O instalador anuncia as alterações, instala dependências pelo `pkg`, verifica o ZIP e cada arquivo pelo SHA-256 do release e cria `$PREFIX/bin/warp-scan`. A coleta começa apenas quando o jogador executa o scanner e digita `ACEITO`. Para autorizar acesso ao armazenamento compartilhado, execute `termux-setup-storage` manualmente.

A instalação padrão inclui `aapt` para identificar o aplicativo no manifesto e `apksigner` para validar o signatário do APK. Este último traz o OpenJDK como dependência. Se precisar economizar espaço, use `bash install.sh --leve`. As verificações que dependem dessas ferramentas ficarão com cobertura parcial. [Pacote apksigner do Termux](https://github.com/termux/termux-packages/tree/master/packages/apksigner)

## Sessão acompanhada

1. Com o convite fixo configurado pela staff na instalação, a Cloudflare autoriza cada envio automaticamente após a confirmação. No modo manual, a staff gera um **código público de sessão** e um **token privado de envio** com o gerador do Worker. O jogador coloca somente o código público na descrição do perfil do Roblox.
2. Para uma verificação real no Termux, execute `warp-scan --adb`. Se a staff fornecer um código de sessão, acrescente `--session-code WARP-...`. O modo `--test` usa uma amostra fictícia e nunca envia ao Discord.
3. O scanner oferece identificar o nick sem digitação. Com ADB local pareado, autorize cada leitura e abra a tela **Configurações → Minha conta** do aplicativo indicado. Deixe o campo **Nome de usuário** visível por 12 segundos e volte ao Termux. Apenas o nick de um campo reconhecido é retido. Se a versão ou o idioma do app não expuser esse campo ao Android, o relatório mostra N/A. Por esse método não se atribui posse, não se guarda ID e não se consulta avatar. As opções antigas de nick explícito continuam disponíveis para a staff.
4. Revise os achados, os caminhos Android, os horários, as fontes, a cobertura e os dados que seguirão nos anexos. Uma captura, quando autorizada, exige revisão da imagem inteira antes do envio.
5. O scanner mostra onde salvou os arquivos no aparelho. Se quiser compartilhar, confirme o envio (o token só é solicitado no modo manual). Ao terminar, remova o código da descrição e desligue a depuração sem fio. [Guia de ADB do Android](https://developer.android.com/tools/adb)

| Opção | Efeito |
|---|---|
| `--test` | Demonstração sintética sem consultar celular, clipboard, DNS ou APIs |
| `--dry-run` | Coleta com consentimento, apresenta o envelope e encerra antes do envio |
| `--plain` ou `NO_COLOR=1` | Banner ASCII e terminal sem cores |
| `--adb` | Pareamento e conexão apenas no próprio celular, por loopback |
| `--window-days N` | Janela de downloads, padrão de 14 dias |
| `--max-file-kb N` | Limite de texto/Lua por arquivo, padrão de 512 KiB |
| `--max-files N`, `--max-seconds N` | Limites da caminhada e da análise de arquivos |
| `--nick`, `--expected-nick`, `--session-code` | Perfil e sessão esperados pela staff |
| `--discord` ou `--discord-user`, `--discord-id` | Nome e ID opcional informados pela pessoa, sem verificação de posse; não acessa o app Discord |
| `--output DIRETORIO` | Escolhe a pasta dos relatórios e salva ali a eventual captura aprovada; em `--test`, permite guardar a demonstração |
| `--direct` | Modo de bancada, requer `WARP_WEBHOOK_URL` no ambiente |

## Cobertura e interpretação

| Modo | Acesso possível | Quando uma consulta falha |
|---|---|---|
| PADRÃO | Pastas permitidas, perfil público, scripts e clipboard autorizados, propriedades do Android | Registra a restrição na matriz de cobertura |
| PADRÃO+ | ADB local pareado disponibiliza consultas adicionais de pacotes, uso, configurações e processos | Tenta a capacidade disponível ou registra NÃO VERIFICADO |
| AVANÇADO | Após `uid=0`, consultas direcionadas a metadados e artefatos permitidos | A falha aparece na cobertura, com fallback quando aplicável |

| Módulo | Evidência principal |
|---|---|
| M1 e M2 | Instalação e identidade pública do Roblox, vínculo de posse por código |
| M3 e M4 | Pacotes da base, arquivos, hashes conhecidos e registros residuais observáveis |
| M5 e M6 | Origens de download filtradas no provedor e configurações do aparelho |
| M7 e M8 | Metadados do processo Roblox, padrões de scripts, arquivo ou clipboard |
| M9 | Marcos de inicialização do Android e tempo de uso do Roblox na janela observável |
| M10 | Identidade do APK e comparação do signatário com referências confiáveis |
| M11 | Configuração de proxy, VPN e DNS, certificados, perfis e sondas consentidas |

Os achados de arquivo exibem o caminho observado, por exemplo `/storage/emulated/0/Download/Delta Executor.apk`. O nome pode ser alterado por qualquer pessoa. A revisão local compara referências e considera a força e a repetição dos sinais. Os detalhes por fonte estão em [Validação e autenticidade](docs/VALIDACAO.md) e [Rede](docs/REDE.md).

Os pesos estão em `settings.json`. Correspondências exatas validadas têm mais peso que nomes ou configuração de risco. A faixa **INCONCLUSIVO (cobertura parcial)** preserva a incerteza quando a pontuação é baixa e faltam módulos críticos. **CONFIRMADO** se refere ao objeto identificado, como um certificado diferente ou uma ferramenta de interceptação reconhecida. A decisão sobre o uso de cheats exige revisão humana.

## Configurar o Discord

Ao fim de uma verificação consentida, o Termux guarda `relatorio_<id>.txt` (para leitura) e `relatorio_<id>.json` (dados estruturados) em `~/.local/share/warp-screenshare/relatorios/`. O terminal mostra os caminhos completos. Isso também funciona em `--dry-run`, sem relay configurado, se o envio falhar ou se o jogador preferir não compartilhar. Para listar as cópias, use `ls -lt ~/.local/share/warp-screenshare/relatorios/`. A imagem de evidência só é gravada junto das cópias se tiver sido aprovada e a pasta tiver sido indicada com `--output`.

A embed branca começa pelo perfil Roblox, Discord informado, marca e modelo, versão do Android e patch de segurança. Em seguida aparecem root, veredito, os quatro achados mais graves com suas localizações, clipboard, downloads, rede, autenticidade do Roblox, uso observado nas últimas 72 h e reinstalação. As embeds pretas detalham evidências, horários e cobertura. Um campo que não pôde ser verificado aparece como **N/A** com o motivo. O tempo observado não é extrapolado para preencher lacunas.

Quando há perfil identificado e o envio é autorizado, o scanner tenta anexar o avatar público como `avatar.png` pela [API de thumbnails do Roblox](https://create.roblox.com/docs/cloud/reference/domains/thumbnails). Falha nessa etapa deixa a mensagem sem imagem. Os IDs numéricos explícitos do perfil e do Discord informado são distintos de identificadores privados do telefone. IPs, MAC e SSID não aparecem nos relatórios textuais; uma captura aprovada deve ser conferida pelo jogador.

O telefone envia o relatório ao Worker da staff por HTTPS. O Worker valida um token HMAC com expiração, controla as tentativas por IP e código e repassa ao Discord embeds, JSON, TXT e eventual imagem autorizada. Configure `DISCORD_WEBHOOK_URL` e `SESSION_SECRET` como segredos do Worker. No celular, configure `WARP_RELAY_URL` com a origem HTTPS do relay. A versão da WARP já inclui o endereço público do Worker. O convite privado de envio fica fora do repositório. [Exemplo completo, instalação e protocolo do Worker](worker/README.md)

O perfil é consultado com `POST /v1/usernames/users` e `GET /v1/users/{userId}` na API pública do Roblox. O relatório guarda a URL do perfil e o resultado da comparação do código. A descrição usada na comparação é descartada. [Referência oficial da API de usuários](https://create.roblox.com/docs/cloud/reference/domains/users)

## Assinaturas, privacidade e limites

A base `signatures.json` reúne sementes não validadas. A staff deve conferir a origem de pacotes, hashes e certificados em instalações de referência e registrar fonte e data. A falta de referência confiável gera cobertura parcial. A atualização opcional por `WARP_SIGNATURES_URL` exige o SHA-256 em `WARP_SIGNATURES_SHA256`, distribuído pela staff por um canal independente. A rota opcional `/signatures` do relay usa o token privado. Falhas preservam a base pública local.

O scanner limita a caminhada às pastas permitidas e a análise é estática. O relatório pode incluir texto reconstruído dos padrões encontrados, caminho, tamanho, datas e hash. A imagem aprovada é enviada inteira e pode revelar notificações. A revisão visual pelo jogador é indispensável. As restrições de coleta, as recomendações de retenção e o contato de segurança estão em [SECURITY.md](SECURITY.md).

A data de compilação do Android não determina a data de formatação. Uso recente, instalação recente e uma pasta vazia são indícios com várias explicações. A cobertura de uso pode abranger menos de 72 horas, dependendo do fabricante e das permissões. O relatório apresenta o intervalo disponível. O scanner não recupera arquivos apagados, nem varre bancos privados de teclados, mensageiros e navegadores. O aparelho controla o processo e pode adulterar o resultado.

## Desenvolvimento e release

```sh
python -m unittest discover -s tests -v
python scan.py --test --plain
node --test worker/test/*.test.mjs
python tools/check_secrets.py
python tools/build_release.py
```

`scan.py` coordena o consentimento e as coletas. `warp_scanner/` contém os módulos, interface, controle de acesso a arquivos e transporte. `worker/` contém o relay e seus testes. `tools/` gera o ZIP e o manifesto SHA-256 do release. `checksums.txt` permite conferir os arquivos distribuídos. Uma cópia local adulterável do manifesto fornece apenas verificação local.

Ao alterar a versão, atualize `config.py`, `install.sh`, `.github/release-tag`, o README e o changelog. Gere novamente o manifesto e revise o commit. O workflow testa e publica um pré-release com ZIP, `SHA256SUMS` e `checksums.txt` quando o marcador de release muda na branch principal. Proteja essa branch, ative autenticação em dois fatores e revise mudanças no instalador e no workflow.
