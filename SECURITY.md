# Segurança e privacidade

O scanner se destina a uma sessão acompanhada e autorizada pelo jogador. A staff deve explicar o propósito, quem acessa o canal do Discord e por quanto tempo os relatórios ficarão disponíveis.

**Dados previstos.** Metadados técnicos e achados por assinatura, caminhos Android dos arquivos correspondentes, perfil público do Roblox, Discord informado pelo jogador, indicadores de privilégio, cobertura, sinais da rede e horários. A leitura de texto e do clipboard exige consentimento próprio. Testes externos de rede expõem o IP aos destinos consultados. Uma imagem real da tela pode ser anexada apenas após captura consentida, abertura da prévia e decisão do jogador.

**Dados excluídos da coleta de arquivos e logs.** Senhas, cookies, tokens, contatos, conversas, galeria, documentos pessoais, localização, IMEI, serial, MAC, SSID, contas Google e conteúdo de apps privados. O scanner não consulta sessões do Roblox ou do Discord. Imagens da tela inteira não podem ser garantidas livres de notificações ou dados pessoais. O jogador deve descartar qualquer prévia que contenha esses dados.

**Segredos da staff.** Cadastre o webhook Discord no segredo do Worker. Rotacione o segredo de assinatura de sessões e revogue webhooks expostos. Tudo disponibilizado ao aparelho, inclusive a base opcional, pode ser copiado. Restrinja o acesso aos anexos no canal da staff. Arquivos de relatórios e credenciais locais são ignorados pelo Git.

**Distribuição.** Proteja a conta do GitHub com dois fatores e controle alterações no instalador e no workflow de release. Rode `python tools/check_secrets.py` antes de publicar. A varredura cobre padrões conhecidos em arquivos e objetos do Git e não substitui revisão humana. Um hash recebido da mesma origem do arquivo detecta corrupção, mas não protege de comprometimento dessa origem.

**Relato de falhas.** Contate a staff em canal privado por meio do [servidor WARP SCREENSHARE](https://discord.gg/pthFZGupmH). Informe versão, módulo, passos mínimos e um exemplo fictício. Não envie relatórios de jogadores, imagens reais ou credenciais em issues públicas.
