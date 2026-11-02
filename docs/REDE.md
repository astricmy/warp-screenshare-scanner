# Rede, proxy e interceptação

M11 consulta configurações de proxy global, PAC, DNS privado, túneis, CAs de usuário e redes com proxy expostas pelo Android. Identifica redes salvas por número. Registra somente a origem do PAC e descarta credenciais, caminho e consulta. Atribui conexões TCP ao Roblox apenas quando o UID é exclusivo do pacote. O relatório contém metadados de destinos e horários.

O teste ativo opcional consulta os domínios públicos predefinidos do Roblox pelo resolvedor do sistema e pelo DNS sobre HTTPS do Google. Também consulta o emissor TLS em uma conexão do Termux. O caminho e a política de confiança do jogo podem ser diferentes. CDNs podem fornecer respostas DNS distintas nas duas consultas. A configuração de um proxy no roteador pode ficar invisível no celular.

Uma VPN ativa ou DNS personalizado é um indício com usos legítimos. Uma correspondência confirmada identifica a infraestrutura ou o emissor da base. A staff deve revisar separadamente se houve interferência no Roblox. Formatos de fabricante sem parser reconhecido, permissões negadas e sondas recusadas ficam na matriz de cobertura.

Perfis de VPN que podem conter chaves privadas fornecem apenas nome, tamanho e datas. O hash de certificado público requer consentimento e reconhecimento do formato. A validação em bancada deve cobrir Wi-Fi com PAC e proxy estático, VPN ativa, CA de teste, aparelho sem proxy e recusa de cada teste ativo.
