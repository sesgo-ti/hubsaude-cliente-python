# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.1.0] - 2026-09-21

Primeira versão funcional do SDK. Ainda não publicada no PyPI (ver
[README](README.md#dependência)) — os artefatos ficam anexados à GitHub
Release. A série `0.x` é provisória enquanto a API pública é
estabilizada.

### Adicionado

- `SmartTokenClientBuilder` — construção fail-fast do cliente, com toda
  a validação de configuração feita em `build()` e sem nenhuma chamada
  de rede: `client_id` obrigatório, exatamente uma fonte de assinatura
  (`signing_strategy`, `private_key_pem` ou `client_key_store`),
  exatamente um entre `token_endpoint` e `fhir_base`, algoritmo JWT
  válido, timeouts positivos e `hub_context` exigindo `ig` e `versao`
  juntos.
- `obtain_token(scope)` / `obtain_token_response(scope)` — obtenção de
  token via SMART Backend Services (RFC 6749 `client_credentials` +
  RFC 7523 JWT bearer assertion), com montagem e assinatura do
  `client_assertion` (claims `iss`/`sub`/`aud`/`iat`/`exp`/`jti`, mais
  `kid` e `hub_ctx` opcionais) e `jti` novo a cada tentativa.
- Cache de token por scope normalizado, com margem de renovação
  configurável (30 s por padrão), teto por LRU (1000 entradas por
  padrão) e possibilidade de desligar; o `expires_in` devolvido é o
  tempo restante no momento da leitura.
- Deduplicação de chamadas concorrentes por scope (_single-flight_) no
  cliente, via _lock striping_ de 32 locks com dupla checagem do cache.
- `invalidate_cache()` — invalidação total ou por scope.
- `close()` idempotente, que aguarda as operações em voo, invalida o
  cache, encerra a conexão HTTP e fecha a estratégia de assinatura
  quando ela suporta; suporte a `with` (context manager); uso após o
  fechamento falha com `SmartTokenError` explícito.
- `get_token_endpoint()` / `get_jwt_algorithm()` / `get_key_id()` para
  introspecção da configuração efetiva.
- Retry com backoff exponencial (1 s, 2 s, 4 s...) e número total de
  tentativas configurável (`max_retries`, 3 por padrão), restrito a
  falhas transitórias de transporte — uma resposta HTTP efetivamente
  recebida, inclusive `429` e `5xx`, falha sem nova tentativa. Cada
  tentativa usa um `client_assertion` e um contexto de trace novos, e o
  erro final preserva a causa original.
- Cinco fontes de material de assinatura: arquivo PEM, string PEM (para
  variável de ambiente ou _secret manager_), chave já carregada em
  memória, bundle PKCS#12 e HSM/_smart token_ via PKCS#11 — este último
  com `python-pkcs11` como extra opcional (`hsm`), importado só quando
  usado.
- Detecção automática de quatro formatos de chave PEM (PKCS#1, PKCS#8,
  PKCS#8 criptografado e OpenSSL tradicional criptografado), com
  mensagens de erro distintas por causa (chave criptografada sem senha,
  senha para chave não criptografada, senha incorreta, formato
  inválido).
- Suporte aos nove algoritmos de assinatura JWT da especificação
  (`RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`,
  `ES256`/`ES384`/`ES512`), com padrão `RS384` e assinaturas ECDSA no
  formato bruto `R||S` (RFC 7518 §3.4).
- Descoberta automática do token endpoint via
  `GET <fhir_base>/.well-known/smart-configuration`, executada uma única
  vez na construção do cliente e reaproveitando a mesma conexão HTTP —
  logo, o mesmo contexto TLS/mTLS e os mesmos timeouts.
- TLS 1.3 por padrão (protocolo configurável entre TLS 1.2 e 1.3, fixado
  exatamente na versão escolhida), trust anchor customizado por arquivo
  PEM ou por certificado já em memória, e mTLS por par chave+certificado
  PEM ou por bundle PKCS#12.
- `TlsSettings` e os `Protocol` `SigningStrategy` e `TlsContextProvider`,
  cuja conformidade é conferida em runtime na construção do cliente.
- Verificação de consistência entre chave privada e certificado na
  construção, assinando um desafio e conferindo com a chave pública do
  certificado, nos caminhos PEM e PKCS#12.
- Validação do período de validade (`notBefore`/`notAfter`) dos
  certificados de cliente e dos trust anchors.
- Detecção de rejeição de certificado de cliente em mTLS em dois níveis
  de confiança: alerta TLS explícito do servidor, que interrompe o retry
  imediatamente, e sinal ambíguo (conexão cai sem alerta, variante
  observada sob TLS 1.3), que continua retriável e apenas acrescenta uma
  dica à mensagem final quando as tentativas se esgotam.
- Salvaguardas na resposta do token endpoint: leitura em streaming com
  teto de 1 MiB, aplicado também ao corpo das respostas de erro;
  validação de JSON, de objeto e de `access_token`; `expires_in` ausente
  assume 3600 s, valor zero/negativo/não numérico é rejeitado e valor
  acima de 24 h é normalizado para o teto.
- Header `traceparent` (W3C Trace Context) em toda requisição HTTP, novo
  a cada tentativa, com o `trace_id` presente nas mensagens de erro e
  nos logs para correlação com o suporte do HubSaúde.
- Logger único e estável (`hubsaude_client.SmartTokenClient`), sem
  dependência de biblioteca de log.
- `ESPECIFICACAO.md` (contrato comportamental compartilhado pelo
  portfólio de SDKs), `docs/integracao-enterprise.md` e
  `docs/troubleshooting.md`.
- Workflow de release disparado por tag, publicando sdist, wheel e SBOM
  CycloneDX na GitHub Release.

### Segurança

- Sanitização de mensagens de erro: `access_token`/`token` redigidos em
  corpos JSON e `form-urlencoded`, corpo truncado em 500 caracteres,
  sempre com a redação aplicada antes do truncamento.
- `__repr__` de `TokenResult`, `TokenResponse` e do token em cache
  mascara o `access_token`.
- Senha de chave e conteúdo PEM lido do disco tratados como `bytearray`
  e zerados após o uso, inclusive em caminho de erro.
- Esquema `https` exigido tanto no endpoint informado quanto no
  `token_endpoint` devolvido pela descoberta (proteção contra
  redirecionamento para texto claro); `http` é aceito apenas para
  `localhost`, `127.0.0.1` e `::1`.
- Rejeição fail-fast de chaves fracas (RSA < 2048 bits, EC < P-256),
  conforme NIST SP 800-57.
- Sem modo "confiar em tudo": a biblioteca não oferece nem executa
  qualquer desativação da verificação de certificado ou de hostname.
- Arquivo temporário usado para carregar o material mTLS criado com
  permissão `0600` e removido logo em seguida.
- Regra arquitetural bloqueante no CI: os módulos de
  assinatura/criptografia não podem depender do cliente HTTP.
