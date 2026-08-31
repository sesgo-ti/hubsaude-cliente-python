# hubsaude-cliente-python

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Biblioteca cliente Python do HubSaúde para obtenção de *access tokens*
via [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR), combinando `client_credentials` e `private_key_jwt`
(RFC 7523).

O ponto de entrada é `hubsaude_client.builder.SmartTokenClientBuilder`,
que produz um `hubsaude_client.client.SmartTokenClient` já validado
(fail-fast) e pronto para assinar o JWT *client assertion* com o
material criptográfico do estabelecimento e negociar o token no
endpoint OAuth 2.0. O pacote reúne os colaboradores internos dessa
jornada: estratégias de assinatura (`SigningStrategy` — PEM, PKCS#12 e
HSM/PKCS#11 já implementados), configuração TLS/mTLS (`TlsContextProvider`
— com implementações concretas prontas para PEM, PKCS#12 e trust anchor
customizado), tolerância a falhas com retry exponencial, cache de token
por scope e propagação de contexto de trace W3C.

**Status:** `0.1.0`, em desenvolvimento iterativo. As duas fatias de
implementação (assinatura/certificados/TLS e cliente HTTP/orquestração
de token) estão concluídas e testadas — ver [Referências](#referências)
para o contrato completo (`ESPECIFICACAO.md`). O que resta é conteúdo de
documentação complementar (guia de integração enterprise, tabela de
erros) e o processo de publicação/release, ainda não definidos.

## Dependência

```bash
pip install hubsaude-client
```

Ainda não publicado no PyPI. Para usar a versão de desenvolvimento
(branch `develop`), instale a partir do código-fonte:

```bash
git clone https://github.com/sesgo-ti/hubsaude-cliente-python.git
cd hubsaude-cliente-python
pip install -e .
```

O extra opcional `hsm` (`pip install "hubsaude-client[hsm]"`) traz a
dependência `python-pkcs11`, necessária apenas para quem usa
`strategy_factory.from_pkcs11` (assinatura via HSM/smart token). Quem
usa só PEM ou PKCS#12 não precisa desse extra.

## Política da API pública

Enquanto a biblioteca estiver na série `0.x`, sua API é provisória:
versões `MINOR` podem introduzir mudanças incompatíveis e versões
`PATCH` preservam compatibilidade. A partir de `1.0.0`, a evolução
seguirá estritamente o
[Versionamento Semântico 2.0.0](https://semver.org/lang/pt-BR/) (mesma
política descrita em [`CONTRIBUTING.md`](CONTRIBUTING.md)).

A API pública atual é o conjunto exportado por `hubsaude_client`
(`__all__` em `__init__.py`):

| Símbolo | Descrição |
|---|---|
| `SmartTokenError` | Exceção de domínio para falhas de parsing/resposta inesperada do servidor de autorização. |
| `SigningStrategy` | `Protocol` que abstrai o mecanismo de assinatura digital. |
| `TraceContext` | Geração e formatação do contexto de trace W3C (`traceparent`). |
| `SigningSettings` / `ResolvedSigning` | Configuração agregada de assinatura (fonte de chave, algoritmo JWT, `key_id`) e o resultado da sua resolução. |
| `TlsSettings` | Configuração agregada de TLS/mTLS (certificado de cliente, trust anchor). |

`SmartTokenClientBuilder`/`SmartTokenClient` (o ponto de entrada
público equivalente ao `SmartTokenClient` de outras linguagens do
portfólio) **não** são reexportados na raiz do pacote — importe-os de
`hubsaude_client.builder`/`hubsaude_client.client` diretamente, mesma
convenção usada pelos demais colaboradores internos (`algorithms`,
`defaults`, `exceptions.SigningError`, `fault_tolerance`, `ports`,
`retry`, `token_cache`, `pem_loader`, `strategy_factory`,
`ssl_context_factory`, `key_certificate_consistency`,
`private_key_signing_strategy`, `pkcs11_signing_strategy`,
`response_guard`, `error_classifier`, `discovery`) — não expostos na
raiz do pacote e podem mudar sem aviso.

## Uso básico

```python
from hubsaude_client.builder import SmartTokenClientBuilder

client = (
    SmartTokenClientBuilder()
    .client_id("meu-client-id")
    .token_endpoint("https://auth.hubsaude.exemplo/token")
    .private_key_pem("/caminho/para/chave-privada.pem")
    .server_trust_anchor("/caminho/para/ca-do-servidor.pem")  # opcional; sem isso, usa o trust store padrão do sistema
    .build()
)

resultado = client.obtain_token(scope="system/Patient.rs")
print(resultado)

client.close()  # ou use `with SmartTokenClientBuilder()...build() as client:`
```

Quando a mesma chave/certificado é usada tanto para assinar o
`client_assertion` quanto para apresentar o certificado de cliente no
handshake mTLS, combine `.private_key_pem()` com `.certificate_pem()`
(o builder confere a consistência do par, RF-15) — ou, se o material
estiver num bundle PKCS#12 único, use só `.client_key_store(path,
password)`, que resolve os dois lados de uma vez. `tls_context_provider()`
continua disponível para quem precisa de uma implementação própria de
`hubsaude_client.ports.TlsContextProvider` (ex.: rotação dinâmica de
certificado vinda de um cofre) — é mutuamente exclusivo com
`certificate_pem()`/`client_key_store()`/`server_trust_anchor()`.

`SmartTokenClientBuilder`/`SmartTokenClient` não são reexportados na
raiz do pacote (`hubsaude_client`) — importe-os diretamente de
`hubsaude_client.builder`/`hubsaude_client.client`.

## Ciclo de vida, cache e erros

O pacote já define duas exceções de domínio, ambas preservando a causa
original (`__cause__`) quando fornecida:

| Exceção | Uso | API pública |
|---|---|---|
| `SmartTokenError` | Falhas de parsing de PEM/JSON, configuração inválida ou resposta inesperada do servidor de autorização. | Sim |
| `SigningError` | Falhas durante a operação de assinatura digital, usada por implementações de `SigningStrategy`. | Ainda não exportada na raiz do pacote |

O cache de tokens (`TokenCacheStrategy`, em `token_cache.py`) é
thread-safe por scope, com margem de expiração configurável
(`margin_seconds`) e janela LRU de tamanho fixo (`max_entries`); uma
entrada expirada — ou dentro da margem de renovação — é removida no
próprio acesso (eviction antecipada). É orquestrado por
`SmartTokenClient` (single-flight por scope via *lock striping* +
*double-checked locking*, ver [Resiliência em
produção](#resiliência-em-produção)) e exposto na API pública via
`client.invalidate_cache(scope=None)`. O ciclo de vida do cliente
(fechamento idempotente via `close()`/context manager, que aguarda
operações em voo — `_ReadersWriterLock` privado — e invalida o cache
antes de liberar recursos) também já está implementado; a invalidação
automática de cache após `401` é apenas uma recomendação de integração
externa (não implementada pelo SDK).

## Fontes de chave (`SigningStrategy`)

A escolha de onde a chave privada reside é a decisão arquitetural mais
relevante para uma integração de produção. O contrato está definido em
`hubsaude_client.SigningStrategy` — um `typing.Protocol`
`@runtime_checkable` com um único método:

```python
class SigningStrategy(Protocol):
    def sign(self, data: bytes) -> bytes: ...
```

`sign` recebe os bytes a assinar (tipicamente `header.payload` do JWT)
e retorna a assinatura digital em formato raw (não Base64).
Implementações concretas sinalizam falhas com `SigningError`.

Quatro fontes já têm factory pronta em `hubsaude_client.strategy_factory`,
além do contrato (`Protocol`) e de um fake para testes
(`tests/fakes.py::FakeSigningStrategy`):

| Fonte | Factory | Uso via builder |
|---|---|---|
| Arquivo PEM (com/sem senha) | `from_pem_file(path, password=None)` | `.private_key_pem(path, password=None)` |
| String PEM (ex.: variável de ambiente) | `from_pem_string(pem_content, password=None, source=...)` | — (uso direto da factory + `.signing_strategy(...)`) |
| Chave já carregada em memória | `from_private_key(private_key)` | — (uso direto da factory + `.signing_strategy(...)`, ex.: chave vinda de um cofre como OpenBao) |
| Bundle PKCS#12 | `from_pkcs12(data, password)` | `.client_key_store(path, password)` (resolve também o certificado de cliente para mTLS) |
| HSM/smart token via PKCS#11 | `from_pkcs11(pkcs11_module_path, token_label, key_label, user_pin)` | — (uso direto da factory + `.signing_strategy(...)`) |

### Tamanho mínimo de chave

Já implementado: `pem_loader.validate_minimum_key_size` rejeita chaves
RSA com módulo menor que 2048 bits e chaves EC com curva menor que
P-256 (NIST SP 800-57), com mensagem indicando a origem da chave.
Aplicado automaticamente por `from_pem_file`/`from_pem_string`/
`from_pkcs12` e por `load_pkcs12_key_and_certificate` (usada por
`.client_key_store()`).

### PKCS#12 direto

Já implementado: `strategy_factory.from_pkcs12(path, password)` carrega
chave e certificado de um bundle PKCS#12 e retorna uma `SigningStrategy`
pronta (combine com `.signing_strategy(...)` no builder se só precisar
do lado de assinatura). Para o caso comum — o mesmo bundle serve tanto
para assinar o `client_assertion` quanto para o certificado de cliente
em mTLS — use `.client_key_store(path, password)` no builder, que
resolve os dois de uma vez via `strategy_factory.load_pkcs12_key_and_certificate`.

### HSM via PKCS#11

Já implementado: `strategy_factory.from_pkcs11(pkcs11_module_path,
token_label, key_label, user_pin)` cria uma `SigningStrategy` que nunca
extrai a chave privada do hardware — guarda só um handle de sessão PKCS#11.
Requer o extra opcional `hsm` (`pip install "hubsaude-client[hsm]"`,
dependência `python-pkcs11`) e uma biblioteca PKCS#11 do fabricante do
token (ex.: `libsofthsm2.so` para testes/homologação com
[SoftHSM2](https://github.com/opendnssec/SoftHSMv2)). Combine com
`.signing_strategy(...)` no builder — não há método de conveniência
dedicado no builder para PKCS#11, já que a configuração (módulo, token,
PIN) não tem um equivalente natural de "caminho de arquivo".

### OpenBao / chave já carregada

Sem um método de conveniência dedicado, mas já possível via o contrato
genérico: `.signing_strategy(strategy_factory.from_private_key(chave))`
no builder aceita qualquer instância que satisfaça `SigningStrategy`,
incluindo uma chave já carregada em memória (ex.: obtida de um cofre
como OpenBao).

### PEM com senha

Já implementado: `.private_key_pem(path, password=None)` no builder
delega a `strategy_factory.from_pem_file`, que carrega a chave privada
de um arquivo PEM (com ou sem senha). A senha é recebida como
`bytearray` (mutável) e é **zerada em memória** logo após o uso —
sucesso ou erro (`pem_loader.clear_password`) — para reduzir o tempo
em que o segredo permanece legível em heap dumps. O mesmo vale para a
senha do bundle PKCS#12 em `.client_key_store(path, password)`/
`from_pkcs12`/`load_pkcs12_key_and_certificate`. O PIN de
`from_pkcs11` continua `str`, deliberadamente: é usado uma única vez,
na própria chamada, para abrir a sessão PKCS#11, e nunca fica retido
num campo do builder entre chamadas (ao contrário da senha de
`.client_key_store()`) — não é uma lacuna pendente, é uma decisão de
escopo já fechada.

## Configuração avançada

Já disponível no builder:

### Contexto de Guia de Implementação (`hub_ctx`)

`.hub_context(ig, versao)` valida `ig` (`[a-z][a-z0-9-]{1,30}`) e
`versao` (SemVer completo `MAJOR.MINOR.PATCH`, sem pre-release) e
inclui o claim `hub_ctx` no `client_assertion` quando configurado.

### Identificador de chave (`kid`)

`.key_id(key_id)` inclui o claim `kid` no header do JWT
`client_assertion`.

### Descoberta automática do endpoint

`.fhir_base(url)` (mutuamente exclusivo com `.token_endpoint(url)`)
resolve o token endpoint via
`GET <fhir_base>/.well-known/smart-configuration`, uma única vez, na
construção do cliente.

### TLS/mTLS e `serverTrustAnchor`

Já implementado (`hubsaude_client.ssl_context_factory`). Por design
(`ports.py`), o cliente HTTP consome um `hubsaude_client.ports.TlsContextProvider`
— `Protocol` `@runtime_checkable` com um único método,
`ssl_context() -> ssl.SSLContext` — em vez de um `ssl.SSLContext` já
pronto direto; isso permite recriar o contexto sob demanda (ex.: em
resposta à rotação de certificados) em vez de fixá-lo para o ciclo de
vida inteiro do processo. Três caminhos equivalentes para configurá-lo,
mutuamente exclusivos entre si:

1. **`.server_trust_anchor(caminho_ou_certificado)`** — substitui o
   trust store padrão por um certificado específico (uso típico:
   homologação/simuladores locais). Sem isso, o cliente valida o
   servidor pelo trust store padrão do sistema
   (`ssl.SSLContext.load_default_certs`). A biblioteca não oferece
   nenhum modo "confiar em tudo" na API pública.
2. **`.certificate_pem(caminho)`** — combinado com `.private_key_pem()`,
   apresenta o certificado de cliente no handshake mTLS (o builder
   confere a consistência do par via
   `key_certificate_consistency.verify_strategy`, RF-15). Sem material
   de cliente, a conexão opera como TLS unidirecional, sem erro.
3. **`.client_key_store(caminho, senha)`** — mesmo efeito do item
   anterior, mas a partir de um bundle PKCS#12 único (também resolve a
   estratégia de assinatura, ver [PKCS#12 direto](#pkcs12-direto)).

Protocolo TLS configurável (`tlsProtocol`, padrão `TLSv1.3`,
`defaults.DEFAULT_TLS_PROTOCOL`); `TLSv1.2` também é aceito.
`.tls_context_provider(...)` continua disponível para quem precisa de
uma implementação própria do Protocol (ex.: buscar o `SSLContext`
dinamicamente de um cofre a cada chamada) — é mutuamente exclusivo com
os três métodos de conveniência acima.

## Preparação de certificados PFX/P12 → PEM

Se preferir usar o material diretamente em PKCS#12, sem converter para
PEM, `.client_key_store(path, password)` já cobre tanto o lado de
assinatura quanto o de mTLS a partir do mesmo bundle (ver
[PKCS#12 direto](#pkcs12-direto) e [TLS/mTLS](#tlsmtls-e-servertrustanchor)).
Um guia de conversão PFX/P12 → PEM (para quem prefere a estratégia via
`.private_key_pem()`/`.certificate_pem()`) ainda não foi escrito.

## Resiliência em produção

O cálculo do atraso de *backoff* exponencial entre tentativas está
implementado como colaborador interno
(`hubsaude_client.retry.compute_retry_delay_seconds`):
`1s × 2^(tentativa - 1)` — 1s, 2s, 4s, 8s... — sem *jitter* e sem teto
superior. Apenas falhas transitórias de rede/transporte (timeout de
conexão, timeout de requisição, recusa/queda de conexão TCP) são
tratadas como retriáveis (`error_classifier.py`); respostas HTTP
efetivamente recebidas — incluindo `429` e `5xx` — não sofrem retry
automático.

A orquestração completa está implementada em `client.SmartTokenClient`:
o laço de tentativas é limitado por `max_retries` (padrão 3,
configurável via `.max_retries(n)` no builder) e, esgotadas as
tentativas, o erro final preserva a causa original (`__cause__`). Uma
falha por rejeição de certificado de cliente (mTLS) é detectada
heuristicamente e falha imediatamente, sem retry
(`error_classifier.is_likely_client_certificate_rejection`) — a
heurística em si está testada, mas ainda não foi exercitada contra um
handshake mTLS real (só com exceções `ssl.SSLError` simuladas), já que
depende de um servidor real para reproduzir a rejeição. Ainda assim,
combine qualquer chamada de rede feita pela sua aplicação com um
*circuit breaker* externo na camada de orquestração — está fora do
escopo do SDK por design.

## Correlação e observabilidade (`traceparent`)

O HubSaúde deriva a correlação de cada requisição exclusivamente do
contexto de trace W3C
([W3C Trace Context](https://www.w3.org/TR/trace-context/)); headers
como `X-Correlation-Id` enviados pelo cliente são ignorados.
`hubsaude_client.TraceContext` já implementa a geração desse contexto,
sem depender do SDK OpenTelemetry:

```python
from hubsaude_client import TraceContext

ctx = TraceContext.generate()
header_value = ctx.traceparent()  # "00-<trace-id>-<parent-id>-00"
```

- **trace-id**: 16 bytes aleatórios criptograficamente (32 caracteres
  hex minúsculos), nunca todo-zeros;
- **span-id** (parent-id): 8 bytes aleatórios criptograficamente (16
  caracteres hex minúsculos), nunca todo-zeros;
- **trace-flags**: sempre `00` (*not sampled*) — a biblioteca não
  grava spans, coerente com o W3C Trace Context §3.2.2.5.1.

`TraceContext` é imutável (`@dataclass(frozen=True)`) e valida o
formato na construção: `trace_id`/`span_id` fora do padrão (tamanho,
maiúsculas, todo-zeros) levantam `ValueError`.
`TraceContext.TRACEPARENT_HEADER` contém o nome do header
(`"traceparent"`).

O uso automático — gerar um novo contexto por requisição HTTP
(inclusive cada retry) e enviar o header — já está implementado em
`client.SmartTokenClient` e `discovery.SmartConfigurationDiscovery`;
`TraceContext` também está disponível para uso direto por quem precisa
gerá-lo manualmente.

## Troubleshooting

Para diagnóstico de confiança de certificado SSL/TLS ao conectar-se ao
HubSaúde (erros como *PKIX path building failed* / *SSL handshake
failed*, com detecção via OpenSSL, Java, C#, Node.js e Python),
consulte o [guia de troubleshooting TLS](docs/troubleshooting.md).

Uma tabela de erros específicos desta biblioteca (assinatura, carga de
chave, cliente HTTP) ainda não foi adicionada aqui, embora
`SmartTokenError`/`SigningError` (ver [Ciclo de vida, cache e
erros](#ciclo-de-vida-cache-e-erros)) já cubram os cenários de erro do
cliente HTTP e de todas as estratégias de assinatura/TLS implementadas.

## Build e testes

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov=hubsaude_client --cov-report=term-missing --cov-fail-under=85
```

Ou, com `tox` (orquestra o mesmo fluxo, envlist padrão `py312, lint, security`):

```bash
tox
```

Os testes do caminho PKCS#11 (`tests/test_pkcs11_strategy_factory.py`
e o caso correspondente em `tests/test_builder.py`) são pulados
automaticamente quando o SoftHSM2 não está disponível no ambiente
(`tests/pkcs11_softhsm_helper.py` detecta e configura um token de
teste quando presente). Para exercitá-los, instale o SoftHSM2 do seu
sistema (ex.: pacote `softhsm2` no Debian/Ubuntu) antes de rodar a
suíte.

### Verificações de qualidade (ambientes `tox`)

| Ambiente `tox` | Ferramentas |
|---|---|
| `lint` | Ruff (lint), Black (`--check`), mypy (`--strict`) |
| `security` | pip-audit (`--strict`), Bandit |
| `archrules` | import-linter (`lint-imports`) |

Execute um ambiente isoladamente com `tox -e lint`, `tox -e security`
ou `tox -e archrules`. A única regra arquitetural definida até o
momento (`pyproject.toml`, `[tool.importlinter]`) proíbe que os módulos
de assinatura/criptografia (`algorithms`, `pem_loader`,
`private_key_signing_strategy`, `key_certificate_consistency`,
`strategy_factory`, `ssl_context_factory`, `pkcs11_signing_strategy`,
`tls_settings`, `settings`) dependam de `httpx`, preservando o
desacoplamento em relação ao cliente HTTP — como esses módulos não
formam um subpacote próprio (layout achatado, listados um a um no
contrato), qualquer módulo novo de assinatura/TLS precisa ser
adicionado manualmente a essa lista. Supressões do Bandit devem ser
inline (`# nosec <código> -- justificativa`); a lista global em
`pyproject.toml` (`[tool.bandit]`) fica reservada a casos amplos e
comprovadamente aceitáveis. Supressões do pip-audit ficam em
`pip-audit-suppressions.toml` (vazio no momento).

## Publicação de nova versão (release)

*Pendente.* Ainda não há workflow de release (`.github/workflows/`)
neste repositório; a lib está na versão `0.1.0` (`pyproject.toml`), em
desenvolvimento iterativo. Esta seção será preenchida quando o
processo de publicação for definido.

## Referências

| Especificação | Descrição |
|---------------|-----------|
| [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html) | Perfil HL7 FHIR para autenticação backend-to-backend |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 (`client_credentials`) |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) |
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework e JWT Bearer Assertion |

O contrato comportamental completo, requisito a requisito, está em
[`ESPECIFICACAO.md`](ESPECIFICACAO.md). O
[guia de integração enterprise](docs/integracao-enterprise.md) ainda
está vazio — é onde a recomendação de circuit breaker externo e a
regra de "uma única renovação após 401" (fora do escopo do SDK)
deveriam ser detalhadas.

## Licença e contribuição

Apache License 2.0 — ver [`LICENSE`](LICENSE).

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — fluxo e DCO
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1