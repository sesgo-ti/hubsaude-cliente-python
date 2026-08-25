# hubsaude-cliente-python

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Biblioteca cliente Python do HubSaúde para obtenção de *access tokens*
via [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR), combinando `client_credentials` e `private_key_jwt`
(RFC 7523).

O ponto de entrada será um cliente HTTP — **ainda não implementado** —
que assinará o JWT *client assertion* com o material criptográfico do
estabelecimento e negociará o token no endpoint OAuth 2.0. O pacote já
reúne os colaboradores internos dessa jornada: estratégias de
assinatura (`SigningStrategy`), tolerância a falhas com retry
exponencial, cache de token por scope e propagação de contexto de
trace W3C. A configuração TLS/mTLS usará `ssl.SSLContext` diretamente,
sem `Protocol` próprio.

**Status:** `0.1.0`, em desenvolvimento ativo e iterativo — nem toda
funcionalidade descrita para o portfólio de SDKs do HubSaúde está
disponível ainda. Cada seção abaixo indica o que já é válido hoje e o
que está pendente.

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

O extra opcional `hsm` (`pip install "hubsaude-client[hsm]"`) já está
declarado em `pyproject.toml` e traz a dependência `python-pkcs11`
para o suporte a HSM planejado; a estratégia de assinatura
correspondente ainda não foi implementada.

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

Os demais módulos (`algorithms`, `defaults`, `exceptions.SigningError`,
`fault_tolerance`, `ports`, `retry`, `token_cache`) são colaboradores
internos — não expostos na raiz do pacote — e podem mudar sem aviso. O
cliente HTTP público (ponto de entrada equivalente ao `SmartTokenClient`
de outras linguagens do portfólio) ainda não foi implementado.

## Uso básico

*Ainda não disponível.* O cliente HTTP que orquestra a obtenção do
token (montagem e assinatura do `client_assertion`, troca no endpoint
OAuth 2.0, cache e retries) ainda não foi implementado nesta
biblioteca — atualmente o pacote expõe apenas os colaboradores internos
dessa jornada. Esta seção será preenchida assim que o ponto de entrada
público existir.

## Ciclo de vida, cache e erros

O pacote já define duas exceções de domínio, ambas preservando a causa
original (`__cause__`) quando fornecida:

| Exceção | Uso | API pública |
|---|---|---|
| `SmartTokenError` | Falhas de parsing de PEM/JSON ou resposta inesperada do servidor de autorização. | Sim |
| `SigningError` | Falhas durante a operação de assinatura digital, usada por implementações de `SigningStrategy`. | Ainda não exportada na raiz do pacote |

O cache de tokens (`TokenCacheStrategy`, em `token_cache.py`) já está
implementado como colaborador interno: cache thread-safe por scope,
com margem de expiração configurável (`margin_seconds`) e janela LRU
de tamanho fixo (`max_entries`); uma entrada expirada — ou dentro da
margem de renovação — é removida no próprio acesso (eviction
antecipada). Ainda não é parte da API pública: será orquestrado pelo
cliente HTTP, que também definirá o ciclo de vida (encerramento,
invalidação de cache após `401` etc.) quando implementado.

## Fontes de chave (`SigningStrategy`)

A escolha de onde a chave privada reside é a decisão arquitetural mais
relevante para uma integração de produção. Hoje, o contrato já está
definido em `hubsaude_client.SigningStrategy` — um `typing.Protocol`
`@runtime_checkable` com um único método:

```python
class SigningStrategy(Protocol):
    def sign(self, data: bytes) -> bytes: ...
```

`sign` recebe os bytes a assinar (tipicamente `header.payload` do JWT)
e retorna a assinatura digital em formato raw (não Base64).
Implementações concretas devem sinalizar falhas com `SigningError`.

Nenhuma implementação concreta foi publicada ainda — apenas o
contrato (`Protocol`) e um fake para testes
(`tests/fakes.py::FakeSigningStrategy`) existem no momento. As
subseções abaixo serão preenchidas conforme cada estratégia for
implementada.

### Tamanho mínimo de chave

*Pendente.* Validação de tamanho mínimo de chave (RSA/EC) ainda não
foi implementada nesta biblioteca.

### PKCS#12 direto

*Pendente.* Estratégia de assinatura via PKCS#12 ainda não
implementada.

### HSM via PKCS#11

*Pendente.* Estratégia de assinatura via PKCS#11 ainda não
implementada. O extra `hsm` (`python-pkcs11`) já está declarado em
`pyproject.toml` para uso futuro.

### OpenBao / chave já carregada

*Pendente.* Estratégia de assinatura a partir de chave já carregada em
memória (ex.: obtida de um cofre como OpenBao) ainda não implementada.

### PEM com senha

*Pendente.* Carga de chave PEM (com ou sem senha) ainda não
implementada.

## Configuração avançada

*Pendente.* Depende de um cliente HTTP/builder, ainda não implementado
nesta biblioteca. As subseções abaixo serão documentadas quando a
funcionalidade correspondente existir.

### Contexto de Guia de Implementação (`hub_ctx`)

*Pendente — ainda não implementado.*

### Identificador de chave (`kid`)

*Pendente — ainda não implementado.*

### Descoberta automática do endpoint

*Pendente — ainda não implementado.*

### `serverTrustAnchor` — quando usar

*Pendente.* Configuração TLS/mTLS ainda não implementada nesta
biblioteca. Por design (`ports.py`), o contrato usará um
`ssl.SSLContext` já pronto, passado diretamente — sem `Protocol`
próprio, já que a stdlib oferece o tipo pronto.

## Preparação de certificados PFX/P12 → PEM

*Pendente.* Nenhuma estratégia de assinatura baseada em PEM ou
PKCS#12 foi implementada ainda (ver
[Fontes de chave](#fontes-de-chave-signingstrategy)).

## Resiliência em produção

O cálculo do atraso de *backoff* exponencial entre tentativas já está
implementado como colaborador interno
(`hubsaude_client.retry.compute_retry_delay_seconds`):
`1s × 2^(tentativa - 1)` — 1s, 2s, 4s, 8s... — sem *jitter* e sem teto
superior. Por decisão de escopo já registrada no módulo, apenas falhas
transitórias de rede/transporte (timeout de conexão, timeout de
requisição, recusa/queda de conexão TCP) devem ser tratadas como
retriáveis; respostas HTTP efetivamente recebidas — incluindo `429` e
`5xx` — não devem sofrer retry automático.

A orquestração completa (cliente HTTP, decisão de *quando* repetir,
número máximo de tentativas) depende do cliente ainda não
implementado; esta seção será expandida quando ele existir. Nesse
meio-tempo, combine qualquer chamada de rede feita pela sua aplicação
com um *circuit breaker* externo na camada de orquestração.

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
(inclusive cada retry) e enviar o header — depende do cliente HTTP,
ainda não implementado; por ora, `TraceContext` está disponível para
uso direto por quem já precisa gerá-lo manualmente.

## Troubleshooting

Para diagnóstico de confiança de certificado SSL/TLS ao conectar-se ao
HubSaúde (erros como *PKIX path building failed* / *SSL handshake
failed*, com detecção via OpenSSL, Java, C#, Node.js e Python),
consulte o [guia de troubleshooting TLS](docs/troubleshooting.md).

Uma tabela de erros específicos desta biblioteca (assinatura, carga de
chave, cliente HTTP) será adicionada aqui conforme essas partes forem
implementadas.

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

### Verificações de qualidade (ambientes `tox`)

| Ambiente `tox` | Ferramentas |
|---|---|
| `lint` | Ruff (lint), Black (`--check`), mypy (`--strict`) |
| `security` | pip-audit (`--strict`), Bandit |
| `archrules` | import-linter (`lint-imports`) |

Execute um ambiente isoladamente com `tox -e lint`, `tox -e security`
ou `tox -e archrules`. A única regra arquitetural definida até o
momento (`pyproject.toml`, `[tool.importlinter]`) proíbe que
`hubsaude_client.algorithms` dependa de `httpx`, preservando o
desacoplamento entre os módulos de assinatura/criptografia e o cliente
HTTP. Supressões do Bandit devem ser inline
(`# nosec <código> -- justificativa`); a lista global em
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

O [guia de integração enterprise](docs/integracao-enterprise.md) ainda
está vazio — será escrito quando o cliente HTTP e as práticas de
lifecycle, resiliência e observabilidade estiverem implementados nesta
biblioteca.

## Licença e contribuição

Apache License 2.0 — ver [`LICENSE`](LICENSE).

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — fluxo e DCO
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
