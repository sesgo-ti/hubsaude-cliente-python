# Integração enterprise

Este guia complementa o contrato de `hubsaude_client` com decisões de
integração que pertencem à aplicação consumidora. O SDK não depende de
nenhum framework web, biblioteca de resiliência, cliente de métricas ou
OpenTelemetry — as recomendações abaixo são para quem for compor essas
peças por fora.

## Ownership e ciclo de vida

`SmartTokenClient` (obtido via `SmartTokenClientBuilder.build()`) é
thread-safe e deve ser uma instância única por configuração de
credencial. A aplicação é proprietária da instância e deve fechá-la
durante o encerramento:

- aplicações *long-lived* (serviços web, workers): guarde a instância
  num escopo de longa duração (singleton do container de DI, atributo
  de módulo, `app.state` em frameworks ASGI) e feche-a no *shutdown*
  da aplicação;
- CLIs, jobs curtos e scripts: use o cliente como *context manager*
  (`with SmartTokenClientBuilder()...build() as client:`), que chama
  `close()` automaticamente ao sair do bloco, inclusive em caso de
  exceção;
- **não** feche a instância após cada chamada a `obtain_token` — isso
  descarta o `httpx.Client` interno (conexões HTTP reaproveitáveis) e
  invalida o cache de token compartilhado entre scopes, anulando o
  propósito de reutilizar o cliente.

```python
from hubsaude_client.builder import SmartTokenClientBuilder

_client = None

def get_hubsaude_client():
    global _client
    if _client is None:
        _client = (
            SmartTokenClientBuilder()
            .client_id(client_id)
            .token_endpoint(token_endpoint)
            .private_key_pem(private_key_path)
            .certificate_pem(certificate_path)
            .build()
        )
    return _client

# No shutdown da aplicação (ex.: evento "shutdown" do framework web):
def close_hubsaude_client():
    if _client is not None:
        _client.close()
```

`close()` é idempotente: aguarda as operações `obtain_token`/
`obtain_token_response` em voo terminarem, invalida todo o cache e
fecha o `httpx.Client` interno. Chamadas de `obtain_token`/
`obtain_token_response` **após** `close()` levantam `SmartTokenError`
— a aplicação deve tratar isso como erro de programação (uso do
cliente após seu encerramento), não como falha transitória.

## Composição de resiliência

O SDK repete automaticamente apenas falhas transitórias de rede
(timeout de conexão, timeout de requisição, recusa/queda de conexão
TCP — ver `error_classifier.is_transient_network_failure`), com
backoff exponencial (`retry.compute_retry_delay_seconds`: 1s, 2s, 4s,
8s..., sem *jitter* e sem teto). Respostas HTTP efetivamente
recebidas, inclusive `429` e `5xx`, **não** são repetidas
automaticamente — chegam ao chamador como `SmartTokenError`. Um
*circuit breaker* externo deve envolver a chamada a `obtain_token`/
`obtain_token_response` na camada de orquestração do integrador (ex.:
`pybreaker`, `purgatory`, ou uma implementação própria), sem criar
outro laço de retry automático por cima do SDK.

Ao configurar a política de resiliência externa:

1. conte `SmartTokenError` (e, se a integração acessar exceções de
   transporte diretamente, `httpx.HTTPError`) como falha para fins do
   circuit breaker;
2. não trate cancelamento cooperativo (ex.: `KeyboardInterrupt` ou
   `asyncio.CancelledError`, quando a chamada estiver envolvida numa
   *task* cancelável) como sucesso nem o absorva silenciosamente —
   propague o cancelamento;
3. trate `429` conforme o header `Retry-After` (quando presente) e a
   política operacional da aplicação — isso é responsabilidade do
   integrador, fora do retry interno do SDK, que nunca repete respostas
   HTTP recebidas;
4. limite qualquer nova tentativa após `401` a **uma única** renovação
   de token: chame `client.invalidate_cache(scope=...)` para descartar
   a entrada em cache daquele scope, obtenha um token novo com uma
   chamada a `obtain_token`/`obtain_token_response` e, se o erro `401`
   persistir mesmo com o token renovado, interrompa o fluxo — é sinal
   de problema de credencial/autorização, não de token expirado, e
   tentativas adicionais só mascarariam o diagnóstico.

## Métricas

Instrumente a fachada da aplicação (o ponto onde `obtain_token`/
`obtain_token_response` é chamado), não o SDK — `hubsaude_client` não
expõe hooks de métricas. Para Prometheus (ex.: via `prometheus-client`),
siga a convenção de métricas:

| Finalidade | Nome recomendado |
|------------|------------------|
| Total de solicitações | `hubsaude_<servico>_token_request_total` |
| Duração | `hubsaude_<servico>_token_request_duration_seconds` |
| Falhas | `hubsaude_<servico>_token_error_total` |

Use labels de baixa cardinalidade, como `outcome` e uma categoria
fechada de erro (ex.: derivada do tipo de `SmartTokenError`/exceção de
transporte capturada, nunca da mensagem livre). Não use `scope`,
`client_id`, o próprio token, trace-id, CPF, CNS ou outro identificador
pessoal como label: scopes livres e identificadores de cliente criam
cardinalidade não limitada; tokens e dados pessoais também violam o
contrato de segredo do SDK e a LGPD.

Os labels de identidade de serviço e ambiente devem ser `service` e
`env`.

## Trace e diagnóstico

Cada requisição HTTP feita pelo SDK (token endpoint e descoberta via
`.well-known/smart-configuration`) envia o header `traceparent` W3C
(`hubsaude_client.TraceContext`, gerado por requisição — inclusive a
cada retry). O trace-id efetivo não aparece automaticamente nos logs da
aplicação (o SDK não configura logging estruturado da requisição por
padrão); para correlacionar com o suporte do HubSaúde, capture o
`traceparent` enviado (ex.: instrumentando o `httpx.Client` ou gerando
o `TraceContext` manualmente antes de uma chamada de diagnóstico) e
inclua o trace-id nos logs/mensagens de erro da própria aplicação.
Informe esse valor ao suporte do HubSaúde para correlacionar a
requisição do integrador com os registros da plataforma.

Nunca registre em log o `access_token`, o `client_assertion` (JWT
assinado), a chave privada, a senha do PEM/PKCS#12, o PIN do PKCS#11
ou o corpo bruto não sanitizado de uma resposta de erro — use
`SmartTokenError`/`SigningError` (mensagens já sanitizadas pelo SDK,
ver `error_classifier.sanitize_error_response`) como fonte de
diagnóstico.

## Referências

- [README do SDK](../README.md)
- [Contrato comportamental](../ESPECIFICACAO.md)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
