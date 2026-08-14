# hubsaude-cliente-python

## Dependência

<!-- Validar -->

## Política da API pública

## Uso básico

## Ciclo de vida, cache e erros

## Fontes de chave (`SigningStrategy`)

### Tamanho mínimo de chave

### PKCS#12 direto

### HSM via PKCS#11

### OpenBao / chave já carregada

### PEM com senha

## Configuração avançada

### Contexto de Guia de Implementação (`hub_ctx`)

### Identificador de chave (`kid`)

### Descoberta automática do endpoint

### `serverTrustAnchor` — quando usar

## Preparação de certificados PFX/P12 → PEM

## Resiliência em produção

## Correlação e observabilidade (`traceparent`)

## Troubleshooting

## Build e testes

### Configurações de qualidade (perfil `quality`)

## Publicação de nova versão (release)

## Referências

| Especificação | Descrição |
|---------------|-----------|
| [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html) | Perfil HL7 FHIR para autenticação backend-to-backend |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 (`client_credentials`) |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) |
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework e JWT Bearer Assertion |

O [guia de integração enterprise](docs/integracao-enterprise.md)
complementa essas referências com lifecycle, resiliência, métricas e
integração com contêineres.

## Licença e contribuição
