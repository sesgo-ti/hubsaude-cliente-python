# Política de Segurança — hubsaude-cliente-python

## Versões suportadas

Segue [Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/) em
duas eras: durante a série `0.x`, é a versão **MINOR** que marca mudança
incompatível (**PATCH** preserva compatibilidade); a partir de `1.0.0`,
é a versão **MAJOR**. Só a versão mais recente da era vigente recebe
correções de segurança — as anteriores são consideradas fim-de-vida
(EOL) a partir do lançamento da próxima.

| Versão / série                 | Suportada |
| ------------------------------- | --------- |
| Série `0.x` (MINOR mais recente) | ✅        |
| Série `0.x` (MINORs anteriores)  | ❌        |
| `1.x+` (MAJOR mais recente)      | ✅        |
| `1.x+` (MAJORs anteriores)       | ❌        |

## Como reportar uma vulnerabilidade

Pedimos **divulgação responsável**. Não abra issues públicas para
vulnerabilidades de segurança. Use um dos canais abaixo.

### Canal preferencial — GitHub Security Advisories

Abra um *private security advisory* em:

<https://github.com/sesgo-ti/hubsaude-cliente-python/security/advisories/new>

Vantagens:
- Histórico privado, com auditoria
- Permite atribuição de CVE pelo GitHub
- Integra com o fluxo de patch

### Canal alternativo — e-mail

Caso não use o GitHub, envie para:

**kyriosdata@ufg.br**

Inclua, sempre que possível:
- Descrição do problema e impacto estimado
- Passos para reproduzir (PoC mínimo)
- Versões afetadas
- Sugestão de mitigação, se houver

## Processo de resposta

| Etapa                                 | Prazo-alvo            |
| ------------------------------------- | --------------------- |
| Acuso de recebimento                  | 3 dias úteis          |
| Avaliação inicial e classificação     | 10 dias úteis         |
| Correção em ramo privado              | conforme severidade   |
| Coordenação de divulgação             | acordada com o autor  |
| Release com correção + advisory       | conforme severidade   |

Severidade segue [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document).

## Reconhecimento

Pesquisadores que reportarem vulnerabilidades de boa-fé serão
reconhecidos publicamente no advisory, salvo solicitação explícita de
anonimato.

## Escopo

Este documento cobre o artefato publicado como `hubsaude-client` no
PyPI (nome do pacote em `pyproject.toml`).
