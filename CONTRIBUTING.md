# Como contribuir com hubsaude-cliente-python

Obrigado pelo interesse em contribuir! Este documento descreve o processo
padronizado de contribuição.

## Código de conduta

Toda interação está sujeita ao [Código de Conduta](CODE_OF_CONDUCT.md),
baseado no Contributor Covenant 2.1.

## Licença das contribuições

Ao submeter um Pull Request, você concorda em licenciar sua contribuição
sob a **Apache License 2.0**, a mesma licença deste projeto. Veja
[LICENSE](LICENSE).

## Developer Certificate of Origin (DCO)

Este projeto adota o [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Toda contribuição precisa ter `Signed-off-by:` em cada commit.

Assine automaticamente:

```bash
git commit -s -m "feat: minha alteração"
```

Isso adiciona ao corpo da mensagem:

```
Signed-off-by: Seu Nome <seu@email.com>
```

Esse trailer atesta que você tem direito de submeter o trabalho sob a
licença do projeto, conforme o texto integral do DCO. Commits sem
`Signed-off-by:` serão bloqueados pelo CI.

## Fluxo de contribuição

1. **Issue primeiro**: abra ou comente em uma issue descrevendo o problema
   ou a feature.
2. **Fork e branch**: trabalhe em branch dedicado a partir de `develop`.
   Nome sugerido: `feat/curto-descritivo`, `fix/issue-123`, `docs/...`.
3. **Conventional Commits**:
   - `feat:` nova funcionalidade
   - `fix:` correção de bug
   - `docs:` documentação
   - `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`
4. **Testes obrigatórios**: toda mudança de comportamento exige teste novo
   ou atualização do existente. Cobertura é monitorada via `pytest-cov`
   (mínimo de 85% no `hubsaude-cliente-python`).
5. **Build verde** localmente antes de abrir PR:
   ```bash
   tox
   ```
   Isso roda a suíte de testes (`py312`, cobertura mínima de 85%), lint
   (`lint`) e checagem de dependências/SAST (`security`) — os mesmos
   três ambientes usados no CI (`envlist` padrão do `tox.ini`). Sem
   `tox`, equivalente manual:
   ```bash
   pytest --cov=hubsaude_client --cov-report=term-missing --cov-fail-under=85
   ```
   O projeto não participa de um workspace/monorepo compartilhado — o
   build deve ser executado a partir da raiz deste repositório, dentro
   do `virtualenv`/`venv` correspondente.
   Para rodar um ambiente isoladamente: `tox -e lint` (Ruff, Black
   `--check`, mypy `--strict`), `tox -e security` (pip-audit `--strict`,
   Bandit) ou `tox -e archrules` (import-linter).
6. **PR pequeno e focado**: prefira PRs de até ~400 linhas modificadas.
7. **Descrição do PR**: explique *o quê*, *por quê* e *como testar*.
   Referencie issues com `Closes #123`.

## Testes do caminho PKCS#11/HSM (SoftHSM2)

Os testes de `strategy_factory.from_pkcs11` (`tests/test_pkcs11_strategy_factory.py`)
usam um token SoftHSM2 efêmero via `tests/pkcs11_softhsm_helper.py` e são
pulados automaticamente (`SKIPPED`) quando o ambiente não tem SoftHSM2
instalado — o que **não** significa que o código do caminho PKCS#11 não
tenha teste, apenas que ele não roda sem essa dependência de sistema.

Para rodá-los localmente (validado em Ubuntu 24.04):

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y softhsm2 opensc

# macOS (Homebrew)
brew install softhsm

# instala o binding Python opcional (extra "hsm" do pyproject.toml)
pip install -e ".[dev,hsm]"

pytest --cov=hubsaude_client --cov-report=term-missing
```

Com o SoftHSM2 presente, os 7 testes deixam de aparecer como `SKIPPED` e
`pkcs11_signing_strategy.py`/`strategy_factory.py` (função `from_pkcs11`)
passam a ter cobertura real medida, não apenas o resto da suíte. Não é
necessário nenhum passo manual de inicialização de token — cada teste cria
e destrói o próprio token SoftHSM2 isolado em um diretório temporário
(`tests/pkcs11_softhsm_helper.py::softhsm2_token`).

## Testes de integração (simulador real)

Os 14 casos de `tests/test_smart_token_client_integration.py` (marcados
`@pytest.mark.integration`) sobem o `hubsaude-simulador` — servidor de
autorização SMART Backend Services simulado, empacotado como JAR
executável — como processo filho real e falam mTLS real com
ele, exercitando o `SmartTokenClient` ponta a ponta. Assim como os testes de
SoftHSM2 acima, são pulados automaticamente (`SKIPPED`) quando o
pré-requisito não está disponível no ambiente — o que **não** significa
ausência de cobertura, apenas que o teste não roda sem essa dependência
de sistema; ficam fora da suíte padrão (`pytest`/`tox` sem seletor de
marker roda com `-m "not integration"`).

Pré-requisitos: Java 21+ no `PATH`, mais o JAR do `hubsaude-simulador`
localizado via `HUBSAUDE_SIMULADOR_JAR` (variável de ambiente) ou, como
alternativa de conveniência, copiado para `.simulator/hubsaude-simulador.jar`
na raiz do repositório (diretório já coberto pelo `.gitignore`). O JAR
em si não é distribuído neste repositório — obtenha-o com quem mantém o
`hubsaude-simulador`.

```bash
export HUBSAUDE_SIMULADOR_JAR=/caminho/para/hubsaude-simulador.jar
# ou: cp /caminho/para/hubsaude-simulador.jar .simulator/
pytest -m integration -v
# ou
tox -e integration
```

A resolução do caminho do JAR (variável de ambiente vs. fallback) tem
teste unitário dedicado, sem depender de JDK, em
`tests/test_hubsaude_simulator_helper.py`.

## Teste contra um HubSaúde real (`real_hub`, opt-in)

Diferente da suíte de integração acima (que sobe o `hubsaude-simulador`
localmente), `tests/test_smart_token_client_real_hub.py` (marcados
`@pytest.mark.real_hub`) fala com um HubSaúde **real** — via mTLS de
verdade, usando uma credencial (`client_id` + chave/certificado) já
emitida no credenciamento. Ver [Teste com credenciais
reais](README.md#teste-com-credenciais-reais-pós-credenciamento) no
`README.md` para o contexto de por que esse teste existe (a lib não tem
— nem terá — uma ferramenta CLI própria para isso).

Nunca disparado por `tox -e integration` nem pela suíte padrão — só
roda com `pytest -m real_hub`, e mesmo assim fica `SKIPPED` sem as
variáveis de ambiente `HUBSAUDE_REAL_CLIENT_ID`,
`HUBSAUDE_REAL_KEY_PATH` e `HUBSAUDE_REAL_CERT_PATH` (mais opcionais —
`HUBSAUDE_REAL_FHIR_BASE`, `HUBSAUDE_REAL_IG`/`HUBSAUDE_REAL_IG_VERSAO`,
`HUBSAUDE_REAL_SCOPE`, `HUBSAUDE_REAL_TLS_PROTOCOL` — ver docstring do
módulo para o papel de cada uma):

```bash
export HUBSAUDE_REAL_CLIENT_ID=...
export HUBSAUDE_REAL_KEY_PATH=/caminho/para/chave-privada-real.pem
export HUBSAUDE_REAL_CERT_PATH=/caminho/para/certificado-real.pem
pytest -m real_hub -v
```

## Categoria `quarantine`

Marker reservado para isolar um teste especificamente instável
(flakiness conhecida) da execução padrão, sem misturá-lo com
`integration` (que exclui por *dependência de sistema*, não por
instabilidade). Nenhum teste usa este marker hoje — é infraestrutura de
categorização disponível para quando for necessário, não uma pendência
de implementação.

## Padrões técnicos

- **Python 3.12**. Build com **pip + venv** (`python -m venv .venv && pip install -e ".[dev]"`_)
  — sem gerenciador de pacotes proprietário, para manter
  a lib acessível a qualquer contribuidor/consumidor.
- **Linhas**: preferencialmente curtas, máximo de 120 caracteres
  conforme o Ruff/Black centrais.
- **Docstrings** em pt-BR para a API pública (padrão Google ou
  NumPy, conforme convenção do time).
- **Sem `print()`**: use o módulo `logging` (ou `structlog`).
- **Imutabilidade** preferida (`@dataclass(frozen=True)`, `NamedTuple`,
  `Final`, coleções imutáveis como `tuple`/`frozenset`).
- **import-linter** (`contracts` em `pyproject.toml` ou
  `.importlinter`) — regras arquiteturais são bloqueantes. As regras
  são mantidas localmente para preservar a independência total do
  cliente (sem dependência do monorepo HubSaúde).
- **Layout achatado do pacote de assinatura/TLS**: `algorithms.py`,
  `pem_loader.py`, `strategy_factory.py`, `ssl_context_factory.py` etc.
  ficam soltos direto em `hubsaude_client/`, sem subpacote `signing/`
  dedicado — decisão definitiva, não provisória. Consequência prática:
  o contrato "Modulos de assinatura nao dependem de HTTP" em
  `[tool.importlinter]` (`pyproject.toml`) lista os módulos um a um em
  `source_modules`, em vez de apontar para um pacote só. **Todo PR que
  adicionar um novo módulo de assinatura/TLS DEVE incluí-lo nessa
  lista** — do contrário a regra deixa de valer para o módulo novo
  silenciosamente (sem falha visível de lint/CI).

## Política de versionamento

[Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/):

- durante a série `0.x`, **MINOR** pode incluir mudanças incompatíveis e
  **PATCH** preserva compatibilidade;
- a partir de `1.0.0`, **MAJOR** indica quebra na API pública, **MINOR**
  adiciona funcionalidade compatível e **PATCH** contém correções compatíveis.

Apenas a MAJOR mais recente recebe correções de segurança
(ver [SECURITY.md](SECURITY.md)).

## Política de segurança

Vulnerabilidades **não** devem ser reportadas como issues públicas. Veja
[SECURITY.md](SECURITY.md) para o canal apropriado.

## Dúvidas

Abra uma [Discussion](https://github.com/sesgo-ti/hubsaude-cliente-python/discussions)
ou contate os mantenedores via issue.
