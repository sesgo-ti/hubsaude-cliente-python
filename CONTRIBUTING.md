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
   ou, sem `tox`:
   ```bash
   cd hubsaude/projetos/hubsaude-cliente-python && pytest --cov=<pacote> --cov-fail-under=85
   ```
   O projeto não participa de um workspace/monorepo compartilhado na raiz
   do repositório — o build deve ser executado dentro do diretório do
   projeto (dentro do `virtualenv`/`venv` correspondente).
   Opcionalmente, execute também as demais verificações de qualidade:
   `tox -e lint` (Flake8/Ruff, Black --check, isort --check-only, mypy) e
   `tox -e security` (pip-audit / Safety para checagem de dependências).
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
