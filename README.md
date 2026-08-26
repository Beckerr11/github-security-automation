# GitHub Security Automation

![CI](https://github.com/Beckerr11/github-security-automation/actions/workflows/ci.yml/badge.svg)

Ferramenta defensiva em Python para transformar configurações e alertas de segurança do GitHub em um **relatório auditável por repositório**.

O projeto consulta a GitHub API, normaliza sinais de proteção e gera saídas em **JSON, Markdown e CSV** com motivos, recomendações e um score de risco heurístico.

## O que é analisado

A listagem de repositórios segue a paginação da GitHub API, em vez de parar nos primeiros 100 resultados. Para cada repositório retornado pela API para o owner consultado, a auditoria pode verificar:

- proteção do branch principal;
- quantidade mínima de reviews;
- exigência de resolução de conversas;
- aplicação das regras a administradores;
- permissão de force push e exclusão do branch;
- alertas abertos do Dependabot;
- alertas de code scanning;
- alertas de secret scanning;
- repositórios sem atividade além do limite configurado.

## Modelo de evidência

A classificação distingue três estados:

- **compliant** — todos os sinais necessários foram observados e atendem aos critérios;
- **non-compliant** — existe ao menos um finding explícito, como branch sem proteção ou alerta aberto;
- **evidência insuficiente** — a API não forneceu todos os sinais necessários para concluir, por exemplo por falta de token, permissão `403` ou recurso indisponível.

Dados indisponíveis aparecem como `n/a`, não recebem penalidade artificial no `risk_score` e, sozinhos, não fazem `--fail-on-findings` falhar.

## Saídas

Uma execução gera três representações do mesmo resultado:

```text
security-report.json
security-report.md
security-report.csv
```

O resumo inclui total analisado, quantidade compliant, non-compliant, evidência insuficiente, alto risco, alertas e repositórios stale.

> O `risk_score` é uma heurística operacional deste projeto. Ele não substitui auditoria de segurança, pentest, certificação ou framework formal de compliance.

## Como executar

Requer Python 3.11+.

```bash
python -m venv .venv
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest -q
python src/audit.py --owner Beckerr11
```

Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
python src/audit.py --owner Beckerr11
```

Para consultar endpoints autenticados, forneça o token por variável de ambiente. Nunca grave tokens no repositório ou nos relatórios.

## Opções úteis

```bash
python src/audit.py \
  --owner Beckerr11 \
  --output-prefix security-report \
  --min-reviews 1 \
  --stale-days 180 \
  --fail-on-findings
```

`--fail-on-findings` encerra com código `2` somente quando há repositórios **non-compliant** pelos critérios configurados. Repositórios sem evidência suficiente permanecem separados para revisão manual.

## Arquitetura

```text
GitHub API
   │
   ├── paginated repositories
   ├── branch protection
   ├── Dependabot alerts
   ├── code scanning alerts
   └── secret scanning alerts
   │
   ▼
normalização de evidência
   │
   ├── compliant / non-compliant / unknown
   ├── reasons
   ├── recommendations
   └── risk_score
   │
   ▼
JSON · Markdown · CSV
```

## Engenharia e segurança

- requests com timeout explícito;
- paginação de repositórios e alertas;
- ausência de token/permissão tratada como evidência indisponível;
- `403` de branch protection não é convertido em falso finding;
- recomendações derivadas de motivos explícitos;
- testes com Pytest;
- CI no GitHub Actions;
- análise CodeQL;
- Dependabot;
- workflow de auditoria automatizada.

## Documentação

- [Deploy](docs/DEPLOY.md)
- [Roadmap](docs/ROADMAP.md)
- [Checklist de produção](docs/PRODUCTION-CHECKLIST.md)
- [Contribuição](CONTRIBUTING.md)
- [Política de segurança](SECURITY.md)

## Limites

A ferramenta avalia somente sinais disponíveis pela GitHub API e pelas permissões concedidas ao token. Um repositório marcado como compliant **não é garantia de ausência de vulnerabilidades**; significa apenas que os critérios implementados e observáveis nesta ferramenta foram atendidos.

## Autor

**Douglas Silva**  
[GitHub](https://github.com/Beckerr11) · [Portfólio](https://douglasdev.tech)
