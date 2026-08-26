# GitHub Security Automation

![CI](https://github.com/Beckerr11/github-security-automation/actions/workflows/ci.yml/badge.svg)

Ferramenta defensiva em Python para transformar configurações e alertas de segurança do GitHub em um **relatório auditável por repositório**.

O projeto consulta a GitHub API, normaliza sinais de proteção e gera saídas em **JSON, Markdown e CSV** com motivos, recomendações e um score de risco heurístico.

## O que é analisado

Para cada repositório acessível, a auditoria pode verificar:

- proteção do branch principal;
- quantidade mínima de reviews;
- exigência de resolução de conversas;
- aplicação das regras a administradores;
- permissão de force push e exclusão do branch;
- alertas abertos do Dependabot;
- alertas de code scanning;
- alertas de secret scanning;
- repositórios sem atividade além do limite configurado.

Quando um endpoint exige permissões que o token não possui, o valor é tratado como **indisponível (`n/a`)**, em vez de ser inventado como seguro ou inseguro.

## Saídas

Uma execução gera três representações do mesmo resultado:

```text
security-report.json
security-report.md
security-report.csv
```

O resumo inclui total analisado, quantidade de repositórios aprovados pelos critérios configurados, pendências, alto risco, alertas e repositórios stale.

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

`--fail-on-findings` encerra com código `2` quando os critérios configurados encontram repositórios pendentes, permitindo usar a ferramenta como gate automatizado.

## Arquitetura

```text
GitHub API
   │
   ├── repositories
   ├── branch protection
   ├── Dependabot alerts
   ├── code scanning alerts
   └── secret scanning alerts
   │
   ▼
normalização + critérios
   │
   ├── reasons
   ├── recommendations
   └── risk_score
   │
   ▼
JSON · Markdown · CSV
```

## Engenharia e segurança

- requests com timeout explícito;
- paginação de alertas;
- ausência de token tratada sem simular evidência;
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

A ferramenta avalia somente sinais disponíveis pela GitHub API e pelas permissões concedidas ao token. Um repositório marcado como aprovado pelos critérios configurados **não é garantia de ausência de vulnerabilidades**.

## Autor

**Douglas Silva**  
[GitHub](https://github.com/Beckerr11) · [Portfólio](https://douglasdev.tech)
