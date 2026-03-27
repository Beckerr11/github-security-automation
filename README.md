# github-security-automation

![CI](https://github.com/Beckerr11/github-security-automation/actions/workflows/ci.yml/badge.svg)

Automacao de seguranca para GitHub.

## Objetivo
Este repositorio faz parte de uma trilha de portfolio profissional full stack, com foco em simplicidade, clareza e boas praticas.

## Stack
Python, GitHub API, auditoria de compliance

## Funcionalidades implementadas
- Auditoria de protection, reviews e enforce_admins
- Coleta de dependabot/code scanning/secret scanning
- Relatorios JSON/Markdown/CSV
- Workflow nightly para auditoria automatica

## Como executar
~~~bash
python -m venv .venv
. .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
~~~

## Scripts uteis
- python src/audit.py --help, python -m pytest -q

## Qualidade
- CI em .github/workflows/ci.yml
- Dependabot em .github/dependabot.yml
- Testes locais obrigatorios antes de merge

## Documentacao
- [Guia de deploy](docs/DEPLOY.md)
- [Roadmap](docs/ROADMAP.md)
- [Checklist de producao](docs/PRODUCTION-CHECKLIST.md)
- [Contribuicao](CONTRIBUTING.md)
- [Seguranca](SECURITY.md)

## Status
- [x] Scaffold inicial
- [x] Base funcional com testes
- [ ] Deploy publico com observabilidade completa
- [ ] Versao 1.0.0 com demo publica

