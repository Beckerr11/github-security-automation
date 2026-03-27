# github-security-automation

Automacao de auditoria de seguranca para repositorios GitHub.

## Objetivo
Construir uma base profissional para portfolio full stack com foco em simplicidade, clareza e evolucao incremental.

## Stack
Python + GitHub API + GitHub Actions

## MVP (v0.1)
- Coleta de alertas
- Resumo de branch protection
- Relatorio markdown
- Checklist automatica

## Estrutura inicial
- docs/ROADMAP.md: plano de evolucao
- src/: codigo fonte principal
- 	ests/: testes iniciais
- .github/workflows/ci.yml: pipeline minima

## Como executar
Veja as instrucoes no docs/ROADMAP.md e no bloco de setup abaixo.
`ash
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
pytest
python src/audit.py --help
`
## Status
- [x] Scaffold inicial
- [ ] MVP funcional
- [ ] Deploy publico
- [ ] Observabilidade e seguranca avancada