# Security Policy

## Reportar vulnerabilidade
Envie o reporte de forma privada para o mantenedor do repositorio.
Inclua passos de reproducao, impacto e possivel mitigacao.

## Baseline de seguranca adotada
- Branch protection ativa em main
- Revisao obrigatoria de PR
- Bloqueio de force push/deletion
- Dependabot habilitado

## Segredos
- Nunca commitar .env com valores reais.
- Usar GitHub Secrets para CI/CD.
- Rotacionar chaves apos qualquer suspeita de exposicao.
