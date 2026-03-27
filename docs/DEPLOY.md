# Deploy

Este repositorio usa deploy por hook HTTP para facilitar integracao com provedores como Render, Railway, Netlify ou Vercel.

## Segredos necessarios (GitHub Actions)
Configure no repositorio:
- `DEPLOY_HOOK_URL_STAGING`
- `DEPLOY_HOOK_URL_PRODUCTION`

## Como disparar
1. Abra **Actions** no GitHub.
2. Execute o workflow **Deploy**.
3. Escolha `staging` ou `production`.

## Observacoes
- O workflow apenas aciona o hook; build e rollout acontecem no provedor.
- Para rollback, use a interface do provedor (release/deploy anterior).
- Garanta que as variaveis de ambiente do provedor estao configuradas antes do deploy.
