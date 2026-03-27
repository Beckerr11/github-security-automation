# Deploy

Este repositorio suporta dois modos de deploy via GitHub Actions:

1. **Deploy Hook HTTP** (qualquer provedor)
2. **Fallback Vercel CLI**

## Segredos aceitos
### Opcao 1: Hook
- `DEPLOY_HOOK_URL_STAGING`
- `DEPLOY_HOOK_URL_PRODUCTION`

### Opcao 2: Vercel
- `VERCEL_TOKEN`
- `VERCEL_ORG_ID`
- `VERCEL_PROJECT_ID`

## Como disparar
1. Abra **Actions** no GitHub.
2. Execute o workflow **Deploy**.
3. Escolha `staging` ou `production`.

## Comportamento
- Se hook estiver configurado para o ambiente, ele sera usado.
- Se nao houver hook, o workflow tenta deploy por Vercel CLI.
- Se nenhum modo estiver configurado, o job falha com mensagem orientativa.
