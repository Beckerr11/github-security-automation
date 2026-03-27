# Contributing

Obrigado por contribuir com **github-security-automation**.

## Fluxo recomendado
1. Abra uma issue descrevendo bug ou melhoria.
2. Crie branch a partir de main.
3. Mantenha PR pequeno e objetivo.
4. Garanta CI verde antes do merge.

## Setup local
~~~bash
python -m venv .venv
. .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
~~~

## Boas praticas
- Nomes claros para funcoes e variaveis.
- Evitar duplicacao e manter simplicidade.
- Preservar compatibilidade de API quando possivel.

## Testes
Execute antes de abrir PR:
- python src/audit.py --help, python -m pytest -q
