# PhantomIntel

Ferramenta local de Threat Intelligence com:
- Busca de IOC em OpenPhish, OTX e AbuseIPDB
- Enriquecimento com Shodan e Censys
- Analise com Grok (xAI)
- Persistencia local e deduplicacao
- Retry/backoff automatico para APIs
- Cache TTL por IOC (configuravel na sidebar)
- Busca em lote por arquivo CSV/TXT
- Paralelismo configuravel no processamento em lote
- Export CSV dedicado do ultimo lote executado
- Limpeza automatica de cache expirado

## Requisitos

- Python 3.10+
- Conta/API keys das fontes opcionais

## Instalar (Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Para armazenamento seguro de credenciais no Linux, instale um backend de keyring (ex.: `gnome-keyring` ou `kwallet`).

## Rodar

```bash
streamlit run phantom_intel.py
```

## Onde os dados ficam salvos

- Linux: `${XDG_DATA_HOME:-~/.local/share}/phantomintel`
- Windows: `%APPDATA%/phantomintel`
- Outros: `~/.phantomintel`

Arquivos:
- `intel_data.json` (historico)
- `keys.json` (fallback quando keyring nao estiver disponivel)

