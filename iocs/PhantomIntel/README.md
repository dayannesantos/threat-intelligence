# PhantomIntel

**Ferramenta de Threat Intelligence 100% local.**

PhantomIntel é uma aplicação simples e completa feita em Python + Streamlit que permite buscar, enriquecer e analisar IOCs (Indicadores de Compromisso) diretamente na sua máquina, sem enviar nenhum dado para a nuvem. Desenvolvida para analistas de Blue Team, SOC, Threat Hunters e pesquisadores de segurança que querem controle total dos seus dados.

## Funcionalidades

- Busca inteligente de IOCs (IP, Domain, URL e Hash)
- Enriquecimento automático com **Shodan** e **Censys** (portas abertas, serviços expostos, vulnerabilidades)
- Integração com OpenPhish, AlienVault OTX e AbuseIPDB
- Coleta automática do feed de phishing mais recente
- Dashboard interativo com métricas e gráficos
- Histórico completo de todas as consultas
- Exportação do relatório em CSV
- Análise avançada com Grok (xAI) — opcional (requer créditos)

## Requisitos

- Python 3.10 ou superior
- Chaves de API opcionais (não são obrigatórias para uso básico):
  - Shodan (recomendado)
  - Censys Personal Access Token
  - AlienVault OTX
  - AbuseIPDB

## Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/dayannesantos/threat-intelligence/iocs/phantomintel.git
   cd phantomintel
   ```

2. Instale as dependências:
   ```bash
   pip install requeriments.txt
   ```

3. Rode a ferramenta:
   ```bash
   streamlit run phantom_intel.py
   ```

A interface vai abrir automaticamente no navegador.

## Como usar

1. Abra o PhantomIntel
2. Cole suas chaves de API no sidebar (opcional)
3. Vá na aba **Busca IOC**
4. Digite um IP, domínio, URL ou hash e clique em "Buscar em todas as fontes"
5. Use os botões **Enriquecer com Shodan** e **Enriquecer com Censys** para dados detalhados
6. Na aba **Análise com Grok** você pode gerar um relatório completo (quando tiver créditos)

## Exemplo de uso

Dados reais testados em março/2026:

- **IP**: `185.196.11.225` → infraestrutura de exploração FortiGate
- **Domain**: `trezor-securite.com` → phishing de carteira Trezor
- **URL**: `https://trezor-securite.com/` → phishing ativo
- **Hash**: `969d2776df0674a1cca0f74c2fccbc43802b4f2b62ecccecc26ed538e9565eae` → documento malicioso APT28

## Capturas de tela
<img width="1366" height="672" alt="Screenshot_2026-03-02_14_10_32" src="https://github.com/user-attachments/assets/0f6b4d6c-b57d-4a9d-b594-27869304c916" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_10_49" src="https://github.com/user-attachments/assets/49bb8cce-2b9d-4e44-aa2c-6b583ece8242" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_11_13" src="https://github.com/user-attachments/assets/70b81383-96cb-4523-9898-0acfa1d949f6" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_11_06" src="https://github.com/user-attachments/assets/22ecf4ab-eb9a-4dc4-8b03-23062eeee533" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_12_13" src="https://github.com/user-attachments/assets/e7370657-f218-405d-8ca2-13bcbcc53dbf" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_12_38" src="https://github.com/user-attachments/assets/76e3be4f-010b-42ca-b45d-eed8e1348da8" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_12_42" src="https://github.com/user-attachments/assets/63c54b71-3684-4d31-9460-8b74e063559c" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_13_03" src="https://github.com/user-attachments/assets/3043e9a7-5c89-4125-bd5b-a74bca42c6ad" /><br><br>

<img width="1366" height="672" alt="Screenshot_2026-03-02_14_13_20" src="https://github.com/user-attachments/assets/b28a3819-142a-42fe-a98e-6d1118500249" /><br><br>

