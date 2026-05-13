import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .risk import score_to_risk


def build_http_session():
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = build_http_session()


def request_json(url, headers=None, timeout=10):
    try:
        response = SESSION.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            return response.json(), None
        if response.status_code == 401:
            return None, "Nao autorizado (401). Verifique sua API key."
        if response.status_code == 429:
            return None, "Rate limit atingido (429)."
        return None, f"Erro HTTP {response.status_code}."
    except requests.exceptions.Timeout:
        return None, "Timeout na consulta."
    except requests.exceptions.RequestException as exc:
        return None, f"Falha de rede: {exc}"


def query_openphish_url(ioc_value):
    try:
        resp = SESSION.get("https://openphish.com/feed.txt", timeout=10)
        if resp.status_code == 200 and ioc_value.lower() in resp.text.lower():
            score = 80
            return {
                "source": "OpenPhish",
                "risk_score": score,
                "risk": score_to_risk(score),
                "details": "URL phishing detectada",
            }, None
        return None, None
    except requests.exceptions.RequestException as exc:
        return None, f"OpenPhish: {exc}"


def query_otx(ioc_type, ioc_value, otx_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type.lower()}/{ioc_value}/general"
    headers = {"X-OTX-API-KEY": otx_key}
    data, err = request_json(url, headers=headers, timeout=10)
    if data:
        pulse_count = len(data.get("pulse_info", {}).get("pulses", []))
        score = min(95, pulse_count * 15) if pulse_count > 0 else 20
        return {
            "source": "OTX",
            "risk_score": score,
            "risk": score_to_risk(score),
            "details": f"{pulse_count} pulses encontrados",
        }, None
    if err:
        return None, f"OTX: {err}"
    return None, None


def query_abuseipdb(ioc_value, abuse_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc_value}&maxAgeInDays=30"
    headers = {"Key": abuse_key, "Accept": "application/json"}
    data, err = request_json(url, headers=headers, timeout=10)
    if data:
        score = data["data"]["abuseConfidenceScore"]
        return {
            "source": "AbuseIPDB",
            "risk_score": score,
            "risk": score_to_risk(score),
            "details": f"Score: {score}/100",
        }, None
    if err:
        return None, f"AbuseIPDB: {err}"
    return None, None


def query_shodan(ioc_value, shodan_key):
    url = f"https://api.shodan.io/shodan/host/{ioc_value}?key={shodan_key}"
    data, err = request_json(url, timeout=12)
    if data:
        ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys())
        services = [item.get("product", item.get("module", "Unknown")) for item in data.get("data", [])]
        summary = f"Portas: {ports[:10]} | Vulns: {len(vulns)} | Servicos: {services[:5]}"
        score = 92 if vulns else 75 if len(ports) > 5 else 50
        details = {"ports": ports[:10], "vulns": vulns[:5]}
        return {
            "source": "Shodan",
            "risk_score": score,
            "risk": score_to_risk(score),
            "details": summary,
            "extra_json": details,
        }, None
    if err:
        return None, f"Shodan: {err}"
    return None, None


def query_censys(ioc_value, censys_token):
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ioc_value}"
    headers = {"Authorization": f"Bearer {censys_token}"}
    data, err = request_json(url, headers=headers, timeout=15)
    if data:
        services = data.get("services", []) if "services" in data else []
        num_services = len(services)
        service_names = [service.get("service_name", "Unknown") for service in services[:6]]
        summary = f"Servicos expostos: {num_services} | Exemplos: {service_names}"
        score = 92 if num_services > 10 else 75 if num_services > 4 else 50
        details = {"total_servicos": num_services, "exemplos": service_names}
        return {
            "source": "Censys",
            "risk_score": score,
            "risk": score_to_risk(score),
            "details": summary,
            "extra_json": details,
        }, None
    if err:
        return None, f"Censys: {err}"
    return None, None


def fetch_openphish_feed(limit=100):
    resp = SESSION.get("https://openphish.com/feed.txt", timeout=15)
    resp.raise_for_status()
    return resp.text.strip().split("\n")[:limit]

