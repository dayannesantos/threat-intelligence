import ipaddress
import re
from urllib.parse import urlparse


IOC_HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    clean = value.strip()
    if ioc_type == "Domain":
        return clean.lower()
    if ioc_type == "Hash":
        return clean.lower()
    return clean


def validate_ioc(ioc_type: str, value: str):
    clean = value.strip()
    if not clean:
        return False, "IOC vazio."

    if ioc_type == "IP":
        try:
            ipaddress.ip_address(clean)
            return True, ""
        except ValueError:
            return False, "IP invalido."
    if ioc_type == "Domain":
        return (True, "") if DOMAIN_RE.match(clean) else (False, "Dominio invalido.")
    if ioc_type == "URL":
        parsed = urlparse(clean)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return True, ""
        return False, "URL invalida. Use formato http(s)://..."
    if ioc_type == "Hash":
        is_valid_hash = any(pattern.match(clean) for pattern in IOC_HASH_PATTERNS.values())
        return (True, "") if is_valid_hash else (False, "Hash invalido (MD5/SHA1/SHA256).")

    return False, "Tipo de IOC nao suportado."

