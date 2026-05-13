import hashlib
import json
import time
from datetime import datetime

from .config import KEYRING_SERVICE, get_data_dir

try:
    import keyring
except Exception:
    keyring = None


DATA_DIR = get_data_dir()
KEYS_FILE = DATA_DIR / "keys.json"
DATA_FILE = DATA_DIR / "intel_data.json"
CACHE_FILE = DATA_DIR / "cache.json"
KEY_NAMES = ["xai_key", "otx_key", "abuse_key", "shodan_key", "censys_token"]


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def load_saved_keys():
    loaded = {}
    if keyring:
        for key_name in KEY_NAMES:
            try:
                loaded[key_name] = keyring.get_password(KEYRING_SERVICE, key_name) or ""
            except Exception:
                loaded[key_name] = ""
        return loaded

    if KEYS_FILE.exists():
        try:
            with open(KEYS_FILE, "r", encoding="utf-8") as file_obj:
                return json.load(file_obj)
        except Exception:
            return {}
    return {}


def save_keys(keys: dict):
    if keyring:
        errors = []
        for key_name, key_value in keys.items():
            try:
                keyring.set_password(KEYRING_SERVICE, key_name, key_value)
            except Exception as exc:
                errors.append(f"{key_name}: {exc}")
        return errors

    try:
        with open(KEYS_FILE, "w", encoding="utf-8") as file_obj:
            json.dump(keys, file_obj, indent=2, ensure_ascii=False)
        return []
    except Exception as exc:
        return [f"file_store: {exc}"]


def load_intel_data():
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as file_obj:
                data = json.load(file_obj)
                return data if isinstance(data, list) else []
        except Exception:
            return []
    return []


def save_intel_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as file_obj:
        json.dump(data, file_obj, indent=2, ensure_ascii=False)


def get_intel_uid(entry: dict) -> str:
    base = f"{entry['type']}|{entry['value']}|{entry['source']}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def upsert_intel_entry(data_list: list, entry: dict):
    entry["uid"] = get_intel_uid(entry)
    for idx, existing in enumerate(data_list):
        if existing.get("uid") == entry["uid"]:
            merged = existing.copy()
            merged.update(entry)
            data_list[idx] = merged
            return False
    data_list.append(entry)
    return True


def load_cache():
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as file_obj:
                data = json.load(file_obj)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def save_cache(cache_data):
    with open(CACHE_FILE, "w", encoding="utf-8") as file_obj:
        json.dump(cache_data, file_obj, indent=2, ensure_ascii=False)


def _cache_key(source: str, ioc_type: str, ioc_value: str) -> str:
    return f"{source}|{ioc_type}|{ioc_value}"


def get_cached_result(cache_data: dict, source: str, ioc_type: str, ioc_value: str, ttl_seconds: int):
    key = _cache_key(source, ioc_type, ioc_value)
    cached = cache_data.get(key)
    if not cached:
        return None
    age = time.time() - cached.get("saved_at_epoch", 0)
    if age > ttl_seconds:
        return None
    return cached.get("result")


def set_cached_result(cache_data: dict, source: str, ioc_type: str, ioc_value: str, result):
    key = _cache_key(source, ioc_type, ioc_value)
    cache_data[key] = {"saved_at_epoch": time.time(), "result": result}


def prune_expired_cache(cache_data: dict, max_age_seconds: int):
    now_epoch = time.time()
    keys_to_remove = []
    for key, payload in cache_data.items():
        age = now_epoch - payload.get("saved_at_epoch", 0)
        if age > max_age_seconds:
            keys_to_remove.append(key)
    for key in keys_to_remove:
        cache_data.pop(key, None)
    return len(keys_to_remove)

