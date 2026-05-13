import os
import platform
from pathlib import Path


APP_NAME = "phantomintel"
KEYRING_SERVICE = APP_NAME


def get_data_dir() -> Path:
    system = platform.system().lower()
    home = Path.home()

    if system == "linux":
        xdg_data_home = os.getenv("XDG_DATA_HOME")
        base = Path(xdg_data_home) if xdg_data_home else home / ".local" / "share"
        data_dir = base / APP_NAME
    elif system == "windows":
        appdata = os.getenv("APPDATA")
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
        data_dir = base / APP_NAME
    else:
        data_dir = home / f".{APP_NAME}"

    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir

