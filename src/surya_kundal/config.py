"""Settings, read once from the environment (and an optional ``.env`` file).

Every environment variable the program understands is listed here, so there is one
place to look and nothing is read ad hoc deep inside the code.
"""

from __future__ import annotations

import logging
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = "~/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_DATABASE_URL = "sqlite:///data/surya_kundal.db"
DEFAULT_GEOIP_DIR = "data/geoip"
DEFAULT_TOR_CACHE = "data/tor_exit_nodes.txt"
DEFAULT_WAZUH_ALERTS = "data/wazuh/wazuh_alerts.jsonl"


@dataclass(frozen=True)
class Settings:
    log_path: Path
    database_url: str
    geoip_dir: Path
    tor_cache_path: Path
    maxmind_account_id: str
    maxmind_license_key: str
    abuseipdb_api_key: str
    virustotal_api_key: str
    wazuh_alerts_path: Path
    dashboard_token: str
    log_level: str
    internal_networks: str = ""
    show_internal: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if environ is None else environ

        def get(name: str, default: str = "") -> str:
            return env.get(name, default).strip() or default

        return cls(
            log_path=Path(get("COWRIE_LOG_PATH", DEFAULT_LOG_PATH)).expanduser(),
            database_url=get("DATABASE_URL", DEFAULT_DATABASE_URL),
            geoip_dir=Path(get("GEOIP_DB_DIR", DEFAULT_GEOIP_DIR)).expanduser(),
            tor_cache_path=Path(get("TOR_EXIT_LIST_PATH", DEFAULT_TOR_CACHE)).expanduser(),
            maxmind_account_id=get("MAXMIND_ACCOUNT_ID"),
            maxmind_license_key=get("MAXMIND_LICENSE_KEY"),
            abuseipdb_api_key=get("ABUSEIPDB_API_KEY"),
            virustotal_api_key=get("VIRUSTOTAL_API_KEY"),
            wazuh_alerts_path=Path(get("WAZUH_ALERTS_PATH", DEFAULT_WAZUH_ALERTS)).expanduser(),
            dashboard_token=get("DASHBOARD_TOKEN"),
            log_level=get("LOG_LEVEL", "INFO").upper(),
            internal_networks=get("INTERNAL_NETWORKS"),
            show_internal=get("DASHBOARD_SHOW_INTERNAL").lower() in ("1", "true", "yes"),
        )


def load_env_file(path: str | Path = ".env") -> None:
    """Load ``path`` into the environment (existing variables win), if it exists.

    A ``.env`` file holds secrets, so warn when other users on the machine can read it.
    """
    env_path = Path(path)
    if not env_path.is_file():
        return
    if os.name == "posix" and env_path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        logger.warning("%s is readable by other users; run: chmod 600 %s", env_path, env_path)
    load_dotenv(env_path)
