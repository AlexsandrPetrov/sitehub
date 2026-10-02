"""Runtime settings stored in the database (editable from the admin panel)."""
from . import db

DEFAULTS: dict[str, str] = {
    # general
    "site_title": "SiteHub",
    "site_subtitle": "",
    "public_dashboard": "1",      # 1 = guests see public sites, 0 = login required
    "default_lang": "ru",
    "show_clock": "1",
    "show_status": "1",
    "background": "neutral",      # neutral | gradient | ocean | warm | aurora
    # monitoring
    "check_interval": "60",
    "check_timeout": "8",
    "history_days": "7",
    # brute-force protection
    "max_attempts": "5",
    "attempt_window": "15",       # minutes
    "lockout_minutes": "15",
    "user_lock_factor": "3",      # per-account lock after max_attempts * factor failures
    "require_2fa_admins": "0",
    "session_hours": "12",
    "trust_proxy": "0",
    "ip_whitelist": "",
    # server
    "host": "0.0.0.0",
    "port": "8080",
    "ssl_mode": "off",            # off | custom | letsencrypt | selfsigned
    "domain": "",
    "le_email": "",
    "le_staging": "0",
    "http_redirect": "1",         # when SSL is on: serve :80 -> https redirect + ACME challenges
}

_cache: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _cache
    if _cache is None:
        data = dict(DEFAULTS)
        for row in db.q("SELECT key, value FROM settings"):
            data[row["key"]] = row["value"]
        _cache = data
    return _cache


def get(key: str) -> str:
    return _load().get(key, DEFAULTS.get(key, ""))


def get_int(key: str, fallback: int = 0) -> int:
    try:
        return int(get(key))
    except (TypeError, ValueError):
        return fallback


def get_bool(key: str) -> bool:
    return get(key) == "1"


def set_many(values: dict[str, str]) -> None:
    global _cache
    for k, v in values.items():
        db.ex("INSERT INTO settings(key,value) VALUES(?,?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
    _cache = None


def all_settings() -> dict[str, str]:
    return dict(_load())


def invalidate() -> None:
    global _cache
    _cache = None
