"""SQLite storage: thread-local connections, schema and small query helpers."""
import os
import sqlite3
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SITEHUB_DATA", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "sitehub.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT,
    password     TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'viewer',
    active       INTEGER NOT NULL DEFAULT 1,
    totp_secret  TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last    INTEGER NOT NULL DEFAULT 0,
    recovery     TEXT,
    stamp        TEXT,
    lang         TEXT,
    created_at   INTEGER,
    last_login   INTEGER,
    last_ip      TEXT
);
CREATE TABLE IF NOT EXISTS groups (
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL,
    icon   TEXT,
    sort   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sites (
    id            INTEGER PRIMARY KEY,
    group_id      INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    title         TEXT NOT NULL,
    url           TEXT NOT NULL,
    description   TEXT,
    icon          TEXT,
    icon_file     TEXT,
    color         TEXT,
    sort          INTEGER NOT NULL DEFAULT 0,
    private       INTEGER NOT NULL DEFAULT 0,
    new_tab       INTEGER NOT NULL DEFAULT 1,
    check_enabled INTEGER NOT NULL DEFAULT 1,
    check_url     TEXT,
    status        INTEGER,
    status_code   INTEGER,
    status_error  TEXT,
    latency       INTEGER,
    checked_at    INTEGER,
    status_since  INTEGER,
    clicks        INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER
);
CREATE TABLE IF NOT EXISTS checks (
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    ts      INTEGER NOT NULL,
    ok      INTEGER NOT NULL,
    latency INTEGER
);
CREATE INDEX IF NOT EXISTS checks_site_ts ON checks(site_id, ts);
CREATE TABLE IF NOT EXISTS login_attempts (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    ip       TEXT,
    username TEXT,
    success  INTEGER NOT NULL,
    stage    TEXT
);
CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts(ip, ts);
CREATE INDEX IF NOT EXISTS login_attempts_user ON login_attempts(username, ts);
CREATE TABLE IF NOT EXISTS bans (
    ip     TEXT PRIMARY KEY,
    until  INTEGER NOT NULL,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    user    TEXT,
    ip      TEXT,
    action  TEXT NOT NULL,
    details TEXT
);
"""

_local = threading.local()


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=15000")
        _local.conn = c
    return c


def init() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn().executescript(SCHEMA)


def q(sql: str, args=()) -> list[sqlite3.Row]:
    return conn().execute(sql, args).fetchall()


def q1(sql: str, args=()):
    return conn().execute(sql, args).fetchone()


def ex(sql: str, args=()) -> int:
    cur = conn().execute(sql, args)
    return cur.lastrowid


def now() -> int:
    return int(time.time())


def audit(action: str, user: str | None = None, ip: str | None = None, details: str = "") -> None:
    ex("INSERT INTO audit(ts,user,ip,action,details) VALUES(?,?,?,?,?)",
       (now(), user, ip, action, details))
