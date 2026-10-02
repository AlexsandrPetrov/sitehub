"""Passwords, TOTP 2FA, CSRF, brute-force protection."""
import hashlib
import io
import ipaddress
import json
import secrets
import time

import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import config, db

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash(secrets.token_hex(16))

ROLES = ("admin", "editor", "viewer")
MIN_PASSWORD = 8


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(hashed: str | None, password: str) -> bool:
    try:
        return _ph.verify(hashed or _DUMMY_HASH, password) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _ph.check_needs_rehash(hashed)
    except InvalidHashError:
        return False


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD:
        return "Пароль должен быть не короче {n} символов"
    if password.isdigit() or password.isalpha():
        return "Пароль должен содержать и буквы, и цифры или символы"
    return None


def new_stamp() -> str:
    return secrets.token_hex(8)


def generate_password(length: int = 14) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.isdigit() for c in pw) and any(c.isalpha() for c in pw):
            return pw


# ---------------------------------------------------------------- TOTP
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    issuer = config.get("site_title") or "SiteHub"
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode()
    return svg[svg.find("<svg"):]


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the accepted time step (for replay protection) or None."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6 or not secret:
        return None
    totp = pyotp.TOTP(secret)
    step_now = int(time.time()) // 30
    for step in (step_now - 1, step_now, step_now + 1):
        if step > last_step and secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").strip().lower().encode()).hexdigest()


def new_recovery_codes(n: int = 8) -> tuple[list[str], str]:
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, json.dumps([_hash_code(c) for c in codes])


def use_recovery_code(stored: str | None, code: str) -> str | None:
    """Return updated JSON with the code removed, or None if the code is invalid."""
    try:
        hashes = json.loads(stored or "[]")
    except ValueError:
        return None
    h = _hash_code(code)
    if h in hashes:
        hashes.remove(h)
        return json.dumps(hashes)
    return None


def recovery_left(stored: str | None) -> int:
    try:
        return len(json.loads(stored or "[]"))
    except ValueError:
        return 0


# ---------------------------------------------------------------- CSRF
def csrf_token(session) -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["csrf"] = tok
    return tok


def csrf_ok(session, token: str | None) -> bool:
    expected = session.get("csrf")
    return bool(expected and token and secrets.compare_digest(expected, token))


# ---------------------------------------------------------------- client IP
def client_ip(request) -> str:
    if config.get_bool("trust_proxy"):
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
    return request.client.host if request.client else "unknown"


def _whitelisted(ip: str) -> bool:
    raw = config.get("ip_whitelist").replace(",", " ").split()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in raw:
        try:
            if addr in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------- brute force
def block_remaining(ip: str, username: str | None) -> int:
    """Seconds until this IP / account may try again (0 = allowed)."""
    if _whitelisted(ip):
        return 0
    now = db.now()
    row = db.q1("SELECT until FROM bans WHERE ip=? AND until>?", (ip, now))
    if row:
        return row["until"] - now
    if username:
        window = config.get_int("attempt_window", 15) * 60
        limit = config.get_int("max_attempts", 5) * max(1, config.get_int("user_lock_factor", 3))
        rows = db.q("SELECT ts FROM login_attempts WHERE username=? AND success=0 AND ts>? "
                    "ORDER BY ts DESC", (username.lower(), now - window))
        if len(rows) >= limit:
            until = rows[0]["ts"] + config.get_int("lockout_minutes", 15) * 60
            if until > now:
                return until - now
    return 0


def record_attempt(ip: str, username: str | None, success: bool, stage: str = "password") -> None:
    now = db.now()
    db.ex("INSERT INTO login_attempts(ts,ip,username,success,stage) VALUES(?,?,?,?,?)",
          (now, ip, (username or "").lower(), int(success), stage))
    if success or _whitelisted(ip):
        return
    window = config.get_int("attempt_window", 15) * 60
    last_ok = db.q1("SELECT MAX(id) AS i FROM login_attempts WHERE ip=? AND success=1", (ip,))["i"] or 0
    fails = db.q1("SELECT COUNT(*) AS n FROM login_attempts WHERE ip=? AND success=0 AND ts>? AND id>?",
                  (ip, now - window, last_ok))["n"]
    if fails >= config.get_int("max_attempts", 5):
        until = now + config.get_int("lockout_minutes", 15) * 60
        db.ex("INSERT INTO bans(ip,until,reason) VALUES(?,?,?) "
              "ON CONFLICT(ip) DO UPDATE SET until=excluded.until, reason=excluded.reason",
              (ip, until, f"{fails} неудачных попыток входа"))
        db.audit("ip_banned", username, ip, f"{fails} неудачных попыток")


def prune() -> None:
    now = db.now()
    db.ex("DELETE FROM bans WHERE until<?", (now,))
    db.ex("DELETE FROM login_attempts WHERE ts<?", (now - 30 * 86400,))
    db.ex("DELETE FROM audit WHERE ts<?", (now - 180 * 86400,))
