"""TLS certificates: custom upload, Let's Encrypt (certbot), self-signed; :80 redirect helper."""
import asyncio
import datetime as dt
import http.server
import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import config, db

log = logging.getLogger("sitehub.tls")

CERTS_DIR = db.DATA_DIR / "certs"
ACME_ROOT = db.DATA_DIR / "acme"
LE_DIR = db.DATA_DIR / "letsencrypt"


def _le_args() -> list[str]:
    return ["--config-dir", str(LE_DIR), "--work-dir", str(db.DATA_DIR / "le-work"),
            "--logs-dir", str(db.DATA_DIR / "le-logs")]


def paths_for(mode: str) -> tuple[Path, Path] | None:
    if mode == "custom":
        return CERTS_DIR / "custom" / "fullchain.pem", CERTS_DIR / "custom" / "privkey.pem"
    if mode == "selfsigned":
        return CERTS_DIR / "selfsigned" / "fullchain.pem", CERTS_DIR / "selfsigned" / "privkey.pem"
    if mode == "letsencrypt":
        domain = config.get("domain").strip()
        if not domain:
            return None
        live = LE_DIR / "live" / domain
        return live / "fullchain.pem", live / "privkey.pem"
    return None


def usable(mode: str) -> tuple[Path, Path] | None:
    """Return (cert, key) if the files for this mode exist and load correctly."""
    p = paths_for(mode)
    if not p or not p[0].exists() or not p[1].exists():
        return None
    try:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(p[0]), str(p[1]))
    except (ssl.SSLError, OSError):
        return None
    return p


def active() -> tuple[Path, Path] | None:
    mode = config.get("ssl_mode")
    return usable(mode) if mode != "off" else None


def cert_info(path: Path) -> dict | None:
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return None
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = sans.get_values_for_type(x509.DNSName) + [str(i) for i in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    def cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()
    not_after = cert.not_valid_after_utc
    days = (not_after - dt.datetime.now(dt.timezone.utc)).days
    return {"subject": cn(cert.subject), "issuer": cn(cert.issuer), "names": names,
            "not_after": not_after.strftime("%d.%m.%Y %H:%M UTC"), "days_left": days,
            "self_signed": cert.issuer == cert.subject}


def validate_pair(cert_pem: bytes, key_pem: bytes) -> str | None:
    """Return an error message or None if the cert/key pair is valid."""
    with tempfile.TemporaryDirectory() as tmp:
        c, k = Path(tmp) / "c.pem", Path(tmp) / "k.pem"
        c.write_bytes(cert_pem)
        k.write_bytes(key_pem)
        try:
            x509.load_pem_x509_certificate(cert_pem)
        except ValueError:
            return "Файл сертификата не похож на PEM-сертификат"
        try:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(str(c), str(k))
        except ssl.SSLError as e:
            return f"Ключ не подходит к сертификату ({e.reason or e})"
    return None


def _write_pair(folder: Path, cert_pem: bytes, key_pem: bytes) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "fullchain.pem").write_bytes(cert_pem)
    key = folder / "privkey.pem"
    key.write_bytes(key_pem)
    os.chmod(key, 0o600)


def save_custom(cert_pem: bytes, key_pem: bytes) -> str | None:
    err = validate_pair(cert_pem, key_pem)
    if err:
        return err
    _write_pair(CERTS_DIR / "custom", cert_pem, key_pem)
    return None


def generate_selfsigned(name: str) -> None:
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SiteHub")])
    alt: list[x509.GeneralName] = []
    try:
        alt.append(x509.IPAddress(ipaddress.ip_address(name)))
    except ValueError:
        alt.append(x509.DNSName(name))
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    _write_pair(CERTS_DIR / "selfsigned",
                cert.public_bytes(serialization.Encoding.PEM),
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


# ---------------------------------------------------------------- Let's Encrypt
def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


class _AcmeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ACME_ROOT), **kw)

    def log_message(self, *a):
        pass


def _run_certbot(cmd: list[str]) -> tuple[bool, str]:
    """Run certbot, serving the ACME webroot on :80 ourselves if nothing listens there."""
    if not shutil.which("certbot"):
        return False, "certbot не установлен (apt install certbot)"
    ACME_ROOT.mkdir(parents=True, exist_ok=True)
    server = None
    if _port_free(80):
        try:
            server = http.server.ThreadingHTTPServer(("0.0.0.0", 80), _AcmeHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        except OSError as e:
            return False, f"Не удалось занять порт 80 для проверки домена: {e}"
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out = (res.stdout + "\n" + res.stderr).strip()
        return res.returncode == 0, out[-3000:]
    except subprocess.TimeoutExpired:
        return False, "certbot не ответил за 5 минут"
    finally:
        if server:
            server.shutdown()
            server.server_close()


def issue_letsencrypt(domain: str, email: str, staging: bool = False) -> tuple[bool, str]:
    cmd = ["certbot", "certonly", "--webroot", "-w", str(ACME_ROOT), "-d", domain,
           "--non-interactive", "--agree-tos", "--keep-until-expiring", "--cert-name", domain,
           *_le_args()]
    cmd += ["-m", email] if email else ["--register-unsafely-without-email"]
    if staging:
        cmd.append("--staging")
    return _run_certbot(cmd)


def renew_letsencrypt() -> tuple[bool, bool, str]:
    """Return (ok, changed, output)."""
    p = paths_for("letsencrypt")
    before = p[0].resolve().stat().st_mtime if p and p[0].exists() else 0
    ok, out = _run_certbot(["certbot", "renew", "--non-interactive", *_le_args()])
    after = p[0].resolve().stat().st_mtime if p and p[0].exists() else 0
    return ok, after != before, out


# ---------------------------------------------------------------- :80 helper
async def _redirect_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        host = ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
        if path.startswith("/.well-known/acme-challenge/"):
            token = path.rsplit("/", 1)[-1]
            f = ACME_ROOT / ".well-known" / "acme-challenge" / token
            if token and "/" not in token and ".." not in token and f.is_file():
                body = f.read_bytes()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            hostname = host.rsplit(":", 1)[0] if host and not host.endswith("]") else host
            hostname = hostname or config.get("domain") or "localhost"
            port = config.get_int("port", 443)
            target = f"https://{hostname}{'' if port == 443 else ':' + str(port)}{path}"
            target = target.replace("\r", "").replace("\n", "")
            writer.write(f"HTTP/1.1 301 Moved Permanently\r\nLocation: {target}\r\n"
                         "Content-Length: 0\r\nConnection: close\r\n\r\n".encode("latin-1", "ignore"))
        await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        writer.close()


async def start_redirect_server():
    if config.get_int("port") == 80 or not active() or not config.get_bool("http_redirect"):
        return None
    try:
        server = await asyncio.start_server(_redirect_client, host=config.get("host") or "0.0.0.0", port=80)
        log.info("HTTP :80 -> HTTPS redirect enabled")
        return server
    except OSError as e:
        log.warning("cannot bind :80 for redirect: %s", e)
        return None


async def renew_loop(restart_cb) -> None:
    await asyncio.sleep(60)
    while True:
        if config.get("ssl_mode") == "letsencrypt" and config.get("domain"):
            p = paths_for("letsencrypt")
            info = cert_info(p[0]) if p and p[0].exists() else None
            if info and info["days_left"] < 30:
                ok, changed, out = await asyncio.to_thread(renew_letsencrypt)
                db.audit("le_renew", None, None, ("ok" if ok else "fail") + (" changed" if changed else ""))
                if ok and changed:
                    restart_cb()
        await asyncio.sleep(12 * 3600)
