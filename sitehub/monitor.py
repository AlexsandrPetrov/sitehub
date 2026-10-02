"""Background availability checks and favicon discovery."""
import asyncio
import logging
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from . import config, db, security

log = logging.getLogger("sitehub.monitor")

ICONS_DIR = db.DATA_DIR / "icons"
UA = "Mozilla/5.0 (X11; Linux x86_64) SiteHub/1.0 (+status check)"
_wake = asyncio.Event()
_loop: asyncio.AbstractEventLoop | None = None

ICON_TYPES = {
    "image/png": "png", "image/x-icon": "ico", "image/vnd.microsoft.icon": "ico",
    "image/svg+xml": "svg", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif",
}


def wake() -> None:
    """Ask the loop to run a check round right now."""
    if _loop is not None:
        _loop.call_soon_threadsafe(_wake.set)


async def _check_one(client: httpx.AsyncClient, sem: asyncio.Semaphore, site) -> None:
    url = site["check_url"] or site["url"]
    ok, code, err, latency = 0, None, None, None
    async with sem:
        start = time.perf_counter()
        try:
            async with client.stream("GET", url) as resp:
                code = resp.status_code
                latency = int((time.perf_counter() - start) * 1000)
                ok = 1 if code < 500 else 0
                if not ok:
                    err = f"HTTP {code}"
        except httpx.TimeoutException:
            err = "timeout"
        except httpx.HTTPError as e:
            err = type(e).__name__
        except Exception as e:  # noqa: BLE001 - never kill the loop
            err = str(e)[:120]
    now = db.now()
    since = site["status_since"] if site["status"] == ok and site["status_since"] else now
    db.ex("UPDATE sites SET status=?, status_code=?, status_error=?, latency=?, checked_at=?, "
          "status_since=? WHERE id=?", (ok, code, err, latency, now, since, site["id"]))
    db.ex("INSERT INTO checks(site_id,ts,ok,latency) VALUES(?,?,?,?)", (site["id"], now, ok, latency))
    if site["status"] is not None and site["status"] != ok:
        db.audit("site_up" if ok else "site_down", None, None, f"{site['title']} ({url}) {err or ''}")


async def run_checks() -> None:
    sites = db.q("SELECT * FROM sites WHERE check_enabled=1")
    if not sites:
        return
    timeout = httpx.Timeout(config.get_int("check_timeout", 8))
    sem = asyncio.Semaphore(16)
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout,
                                 headers={"User-Agent": UA}) as client:
        await asyncio.gather(*(_check_one(client, sem, s) for s in sites))


async def loop() -> None:
    global _loop
    _loop = asyncio.get_running_loop()
    await asyncio.sleep(2)
    last_prune = 0.0
    while True:
        try:
            await run_checks()
            if time.time() - last_prune > 3600:
                keep = config.get_int("history_days", 7) * 86400
                db.ex("DELETE FROM checks WHERE ts<?", (db.now() - keep,))
                security.prune()
                last_prune = time.time()
        except Exception:  # noqa: BLE001
            log.exception("monitor round failed")
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), timeout=max(10, config.get_int("check_interval", 60)))
        except asyncio.TimeoutError:
            pass


def uptime(site_id: int, hours: int = 24) -> float | None:
    row = db.q1("SELECT COUNT(*) AS n, SUM(ok) AS up FROM checks WHERE site_id=? AND ts>?",
                (site_id, db.now() - hours * 3600))
    if not row["n"]:
        return None
    return round(100.0 * (row["up"] or 0) / row["n"], 1)


def uptime_map(hours: int = 24) -> dict[int, float]:
    rows = db.q("SELECT site_id, COUNT(*) AS n, SUM(ok) AS up FROM checks WHERE ts>? GROUP BY site_id",
                (db.now() - hours * 3600,))
    return {r["site_id"]: round(100.0 * (r["up"] or 0) / r["n"], 1) for r in rows if r["n"]}


def history(site_id: int, limit: int = 40) -> list:
    rows = db.q("SELECT ts, ok, latency FROM checks WHERE site_id=? ORDER BY ts DESC LIMIT ?",
                (site_id, limit))
    return list(reversed(rows))


# ---------------------------------------------------------------- favicons
_LINK_RE = re.compile(r"<link\b[^>]*>", re.I)
_ATTR_RE = re.compile(r'(\w[\w-]*)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)')


def _icon_candidates(html: str, base: str) -> list[str]:
    found = []
    for tag in _LINK_RE.findall(html[:200_000]):
        attrs = {k.lower(): v.strip("'\"") for k, v in _ATTR_RE.findall(tag)}
        rel = attrs.get("rel", "").lower()
        href = attrs.get("href")
        if not href or "icon" not in rel or "mask-icon" in rel:
            continue
        size = 0
        m = re.search(r"(\d+)x\d+", attrs.get("sizes", ""))
        if m:
            size = int(m.group(1))
        if "apple-touch" in rel:
            size = max(size, 180)
        if href.endswith(".svg") or attrs.get("type") == "image/svg+xml":
            size = max(size, 256)
        found.append((size, urljoin(base, href)))
    found.sort(key=lambda x: -x[0])
    return [u for _, u in found]


def _sniff(data: bytes, ctype: str) -> str | None:
    ctype = ctype.split(";")[0].strip().lower()
    if data.startswith(b"\x89PNG"):
        return "png"
    if data[:4] == b"\x00\x00\x01\x00":
        return "ico"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == b"GIF8":
        return "gif"
    head = data[:500].lstrip().lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in data[:2000].lower()):
        return "svg"
    return ICON_TYPES.get(ctype) if ctype in ("image/x-icon", "image/vnd.microsoft.icon") else None


def save_icon(site_id: int, data: bytes, ext: str) -> str:
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    for old in ICONS_DIR.glob(f"{site_id}.*"):
        old.unlink(missing_ok=True)
    name = f"{site_id}.{ext}"
    (ICONS_DIR / name).write_bytes(data)
    db.ex("UPDATE sites SET icon_file=? WHERE id=?", (f"{name}?v={int(time.time())}", site_id))
    return name


async def fetch_favicon(site_id: int) -> bool:
    site = db.q1("SELECT id, url FROM sites WHERE id=?", (site_id,))
    if not site:
        return False
    url = site["url"]
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10,
                                     headers={"User-Agent": UA}) as client:
            candidates = []
            try:
                resp = await client.get(url)
                if "html" in resp.headers.get("content-type", ""):
                    candidates = _icon_candidates(resp.text, str(resp.url))
                base = f"{resp.url.scheme}://{resp.url.host}" + (f":{resp.url.port}" if resp.url.port else "")
            except httpx.HTTPError:
                base = f"{parsed.scheme}://{parsed.netloc}"
            candidates.append(base + "/favicon.ico")
            for cand in candidates[:5]:
                try:
                    r = await client.get(cand)
                except httpx.HTTPError:
                    continue
                if r.status_code != 200 or not r.content or len(r.content) > 1_000_000:
                    continue
                ext = _sniff(r.content, r.headers.get("content-type", ""))
                if ext:
                    save_icon(site_id, r.content, ext)
                    return True
    except Exception:  # noqa: BLE001
        log.exception("favicon fetch failed for %s", url)
    return False


def delete_icons(site_id: int) -> None:
    for old in Path(ICONS_DIR).glob(f"{site_id}.*"):
        old.unlink(missing_ok=True)
