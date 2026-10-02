"""SiteHub web application."""
import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import signal
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, config, db, i18n, monitor, security, tls

log = logging.getLogger("sitehub")
BASE_DIR = db.BASE_DIR

db.init()


# ---------------------------------------------------------------- helpers
def _secret_key() -> str:
    path = db.DATA_DIR / "secret.key"
    if not path.exists():
        path.write_text(secrets.token_urlsafe(48))
        os.chmod(path, 0o600)
    return path.read_text().strip()


def schedule_restart(delay: float = 1.5) -> None:
    """Exit gracefully; systemd (Restart=always) brings us back with the new settings."""
    threading.Timer(delay, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()


_background: set = set()


def spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


class Redirect(Exception):
    def __init__(self, url: str):
        self.url = url


def current_user(request: Request):
    if "user" in request.state._state:
        return request.state.user
    user = None
    uid = request.session.get("uid")
    if uid:
        row = db.q1("SELECT * FROM users WHERE id=? AND active=1", (uid,))
        if row and row["stamp"] == request.session.get("stamp") and request.session.get("exp", 0) > time.time():
            user = row
        else:
            request.session.clear()
    request.state.user = user
    return user


def get_lang(request: Request, user=None) -> str:
    if user and user["lang"] in i18n.LANGS:
        return user["lang"]
    cookie = request.cookies.get("lang")
    if cookie in i18n.LANGS:
        return cookie
    default = config.get("default_lang")
    return default if default in i18n.LANGS else "ru"


def tr(request: Request, text: str, **kw) -> str:
    return i18n.t(text, get_lang(request, current_user(request)), **kw)


def flash(request: Request, text: str, kind: str = "ok", **kw) -> None:
    request.session.setdefault("flash", [])
    request.session["flash"] = request.session["flash"] + [[kind, tr(request, text, **kw)]]


def require(request: Request, *roles: str):
    user = current_user(request)
    if not user:
        raise Redirect("/login?next=" + quote(request.url.path))
    if roles and user["role"] not in roles:
        raise HTTPException(403)
    if (config.get_bool("require_2fa_admins") and user["role"] == "admin" and not user["totp_enabled"]
            and not request.url.path.startswith("/account")):
        flash(request, "Администраторы обязаны включить двухфакторную аутентификацию", "warn")
        raise Redirect("/account#twofa")
    return user


async def form_of(request: Request):
    form = await request.form()
    token = form.get("csrf") or request.headers.get("x-csrf-token")
    if not security.csrf_ok(request.session, token):
        raise HTTPException(400, "CSRF")
    return form


def safe_next(target: str | None) -> str:
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


def back(request: Request, fallback: str = "/") -> RedirectResponse:
    ref = request.headers.get("referer")
    if ref:
        p = urlparse(ref)
        if p.netloc == request.url.netloc:
            return RedirectResponse((p.path or "/") + (f"?{p.query}" if p.query else ""), 303)
    return RedirectResponse(fallback, 303)


def fmt_ts(ts) -> str:
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts)) if ts else "—"


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.filters["dt"] = fmt_ts
templates.env.filters["host"] = lambda u: (urlparse(u).netloc or u) if u else ""
templates.env.globals["version"] = __version__


def render(request: Request, name: str, ctx: dict | None = None, status: int = 200):
    user = current_user(request)
    lang = get_lang(request, user)
    base = {
        "user": user,
        "lang": lang,
        "langs": i18n.LANGS,
        "_": lambda s, **kw: i18n.t(s, lang, **kw),
        "ago": lambda ts: i18n.ago(ts, lang),
        "csrf": security.csrf_token(request.session),
        "cfg": config.all_settings(),
        "flashes": request.session.pop("flash", []),
        "path": request.url.path,
        "can_edit": bool(user and user["role"] in ("admin", "editor")),
        "is_admin": bool(user and user["role"] == "admin"),
    }
    base.update(ctx or {})
    return templates.TemplateResponse(request, name, base, status_code=status)


# ---------------------------------------------------------------- app
@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    tasks = [asyncio.create_task(monitor.loop()), asyncio.create_task(tls.renew_loop(schedule_restart))]
    redirect_server = await tls.start_redirect_server()
    yield
    for t in tasks:
        t.cancel()
    if redirect_server:
        redirect_server.close()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

_HTTPS = tls.active() is not None
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h.setdefault("Content-Security-Policy", CSP)
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if _HTTPS and config.get("ssl_mode") in ("letsencrypt", "custom"):
        h["Strict-Transport-Security"] = "max-age=15552000"
    if request.url.path.startswith(("/admin", "/account", "/login")):
        h["Cache-Control"] = "no-store"
    return response


app.add_middleware(SessionMiddleware, secret_key=_secret_key(), session_cookie="sitehub_session",
                   max_age=14 * 86400, same_site="lax", https_only=_HTTPS)


@app.exception_handler(Redirect)
async def _redirect_handler(request: Request, exc: Redirect):
    return RedirectResponse(exc.url, 303)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    titles = {403: "Доступ запрещён", 404: "Страница не найдена", 400: "Некорректный запрос",
              429: "Слишком много запросов"}
    return render(request, "error.html", {"code": exc.status_code,
                                          "title": titles.get(exc.status_code, "Ошибка")},
                  status=exc.status_code)


# ---------------------------------------------------------------- public
def visible_sites(user):
    if user:
        return db.q("SELECT * FROM sites ORDER BY sort, id")
    return db.q("SELECT * FROM sites WHERE private=0 ORDER BY sort, id")


@app.get("/")
async def dashboard(request: Request):
    user = current_user(request)
    if not user and not config.get_bool("public_dashboard"):
        raise Redirect("/login")
    groups = db.q("SELECT * FROM groups ORDER BY sort, id")
    sites = visible_sites(user)
    by_group: dict = {}
    for s in sites:
        by_group.setdefault(s["group_id"], []).append(s)
    sections = [(g, by_group.pop(g["id"])) for g in groups if g["id"] in by_group]
    rest = [s for lst in by_group.values() for s in lst]
    if rest:
        sections.append((None, rest))
    up = sum(1 for s in sites if s["check_enabled"] and s["status"] == 1)
    down = sum(1 for s in sites if s["check_enabled"] and s["status"] == 0)
    return render(request, "dashboard.html", {
        "sections": sections, "uptime": monitor.uptime_map(), "total": len(sites),
        "up": up, "down": down, "groups_count": len(groups),
    })


@app.get("/api/status")
async def api_status(request: Request):
    user = current_user(request)
    if not user and not config.get_bool("public_dashboard"):
        raise HTTPException(401)
    up = monitor.uptime_map()
    return [{"id": s["id"], "status": s["status"], "latency": s["latency"], "code": s["status_code"],
             "error": s["status_error"], "uptime": up.get(s["id"]), "checked": s["checked_at"]}
            for s in visible_sites(user) if s["check_enabled"]]


@app.post("/api/click/{site_id}")
async def api_click(site_id: int):
    db.ex("UPDATE sites SET clicks=clicks+1 WHERE id=?", (site_id,))
    return Response(status_code=204)


@app.get("/icons/{name}")
async def icon_file(name: str):
    if not re.fullmatch(r"\d+\.(png|ico|svg|jpg|webp|gif)", name):
        raise HTTPException(404)
    path = monitor.ICONS_DIR / name
    if not path.is_file():
        raise HTTPException(404)
    resp = FileResponse(path, headers={"Cache-Control": "public, max-age=604800"})
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return resp


@app.get("/.well-known/acme-challenge/{token}")
async def acme(token: str):
    f = tls.ACME_ROOT / ".well-known" / "acme-challenge" / token
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token) or not f.is_file():
        raise HTTPException(404)
    return Response(f.read_bytes(), media_type="text/plain")


@app.get("/healthz")
async def healthz():
    return {"ok": True, "version": __version__}


@app.get("/lang/{code}")
async def set_lang(request: Request, code: str):
    if code not in i18n.LANGS:
        raise HTTPException(404)
    user = current_user(request)
    if user:
        db.ex("UPDATE users SET lang=? WHERE id=?", (code, user["id"]))
    resp = back(request)
    resp.set_cookie("lang", code, max_age=365 * 86400, samesite="lax")
    return resp


# ---------------------------------------------------------------- auth
@app.get("/login")
async def login_page(request: Request, next: str = "/"):
    if current_user(request):
        return RedirectResponse(safe_next(next), 303)
    return render(request, "login.html", {"next": safe_next(next)})


def _blocked_msg(request: Request, seconds: int) -> str:
    return tr(request, "Слишком много неудачных попыток. Повторите через {m} мин.",
              m=max(1, (seconds + 59) // 60))


def finish_login(request: Request, user, ip: str, next_url: str) -> RedirectResponse:
    request.session.clear()
    request.session.update({"uid": user["id"], "stamp": user["stamp"],
                            "exp": time.time() + config.get_int("session_hours", 12) * 3600})
    db.ex("UPDATE users SET last_login=?, last_ip=? WHERE id=?", (db.now(), ip, user["id"]))
    security.record_attempt(ip, user["username"], True, "login")
    db.audit("login", user["username"], ip)
    resp = RedirectResponse(safe_next(next_url), 303)
    if user["lang"]:
        resp.set_cookie("lang", user["lang"], max_age=365 * 86400, samesite="lax")
    return resp


@app.post("/login")
async def login_submit(request: Request):
    form = await form_of(request)
    username = str(form.get("username", "")).strip()[:64]
    password = str(form.get("password", ""))[:256]
    next_url = safe_next(form.get("next"))
    ip = security.client_ip(request)
    ctx = {"next": next_url, "username": username}

    wait = security.block_remaining(ip, username)
    if wait:
        return render(request, "login.html", {**ctx, "error": _blocked_msg(request, wait)}, 429)

    user = db.q1("SELECT * FROM users WHERE username=?", (username,)) if username else None
    ok = await run_in_threadpool(security.verify_password, user["password"] if user else None, password)
    if not ok or not user["active"]:
        security.record_attempt(ip, username, False, "password")
        await asyncio.sleep(0.4 + secrets.randbelow(400) / 1000)
        wait = security.block_remaining(ip, username)
        err = _blocked_msg(request, wait) if wait else tr(request, "Неверный логин или пароль")
        return render(request, "login.html", {**ctx, "error": err}, 429 if wait else 401)

    if security.needs_rehash(user["password"]):
        db.ex("UPDATE users SET password=? WHERE id=?", (security.hash_password(password), user["id"]))

    if user["totp_enabled"]:
        csrf = request.session.get("csrf")
        request.session.clear()
        request.session.update({"pending_uid": user["id"], "pending_ts": time.time(),
                                "next": next_url, "csrf": csrf})
        return RedirectResponse("/login/2fa", 303)
    return finish_login(request, user, ip, next_url)


def _pending_user(request: Request):
    uid = request.session.get("pending_uid")
    if not uid or time.time() - request.session.get("pending_ts", 0) > 300:
        return None
    return db.q1("SELECT * FROM users WHERE id=? AND active=1", (uid,))


@app.get("/login/2fa")
async def twofa_page(request: Request):
    if not _pending_user(request):
        return RedirectResponse("/login", 303)
    return render(request, "login_2fa.html")


@app.post("/login/2fa")
async def twofa_submit(request: Request):
    form = await form_of(request)
    user = _pending_user(request)
    if not user:
        flash(request, "Время на ввод кода истекло, войдите заново", "warn")
        return RedirectResponse("/login", 303)
    ip = security.client_ip(request)
    wait = security.block_remaining(ip, user["username"])
    if wait:
        request.session.clear()
        return render(request, "login.html", {"error": _blocked_msg(request, wait)}, 429)

    code = str(form.get("code", "")).strip()
    step = security.verify_totp(user["totp_secret"], code, user["totp_last"])
    if step:
        db.ex("UPDATE users SET totp_last=? WHERE id=?", (step, user["id"]))
        return finish_login(request, user, ip, request.session.get("next", "/"))
    remaining = security.use_recovery_code(user["recovery"], code) if len(code) >= 10 else None
    if remaining is not None:
        db.ex("UPDATE users SET recovery=? WHERE id=?", (remaining, user["id"]))
        db.audit("recovery_code_used", user["username"], ip)
        flash(request, "Использован резервный код. Осталось: {n}", "warn", n=security.recovery_left(remaining))
        return finish_login(request, user, ip, request.session.get("next", "/"))

    security.record_attempt(ip, user["username"], False, "2fa")
    await asyncio.sleep(0.4)
    return render(request, "login_2fa.html", {"error": tr(request, "Неверный код")}, 401)


@app.post("/logout")
async def logout(request: Request):
    await form_of(request)
    user = current_user(request)
    if user:
        db.audit("logout", user["username"], security.client_ip(request))
    request.session.clear()
    return RedirectResponse("/", 303)


# ---------------------------------------------------------------- account
@app.get("/account")
async def account(request: Request):
    user = require(request)
    pending = request.session.get("totp_pending")
    ctx = {"recovery_left": security.recovery_left(user["recovery"]),
           "recovery_codes": request.session.pop("recovery_show", None)}
    if pending:
        uri = security.totp_uri(pending, user["username"])
        ctx.update({"totp_pending": pending, "qr": security.qr_svg(uri), "totp_uri": uri})
    return render(request, "account.html", ctx)


@app.post("/account/profile")
async def account_profile(request: Request):
    user = require(request)
    form = await form_of(request)
    lang = form.get("lang") if form.get("lang") in i18n.LANGS else None
    db.ex("UPDATE users SET display_name=?, lang=? WHERE id=?",
          (str(form.get("display_name", "")).strip()[:64] or None, lang, user["id"]))
    flash(request, "Профиль сохранён")
    resp = RedirectResponse("/account", 303)
    if lang:
        resp.set_cookie("lang", lang, max_age=365 * 86400, samesite="lax")
    return resp


@app.post("/account/password")
async def account_password(request: Request):
    user = require(request)
    form = await form_of(request)
    current, new, confirm = (str(form.get(k, "")) for k in ("current", "new", "confirm"))
    if not await run_in_threadpool(security.verify_password, user["password"], current):
        security.record_attempt(security.client_ip(request), user["username"], False, "password_change")
        flash(request, "Текущий пароль указан неверно", "error")
    elif new != confirm:
        flash(request, "Пароли не совпадают", "error")
    elif problem := security.password_problem(new):
        flash(request, problem, "error", n=security.MIN_PASSWORD)
    else:
        stamp = security.new_stamp()
        db.ex("UPDATE users SET password=?, stamp=? WHERE id=?",
              (await run_in_threadpool(security.hash_password, new), stamp, user["id"]))
        request.session["stamp"] = stamp
        db.audit("password_changed", user["username"], security.client_ip(request))
        flash(request, "Пароль изменён. Остальные сеансы завершены")
    return RedirectResponse("/account", 303)


@app.post("/account/logout-all")
async def account_logout_all(request: Request):
    user = require(request)
    await form_of(request)
    stamp = security.new_stamp()
    db.ex("UPDATE users SET stamp=? WHERE id=?", (stamp, user["id"]))
    request.session["stamp"] = stamp
    flash(request, "Все остальные сеансы завершены")
    return RedirectResponse("/account", 303)


@app.post("/account/2fa/start")
async def twofa_start(request: Request):
    require(request)
    await form_of(request)
    request.session["totp_pending"] = security.new_totp_secret()
    return RedirectResponse("/account#twofa", 303)


@app.post("/account/2fa/cancel")
async def twofa_cancel(request: Request):
    require(request)
    await form_of(request)
    request.session.pop("totp_pending", None)
    return RedirectResponse("/account#twofa", 303)


@app.post("/account/2fa/enable")
async def twofa_enable(request: Request):
    user = require(request)
    form = await form_of(request)
    secret = request.session.get("totp_pending")
    step = security.verify_totp(secret, str(form.get("code", "")), 0) if secret else None
    if not step:
        flash(request, "Код не подошёл. Проверьте время на телефоне и попробуйте снова", "error")
        return RedirectResponse("/account#twofa", 303)
    codes, stored = security.new_recovery_codes()
    db.ex("UPDATE users SET totp_secret=?, totp_enabled=1, totp_last=?, recovery=? WHERE id=?",
          (secret, step, stored, user["id"]))
    request.session.pop("totp_pending", None)
    request.session["recovery_show"] = codes
    db.audit("2fa_enabled", user["username"], security.client_ip(request))
    flash(request, "Двухфакторная аутентификация включена")
    return RedirectResponse("/account#twofa", 303)


@app.post("/account/2fa/disable")
async def twofa_disable(request: Request):
    user = require(request)
    form = await form_of(request)
    if config.get_bool("require_2fa_admins") and user["role"] == "admin":
        flash(request, "Для администраторов 2FA обязательна — отключить нельзя", "error")
        return RedirectResponse("/account#twofa", 303)
    if not await run_in_threadpool(security.verify_password, user["password"], str(form.get("password", ""))):
        flash(request, "Текущий пароль указан неверно", "error")
        return RedirectResponse("/account#twofa", 303)
    db.ex("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last=0, recovery=NULL WHERE id=?",
          (user["id"],))
    db.audit("2fa_disabled", user["username"], security.client_ip(request))
    flash(request, "Двухфакторная аутентификация отключена", "warn")
    return RedirectResponse("/account#twofa", 303)


@app.post("/account/2fa/recovery")
async def twofa_recovery(request: Request):
    user = require(request)
    form = await form_of(request)
    if not user["totp_enabled"]:
        return RedirectResponse("/account", 303)
    if not await run_in_threadpool(security.verify_password, user["password"], str(form.get("password", ""))):
        flash(request, "Текущий пароль указан неверно", "error")
        return RedirectResponse("/account#twofa", 303)
    codes, stored = security.new_recovery_codes()
    db.ex("UPDATE users SET recovery=? WHERE id=?", (stored, user["id"]))
    request.session["recovery_show"] = codes
    flash(request, "Созданы новые резервные коды, старые больше не действуют")
    return RedirectResponse("/account#twofa", 303)


# ---------------------------------------------------------------- admin: overview
@app.get("/admin")
async def admin_home(request: Request):
    require(request, "admin", "editor")
    stats = {
        "sites": db.q1("SELECT COUNT(*) n FROM sites")["n"],
        "groups": db.q1("SELECT COUNT(*) n FROM groups")["n"],
        "up": db.q1("SELECT COUNT(*) n FROM sites WHERE check_enabled=1 AND status=1")["n"],
        "down": db.q1("SELECT COUNT(*) n FROM sites WHERE check_enabled=1 AND status=0")["n"],
        "users": db.q1("SELECT COUNT(*) n FROM users")["n"],
        "bans": db.q1("SELECT COUNT(*) n FROM bans WHERE until>?", (db.now(),))["n"],
        "fails24": db.q1("SELECT COUNT(*) n FROM login_attempts WHERE success=0 AND ts>?",
                         (db.now() - 86400,))["n"],
        "clicks": db.q1("SELECT COALESCE(SUM(clicks),0) n FROM sites")["n"],
    }
    down_sites = db.q("SELECT * FROM sites WHERE check_enabled=1 AND status=0 ORDER BY title")
    top = db.q("SELECT * FROM sites WHERE clicks>0 ORDER BY clicks DESC LIMIT 6")
    events = db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 12")
    return render(request, "admin/overview.html", {"stats": stats, "down_sites": down_sites,
                                                    "top": top, "events": events,
                                                    "https": tls.active() is not None})


# ---------------------------------------------------------------- admin: sites & groups
@app.get("/admin/sites")
async def admin_sites(request: Request):
    require(request, "admin", "editor")
    groups = db.q("SELECT * FROM groups ORDER BY sort, id")
    sites = db.q("SELECT * FROM sites ORDER BY sort, id")
    group_ids = {g["id"] for g in groups}
    by_group = {g["id"]: [] for g in groups}
    ungrouped = []
    for s in sites:
        (by_group[s["group_id"]] if s["group_id"] in group_ids else ungrouped).append(s)
    return render(request, "admin/sites.html", {"groups": groups, "by_group": by_group,
                                                 "ungrouped": ungrouped, "uptime": monitor.uptime_map()})


@app.get("/admin/sites/edit")
async def admin_site_edit(request: Request, id: int | None = None, group: int | None = None):
    require(request, "admin", "editor")
    site = db.q1("SELECT * FROM sites WHERE id=?", (id,)) if id else None
    if id and not site:
        raise HTTPException(404)
    hist = monitor.history(site["id"], 60) if site else []
    return render(request, "admin/site_edit.html", {
        "site": site, "groups": db.q("SELECT * FROM groups ORDER BY sort, id"), "preset_group": group,
        "history": hist, "uptime24": monitor.uptime(site["id"]) if site else None,
        "uptime7": monitor.uptime(site["id"], 24 * 7) if site else None})


def _normalize_url(url: str) -> str | None:
    url = url.strip()
    if not url:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url):
        url = "https://" + url
    scheme = url.split(":", 1)[0].lower()
    if scheme in ("javascript", "data", "vbscript", "file"):
        return None
    return url[:2000]


async def _read_upload(item) -> tuple[bytes, str] | None:
    if not isinstance(item, UploadFile) or not item.filename:
        return None
    data = await item.read(1_000_001)
    if not data or len(data) > 1_000_000:
        return None
    ext = monitor._sniff(data, item.content_type or "")
    return (data, ext) if ext else None


@app.post("/admin/sites/save")
async def admin_site_save(request: Request):
    user = require(request, "admin", "editor")
    form = await form_of(request)
    site_id = int(form.get("id") or 0) or None
    title = str(form.get("title", "")).strip()[:120]
    url = _normalize_url(str(form.get("url", "")))
    if not title or not url:
        flash(request, "Укажите название и корректный адрес", "error")
        return back(request, "/admin/sites")
    is_http = url.lower().startswith(("http://", "https://"))
    check_url = _normalize_url(str(form.get("check_url", ""))) if form.get("check_url") else None
    color = str(form.get("color", "")).strip()
    color = color if re.fullmatch(r"#[0-9a-fA-F]{6}", color) else None
    group_id = int(form.get("group_id") or 0) or None
    if group_id and not db.q1("SELECT id FROM groups WHERE id=?", (group_id,)):
        group_id = None
    values = (group_id, title, url, str(form.get("description", "")).strip()[:300] or None,
              str(form.get("icon", "")).strip()[:16] or None, color,
              1 if form.get("private") else 0, 1 if form.get("new_tab") else 0,
              1 if (form.get("check_enabled") and is_http) else 0, check_url)
    if site_id:
        old = db.q1("SELECT * FROM sites WHERE id=?", (site_id,))
        if not old:
            raise HTTPException(404)
        db.ex("UPDATE sites SET group_id=?, title=?, url=?, description=?, icon=?, color=?, private=?, "
              "new_tab=?, check_enabled=?, check_url=? WHERE id=?", (*values, site_id))
        if old["url"] != url or old["check_url"] != check_url:
            db.ex("UPDATE sites SET status=NULL, status_since=NULL WHERE id=?", (site_id,))
        action = "site_updated"
    else:
        sort = db.q1("SELECT COALESCE(MAX(sort),0)+1 n FROM sites")["n"]
        site_id = db.ex("INSERT INTO sites(group_id,title,url,description,icon,color,private,new_tab,"
                        "check_enabled,check_url,sort,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (*values, sort, db.now()))
        old = None
        action = "site_added"
    upload = await _read_upload(form.get("icon_upload"))
    if upload:
        monitor.save_icon(site_id, *upload)
    elif form.get("icon_remove"):
        monitor.delete_icons(site_id)
        db.ex("UPDATE sites SET icon_file=NULL WHERE id=?", (site_id,))
    elif is_http and (old is None or old["url"] != url or not old["icon_file"]) and not form.get("icon"):
        spawn(monitor.fetch_favicon(site_id))
    db.audit(action, user["username"], security.client_ip(request), f"{title} — {url}")
    monitor.wake()
    flash(request, "Сайт «{t}» сохранён", t=title)
    return RedirectResponse("/admin/sites", 303)


@app.post("/admin/sites/{site_id}/delete")
async def admin_site_delete(request: Request, site_id: int):
    user = require(request, "admin", "editor")
    await form_of(request)
    site = db.q1("SELECT * FROM sites WHERE id=?", (site_id,))
    if site:
        db.ex("DELETE FROM sites WHERE id=?", (site_id,))
        monitor.delete_icons(site_id)
        db.audit("site_deleted", user["username"], security.client_ip(request), site["title"])
        flash(request, "Сайт «{t}» удалён", "warn", t=site["title"])
    return RedirectResponse("/admin/sites", 303)


@app.post("/admin/sites/{site_id}/favicon")
async def admin_site_favicon(request: Request, site_id: int):
    require(request, "admin", "editor")
    await form_of(request)
    ok = await monitor.fetch_favicon(site_id)
    flash(request, "Иконка обновлена" if ok else "Не удалось получить иконку сайта", "ok" if ok else "warn")
    return back(request, "/admin/sites")


@app.post("/admin/sites/reorder")
async def admin_sites_reorder(request: Request):
    require(request, "admin", "editor")
    if not security.csrf_ok(request.session, request.headers.get("x-csrf-token")):
        raise HTTPException(400, "CSRF")
    data = await request.json()
    for gi, gid in enumerate(data.get("groups", [])):
        db.ex("UPDATE groups SET sort=? WHERE id=?", (gi, int(gid)))
    n = 0
    for col in data.get("columns", []):
        gid = int(col.get("group") or 0) or None
        for sid in col.get("sites", []):
            n += 1
            db.ex("UPDATE sites SET sort=?, group_id=? WHERE id=?", (n, gid, int(sid)))
    return {"ok": True}


@app.post("/admin/check-now")
async def admin_check_now(request: Request):
    require(request, "admin", "editor")
    await form_of(request)
    await monitor.run_checks()
    flash(request, "Проверка доступности выполнена")
    return back(request, "/admin/sites")


@app.post("/admin/groups/save")
async def admin_group_save(request: Request):
    user = require(request, "admin", "editor")
    form = await form_of(request)
    name = str(form.get("name", "")).strip()[:80]
    icon = str(form.get("icon", "")).strip()[:16] or None
    gid = int(form.get("id") or 0)
    if not name:
        flash(request, "Укажите название группы", "error")
    elif gid:
        db.ex("UPDATE groups SET name=?, icon=? WHERE id=?", (name, icon, gid))
        flash(request, "Группа сохранена")
    else:
        sort = db.q1("SELECT COALESCE(MAX(sort),0)+1 n FROM groups")["n"]
        db.ex("INSERT INTO groups(name,icon,sort) VALUES(?,?,?)", (name, icon, sort))
        db.audit("group_added", user["username"], security.client_ip(request), name)
        flash(request, "Группа «{t}» создана", t=name)
    return RedirectResponse("/admin/sites", 303)


@app.post("/admin/groups/{gid}/delete")
async def admin_group_delete(request: Request, gid: int):
    user = require(request, "admin", "editor")
    await form_of(request)
    g = db.q1("SELECT * FROM groups WHERE id=?", (gid,))
    if g:
        db.ex("UPDATE sites SET group_id=NULL WHERE group_id=?", (gid,))
        db.ex("DELETE FROM groups WHERE id=?", (gid,))
        db.audit("group_deleted", user["username"], security.client_ip(request), g["name"])
        flash(request, "Группа удалена, её сайты перенесены в «Без группы»", "warn")
    return RedirectResponse("/admin/sites", 303)


# ---------------------------------------------------------------- admin: users
@app.get("/admin/users")
async def admin_users(request: Request):
    require(request, "admin")
    users = db.q("SELECT * FROM users ORDER BY username")
    return render(request, "admin/users.html", {"users": users, "roles": security.ROLES,
                                                 "new_password": request.session.pop("new_password", None)})


@app.get("/admin/users/{uid}")
async def admin_user_edit(request: Request, uid: int):
    require(request, "admin")
    u = db.q1("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        raise HTTPException(404)
    logins = db.q("SELECT * FROM login_attempts WHERE username=? ORDER BY id DESC LIMIT 20",
                  (u["username"].lower(),))
    return render(request, "admin/user_edit.html", {"u": u, "roles": security.ROLES, "logins": logins,
                                                     "new_password": request.session.pop("new_password", None)})


def _active_admins(exclude: int | None = None) -> int:
    return db.q1("SELECT COUNT(*) n FROM users WHERE role='admin' AND active=1 AND id!=?",
                 (exclude or 0,))["n"]


@app.post("/admin/users/create")
async def admin_user_create(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    username = str(form.get("username", "")).strip()
    role = form.get("role") if form.get("role") in security.ROLES else "viewer"
    password = str(form.get("password", ""))
    generated = not password
    if generated:
        password = security.generate_password()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", username):
        flash(request, "Логин: 3–64 символа — латиница, цифры, точка, дефис, подчёркивание, @", "error")
    elif db.q1("SELECT id FROM users WHERE username=?", (username,)):
        flash(request, "Пользователь с таким логином уже существует", "error")
    elif (problem := security.password_problem(password)):
        flash(request, problem, "error", n=security.MIN_PASSWORD)
    else:
        db.ex("INSERT INTO users(username,display_name,password,role,stamp,created_at) VALUES(?,?,?,?,?,?)",
              (username, str(form.get("display_name", "")).strip()[:64] or None,
               await run_in_threadpool(security.hash_password, password), role, security.new_stamp(), db.now()))
        db.audit("user_created", me["username"], security.client_ip(request), f"{username} ({role})")
        if generated:
            request.session["new_password"] = [username, password]
        flash(request, "Пользователь {u} создан", u=username)
    return RedirectResponse("/admin/users", 303)


@app.post("/admin/users/{uid}/save")
async def admin_user_save(request: Request, uid: int):
    me = require(request, "admin")
    form = await form_of(request)
    u = db.q1("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        raise HTTPException(404)
    role = form.get("role") if form.get("role") in security.ROLES else u["role"]
    active = 1 if form.get("active") else 0
    if u["id"] == me["id"] and (role != "admin" or not active):
        flash(request, "Нельзя снять с себя права администратора или заблокировать себя", "error")
        return RedirectResponse(f"/admin/users/{uid}", 303)
    if u["role"] == "admin" and (role != "admin" or not active) and _active_admins(exclude=uid) == 0:
        flash(request, "Должен остаться хотя бы один активный администратор", "error")
        return RedirectResponse(f"/admin/users/{uid}", 303)
    stamp = u["stamp"] if (active and role == u["role"]) else security.new_stamp()
    db.ex("UPDATE users SET display_name=?, role=?, active=?, stamp=? WHERE id=?",
          (str(form.get("display_name", "")).strip()[:64] or None, role, active, stamp, uid))
    password = str(form.get("password", ""))
    if password or form.get("generate"):
        if form.get("generate"):
            password = security.generate_password()
            request.session["new_password"] = [u["username"], password]
        if problem := security.password_problem(password):
            flash(request, problem, "error", n=security.MIN_PASSWORD)
            return RedirectResponse(f"/admin/users/{uid}", 303)
        db.ex("UPDATE users SET password=?, stamp=? WHERE id=?",
              (await run_in_threadpool(security.hash_password, password), security.new_stamp(), uid))
        db.audit("password_reset", me["username"], security.client_ip(request), u["username"])
    db.audit("user_updated", me["username"], security.client_ip(request), f"{u['username']} ({role})")
    flash(request, "Изменения сохранены")
    return RedirectResponse(f"/admin/users/{uid}", 303)


@app.post("/admin/users/{uid}/reset-2fa")
async def admin_user_reset_2fa(request: Request, uid: int):
    me = require(request, "admin")
    await form_of(request)
    u = db.q1("SELECT * FROM users WHERE id=?", (uid,))
    if u:
        db.ex("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last=0, recovery=NULL WHERE id=?", (uid,))
        db.audit("2fa_reset", me["username"], security.client_ip(request), u["username"])
        flash(request, "2FA для {u} сброшена", "warn", u=u["username"])
    return RedirectResponse(f"/admin/users/{uid}", 303)


@app.post("/admin/users/{uid}/delete")
async def admin_user_delete(request: Request, uid: int):
    me = require(request, "admin")
    await form_of(request)
    u = db.q1("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        raise HTTPException(404)
    if u["id"] == me["id"]:
        flash(request, "Нельзя удалить самого себя", "error")
        return RedirectResponse(f"/admin/users/{uid}", 303)
    if u["role"] == "admin" and _active_admins(exclude=uid) == 0:
        flash(request, "Должен остаться хотя бы один активный администратор", "error")
        return RedirectResponse(f"/admin/users/{uid}", 303)
    db.ex("DELETE FROM users WHERE id=?", (uid,))
    db.audit("user_deleted", me["username"], security.client_ip(request), u["username"])
    flash(request, "Пользователь {u} удалён", "warn", u=u["username"])
    return RedirectResponse("/admin/users", 303)


# ---------------------------------------------------------------- admin: security
@app.get("/admin/security")
async def admin_security(request: Request):
    require(request, "admin")
    return render(request, "admin/security.html", {
        "bans": db.q("SELECT * FROM bans WHERE until>? ORDER BY until DESC", (db.now(),)),
        "attempts": db.q("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 60"),
        "audit": db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 100"),
        "my_ip": security.client_ip(request),
    })


@app.post("/admin/security/save")
async def admin_security_save(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    def clamp(key, lo, hi):
        try:
            return str(min(hi, max(lo, int(form.get(key, "")))))
        except ValueError:
            return config.get(key)
    values = {
        "max_attempts": clamp("max_attempts", 1, 100),
        "attempt_window": clamp("attempt_window", 1, 1440),
        "lockout_minutes": clamp("lockout_minutes", 1, 10080),
        "user_lock_factor": clamp("user_lock_factor", 1, 100),
        "session_hours": clamp("session_hours", 1, 720),
        "require_2fa_admins": "1" if form.get("require_2fa_admins") else "0",
        "trust_proxy": "1" if form.get("trust_proxy") else "0",
        "ip_whitelist": " ".join(str(form.get("ip_whitelist", "")).replace(",", " ").split())[:1000],
    }
    if values["require_2fa_admins"] == "1" and not me["totp_enabled"]:
        values["require_2fa_admins"] = "0"
        flash(request, "Сначала включите 2FA для своей учётной записи, затем делайте её обязательной", "warn")
    config.set_many(values)
    db.audit("security_settings", me["username"], security.client_ip(request))
    flash(request, "Настройки безопасности сохранены")
    return RedirectResponse("/admin/security", 303)


@app.post("/admin/security/unban")
async def admin_unban(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    ip = str(form.get("ip", ""))
    if form.get("all"):
        db.ex("DELETE FROM bans")
        db.ex("UPDATE login_attempts SET success=-1 WHERE success=0")
    else:
        db.ex("DELETE FROM bans WHERE ip=?", (ip,))
        db.ex("UPDATE login_attempts SET success=-1 WHERE success=0 AND ip=?", (ip,))
    db.audit("ip_unbanned", me["username"], security.client_ip(request), "все" if form.get("all") else ip)
    flash(request, "Блокировка снята")
    return RedirectResponse("/admin/security", 303)


# ---------------------------------------------------------------- admin: server
@app.get("/admin/server")
async def admin_server(request: Request):
    require(request, "admin")
    infos = {}
    for mode in ("custom", "selfsigned", "letsencrypt"):
        p = tls.paths_for(mode)
        infos[mode] = tls.cert_info(p[0]) if p and p[0].exists() else None
    return render(request, "admin/server.html", {
        "certs": infos, "active_https": tls.active() is not None,
        "le_output": request.session.pop("le_output", None),
        "current_host": request.url.hostname,
    })


@app.post("/admin/server/save")
async def admin_server_save(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    try:
        port = int(form.get("port", ""))
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        flash(request, "Порт должен быть числом от 1 до 65535", "error")
        return RedirectResponse("/admin/server", 303)
    mode = form.get("ssl_mode") if form.get("ssl_mode") in ("off", "custom", "letsencrypt", "selfsigned") else "off"
    host = str(form.get("host", "0.0.0.0")).strip() or "0.0.0.0"
    domain = str(form.get("domain", "")).strip().lower()[:253]
    if domain and not re.fullmatch(r"[a-z0-9.-]+", domain):
        flash(request, "Некорректное доменное имя", "error")
        return RedirectResponse("/admin/server", 303)
    old = config.all_settings()
    if port != int(old["port"]) and not tls._port_free(port):
        flash(request, "Порт {p} уже занят другим процессом", "error", p=port)
        return RedirectResponse("/admin/server", 303)
    new = {"port": str(port), "host": host, "ssl_mode": mode, "domain": domain,
           "le_email": str(form.get("le_email", "")).strip()[:200],
           "http_redirect": "1" if form.get("http_redirect") else "0"}
    config.set_many({"domain": domain})
    if mode != "off" and not tls.usable(mode):
        config.set_many({"domain": old["domain"]})
        flash(request, "Для выбранного режима HTTPS нет действующего сертификата — сначала получите или загрузите его",
              "error")
        return RedirectResponse("/admin/server", 303)
    config.set_many(new)
    restart_needed = any(new[k] != old.get(k) for k in ("port", "host", "ssl_mode", "http_redirect")) or \
        (mode == "letsencrypt" and domain != old["domain"])
    db.audit("server_settings", me["username"], security.client_ip(request),
             f"port={port} ssl={mode} host={host}")
    if not restart_needed:
        flash(request, "Настройки сохранены")
        return RedirectResponse("/admin/server", 303)
    scheme = "https" if mode != "off" else "http"
    hostname = request.url.hostname or "localhost"
    if mode == "letsencrypt" and domain:
        hostname = domain
    default_port = 443 if scheme == "https" else 80
    new_url = f"{scheme}://{hostname}{'' if port == default_port else ':' + str(port)}/admin/server"
    schedule_restart()
    return render(request, "restarting.html", {"new_url": new_url})


@app.post("/admin/server/restart")
async def admin_server_restart(request: Request):
    me = require(request, "admin")
    await form_of(request)
    db.audit("restart", me["username"], security.client_ip(request))
    schedule_restart()
    return render(request, "restarting.html", {"new_url": "/admin/server"})


@app.post("/admin/server/cert")
async def admin_server_cert(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    cert = form.get("cert_file")
    key = form.get("key_file")
    cert_pem = (await cert.read(200_000)) if isinstance(cert, UploadFile) and cert.filename else \
        str(form.get("cert_text", "")).encode()
    key_pem = (await key.read(200_000)) if isinstance(key, UploadFile) and key.filename else \
        str(form.get("key_text", "")).encode()
    if not cert_pem.strip() or not key_pem.strip():
        flash(request, "Нужны и сертификат, и закрытый ключ", "error")
    elif err := tls.save_custom(cert_pem, key_pem):
        flash(request, err, "error")
    else:
        db.audit("cert_uploaded", me["username"], security.client_ip(request))
        flash(request, "Сертификат загружен. Выберите режим «Свой сертификат» и сохраните настройки")
    return RedirectResponse("/admin/server#ssl", 303)


@app.post("/admin/server/selfsigned")
async def admin_server_selfsigned(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    name = str(form.get("name", "")).strip() or request.url.hostname or "localhost"
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", name):
        flash(request, "Некорректное имя хоста", "error")
    else:
        await run_in_threadpool(tls.generate_selfsigned, name)
        db.audit("cert_selfsigned", me["username"], security.client_ip(request), name)
        flash(request, "Самоподписанный сертификат для {n} создан", n=name)
    return RedirectResponse("/admin/server#ssl", 303)


@app.post("/admin/server/letsencrypt")
async def admin_server_le(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    domain = str(form.get("domain", "")).strip().lower()
    email = str(form.get("le_email", "")).strip()
    if not re.fullmatch(r"(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}", domain):
        flash(request, "Укажите доменное имя, например hub.example.ru", "error")
        return RedirectResponse("/admin/server#ssl", 303)
    staging = bool(form.get("staging"))
    config.set_many({"le_email": email, "le_staging": "1" if staging else "0"})
    ok, out = await run_in_threadpool(tls.issue_letsencrypt, domain, email, staging)
    request.session["le_output"] = out
    db.audit("le_issue", me["username"], security.client_ip(request), f"{domain}: {'ok' if ok else 'fail'}")
    if ok:
        if config.get("ssl_mode") != "letsencrypt":
            config.set_many({"domain": domain})
        flash(request, "Сертификат Let's Encrypt для {d} получен. Выберите режим Let's Encrypt и сохраните",
              d=domain)
    else:
        flash(request, "Не удалось получить сертификат — смотрите вывод certbot ниже. Домен должен указывать "
                       "на этот сервер, а порт 80 — быть доступен из интернета", "error")
    return RedirectResponse("/admin/server#ssl", 303)


# ---------------------------------------------------------------- admin: settings, import/export
@app.get("/admin/settings")
async def admin_settings(request: Request):
    require(request, "admin")
    return render(request, "admin/settings.html", {"backgrounds": BACKGROUNDS})


@app.post("/admin/settings/save")
async def admin_settings_save(request: Request):
    me = require(request, "admin")
    form = await form_of(request)
    def num(key, lo, hi):
        try:
            return str(min(hi, max(lo, int(form.get(key, "")))))
        except ValueError:
            return config.get(key)
    config.set_many({
        "site_title": str(form.get("site_title", "")).strip()[:60] or "SiteHub",
        "site_subtitle": str(form.get("site_subtitle", "")).strip()[:160],
        "public_dashboard": "1" if form.get("public_dashboard") else "0",
        "show_clock": "1" if form.get("show_clock") else "0",
        "show_status": "1" if form.get("show_status") else "0",
        "background": form.get("background") if form.get("background") in BACKGROUNDS else "neutral",
        "default_lang": form.get("default_lang") if form.get("default_lang") in i18n.LANGS else "ru",
        "check_interval": num("check_interval", 10, 86400),
        "check_timeout": num("check_timeout", 1, 60),
        "history_days": num("history_days", 1, 365),
    })
    db.audit("settings", me["username"], security.client_ip(request))
    monitor.wake()
    flash(request, "Настройки сохранены")
    return RedirectResponse("/admin/settings", 303)


BACKGROUNDS = ("neutral", "gradient", "ocean", "warm", "aurora")
SITE_FIELDS = ("title", "url", "description", "icon", "color", "private", "new_tab", "check_enabled", "check_url")


@app.get("/admin/export")
async def admin_export(request: Request):
    require(request, "admin", "editor")
    out = {"app": "sitehub", "version": 1, "exported": db.now(), "groups": [], "ungrouped": []}
    groups = db.q("SELECT * FROM groups ORDER BY sort, id")
    for g in groups:
        sites = db.q("SELECT * FROM sites WHERE group_id=? ORDER BY sort, id", (g["id"],))
        out["groups"].append({"name": g["name"], "icon": g["icon"],
                              "sites": [{k: s[k] for k in SITE_FIELDS} for s in sites]})
    for s in db.q("SELECT * FROM sites WHERE group_id IS NULL ORDER BY sort, id"):
        out["ungrouped"].append({k: s[k] for k in SITE_FIELDS})
    body = json.dumps(out, ensure_ascii=False, indent=2)
    return Response(body, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="sitehub-{time.strftime("%Y%m%d")}.json"'})


@app.post("/admin/import")
async def admin_import(request: Request):
    me = require(request, "admin", "editor")
    form = await form_of(request)
    upload = form.get("file")
    try:
        data = json.loads((await upload.read(5_000_000)).decode("utf-8"))
        assert isinstance(data, dict)
    except Exception:  # noqa: BLE001
        flash(request, "Файл не похож на экспорт SiteHub (JSON)", "error")
        return RedirectResponse("/admin/settings", 303)
    if form.get("replace"):
        db.ex("DELETE FROM sites")
        db.ex("DELETE FROM groups")
    count = 0
    sort = db.q1("SELECT COALESCE(MAX(sort),0) n FROM sites")["n"]

    def add_site(s: dict, gid):
        nonlocal count, sort
        url = _normalize_url(str(s.get("url") or ""))
        title = str(s.get("title") or "").strip()[:120]
        if not url or not title:
            return
        sort += 1
        db.ex("INSERT INTO sites(group_id,title,url,description,icon,color,private,new_tab,check_enabled,"
              "check_url,sort,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (gid, title, url, s.get("description"), s.get("icon"), s.get("color"), int(bool(s.get("private"))),
               int(s.get("new_tab", 1) not in (0, False)), int(s.get("check_enabled", 1) not in (0, False)),
               s.get("check_url"), sort, db.now()))
        count += 1

    for g in data.get("groups", []):
        name = str(g.get("name") or "").strip()[:80]
        if not name:
            continue
        existing = db.q1("SELECT id FROM groups WHERE name=?", (name,))
        gid = existing["id"] if existing else db.ex(
            "INSERT INTO groups(name,icon,sort) VALUES(?,?,(SELECT COALESCE(MAX(sort),0)+1 FROM groups))",
            (name, g.get("icon")))
        for s in g.get("sites", []):
            add_site(s, gid)
    for s in data.get("ungrouped", []):
        add_site(s, None)
    db.audit("import", me["username"], security.client_ip(request), f"{count} сайтов")
    monitor.wake()
    for s in db.q("SELECT id FROM sites WHERE icon_file IS NULL AND (icon IS NULL OR icon='')"):
        spawn(monitor.fetch_favicon(s["id"]))
    flash(request, "Импортировано сайтов: {n}", n=count)
    return RedirectResponse("/admin/sites", 303)
