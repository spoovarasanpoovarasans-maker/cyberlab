"""CyberLab control plane: authentication, orchestration, scoring, and audit."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import shutil
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .catalog import Challenge, load_catalog
from .config import Settings, load_settings
from .db import Database, utcnow
from .orchestrator import DockerOrchestrator, OrchestratorError
from .security import (
    RateLimiter,
    burn_password_check,
    csrf_ok,
    hash_password,
    new_csrf_token,
    sha256_hex,
    verify_password,
)

logger = logging.getLogger("cyberlab")

APP_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# request helpers
# ---------------------------------------------------------------------------
def _db(request: Request) -> Database:
    return request.app.state.db


def _catalog(request: Request) -> dict[str, Challenge]:
    return request.app.state.catalog


def _orchestrator(request: Request) -> DockerOrchestrator:
    return request.app.state.orchestrator


def _templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates


def _limiter(request: Request) -> RateLimiter:
    return request.app.state.limiter


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_user(request: Request):
    user_id = request.session.get("uid")
    if not user_id:
        return None
    try:
        return _db(request).get_user_by_id(int(user_id))
    except (TypeError, ValueError):
        return None


def ensure_csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = new_csrf_token()
        request.session["csrf"] = token
    return token


def check_csrf(request: Request, provided: str | None) -> None:
    if not csrf_ok(request.session.get("csrf"), provided):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def require_user(request: Request):
    user = current_user(request)
    if not user:
        return None, RedirectResponse("/login", status_code=303)
    return user, None


def context(request: Request, **extra) -> dict:
    settings = _settings(request)
    return {
        "request": request,
        "user": current_user(request),
        "csrf": ensure_csrf(request),
        "app_name": settings.app_name,
        "public_host": settings.public_host,
        "environment": settings.environment,
        **extra,
    }


def instance_url(request: Request, instance) -> str:
    settings = _settings(request)
    # Deliberately a different hostname from the dashboard. Cookies are not
    # scoped by port, so this is what keeps the admin session cookie out of
    # hostile challenge containers.
    return f"http://{settings.challenge_host}:{instance['host_port']}/"


# ---------------------------------------------------------------------------
# application factory
# ---------------------------------------------------------------------------
def create_app(
    settings: Settings | None = None,
    orchestrator: DockerOrchestrator | None = None,
) -> FastAPI:
    settings = settings or load_settings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.data_dir / "cyberlab.db")
    db.seed_admin(settings.admin_username, hash_password(settings.admin_password))
    catalog = load_catalog(settings.catalog_dir)
    orch = orchestrator or DockerOrchestrator(settings)
    limiter = RateLimiter()
    templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

    async def expiry_loop(app: FastAPI) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                now = utcnow()
                for instance in app.state.db.expired_instances(now):
                    try:
                        if instance["container_id"]:
                            app.state.orchestrator.stop(
                                instance["container_id"], instance["id"]
                            )
                    except Exception:  # noqa: BLE001 - keep the sweep alive
                        logger.exception("could not stop expired instance %s", instance["id"])
                    app.state.db.set_instance_status(instance["id"], "expired", now)
                    app.state.db.audit("system", "instance.expired", instance["id"], "")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("expiry sweep failed")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            orch.ensure_network()
        except Exception as exc:  # noqa: BLE001
            logger.warning("lab network unavailable at startup: %s", exc)
        try:
            removed = orch.reconcile(db)
            if removed:
                logger.info("removed %d orphan challenge containers", removed)
        except Exception:  # noqa: BLE001
            logger.warning("reconcile failed at startup", exc_info=True)

        task = asyncio.create_task(expiry_loop(app))
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(
        title=settings.app_name,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.db = db
    app.state.catalog = catalog
    app.state.orchestrator = orch
    app.state.limiter = limiter
    app.state.templates = templates

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie=(
            "__Host-cyberlab_session"
            if settings.session_https_only
            else "cyberlab_session"
        ),
        max_age=8 * 60 * 60,
        same_site="strict",
        https_only=settings.session_https_only,
    )

    @app.middleware("http")
    async def canonical_host(request: Request, call_next):
        # /healthz is used by container health checks and never sets a session.
        if request.url.path == "/healthz":
            return await call_next(request)
        raw = request.headers.get("host", "")
        if raw.startswith("["):
            host = raw[1 : raw.find("]")] if "]" in raw else raw
        else:
            host = raw.split(":")[0]
        allowed = {name.strip().lower() for name in settings.allowed_hosts}
        if host.lower() not in allowed:
            return PlainTextResponse("Invalid Host header", status_code=400)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'none'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        if settings.session_https_only:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

    # ---------- auth ----------
    @app.get("/", include_in_schema=False)
    def index(request: Request):
        if current_user(request):
            return RedirectResponse("/dashboard", status_code=303)
        return RedirectResponse("/login", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        if current_user(request):
            return RedirectResponse("/dashboard", status_code=303)
        return templates.TemplateResponse(request, "login.html", context(request, error=None))

    @app.post("/login", response_class=HTMLResponse)
    def login_submit(
        request: Request,
        username: str = Form(""),
        password: str = Form(""),
        csrf: str = Form(""),
    ):
        check_csrf(request, csrf)
        ip = client_ip(request)
        if not limiter.allow(f"login:{ip}", 8, 300):
            db.audit(username.strip() or "anonymous", "auth.rate_limited", "", ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                context(request, error="Too many attempts. Try again in a few minutes."),
                status_code=429,
            )

        user = db.get_user(username.strip())
        if user:
            ok = verify_password(user["password_hash"], password)
        else:
            burn_password_check(password)
            ok = False

        if not ok:
            db.audit(username.strip() or "anonymous", "auth.failed", "bad credentials", ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                context(request, error="Invalid username or password."),
                status_code=401,
            )

        request.session.clear()
        request.session["uid"] = user["id"]
        request.session["csrf"] = new_csrf_token()
        db.audit(user["username"], "auth.login", "success", ip)
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        check_csrf(request, csrf)
        user = current_user(request)
        if user:
            db.audit(user["username"], "auth.logout", "", client_ip(request))
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ---------- dashboard ----------
    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        active = {row["challenge_id"]: row for row in db.active_instances(user["id"])}
        solved = db.solves(user["id"])
        items = [
            {
                "challenge": challenge,
                "instance": active.get(challenge.id),
                "solved": challenge.id in solved,
                "url": instance_url(request, active[challenge.id])
                if challenge.id in active
                else None,
            }
            for challenge in catalog.values()
        ]
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            context(request, items=items, health=orch.health()),
        )

    @app.get("/challenges/{challenge_id}", response_class=HTMLResponse)
    def challenge_detail(request: Request, challenge_id: str):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        challenge = catalog.get(challenge_id)
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")
        return _render_challenge(request, user, challenge)

    # ---------- instance lifecycle ----------
    @app.post("/challenges/{challenge_id}/start")
    def start_challenge(
        request: Request, challenge_id: str, csrf: str = Form("")
    ):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        check_csrf(request, csrf)
        challenge = catalog.get(challenge_id)
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")

        if db.active_instance(user["id"], challenge_id):
            return RedirectResponse(f"/challenges/{challenge_id}", status_code=303)

        if db.running_count() >= settings.max_running_instances:
            return templates.TemplateResponse(
                request,
                "error.html",
                context(
                    request,
                    title="Instance limit reached",
                    message=(
                        f"You already have {db.running_count()} running instances. "
                        "Stop one before starting another."
                    ),
                ),
                status_code=429,
            )

        instance_id = uuid.uuid4().hex
        flag = f"FLAG{{{challenge_id}_{secrets.token_hex(12)}}}"
        try:
            container_id, host_port = orch.start(challenge, flag, instance_id)
        except OrchestratorError as exc:
            db.audit(user["username"], "instance.start_failed", f"{challenge_id}: {exc}", client_ip(request))
            return templates.TemplateResponse(
                request,
                "error.html",
                context(request, title="Could not start challenge", message=str(exc)),
                status_code=503,
            )

        now = utcnow()
        ttl = challenge.ttl_minutes or settings.instance_ttl_minutes
        db.create_instance(
            instance_id=instance_id,
            challenge_id=challenge_id,
            user_id=user["id"],
            container_id=container_id,
            host_port=host_port,
            flag_hash=sha256_hex(flag),
            created_at=now,
            expires_at=now + timedelta(minutes=ttl),
        )
        db.audit(
            user["username"],
            "instance.started",
            f"{challenge_id} instance={instance_id} port={host_port}",
            client_ip(request),
        )
        return RedirectResponse(f"/challenges/{challenge_id}", status_code=303)

    @app.post("/instances/{instance_id}/stop")
    def stop_instance(request: Request, instance_id: str, csrf: str = Form("")):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        check_csrf(request, csrf)
        instance = db.get_instance(instance_id)
        if not instance or instance["user_id"] != user["id"]:
            raise HTTPException(status_code=404, detail="Instance not found")

        if instance["status"] == "running" and instance["container_id"]:
            try:
                orch.stop(instance["container_id"], instance["id"])
            except OrchestratorError as exc:
                logger.warning("stop failed for %s: %s", instance_id, exc)
        db.set_instance_status(instance_id, "stopped", utcnow())
        db.audit(
            user["username"],
            "instance.stopped",
            f"{instance['challenge_id']} instance={instance_id}",
            client_ip(request),
        )
        return RedirectResponse(
            f"/challenges/{instance['challenge_id']}", status_code=303
        )

    # ---------- scoring ----------
    @app.post("/challenges/{challenge_id}/submit", response_class=HTMLResponse)
    def submit_flag(
        request: Request,
        challenge_id: str,
        flag: str = Form(""),
        csrf: str = Form(""),
    ):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        check_csrf(request, csrf)
        challenge = catalog.get(challenge_id)
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")

        ip = client_ip(request)
        if not limiter.allow(f"flag:{user['id']}:{ip}", 20, 60):
            return templates.TemplateResponse(
                request,
                "error.html",
                context(request, title="Slow down", message="Too many flag attempts."),
                status_code=429,
            )

        flag = flag.strip()
        if not flag or len(flag) > 256:
            return _render_challenge(
                request, user, challenge, error="That does not look like a flag."
            )

        instance = db.active_instance(user["id"], challenge_id)
        accepted = db.is_solved(user["id"], challenge_id) or db.flag_matches(
            user["id"], challenge_id, sha256_hex(flag)
        )
        if accepted:
            db.record_solve(
                user["id"], challenge_id, instance["id"] if instance else None
            )
            db.audit(user["username"], "flag.accepted", challenge_id, ip)
            return RedirectResponse(f"/challenges/{challenge_id}", status_code=303)

        db.audit(user["username"], "flag.rejected", challenge_id, ip)
        return _render_challenge(
            request,
            user,
            challenge,
            error="That flag is not valid for this challenge.",
            status_code=400,
        )

    # ---------- admin ----------
    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        return templates.TemplateResponse(
            request,
            "audit.html",
            context(request, rows=db.list_audit(300)),
        )

    @app.get("/health", response_class=HTMLResponse)
    def health_page(request: Request):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        usage = shutil.disk_usage(settings.data_dir)
        return templates.TemplateResponse(
            request,
            "health.html",
            context(
                request,
                health=orch.health(),
                stats=db.stats(),
                catalog_size=len(catalog),
                disk_free_gb=round(usage.free / (1024**3), 2),
                disk_total_gb=round(usage.total / (1024**3), 2),
            ),
        )

    @app.post("/admin/reconcile")
    def admin_reconcile(request: Request, csrf: str = Form("")):
        user, redirect = require_user(request)
        if redirect:
            return redirect
        check_csrf(request, csrf)
        removed = orch.reconcile(db)
        db.audit(
            user["username"], "admin.reconcile", f"removed={removed}", client_ip(request)
        )
        return RedirectResponse("/health", status_code=303)

    @app.get("/healthz")
    def healthz():
        return JSONResponse({"status": "ok"})

    return app


def _render_challenge(
    request: Request,
    user,
    challenge: Challenge,
    error: str | None = None,
    status_code: int = 200,
):
    db = _db(request)
    instance = db.active_instance(user["id"], challenge.id)
    solved = db.is_solved(user["id"], challenge.id)
    return _templates(request).TemplateResponse(
        request,
        "challenge.html",
        context(
            request,
            challenge=challenge,
            instance=instance,
            solved=solved,
            url=instance_url(request, instance) if instance else None,
            error=error,
        ),
        status_code=status_code,
    )
