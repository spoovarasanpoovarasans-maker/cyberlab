"""Configuration loaded from environment / .env with safe production defaults."""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _bool(name: str, default: bool = False) -> bool:
    return str(_env(name, str(default))).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = _env(name, str(default))
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be a number, got {raw!r}") from exc


def _path(name: str, default: Path) -> Path:
    return Path(_env(name, str(default)) or default).expanduser().resolve()


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    secret_key: str
    admin_username: str
    admin_password: str
    data_dir: Path
    catalog_dir: Path
    bind_ip: str
    public_host: str
    challenge_host: str
    control_port: int
    session_https_only: bool
    allowed_hosts: tuple[str, ...]
    instance_ttl_minutes: int
    max_running_instances: int
    instance_port_min: int
    instance_port_max: int
    docker_host: str | None
    docker_network: str
    docker_edge_network: str
    forwarder_image: str
    lab_memory_limit: str
    lab_cpu_limit: float
    lab_pids_limit: int
    log_level: str

    @property
    def production(self) -> bool:
        return self.environment == "production"


def load_settings() -> Settings:
    environment = (_env("CYBERLAB_ENV", "development") or "development").lower()
    if environment not in {"development", "production"}:
        raise RuntimeError("CYBERLAB_ENV must be 'development' or 'production'")

    secret_key = _env("CYBERLAB_SECRET_KEY")
    if not secret_key:
        if environment == "production":
            raise RuntimeError("CYBERLAB_SECRET_KEY is required when CYBERLAB_ENV=production")
        secret_key = secrets.token_urlsafe(48)
        print(
            "WARNING: CYBERLAB_SECRET_KEY is unset; using an ephemeral key. "
            "Sessions will reset on restart.",
            file=sys.stderr,
        )

    admin_password = _env("CYBERLAB_ADMIN_PASSWORD")
    if not admin_password:
        if environment == "production":
            raise RuntimeError("CYBERLAB_ADMIN_PASSWORD is required when CYBERLAB_ENV=production")
        admin_password = "change-me-now"
        print(
            "WARNING: CYBERLAB_ADMIN_PASSWORD is unset; using the development "
            "password 'change-me-now'.",
            file=sys.stderr,
        )

    if environment == "production":
        if len(secret_key) < 32:
            raise RuntimeError("CYBERLAB_SECRET_KEY must be at least 32 characters in production")
        if len(admin_password) < 16:
            raise RuntimeError("CYBERLAB_ADMIN_PASSWORD must be at least 16 characters in production")
        if not _bool("CYBERLAB_SESSION_HTTPS_ONLY", False):
            print(
                "WARNING: production mode without CYBERLAB_SESSION_HTTPS_ONLY=true. "
                "Session cookies will not have the Secure flag.",
                file=sys.stderr,
            )

    bind_ip = _env("CYBERLAB_BIND_IP", "127.0.0.1") or "127.0.0.1"
    public_host = _env("CYBERLAB_PUBLIC_HOST", "localhost") or "localhost"
    challenge_host = _env("CYBERLAB_CHALLENGE_HOST", "127.0.0.1") or "127.0.0.1"

    # Cookies are scoped by hostname, NOT by port. If the dashboard and the
    # challenge instances share a hostname, a hostile challenge container will
    # receive the admin session cookie on every request. Refuse to run that way
    # in production and warn loudly in development.
    if public_host.strip().lower() == challenge_host.strip().lower():
        message = (
            "CYBERLAB_CHALLENGE_HOST must differ from CYBERLAB_PUBLIC_HOST. "
            "Cookies are not isolated by port, so a shared hostname would send "
            "the admin session cookie to hostile challenge containers."
        )
        if environment == "production":
            raise RuntimeError(message)
        print(f"WARNING: {message}", file=sys.stderr)

    allowed_hosts = tuple(
        host.strip()
        for host in (
            _env("CYBERLAB_ALLOWED_HOSTS", public_host) or public_host
        ).split(",")
        if host.strip()
    )

    port_min = max(1024, _int("CYBERLAB_INSTANCE_PORT_MIN", 20000))
    port_max = min(65535, _int("CYBERLAB_INSTANCE_PORT_MAX", 20099))
    if port_min > port_max:
        raise RuntimeError("CYBERLAB_INSTANCE_PORT_MIN must be <= CYBERLAB_INSTANCE_PORT_MAX")
    if port_max - port_min > 1000:
        raise RuntimeError("challenge port range must contain at most 1001 ports")

    return Settings(
        app_name=_env("CYBERLAB_APP_NAME", "CyberLab") or "CyberLab",
        environment=environment,
        secret_key=secret_key,
        admin_username=_env("CYBERLAB_ADMIN_USERNAME", "admin") or "admin",
        admin_password=admin_password,
        data_dir=_path("CYBERLAB_DATA_DIR", BASE_DIR / "data"),
        catalog_dir=_path("CYBERLAB_CATALOG_DIR", BASE_DIR / "challenges"),
        bind_ip=bind_ip,
        public_host=public_host,
        challenge_host=challenge_host,
        control_port=_int("CYBERLAB_CONTROL_PORT", 8443),
        session_https_only=_bool("CYBERLAB_SESSION_HTTPS_ONLY", False),
        allowed_hosts=allowed_hosts,
        instance_ttl_minutes=max(1, _int("CYBERLAB_INSTANCE_TTL_MINUTES", 30)),
        max_running_instances=max(1, _int("CYBERLAB_MAX_RUNNING_INSTANCES", 4)),
        instance_port_min=port_min,
        instance_port_max=port_max,
        docker_host=_env("CYBERLAB_DOCKER_HOST"),
        docker_network=_env("CYBERLAB_DOCKER_NETWORK", "cyberlab_labs") or "cyberlab_labs",
        docker_edge_network=(
            _env("CYBERLAB_DOCKER_EDGE_NETWORK", "cyberlab_edge") or "cyberlab_edge"
        ),
        forwarder_image=(
            _env("CYBERLAB_FORWARDER_IMAGE", "cyberlab/forwarder:latest")
            or "cyberlab/forwarder:latest"
        ),
        lab_memory_limit=_env("CYBERLAB_LAB_MEMORY_LIMIT", "256m") or "256m",
        lab_cpu_limit=max(0.05, _float("CYBERLAB_LAB_CPU_LIMIT", 0.5)),
        lab_pids_limit=max(16, _int("CYBERLAB_LAB_PIDS_LIMIT", 64)),
        log_level=(_env("CYBERLAB_LOG_LEVEL", "INFO") or "INFO").upper(),
    )
