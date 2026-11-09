import pytest

from app.config import load_settings


def _production_env(monkeypatch, **overrides):
    values = {
        "CYBERLAB_ENV": "production",
        "CYBERLAB_SECRET_KEY": "s" * 48,
        "CYBERLAB_ADMIN_PASSWORD": "p" * 20,
        "CYBERLAB_SESSION_HTTPS_ONLY": "true",
        "CYBERLAB_PUBLIC_HOST": "lab.internal",
        "CYBERLAB_CHALLENGE_HOST": "challenges.lab.internal",
        "CYBERLAB_ALLOWED_HOSTS": "lab.internal",
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_production_rejects_shared_dashboard_and_challenge_host(monkeypatch):
    _production_env(monkeypatch, CYBERLAB_CHALLENGE_HOST="lab.internal")
    with pytest.raises(RuntimeError, match="must differ"):
        load_settings()


def test_production_accepts_distinct_hosts(monkeypatch):
    _production_env(monkeypatch)
    settings = load_settings()
    assert settings.public_host == "lab.internal"
    assert settings.challenge_host == "challenges.lab.internal"
    assert settings.allowed_hosts == ("lab.internal",)
    assert settings.instance_port_min == 20000
    assert settings.instance_port_max == 20099


def test_port_range_is_validated(monkeypatch):
    monkeypatch.setenv("CYBERLAB_INSTANCE_PORT_MIN", "30000")
    monkeypatch.setenv("CYBERLAB_INSTANCE_PORT_MAX", "20000")
    with pytest.raises(RuntimeError, match="PORT_MIN"):
        load_settings()
