import re

from fastapi.testclient import TestClient

from app.factory import create_app

from .helpers import FakeOrchestrator, make_settings

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


def csrf_from(response) -> str:
    match = CSRF_RE.search(response.text)
    assert match, response.text
    return match.group(1)


def login(client: TestClient) -> None:
    page = client.get("/login")
    token = csrf_from(page)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "test-password-123", "csrf": token},
    )
    assert response.status_code == 303


def test_noncanonical_host_is_rejected(tmp_path):
    app = create_app(make_settings(tmp_path), orchestrator=FakeOrchestrator())
    with TestClient(app, follow_redirects=False) as client:
        blocked = client.get("/login", headers={"Host": "127.0.0.1"})
        assert blocked.status_code == 400
        # Container health checks must still work without the canonical host.
        healthy = client.get("/healthz", headers={"Host": "127.0.0.1"})
        assert healthy.status_code == 200


def test_requires_login(tmp_path):
    app = create_app(make_settings(tmp_path), orchestrator=FakeOrchestrator())
    with TestClient(app, follow_redirects=False) as client:
        response = client.get("/dashboard")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_login_rejects_bad_password(tmp_path):
    app = create_app(make_settings(tmp_path), orchestrator=FakeOrchestrator())
    with TestClient(app, follow_redirects=False) as client:
        page = client.get("/login")
        token = csrf_from(page)
        response = client.post(
            "/login",
            data={"username": "admin", "password": "nope", "csrf": token},
        )
        assert response.status_code == 401
        assert "Invalid username or password" in response.text


def test_session_cookie_is_hardened(tmp_path):
    app = create_app(make_settings(tmp_path), orchestrator=FakeOrchestrator())
    with TestClient(app, follow_redirects=False) as client:
        page = client.get("/login")
        token = csrf_from(page)
        response = client.post(
            "/login",
            data={"username": "admin", "password": "test-password-123", "csrf": token},
        )
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
        assert "path=/" in cookie


def test_csrf_is_required(tmp_path):
    app = create_app(make_settings(tmp_path), orchestrator=FakeOrchestrator())
    with TestClient(app, follow_redirects=False) as client:
        login(client)
        response = client.post(
            "/challenges/sqli-login/start", data={"csrf": "wrong-token"}
        )
        assert response.status_code == 403


def test_start_submit_and_stop(tmp_path):
    orchestrator = FakeOrchestrator()
    app = create_app(make_settings(tmp_path), orchestrator=orchestrator)
    with TestClient(app, follow_redirects=False) as client:
        login(client)

        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 200
        token = csrf_from(dashboard)

        start = client.post("/challenges/sqli-login/start", data={"csrf": token})
        assert start.status_code == 303
        assert len(orchestrator.started) == 1
        challenge_id, flag, instance_id = orchestrator.started[0]
        assert challenge_id == "sqli-login"
        assert flag.startswith("FLAG{sqli-login_")

        detail = client.get("/challenges/sqli-login")
        assert detail.status_code == 200
        assert "19000" in detail.text
        token = csrf_from(detail)

        rejected = client.post(
            "/challenges/sqli-login/submit",
            data={"csrf": token, "flag": "FLAG{not_it}"},
        )
        assert rejected.status_code == 400

        accepted = client.post(
            "/challenges/sqli-login/submit",
            data={"csrf": token, "flag": flag},
        )
        assert accepted.status_code == 303

        solved = client.get("/challenges/sqli-login")
        assert "solved" in solved.text
        assert "Write-up" in solved.text
        token = csrf_from(solved)

        stopped = client.post(
            f"/instances/{instance_id}/stop", data={"csrf": token}
        )
        assert stopped.status_code == 303
        assert orchestrator.stopped


def test_instance_limit(tmp_path):
    orchestrator = FakeOrchestrator()
    app = create_app(
        make_settings(tmp_path, max_running_instances=1), orchestrator=orchestrator
    )
    with TestClient(app, follow_redirects=False) as client:
        login(client)
        token = csrf_from(client.get("/dashboard"))
        assert (
            client.post("/challenges/sqli-login/start", data={"csrf": token}).status_code
            == 303
        )
        token = csrf_from(client.get("/dashboard"))
        response = client.post("/challenges/xss-guestbook/start", data={"csrf": token})
        assert response.status_code == 429
        assert len(orchestrator.started) == 1
