#!/usr/bin/env python3
"""Deliberately vulnerable SQL-injection login.

CyberLab challenge container. Never run this outside the lab.
The SQL is built by string concatenation on purpose.
"""

from __future__ import annotations

import base64
import html
import os
import sqlite3
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8000"))
FLAG = os.environ.get("LAB_FLAG", "FLAG{missing_flag}")

_LOCK = threading.Lock()
_CON = sqlite3.connect(":memory:", check_same_thread=False)
_CON.execute(
    "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, secret TEXT)"
)
_CON.executemany(
    "INSERT INTO users(username, password, role, secret) VALUES(?,?,?,?)",
    [
        ("admin", "sup3r_s3cret_pw", "admin", FLAG),
        ("alice", "alice123", "user", "Nothing interesting here."),
        ("bob", "hunter2", "user", "Pineapple belongs on pizza."),
    ],
)
_CON.commit()

CSS = """
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1117;color:#e6e8ee}
main{max-width:640px;margin:40px auto;padding:0 18px}
.card{background:#171a23;border:1px solid #232838;border-radius:10px;padding:18px}
h1{margin:0 0 6px;font-size:22px}p{color:#98a0b3}
label{display:block;font-size:13px;color:#98a0b3;margin-top:8px}
input{width:100%;padding:10px;border-radius:8px;border:1px solid #2b3247;background:#0e1016;color:#e6e8ee;margin:4px 0 12px;box-sizing:border-box}
button{padding:9px 16px;border-radius:8px;border:0;background:#7aa2ff;color:#08101f;font-weight:600;cursor:pointer}
code,pre{background:#0b0d12;border:1px solid #232838;padding:2px 6px;border-radius:6px}
pre{padding:12px;white-space:pre-wrap}
a{color:#7aa2ff}.small{font-size:13px;color:#98a0b3}.error{color:#ff6b6b}
"""


def page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{html.escape(title)} - ShopLogin</title><style>{CSS}</style></head>"
        f"<body><main><div class=\"card\">{body}</div></main></body></html>"
    )


def cookies(header: str) -> dict[str, str]:
    jar: dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            jar[key.strip()] = value.strip()
    return jar


class Handler(BaseHTTPRequestHandler):
    server_version = "ShopLogin/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def send_page(self, body: str, status: int = 200, extra_headers: list[str] | None = None) -> None:
        data = page("ShopLogin", body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for header in extra_headers or []:
            self.send_header("Set-Cookie", header)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str, extra_headers: list[str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for header in extra_headers or []:
            self.send_header("Set-Cookie", header)
        self.end_headers()

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path in {"/", "/login"}:
            self.send_page(
                "<h1>ShopLogin</h1>"
                "<p>Sign in to view your account.</p>"
                '<form method="post" action="/login">'
                '<label for="u">Username</label><input id="u" name="username" autocomplete="off">'
                '<label for="p">Password</label><input id="p" name="password" type="password">'
                "<button type=\"submit\">Sign in</button></form>"
                '<p class="small">Demo accounts: alice/alice123, bob/hunter2</p>'
            )
            return

        if path == "/profile":
            auth = cookies(self.headers.get("Cookie", "")).get("auth")
            if not auth:
                self.redirect("/login")
                return
            try:
                decoded = base64.b64decode(auth).decode("utf-8")
                username, _role = decoded.split("|", 1)
            except Exception:
                self.redirect("/login")
                return
            with _LOCK:
                row = _CON.execute(
                    "SELECT username, role, secret FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
            if not row:
                self.redirect("/login")
                return
            self.send_page(
                f"<h1>Profile</h1><p>Signed in as <b>{html.escape(row[0])}</b> ({html.escape(row[1])}).</p>"
                f"<p>Your account secret:</p><pre>{html.escape(row[2])}</pre>"
                '<p class="small"><a href="/logout">Sign out</a></p>'
            )
            return

        if path == "/logout":
            self.redirect("/login", ["auth=deleted; Path=/; Max-Age=0"])
            return

        self.send_page("<h1>404</h1><p>No such page.</p>", status=404)

    def do_POST(self) -> None:
        if urllib.parse.urlparse(self.path).path != "/login":
            self.send_page("<h1>404</h1>", status=404)
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = urllib.parse.parse_qs(raw)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        # VULNERABLE ON PURPOSE: string-concatenated SQL.
        sql = (
            "SELECT username, role, secret FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        try:
            with _LOCK:
                row = _CON.execute(sql).fetchone()
        except Exception as exc:
            self.send_page(
                f"<h1>SQL error</h1><pre>{html.escape(str(exc))}</pre>"
                '<p class="small"><a href="/login">Back</a></p>',
                status=500,
            )
            return

        if not row:
            self.send_page(
                "<h1>Login failed</h1><p class=\"error\">Invalid credentials.</p>"
                '<p class="small"><a href="/login">Try again</a></p>',
                status=401,
            )
            return

        token = base64.b64encode(f"{row[0]}|{row[1]}".encode()).decode()
        self.redirect("/profile", [f"auth={token}; Path=/"])


if __name__ == "__main__":
    print(f"ShopLogin listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
