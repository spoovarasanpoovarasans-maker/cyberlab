#!/usr/bin/env python3
"""Deliberately vulnerable guestbook with stored and reflected XSS.

CyberLab challenge container. Never run this outside the lab.
The flag is placed in a non-HttpOnly cookie on purpose.
"""

from __future__ import annotations

import html
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8000"))
FLAG = os.environ.get("LAB_FLAG", "FLAG{missing_flag}")

_LOCK = threading.Lock()
_MESSAGES: list[tuple[str, str]] = [
    ("system", "Welcome to the guestbook. Say hi!"),
]

CSS = """
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1117;color:#e6e8ee}
main{max-width:720px;margin:40px auto;padding:0 18px}
.card{background:#171a23;border:1px solid #232838;border-radius:10px;padding:18px;margin:12px 0}
h1{margin:0 0 6px;font-size:22px}h2{font-size:16px;margin:0 0 6px}p{color:#98a0b3}
label{display:block;font-size:13px;color:#98a0b3;margin-top:8px}
input,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid #2b3247;background:#0e1016;color:#e6e8ee;margin:4px 0 12px;box-sizing:border-box;font:inherit}
button{padding:9px 16px;border-radius:8px;border:0;background:#7aa2ff;color:#08101f;font-weight:600;cursor:pointer}
code,pre{background:#0b0d12;border:1px solid #232838;padding:2px 6px;border-radius:6px}
a{color:#7aa2ff}.small{font-size:13px;color:#98a0b3}.muted{color:#98a0b3}
"""


def page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{html.escape(title)} - Guestbook</title><style>{CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "Guestbook/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def send_page(self, body: str, status: int = 200) -> None:
        data = page("Guestbook", body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        # VULNERABLE ON PURPOSE: no HttpOnly, no Secure, no SameSite.
        self.send_header("Set-Cookie", f"lab_flag={FLAG}; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Set-Cookie", f"lab_flag={FLAG}; Path=/")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {"/", "/guestbook"}:
            self.send_page("<h1>404</h1><p>No such page.</p>", status=404)
            return

        q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
        with _LOCK:
            messages = list(_MESSAGES)

        reflected = ""
        if q:
            # VULNERABLE ON PURPOSE: reflected without escaping.
            reflected = f'<div class="card"><p>You searched for: {q}</p></div>'

        items = "".join(
            f'<div class="card"><b>{author}</b><p>{body}</p></div>'
            for author, body in reversed(messages)
        )

        body = (
            "<h1>Guestbook</h1>"
            '<p class="small">The flag is in a cookie. Get JavaScript to run in this page '
            'and read <code>document.cookie</code>.</p>'
            f"{reflected}"
            '<div class="card"><h2>Leave a message</h2>'
            '<form method="post" action="/guestbook">'
            '<label for="a">Name</label><input id="a" name="author" value="guest">'
            '<label for="m">Message</label><textarea id="m" name="body" rows="3"></textarea>'
            '<button type="submit">Post</button></form></div>'
            '<div class="card"><h2>Search</h2>'
            '<form method="get" action="/guestbook">'
            '<input name="q" placeholder="Search messages...">'
            '<button type="submit">Search</button></form></div>'
            f"<h2>Messages</h2>{items}"
        )
        self.send_page(body)

    def do_POST(self) -> None:
        if urllib.parse.urlparse(self.path).path != "/guestbook":
            self.send_page("<h1>404</h1>", status=404)
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = urllib.parse.parse_qs(raw)
        author = form.get("author", ["guest"])[0] or "guest"
        message = form.get("body", [""])[0]

        with _LOCK:
            _MESSAGES.append((author, message))

        self.redirect("/guestbook")


if __name__ == "__main__":
    print(f"Guestbook listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
