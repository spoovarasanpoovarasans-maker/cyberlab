#!/usr/bin/env python3
"""Deliberately vulnerable command-injection ping tool.

CyberLab challenge container. Never run this outside the lab.
The host field is passed to a shell on purpose.
"""

from __future__ import annotations

import html
import os
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8000"))
FLAG = os.environ.get("LAB_FLAG", "FLAG{missing_flag}")
FLAG_PATH = "/tmp/flag.txt"

# The container root is read-only; /tmp is a tmpfs.
with open(FLAG_PATH, "w", encoding="utf-8") as handle:
    handle.write(FLAG + "\n")

CSS = """
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1117;color:#e6e8ee}
main{max-width:720px;margin:40px auto;padding:0 18px}
.card{background:#171a23;border:1px solid #232838;border-radius:10px;padding:18px}
h1{margin:0 0 6px;font-size:22px}p{color:#98a0b3}
label{display:block;font-size:13px;color:#98a0b3;margin-top:8px}
input{width:100%;padding:10px;border-radius:8px;border:1px solid #2b3247;background:#0e1016;color:#e6e8ee;margin:4px 0 12px;box-sizing:border-box}
button{padding:9px 16px;border-radius:8px;border:0;background:#7aa2ff;color:#08101f;font-weight:600;cursor:pointer}
code,pre{background:#0b0d12;border:1px solid #232838;padding:2px 6px;border-radius:6px}
pre{padding:12px;white-space:pre-wrap}
a{color:#7aa2ff}.small{font-size:13px;color:#98a0b3}
"""


def page(body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>NetTool</title><style>{CSS}</style></head>"
        f"<body><main><div class=\"card\">{body}</div></main></body></html>"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "NetTool/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def send_page(self, body: str, status: int = 200) -> None:
        data = page(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {"/", "/tools"}:
            self.send_page("<h1>404</h1><p>No such page.</p>", status=404)
            return

        host = urllib.parse.parse_qs(parsed.query).get("host", [""])[0]
        output = ""
        if host:
            # VULNERABLE ON PURPOSE: shell=True with unsanitized input.
            command = "ping -c 1 " + host
            try:
                proc = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = (proc.stdout or "") + (proc.stderr or "")
            except Exception as exc:  # noqa: BLE001
                output = f"error: {exc}"

        self.send_page(
            "<h1>NetTool</h1>"
            "<p>Quick reachability check.</p>"
            '<form method="get" action="/tools">'
            '<label for="h">Host</label>'
            f'<input id="h" name="host" value="{html.escape(host)}" placeholder="127.0.0.1">'
            '<button type="submit">Ping</button></form>'
            f"<pre>{html.escape(output)}</pre>"
        )


if __name__ == "__main__":
    print(f"NetTool listening on 0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
