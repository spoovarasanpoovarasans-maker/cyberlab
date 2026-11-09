# CyberLab

A private, self-hosted cyber-security training lab. It runs deliberately vulnerable web
challenges in disposable, network-isolated containers and gives you one hardened dashboard
to start, stop, and score them.

> **Authorized use only.** Every challenge is intentionally insecure. Run this platform only
> on infrastructure you own or are explicitly authorized to test. The default design keeps
> it private (loopback or VPN) and blocks challenge containers from reaching the internet.

## What it gives you

- **One control plane** — login, challenge catalog, start/stop, flags, scoreboard, audit log.
- **Per-instance flags** — every launch gets a fresh random flag, stored only as a SHA-256 hash.
- **Disposable targets** — each challenge runs in its own container with a read-only root
  filesystem, no capabilities, no host mounts, CPU/memory/PID limits, and a hard TTL.
- **No egress** — challenge containers live on an `internal` Docker network. They cannot
  reach the internet, the host, or other lab networks. A tiny trusted relay (one per
  instance) publishes the host port so the browser can reach the challenge without giving the
  challenge any outbound path.
- **Cookie isolation** — the dashboard and challenges use **different hostnames**, not just
  different ports. Browsers scope cookies by hostname, not port, so this is what keeps the
  admin session cookie out of hostile challenge containers.
- **Audit trail** — logins, launches, stops, flag attempts, and admin actions are recorded.

## Architecture at a glance

```
                 private network / VPN only
                           |
                    +------+------+
                    |   Caddy     |  optional TLS edge
                    +------+------+
                           |
                    +------+------+        +------------------+
   you (browser) --> |  CyberLab   | -----> | docker-socket-   |
                    |  FastAPI    |        | proxy (read-only)|
                    +------+------+        +--------+---------+
                           |                        |
                           | Docker API             | /var/run/docker.sock
                           v                        v
                 +---------+--------------------------+---------+
                 |              Docker engine                    |
                 |  +-------------+  +-------------+            |
                 |  | challenge   |  | challenge   |  internal  |
                 |  | container   |  | container   |  network   |
                 |  | (no egress) |  | (no egress) |  (no WAN)  |
                 |  +------+------+  +------+------+            |
                 |         |                |                   |
                 |  +------+------+  +------+------+            |
                 |  | relay       |  | relay       |  publishes |
                 |  | (trusted)   |  | (trusted)   |  host port |
                 |  +-------------+  +-------------+            |
                 +----------------------------------------------+
```

Full details: [ARCHITECTURE.md](ARCHITECTURE.md). Hardening checklist and threat model:
[SECURITY.md](SECURITY.md).

## Requirements

- Linux host (bare metal, VM, or WSL2) with Docker Engine 24+, or Windows with Docker
  Desktop using the WSL2 backend.
- Python 3.11+ for development outside containers.
- 2 vCPU / 2 GB RAM minimum for the control plane; each challenge is capped at 256 MB.
- A private access path: loopback, LAN, WireGuard/Tailscale, or an SSH tunnel. Do **not**
  expose the dashboard directly to the public internet.

## Quick start (Linux or WSL2)

```bash
cd cyberlab
cp .env.example .env
# edit .env: set a long CYBERLAB_SECRET_KEY and a strong CYBERLAB_ADMIN_PASSWORD

# 1. build the challenge and relay images
./scripts/build-challenges.sh

# 2. start the control plane with the Docker socket proxy
docker compose up -d --build

# 3. open the dashboard
#    http://localhost:8443
```

The control plane creates the `cyberlab_labs` internal network and the `cyberlab_edge`
network on first start. Challenge containers are attached only to the internal network and
have no published ports. Docker refuses to publish ports for internal-only containers, so
each instance also gets a small trusted relay container: it joins both networks, publishes a
port on `CYBERLAB_BIND_IP` (default `127.0.0.1`), and forwards to the challenge. Only the
relay is on the edge network; the challenge itself still cannot reach the internet.

Published ports come only from the fixed range `CYBERLAB_INSTANCE_PORT_MIN`–`MAX` (default
`20000-20099`), so the host firewall can allow just that range to your VPN.

The dashboard uses `CYBERLAB_PUBLIC_HOST` (default `localhost`) and challenge links use
`CYBERLAB_CHALLENGE_HOST` (default `127.0.0.1`). **Keep these different.** Cookies are not
isolated by port; a shared hostname would leak the admin session cookie to the intentionally
vulnerable challenge containers. The control plane refuses to start this way in production.

### Without Docker Compose (bare-metal Python)

Useful while developing on Windows or when you already run Docker locally:

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
./scripts/build-challenges.sh
uvicorn app.main:app --host 127.0.0.1 --port 8443 --reload
```

On Windows, Docker Desktop must be running. The orchestrator talks to the default Docker
socket. Bind the dashboard to `127.0.0.1` and use an SSH tunnel or VPN for remote access.
See [deploy/WSL.md](deploy/WSL.md) for the WSL2 + Docker Engine setup, including how to make
challenge ports reachable from Windows and the VPN.

## Using the lab

1. Sign in with the admin credentials from `.env`.
2. Pick a challenge and click **Start**. Wait a second, then **Open**.
3. Solve it. The challenge page explains the goal and gives optional hints.
4. Paste the flag into the submission form. Solved challenges show their write-up.
5. Stop the instance when done. Unstopped instances expire automatically after the TTL.

## Adding a challenge

Create `challenges/<id>/` with:

```
challenges/my-challenge/
  challenge.yaml
  Dockerfile
  app.py            # listens on $PORT (default 8000)
```

`challenge.yaml`:

```yaml
id: my-challenge
title: My Challenge
category: web
difficulty: easy          # easy | medium | hard | insane
description: What the learner should do.
image: cyberlab/challenge-my-challenge:latest
container_port: 8000
ttl_minutes: 30
points: 100
hints:
  - A nudge that does not give it away.
solution: |
  Step-by-step fix / walkthrough shown after solving.
```

The app receives the per-instance flag in the `LAB_FLAG` environment variable. Put it
somewhere the vulnerability can reach (a seeded row, a cookie, `/tmp/flag.txt`, etc.).
Then rebuild:

```bash
./scripts/build-challenges.sh
```

The catalog is read at startup, so restart the control plane after adding a challenge.

## Operations

| Task | Command |
|---|---|
| Build all challenge and relay images | `./scripts/build-challenges.sh` |
| Start stack | `docker compose up -d --build` |
| Stop stack | `docker compose down` |
| View logs | `docker compose logs -f cyberlab` |
| Change admin password | `python -m app.cli set-password` |
| List managed containers | `docker ps --filter label=cyberlab.managed=true` |
| Kill everything immediately | `docker ps -aq --filter label=cyberlab.managed=true \| xargs -r docker rm -f` |

## Security boundaries (read this)

- The control plane is **not** a multi-tenant sandbox. It is designed for one trusted admin
  on a private network. Do not enable public signups or expose it to the internet.
- `CYBERLAB_PUBLIC_HOST` and `CYBERLAB_CHALLENGE_HOST` must be different hostnames. This is
  a security requirement, not a cosmetic preference.
- Docker socket access is powerful. The compose stack uses a restricted socket proxy, but
  the control plane can still create containers. Treat a control-plane compromise as a host
  compromise and follow [SECURITY.md](SECURITY.md).
- Challenge containers are hostile by design. They are capped and isolated, but container
  escapes are always possible in principle. Keep Docker patched, prefer rootless Docker, and
  run the lab on a host you can rebuild.
- Never add host mounts, `--privileged`, or an external network to a challenge container.

## Roadmap

- [ ] VM/network ranges (Kali + targets) behind the same orchestrator
- [ ] Per-user accounts and isolated instances
- [ ] Wazuh/ELK log pipeline and detection exercises
- [ ] WebSocket terminal for container-based challenges
- [ ] Signed challenge images and reproducible builds
