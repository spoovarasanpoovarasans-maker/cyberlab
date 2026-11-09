# Running CyberLab on Windows with WSL2

This is the recommended local setup for this machine: Docker Engine runs inside WSL2 Ubuntu,
the control plane runs in containers, and the Windows browser reaches the dashboard and
challenge ports through WSL's mirrored networking.

> The lab is private. Do not expose it through your router. For remote access, use a VPN or
> an SSH tunnel and read [SECURITY.md](../SECURITY.md) first.

## 1. Enable systemd and mirrored networking in WSL2

Windows 11 22H2+ supports mirrored networking, which lets Windows reach services bound to
`127.0.0.1` inside WSL. Without it, dynamic challenge ports are painful to forward.

In Windows PowerShell:

```powershell
notepad $env:USERPROFILE\.wslconfig
```

Add:

```ini
[wsl2]
networkingMode=mirrored
```

Inside WSL, enable systemd:

```bash
sudo tee /etc/wsl.conf >/dev/null <<'EOF'
[boot]
systemd=true
EOF
```

Then restart WSL from Windows:

```powershell
wsl --shutdown
```

Start Ubuntu again and verify:

```bash
systemctl is-system-running
# expected: running (or "degraded" is usually fine)
```

## 2. Install Docker Engine inside WSL

Run inside Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker
```

Verify:

```bash
docker run --rm hello-world
docker compose version
```

> **Security note:** membership in the `docker` group is root-equivalent on the host. For a
> higher-assurance setup, use rootless Docker or run the lab on a dedicated, disposable Linux
> host.

## 3. Put the project on the Linux filesystem

Building from `/mnt/c/...` works but is slow and can hit permission quirks. Copy it into WSL:

```bash
cp -r /mnt/c/Users/spoov/cyberlab ~/cyberlab
cd ~/cyberlab
chmod +x scripts/*.sh
```

## 4. Configure

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # secret key
nano .env
```

Set at least:

```ini
CYBERLAB_ENV=development
CYBERLAB_SECRET_KEY=<paste the generated value>
CYBERLAB_ADMIN_PASSWORD=<a long unique password>

CYBERLAB_BIND_IP=127.0.0.1
CYBERLAB_PUBLIC_HOST=localhost
CYBERLAB_CHALLENGE_HOST=127.0.0.1
CYBERLAB_ALLOWED_HOSTS=localhost
```

`CYBERLAB_PUBLIC_HOST` and `CYBERLAB_CHALLENGE_HOST` must differ. This is what prevents the
admin session cookie from being sent to the vulnerable challenge containers.

## 5. Build and run

```bash
./scripts/build-challenges.sh   # builds challenge images + cyberlab/forwarder
docker compose up -d --build
docker compose logs -f cyberlab
```

Open **http://localhost:8443** in Windows. The challenge links use `127.0.0.1:<port>`; with
mirrored networking they work from the Windows browser too.

## 6. Verify isolation

Inside WSL, after starting a challenge:

```bash
./scripts/security-check.sh
```

Expected:

- `cyberlab_labs` is `internal=true`.
- A test container on that network cannot reach `https://example.com`.
- Challenge containers are non-root, read-only, unprivileged, with no added capabilities.
- Challenge containers have **no published ports**; only the trusted relay publishes a port,
  and it is bound to `127.0.0.1` (or the VPN IP), not `0.0.0.0`.
- The challenge container is on `cyberlab_labs` only; the relay is on both
  `cyberlab_labs` and `cyberlab_edge`.

## 7. Remote / VPN access

Do not port-forward the dashboard or challenge range on your router. Instead:

1. Install WireGuard or Tailscale on the machine that hosts the lab.
2. Give the lab two private DNS names that resolve to the VPN address:
   - `lab.internal` → dashboard (`CYBERLAB_PUBLIC_HOST`)
   - `challenges.lab.internal` → challenge ports (`CYBERLAB_CHALLENGE_HOST`)
3. Set `CYBERLAB_BIND_IP` to the VPN interface address (for example `10.8.0.1`), and
   `CYBERLAB_ALLOWED_HOSTS=lab.internal`.
4. Firewall only these to the VPN subnet:
   - `8443/tcp` (dashboard)
   - `20000-20099/tcp` (challenge range, configurable)
5. Optionally add Caddy with `docker-compose.edge.yml` for TLS.

If you use a plain SSH tunnel instead of a VPN, tunnel the dashboard only:

```bash
ssh -L 8443:127.0.0.1:8443 user@lab-host
```

Dynamic challenge ports do not tunnel cleanly one-by-one; use a VPN or an SSH SOCKS proxy with
remote DNS for those.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard shows "Docker is not available" | `sudo systemctl status docker`; ensure `DOCKER_HOST` is reachable from the container |
| "image ... is not built" | run `./scripts/build-challenges.sh` |
| "Invalid Host header" | use the exact `CYBERLAB_PUBLIC_HOST` in the URL, or add the host to `CYBERLAB_ALLOWED_HOSTS` |
| Challenge link does not load from Windows | enable `networkingMode=mirrored` and `wsl --shutdown`, or use Docker Desktop on Windows instead |
| Permission denied on `/data` | use the provided named volume; if you bind-mount, `chown 1000:1000 ./data` |
| Port range exhausted | stop instances or widen `CYBERLAB_INSTANCE_PORT_MIN/MAX` |
| Sessions reset on restart | `CYBERLAB_SECRET_KEY` is unset or changing between runs |
