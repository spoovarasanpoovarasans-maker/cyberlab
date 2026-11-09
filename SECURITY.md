# Security model and hardening

This document is the operating contract for CyberLab. If you change the architecture, update
this file first.

## Threat model

### Assets

- The Docker host and everything reachable from it.
- The control-plane database (admin hash, flag hashes, audit log).
- The integrity of the lab (flags, scoreboard, challenge images).
- The private network the lab is attached to.

### Adversaries

| Adversary | Capability | Goal |
|---|---|---|
| Learner / admin | Can attack challenge containers and use the dashboard | Solve challenges; accidentally escape |
| Malicious challenge payload | Code running inside a challenge container | Reach the host, internet, control plane, or other instances |
| Network attacker | On the same LAN/VPN | Reach the dashboard or challenge ports |
| Stolen session | Has an admin cookie | Control the lab |
| Supply-chain attacker | Compromises a base image or dependency | Persist on the host |

### Trust boundaries

1. **Browser ↔ control plane** — authenticated, CSRF-protected, TLS via Caddy or SSH tunnel.
2. **Control plane ↔ Docker** — via a restricted socket proxy. This is the most sensitive
   boundary. A control-plane compromise is a host compromise.
3. **Challenge container ↔ everything** — hostile. No egress, no host mounts, no socket,
   read-only root, dropped capabilities.
4. **Host ↔ private network** — firewall allows only the VPN/SSH and dashboard ports.

### Explicit non-goals

- Multi-tenant isolation between mutually distrusting users.
- Public internet exposure of vulnerable workloads.
- Protection against a kernel/container-runtime escape by a determined attacker. Use a
  disposable host, rootless Docker, and current patches.

## Controls

### Host

- [ ] Dedicated Linux host or VM; no personal data, no production credentials.
- [ ] Full-disk encryption.
- [ ] Automatic security updates (`unattended-upgrades`).
- [ ] SSH keys only, no root login, fail2ban.
- [ ] Host firewall: default deny inbound; allow SSH/VPN and the dashboard only.
- [ ] Access via WireGuard/Tailscale/SSH tunnel. No port forwarding on the router.
- [ ] Docker Engine and kernel patched; reboot after kernel updates.
- [ ] Prefer rootless Docker or `userns-remap` if your setup allows it.
- [ ] Snapshot the host before adding new challenge images.

### Control plane

- [ ] Strong, unique `CYBERLAB_SECRET_KEY` (32+ random bytes).
- [ ] Strong admin password; Argon2id hash in SQLite; change with `python -m app.cli set-password`.
- [ ] `CYBERLAB_SESSION_HTTPS_ONLY=true` when served over TLS.
- [ ] `CYBERLAB_PUBLIC_HOST` and `CYBERLAB_CHALLENGE_HOST` are **different hostnames**.
      Cookies are not scoped by port; a shared hostname leaks the admin session cookie to
      hostile challenge containers. Production mode refuses to start otherwise.
- [ ] `CYBERLAB_ALLOWED_HOSTS` contains only the canonical dashboard hostname(s).
- [ ] Bind to `127.0.0.1` or the VPN interface, never `0.0.0.0` on a public host.
- [ ] Login rate limiting and audit logging enabled (built in).
- [ ] Keep `python-multipart`, `fastapi`, `uvicorn`, `docker`, `argon2-cffi` patched.
- [ ] Run as an unprivileged user. Do not run as root.

### Docker / orchestration

- [ ] Use the socket proxy in `docker-compose.yml`; never mount the raw socket into the
      control plane if you can avoid it.
- [ ] Restrict the proxy to `CONTAINERS`, `IMAGES`, `NETWORKS`, `POST`, `DELETE`; leave
      `EXEC`, `BUILD`, `VOLUMES`, `SWARM` disabled.
- [ ] Challenge containers: non-root, read-only root, `cap_drop=ALL`,
      `no-new-privileges`, memory/CPU/PID limits, no host mounts, no socket.
- [ ] Challenge network is `internal=True`; verify egress is blocked after every Docker
      upgrade.
- [ ] The challenge container has **no published ports**. Only the per-instance relay
      (`cyberlab/forwarder`) joins the edge network and publishes a port.
- [ ] The relay runs the same hardening profile and only executes `socat` with a fixed
      target; never add a shell, package manager, or arbitrary command to it.
- [ ] Publish challenge ports to the VPN/loopback address only.
- [ ] Firewall only `CYBERLAB_INSTANCE_PORT_MIN`–`CYBERLAB_INSTANCE_PORT_MAX` to the VPN
      subnet, plus the dashboard port. Do not open the whole ephemeral range.
- [ ] No `--privileged`, no `--pid=host`, no `--network=host`, no devices.
- [ ] Delete containers on stop and expire; reconcile orphans on startup.

### Data

- [ ] `data/` is `0700`, owned by the service user; back it up encrypted.
- [ ] Flags are stored as SHA-256 hashes; per-instance flags are high entropy.
- [ ] Audit log is append-only in the DB; ship it off-host if you need tamper evidence.
- [ ] Do not commit `.env`, `data/`, or backups to git.

### Operations

- [ ] Review `/audit` after each session.
- [ ] Keep the lab powered off when not in use.
- [ ] Kill switch: `docker ps -aq --filter label=cyberlab.managed=true | xargs -r docker rm -f`.
- [ ] Rebuild challenge images after any base-image security update.
- [ ] Test isolation after Docker upgrades (see verification below).

## Verification

Run these from the host after starting the stack and launching one challenge.

```bash
# 1. The dashboard is not public
ss -ltnp | grep -E '8443|443'          # must be 127.0.0.1 or the VPN IP

# 2. A challenge port is not public
ss -ltnp | grep <challenge_port>       # must be 127.0.0.1 or the VPN IP

# 3. The challenge has no internet egress
docker run --rm --network cyberlab_labs alpine:3.20 \
  sh -c 'wget -T 3 -qO- https://example.com && echo REACHABLE || echo BLOCKED'
# expected: BLOCKED

# 4. The challenge cannot reach the control plane
docker run --rm --network cyberlab_labs alpine:3.20 \
  sh -c 'nc -z -w2 host.docker.internal 8443 && echo REACHABLE || echo BLOCKED'
# expected: BLOCKED (or no route)

# 5. No privileged containers
docker ps --filter label=cyberlab.managed=true \
  --format '{{.Names}}' | xargs -r -n1 docker inspect \
  --format '{{.Name}} privileged={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}}'
# expected: privileged=false caps=[]

# 5b. The challenge container is internal-only; only the relay publishes a port
docker ps -q --filter label=cyberlab.role=challenge | xargs -r docker inspect \
  --format '{{.Name}} nets={{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}ports={{json .HostConfig.PortBindings}}'
# expected: nets=cyberlab_labs ports={}
docker ps -q --filter label=cyberlab.role=forwarder | xargs -r docker inspect \
  --format '{{.Name}} nets={{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
# expected: both cyberlab_labs and cyberlab_edge

# 6. Containers are read-only and non-root
docker ps -q --filter label=cyberlab.managed=true | xargs -r docker inspect \
  --format '{{.Name}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}}'
# expected: user=1000:1000 readonly=true

# 7. The admin session cookie is not sent to a challenge host
#    (log in at the dashboard first, then run this)
curl -sv "http://${CYBERLAB_CHALLENGE_HOST:-127.0.0.1}:<challenge_port>/" 2>&1 \
  | grep -i '^> cookie' || echo "no cookies sent"
# expected: no cyberlab_session / __Host-cyberlab_session
```

## Incident response

If you suspect a challenge container escaped or the control plane was compromised:

1. **Contain:** `docker ps -aq --filter label=cyberlab.managed=true | xargs -r docker rm -f`
   and `docker compose down`.
2. **Isolate:** disconnect the host from the network (or move it to a quarantine VLAN).
3. **Preserve:** snapshot the VM/disk and copy `data/`, Docker logs, and `docker inspect`
   output before rebuilding.
4. **Rotate:** `CYBERLAB_SECRET_KEY`, admin password, VPN keys, and any host credentials.
5. **Rebuild:** recreate the host from a trusted image; do not reuse the old Docker engine.
6. **Review:** audit log, Docker events, and host auth logs for the blast radius.

## Residual risks

- Docker socket access by the control plane is root-equivalent even through a proxy. The
  proxy reduces the API surface, not the trust requirement.
- A kernel or runc vulnerability could allow escape. Keep the host disposable and patched.
- Published challenge ports are reachable by anyone who can reach the bind IP. Firewall the
  port range to the VPN subnet.
- The relay is trusted infrastructure and sits on both the internal and edge networks. It
  runs only `socat` with a fixed target, but treat a relay compromise as a bridge between
  zones and rebuild it from the pinned image.
- A determined learner can DoS their own challenge container; limits bound the blast radius.
- Challenges share a hostname (`CYBERLAB_CHALLENGE_HOST`) and therefore can read each
  other's cookies. This matters only if you later support mutually distrusting users; use
  per-instance subdomains plus wildcard DNS at that point.
- SQLite is single-node. Back it up; do not run multiple control-plane replicas.
