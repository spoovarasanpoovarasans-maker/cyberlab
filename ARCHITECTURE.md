# Architecture

## Goals

1. **Safe by default** — vulnerable workloads cannot reach the internet, the host, or each
   other beyond their own container.
2. **Disposable** — every instance is recreated from an image, has a TTL, and leaves no state.
3. **Simple to operate** — one Python service, one Docker engine, one SQLite database.
4. **Private** — loopback or VPN only; no public registration, no public challenge exposure.
5. **Auditable** — every privileged action is recorded.

## Components

| Component | Responsibility | Trust level |
|---|---|---|
| Browser (admin) | Uses the dashboard, opens challenge ports | Trusted user |
| Caddy (optional) | TLS termination and reverse proxy | Trusted |
| CyberLab control plane | Auth, catalog, orchestration, scoring, audit | Trusted, high value |
| docker-socket-proxy | Restricts Docker API verbs to create/start/stop/remove | Trusted, narrow |
| Docker engine | Runs containers | Trusted, host-level |
| Challenge containers | Intentionally vulnerable targets | **Untrusted / hostile** |
| `cyberlab_labs` network | Internal bridge, no gateway to WAN | Isolation boundary |
| SQLite `data/cyberlab.db` | Users, instances, hashes, solves, audit | Sensitive |

## Network zones

```
+---------------------------- private access zone ----------------------------+
|  admin browser  --VPN/loopback-->  Caddy :443  -->  CyberLab :8443           |
+------------------------------------+-----------------------------------------+
                                     | Docker API (tcp://socket-proxy:2375)
                                     v
+---------------------------- docker host ------------------------------------+
|  socket-proxy  --/var/run/docker.sock (ro)-->  Docker engine                 |
|                                                                              |
|  challenge A (internal only)          challenge B (internal only)          |
|  relay A :<host port bound to CYBERLAB_BIND_IP>  relay B :<host port>       |
|        \___________ cyberlab_labs (internal, no WAN) ___________/           |
+------------------------------------------------------------------------------+
```

- Challenge ports bind to `CYBERLAB_BIND_IP` only. Default `127.0.0.1`; set it to the VPN
  interface address if remote users must reach instances.
- The dashboard is reached through `CYBERLAB_PUBLIC_HOST`; challenge links use
  `CYBERLAB_CHALLENGE_HOST`. They must be different hostnames (see below).
- `cyberlab_labs` is created with `internal=True`. Docker does not install a default route
  or NAT for it, so containers cannot reach the internet.
- Docker does not publish ports for containers attached only to an internal network. Each
  instance therefore gets one trusted **relay** container (`cyberlab/forwarder`): it joins
  both `cyberlab_labs` and the normal `cyberlab_edge` network, publishes the host port, and
  forwards to the challenge container by name. The challenge itself never joins the edge
  network and has no outbound path. The relay runs the same hardening profile and only runs
  `socat` with a fixed target.
- The control plane should bind to loopback and be fronted by Caddy or an SSH tunnel. It
  must never be reachable from the challenge network.

## Instance lifecycle

```
POST /challenges/{id}/start
        |
        v
  auth + CSRF + rate limit
        |
        v
  generate instance_id (uuid4 hex)
  generate flag = FLAG{<id>_<random>}
  flag_hash = SHA-256(flag)
        |
        v
  orchestrator.start():
    ensure internal + edge networks
    verify challenge and relay images exist
    pick free host port on bind IP
    run challenge container (internal net, no ports)
    run relay container (edge net, published port)
    attach relay to internal net
        |
        v
  INSERT instance(status=running, flag_hash, port, container_id)
        |
        v
  redirect -> dashboard / challenge page
        |
        +--> user stops it  -> remove challenge + relay, status=stopped
        +--> TTL expires   -> background sweep removes both, status=expired
        +--> restart       -> reconcile removes orphans not tied to a running instance
```

Flag submission hashes the input and compares it to the `flag_hash` of any instance of that
challenge owned by the user. The plaintext flag exists only inside the challenge container
and in the browser at solve time. Solved challenges are stored per user and unlock the
write-up.

## Container hardening

Every challenge is launched with:

| Control | Value |
|---|---|
| User | `1000:1000` (non-root) |
| Root filesystem | read-only |
| Writable paths | `/tmp` tmpfs, `noexec,nosuid`, 32 MB |
| Capabilities | all dropped |
| Privilege escalation | `no-new-privileges:true` |
| Memory | 256 MB, swap disabled |
| CPU | 0.5 cores |
| PIDs | 64 |
| Host mounts | none |
| Network | challenge: `cyberlab_labs` (internal) only; relay: `cyberlab_labs` + `cyberlab_edge` |
| Published port | none on the challenge; the relay publishes one port on `CYBERLAB_BIND_IP` |
| Relay | `cyberlab/forwarder`, `socat` with a fixed target, same hardening profile |
| Restart policy | none |
| TTL | per challenge (default 30 min) |
| Docker socket | not mounted |

The control plane validates the catalog image name and never accepts a user-supplied image
or command.

## Data model

```sql
users(id, username UNIQUE, password_hash, role, created_at)
instances(id, challenge_id, user_id, container_id, host_port, flag_hash,
          status, created_at, expires_at, stopped_at)
solves(user_id, challenge_id, instance_id, solved_at, PRIMARY KEY(user_id, challenge_id))
audit(id, ts, actor, action, detail, ip)
```

- Passwords: Argon2id (`argon2-cffi`).
- Flags: SHA-256 hashes only.
- Sessions: signed cookies (`itsdangerous`), `HttpOnly`, `SameSite=Strict`, optional `Secure`.
- All SQL uses parameters. The only string-built SQL is inside the intentionally vulnerable
  challenge containers, never in the control plane.

## Failure modes

| Failure | Behavior |
|---|---|
| Docker unavailable | Dashboard loads; start/stop return a clear error; health shows red |
| Image missing | Start fails with "run scripts/build-challenges.sh" |
| Port collision | Start retries with a new port (up to 3 attempts) |
| Container exits early | Start fails with the container logs and both containers are removed |
| Relay exits early | Start fails; the challenge container is removed |
| Control plane restarts | Orphan containers (challenge + relay) are removed by reconcile; DB rows older than TTL are expired |
| Database corrupt | Stop the stack, restore `data/cyberlab.db` from backup, restart |
| Flag brute force | Rate limited per IP; flags are high-entropy per instance |

## Hostname and cookie isolation

Cookies are scoped by **hostname and path, not by port**. Serving the dashboard on
`localhost:8443` and challenges on `127.0.0.1:<port>` keeps the admin session cookie out of
challenge containers because the hostnames differ. For VPN deployments use two names, for
example `lab.internal` for the dashboard and `challenges.lab.internal` for instances, both
resolving to the VPN address.

The control plane enforces this in two ways:

1. It refuses to start in production if `CYBERLAB_PUBLIC_HOST` and
   `CYBERLAB_CHALLENGE_HOST` are identical.
2. It rejects requests whose `Host` header is not in `CYBERLAB_ALLOWED_HOSTS` (except
   `/healthz`), so you cannot accidentally log in on a hostname that challenge containers
   also use.

Path-based proxying (`/lab/<id>/`) was rejected because it breaks absolute URLs in real web
apps and still shares a hostname. Subdomain-per-instance (`<id>.challenges.lab.internal`)
would isolate challenges from each other too; it needs wildcard DNS and is a future
enhancement. The trade-off today is a port range; bind it to the VPN interface and firewall
the range to the VPN. The relay exists because Docker will not publish a port for a container
that is only on an internal network; the relay is the only component that touches both zones.

## Why not path-based proxying?

Path prefixes (`/lab/<id>/`) break absolute URLs and cookies in real web apps. Giving each
instance its own host port avoids rewriting application HTML. The hostname split above is
what actually isolates cookies; the port split isolates browser origins for the same-origin
policy.

## Future: VM ranges

The orchestrator interface is deliberately narrow (`start`, `stop`, `reconcile`, `health`).
A future `VmOrchestrator` can implement the same interface with libvirt/Proxmox and reuse the
catalog, scoring, auth, and audit layers. VM ranges would live on a separate host-only
network and require a firewall VM for egress control.
