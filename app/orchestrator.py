"""Docker orchestration with a deliberately small, hardened surface.

Every challenge container is launched with the same security profile. The
orchestrator never accepts a user-supplied image, command, mount, or capability.
"""

from __future__ import annotations

import errno
import logging
import random
import socket
import threading

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.types import Ulimit

from .catalog import Challenge
from .config import Settings
from .db import Database, utcnow

logger = logging.getLogger(__name__)


class OrchestratorError(RuntimeError):
    """Raised when a container cannot be started or stopped safely."""


class DockerOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: docker.DockerClient | None = None
        self._lock = threading.Lock()

    @property
    def client(self) -> docker.DockerClient:
        with self._lock:
            if self._client is None:
                try:
                    if self.settings.docker_host:
                        self._client = docker.DockerClient(base_url=self.settings.docker_host)
                    else:
                        self._client = docker.from_env()
                except DockerException as exc:  # pragma: no cover - host dependent
                    raise OrchestratorError(f"Docker is not available: {exc}") from exc
        return self._client

    # ---------- lifecycle ----------
    def ensure_network(self) -> None:
        """Create the internal lab network and the edge network if missing."""
        try:
            self.client.networks.get(self.settings.docker_network)
        except NotFound:
            try:
                self.client.networks.create(
                    self.settings.docker_network,
                    driver="bridge",
                    internal=True,
                    labels={"cyberlab.managed": "true"},
                )
                logger.info("created internal network %s", self.settings.docker_network)
            except APIError as exc:
                raise OrchestratorError(f"could not create lab network: {exc}") from exc

        # Docker refuses to publish ports for containers that are only on an
        # internal network. Forwarders need a normal network for the published
        # port; the challenge container itself stays internal-only.
        try:
            self.client.networks.get(self.settings.docker_edge_network)
        except NotFound:
            try:
                self.client.networks.create(
                    self.settings.docker_edge_network,
                    driver="bridge",
                    labels={"cyberlab.managed": "true"},
                )
                logger.info("created edge network %s", self.settings.docker_edge_network)
            except APIError as exc:
                raise OrchestratorError(f"could not create edge network: {exc}") from exc

    def _hardening(self) -> dict:
        """Security options shared by challenge and forwarder containers."""
        return {
            "user": "1000:1000",
            "read_only": True,
            "tmpfs": {
                "/tmp": "rw,noexec,nosuid,size=32m",
            },
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "mem_limit": self.settings.lab_memory_limit,
            "memswap_limit": self.settings.lab_memory_limit,
            "nano_cpus": int(self.settings.lab_cpu_limit * 1_000_000_000),
            "pids_limit": self.settings.lab_pids_limit,
            "ulimits": [Ulimit(name="nofile", soft=256, hard=256)],
            "restart_policy": {"Name": "no"},
            "stdin_open": False,
            "tty": False,
            "init": True,
        }

    @staticmethod
    def _remove(*containers) -> None:
        for container in containers:
            if container is None:
                continue
            try:
                container.remove(force=True)
            except DockerException:
                pass

    def image_present(self, image: str) -> bool:
        try:
            self.client.images.get(image)
            return True
        except ImageNotFound:
            return False

    def _free_port(self) -> int:
        """Pick a free port from the configured range.

        A fixed range lets the host firewall allow only these ports to the VPN
        instead of opening the whole ephemeral range.
        """
        low = self.settings.instance_port_min
        high = self.settings.instance_port_max
        candidates = list(range(low, high + 1))
        random.SystemRandom().shuffle(candidates)
        for port in candidates:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((self.settings.bind_ip, port))
                except OSError as exc:
                    # When the control plane runs in a container, the host's
                    # bind address (for example a VPN IP) may not exist inside
                    # this namespace. We cannot pre-check then; let Docker's
                    # allocator decide and retry on "port is already allocated".
                    unavailable = exc.errno in {
                        errno.EADDRNOTAVAIL,
                        errno.EAFNOSUPPORT,
                    } or getattr(exc, "winerror", None) == 10049
                    if unavailable:
                        return port
                    continue
                return port
        raise OrchestratorError(
            f"no free challenge port in range {low}-{high}; stop an instance or widen the range"
        )

    def start(self, challenge: Challenge, flag: str, instance_id: str) -> tuple[str, int]:
        """Start one hardened challenge container and its port forwarder.

        The challenge container is attached only to the internal network and has
        no published port, so it cannot reach the internet. A small trusted
        forwarder is attached to both the internal and edge networks, publishes
        the host port, and relays to the challenge container.

        Returns (challenge_container_id, host_port).
        """
        self.ensure_network()
        for image in (challenge.image, self.settings.forwarder_image):
            if not self.image_present(image):
                raise OrchestratorError(
                    f"image {image} is not built. Run scripts/build-challenges.sh first."
                )

        name = f"cyberlab-{challenge.id}-{instance_id[:12]}"
        forwarder_name = f"{name}-fwd"
        labels = {
            "cyberlab.managed": "true",
            "cyberlab.challenge": challenge.id,
            "cyberlab.instance": instance_id,
        }
        lab_net = self.client.networks.get(self.settings.docker_network)
        last_error: Exception | None = None

        for _ in range(3):
            port = self._free_port()
            challenge_container = None
            forwarder = None
            try:
                challenge_container = self.client.containers.run(
                    challenge.image,
                    detach=True,
                    name=name,
                    network=self.settings.docker_network,
                    environment={
                        "LAB_FLAG": flag,
                        "PORT": str(challenge.container_port),
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONUNBUFFERED": "1",
                    },
                    labels={**labels, "cyberlab.role": "challenge"},
                    **self._hardening(),
                )
                # Start the forwarder on the normal edge network so the port is
                # published, then attach it to the internal lab network so it can
                # reach the challenge container by name.
                forwarder = self.client.containers.run(
                    self.settings.forwarder_image,
                    command=[
                        f"TCP-LISTEN:{challenge.container_port},fork,reuseaddr",
                        f"TCP:{name}:{challenge.container_port}",
                    ],
                    detach=True,
                    name=forwarder_name,
                    network=self.settings.docker_edge_network,
                    ports={
                        f"{challenge.container_port}/tcp": (
                            self.settings.bind_ip,
                            port,
                        )
                    },
                    labels={**labels, "cyberlab.role": "forwarder"},
                    **self._hardening(),
                )
                lab_net.connect(forwarder)
            except DockerException as exc:
                last_error = exc
                self._remove(challenge_container, forwarder)
                if "port is already allocated" in str(exc).lower():
                    continue
                raise OrchestratorError(f"could not start challenge: {exc}") from exc

            try:
                for container, role in (
                    (challenge_container, "challenge"),
                    (forwarder, "forwarder"),
                ):
                    container.reload()
                    if container.status in {"exited", "dead"}:
                        logs = container.logs(tail=40).decode("utf-8", "replace")
                        self._remove(challenge_container, forwarder)
                        raise OrchestratorError(
                            f"{role} exited immediately "
                            f"(status={container.status}): {logs}"
                        )
            except DockerException as exc:
                self._remove(challenge_container, forwarder)
                raise OrchestratorError(
                    f"could not inspect challenge containers: {exc}"
                ) from exc

            logger.info(
                "started %s instance=%s port=%s container=%s forwarder=%s",
                challenge.id,
                instance_id,
                port,
                challenge_container.short_id,
                forwarder.short_id,
            )
            return challenge_container.id, port

        raise OrchestratorError(f"could not allocate a host port: {last_error}")

    def stop(self, container_id: str, instance_id: str | None = None) -> None:
        """Stop and remove every container that belongs to an instance."""
        if instance_id:
            self._remove_instance(instance_id)
            return

        try:
            container = self.client.containers.get(container_id)
        except NotFound:
            return
        except DockerException as exc:
            raise OrchestratorError(f"could not find container: {exc}") from exc

        owner = (container.labels or {}).get("cyberlab.instance")
        if owner:
            self._remove_instance(owner)
        else:
            self._remove(container)

    def _remove_instance(self, instance_id: str) -> None:
        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"cyberlab.instance={instance_id}"}
            )
        except DockerException as exc:
            raise OrchestratorError(f"could not list instance containers: {exc}") from exc

        for container in containers:
            try:
                container.stop(timeout=5)
            except DockerException:
                pass
            self._remove(container)

    def reconcile(self, db: Database) -> int:
        """Reconcile container state with the database.

        Instances the database still marks "running" whose challenge container
        is gone or stopped (for example after a host or Docker restart) are
        marked stopped so the dashboard and port accounting match reality.
        Every managed container that no longer belongs to an active instance is
        then removed.
        """
        try:
            containers = self.client.containers.list(
                all=True, filters={"label": "cyberlab.managed=true"}
            )
        except (DockerException, OrchestratorError) as exc:
            logger.warning("reconcile skipped: %s", exc)
            return 0

        by_instance: dict[str, list] = {}
        for container in containers:
            instance_id = (container.labels or {}).get("cyberlab.instance")
            if instance_id:
                by_instance.setdefault(instance_id, []).append(container)

        for instance_id in db.active_instance_ids():
            group = by_instance.get(instance_id, [])
            alive = any(
                (container.labels or {}).get("cyberlab.role") == "challenge"
                and container.status == "running"
                for container in group
            )
            if not alive:
                db.set_instance_status(instance_id, "stopped", utcnow())
                logger.info("marked stale instance %s stopped", instance_id)

        known = db.active_instance_ids()
        removed = 0
        for container in containers:
            instance_id = (container.labels or {}).get("cyberlab.instance")
            if instance_id and instance_id in known:
                continue
            self._remove(container)
            removed += 1
            logger.info("removed orphan container %s", container.short_id)
        return removed

    def health(self) -> dict:
        try:
            self.client.ping()
        except Exception as exc:  # noqa: BLE001 - surfaced to the admin
            return {
                "docker": False,
                "error": str(exc),
                "network": False,
                "edge_network": False,
            }

        def network_ok(name: str) -> bool:
            try:
                self.client.networks.get(name)
                return True
            except Exception:  # noqa: BLE001
                return False

        managed = 0
        try:
            managed = len(
                self.client.containers.list(
                    all=True, filters={"label": "cyberlab.managed=true"}
                )
            )
        except Exception:  # noqa: BLE001
            pass

        return {
            "docker": True,
            "network": network_ok(self.settings.docker_network),
            "edge_network": network_ok(self.settings.docker_edge_network),
            "managed_containers": managed,
            "error": None,
        }
