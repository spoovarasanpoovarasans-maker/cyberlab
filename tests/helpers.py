"""Shared test helpers: isolated settings and a fake orchestrator."""

from __future__ import annotations

from pathlib import Path

from app.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = dict(
        app_name="CyberLab Test",
        environment="development",
        secret_key="test-secret-key-not-for-production-0123456789",
        admin_username="admin",
        admin_password="test-password-123",
        data_dir=tmp_path / "data",
        catalog_dir=PROJECT_ROOT / "challenges",
        bind_ip="127.0.0.1",
        public_host="localhost",
        challenge_host="127.0.0.1",
        control_port=8443,
        session_https_only=False,
        allowed_hosts=("testserver",),
        instance_ttl_minutes=30,
        max_running_instances=4,
        instance_port_min=20000,
        instance_port_max=20099,
        docker_host=None,
        docker_network="cyberlab_test",
        docker_edge_network="cyberlab_test_edge",
        forwarder_image="cyberlab/forwarder:test",
        lab_memory_limit="128m",
        lab_cpu_limit=0.25,
        lab_pids_limit=32,
        log_level="WARNING",
    )
    values.update(overrides)
    return Settings(**values)


class FakeOrchestrator:
    """In-memory stand-in for DockerOrchestrator."""

    def __init__(self) -> None:
        self.started: list[tuple[str, str, str]] = []
        self.stopped: list[str] = []
        self.next_port = 19000

    def ensure_network(self) -> None:
        return None

    def reconcile(self, db) -> int:  # noqa: ANN001
        return 0

    def health(self) -> dict:
        return {
            "docker": True,
            "network": True,
            "edge_network": True,
            "managed_containers": len(self.started),
            "error": None,
        }

    def start(self, challenge, flag: str, instance_id: str) -> tuple[str, int]:
        self.started.append((challenge.id, flag, instance_id))
        port = self.next_port
        self.next_port += 1
        return f"cid-{instance_id[:8]}", port

    def stop(self, container_id: str, instance_id: str | None = None) -> None:
        self.stopped.append(instance_id or container_id)
