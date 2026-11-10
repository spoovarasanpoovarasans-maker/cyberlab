from datetime import timedelta

from app.db import Database, utcnow
from app.orchestrator import DockerOrchestrator
from app.security import hash_password, sha256_hex
from tests.helpers import make_settings


class FakeContainer:
    def __init__(self, labels, status="running", short_id="abc123"):
        self.labels = labels
        self.status = status
        self.short_id = short_id
        self.removed = False

    def remove(self, force=False):
        self.removed = True


class FakeContainers:
    def __init__(self, items):
        self.items = items

    def list(self, all=False, filters=None):
        return list(self.items)


class FakeClient:
    def __init__(self, items):
        self.containers = FakeContainers(items)


def _db(tmp_path):
    db = Database(tmp_path / "lab.db")
    db.seed_admin("admin", hash_password("test-password-123"))
    return db


def _running_instance(db, instance_id="i1"):
    user = db.get_user("admin")
    now = utcnow()
    db.create_instance(
        instance_id=instance_id,
        challenge_id="demo",
        user_id=user["id"],
        container_id=f"cid-{instance_id}",
        host_port=19000,
        flag_hash=sha256_hex("FLAG{x}"),
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )


def _orchestrator(tmp_path, containers):
    orch = DockerOrchestrator(make_settings(tmp_path))
    orch._client = FakeClient(containers)
    return orch


def test_reconcile_keeps_live_instance(tmp_path):
    db = _db(tmp_path)
    _running_instance(db)
    challenge = FakeContainer(
        {
            "cyberlab.managed": "true",
            "cyberlab.instance": "i1",
            "cyberlab.role": "challenge",
        }
    )
    orch = _orchestrator(tmp_path, [challenge])

    assert orch.reconcile(db) == 0
    assert db.active_instance_ids() == {"i1"}
    assert not challenge.removed


def test_reconcile_marks_dead_instance_stopped_and_removes_it(tmp_path):
    db = _db(tmp_path)
    _running_instance(db)
    challenge = FakeContainer(
        {
            "cyberlab.managed": "true",
            "cyberlab.instance": "i1",
            "cyberlab.role": "challenge",
        },
        status="exited",
    )
    forwarder = FakeContainer(
        {
            "cyberlab.managed": "true",
            "cyberlab.instance": "i1",
            "cyberlab.role": "forwarder",
        },
        status="exited",
    )
    orch = _orchestrator(tmp_path, [challenge, forwarder])

    assert orch.reconcile(db) == 2
    assert db.active_instance_ids() == set()
    assert challenge.removed and forwarder.removed


def test_reconcile_removes_orphan_containers(tmp_path):
    db = _db(tmp_path)
    orphan = FakeContainer(
        {
            "cyberlab.managed": "true",
            "cyberlab.instance": "gone",
            "cyberlab.role": "challenge",
        }
    )
    orch = _orchestrator(tmp_path, [orphan])

    assert orch.reconcile(db) == 1
    assert orphan.removed
