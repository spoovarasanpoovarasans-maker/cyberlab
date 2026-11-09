from datetime import timedelta

from app.db import Database, utcnow
from app.security import hash_password, sha256_hex


def _db(tmp_path):
    db = Database(tmp_path / "lab.db")
    db.seed_admin("admin", hash_password("test-password-123"))
    return db


def test_seed_admin_is_idempotent(tmp_path):
    db = _db(tmp_path)
    db.seed_admin("other", hash_password("other-password"))
    user = db.get_user("admin")
    assert user is not None
    assert db.get_user("other") is None


def test_instance_lifecycle_and_flag_match(tmp_path):
    db = _db(tmp_path)
    user = db.get_user("admin")
    now = utcnow()
    flag = "FLAG{example_123}"

    db.create_instance(
        instance_id="i1",
        challenge_id="demo",
        user_id=user["id"],
        container_id="cid-1",
        host_port=19000,
        flag_hash=sha256_hex(flag),
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )

    active = db.active_instance(user["id"], "demo")
    assert active["id"] == "i1"
    assert db.running_count() == 1
    assert db.active_container_ids() == {"cid-1"}
    assert db.active_instance_ids() == {"i1"}
    assert db.flag_matches(user["id"], "demo", sha256_hex(flag))
    assert not db.flag_matches(user["id"], "demo", sha256_hex("FLAG{other}"))

    db.record_solve(user["id"], "demo", "i1")
    db.record_solve(user["id"], "demo", "i1")
    assert db.is_solved(user["id"], "demo")
    assert list(db.solves(user["id"])) == ["demo"]

    db.set_instance_status("i1", "stopped", now)
    assert db.active_instance(user["id"], "demo") is None
    assert db.running_count() == 0
    assert db.active_container_ids() == set()
    assert db.active_instance_ids() == set()


def test_expired_instances(tmp_path):
    db = _db(tmp_path)
    user = db.get_user("admin")
    now = utcnow()
    db.create_instance(
        instance_id="old",
        challenge_id="demo",
        user_id=user["id"],
        container_id="cid-old",
        host_port=19001,
        flag_hash=sha256_hex("FLAG{x}"),
        created_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )
    expired = db.expired_instances(now)
    assert [row["id"] for row in expired] == ["old"]


def test_audit_is_recorded(tmp_path):
    db = _db(tmp_path)
    db.audit("admin", "test.action", "detail", "127.0.0.1")
    rows = db.list_audit(10)
    assert rows[0]["action"] == "test.action"
    assert rows[0]["actor"] == "admin"
