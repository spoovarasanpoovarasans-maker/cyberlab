"""SQLite persistence for users, instances, solves, and the audit trail."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instances (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    container_id TEXT,
    host_port INTEGER,
    flag_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    stopped_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_instances_active
    ON instances(user_id, challenge_id, status);
CREATE INDEX IF NOT EXISTS idx_instances_expiry
    ON instances(status, expires_at);

CREATE TABLE IF NOT EXISTS solves (
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    instance_id TEXT,
    solved_at TEXT NOT NULL,
    PRIMARY KEY (user_id, challenge_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    ip TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self.init()

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=15)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA busy_timeout = 15000")
        return con

    def init(self) -> None:
        con = self.connect()
        try:
            con.executescript(SCHEMA)
            con.commit()
        finally:
            con.close()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ---------- users ----------
    def seed_admin(self, username: str, password_hash: str) -> None:
        con = self.connect()
        try:
            count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                con.execute(
                    "INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)",
                    (username, password_hash, "admin", iso(utcnow())),
                )
                con.commit()
        finally:
            con.close()

    def get_user(self, username: str) -> sqlite3.Row | None:
        con = self.connect()
        try:
            return con.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            con.close()

    def get_user_by_id(self, user_id: int) -> sqlite3.Row | None:
        con = self.connect()
        try:
            return con.execute(
                "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        finally:
            con.close()

    def set_password(self, username: str, password_hash: str) -> bool:
        con = self.connect()
        try:
            cur = con.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (password_hash, username),
            )
            con.commit()
            return cur.rowcount > 0
        finally:
            con.close()

    # ---------- instances ----------
    def create_instance(
        self,
        *,
        instance_id: str,
        challenge_id: str,
        user_id: int,
        container_id: str,
        host_port: int,
        flag_hash: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        con = self.connect()
        try:
            con.execute(
                """INSERT INTO instances(
                       id, challenge_id, user_id, container_id, host_port,
                       flag_hash, status, created_at, expires_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    instance_id,
                    challenge_id,
                    user_id,
                    container_id,
                    host_port,
                    flag_hash,
                    "running",
                    iso(created_at),
                    iso(expires_at),
                ),
            )
            con.commit()
        finally:
            con.close()

    def active_instance(self, user_id: int, challenge_id: str) -> sqlite3.Row | None:
        con = self.connect()
        try:
            return con.execute(
                """SELECT * FROM instances
                   WHERE user_id = ? AND challenge_id = ? AND status = 'running'
                   ORDER BY created_at DESC LIMIT 1""",
                (user_id, challenge_id),
            ).fetchone()
        finally:
            con.close()

    def active_instances(self, user_id: int) -> list[sqlite3.Row]:
        con = self.connect()
        try:
            return list(
                con.execute(
                    """SELECT * FROM instances
                       WHERE user_id = ? AND status = 'running'
                       ORDER BY created_at DESC""",
                    (user_id,),
                ).fetchall()
            )
        finally:
            con.close()

    def get_instance(self, instance_id: str) -> sqlite3.Row | None:
        con = self.connect()
        try:
            return con.execute(
                "SELECT * FROM instances WHERE id = ?", (instance_id,)
            ).fetchone()
        finally:
            con.close()

    def set_instance_status(
        self, instance_id: str, status: str, stopped_at: datetime | None = None
    ) -> None:
        con = self.connect()
        try:
            con.execute(
                "UPDATE instances SET status = ?, stopped_at = ? WHERE id = ?",
                (status, iso(stopped_at) if stopped_at else None, instance_id),
            )
            con.commit()
        finally:
            con.close()

    def expired_instances(self, now: datetime | None = None) -> list[sqlite3.Row]:
        now = now or utcnow()
        con = self.connect()
        try:
            return list(
                con.execute(
                    """SELECT * FROM instances
                       WHERE status = 'running' AND expires_at <= ?
                       ORDER BY expires_at""",
                    (iso(now),),
                ).fetchall()
            )
        finally:
            con.close()

    def running_count(self) -> int:
        con = self.connect()
        try:
            return con.execute(
                "SELECT COUNT(*) FROM instances WHERE status = 'running'"
            ).fetchone()[0]
        finally:
            con.close()

    def active_container_ids(self) -> set[str]:
        con = self.connect()
        try:
            rows = con.execute(
                "SELECT container_id FROM instances WHERE status = 'running' AND container_id IS NOT NULL"
            ).fetchall()
            return {row[0] for row in rows}
        finally:
            con.close()

    def active_instance_ids(self) -> set[str]:
        con = self.connect()
        try:
            rows = con.execute(
                "SELECT id FROM instances WHERE status = 'running'"
            ).fetchall()
            return {row[0] for row in rows}
        finally:
            con.close()

    def flag_matches(self, user_id: int, challenge_id: str, flag_hash: str) -> bool:
        con = self.connect()
        try:
            row = con.execute(
                """SELECT 1 FROM instances
                   WHERE user_id = ? AND challenge_id = ? AND flag_hash = ?
                   LIMIT 1""",
                (user_id, challenge_id, flag_hash),
            ).fetchone()
            return row is not None
        finally:
            con.close()

    # ---------- solves ----------
    def record_solve(
        self, user_id: int, challenge_id: str, instance_id: str | None = None
    ) -> None:
        con = self.connect()
        try:
            con.execute(
                """INSERT OR IGNORE INTO solves(user_id, challenge_id, instance_id, solved_at)
                   VALUES(?,?,?,?)""",
                (user_id, challenge_id, instance_id, iso(utcnow())),
            )
            con.commit()
        finally:
            con.close()

    def is_solved(self, user_id: int, challenge_id: str) -> bool:
        con = self.connect()
        try:
            return (
                con.execute(
                    "SELECT 1 FROM solves WHERE user_id = ? AND challenge_id = ?",
                    (user_id, challenge_id),
                ).fetchone()
                is not None
            )
        finally:
            con.close()

    def solves(self, user_id: int) -> dict[str, str]:
        con = self.connect()
        try:
            rows = con.execute(
                "SELECT challenge_id, solved_at FROM solves WHERE user_id = ?",
                (user_id,),
            ).fetchall()
            return {row[0]: row[1] for row in rows}
        finally:
            con.close()

    # ---------- audit ----------
    def audit(
        self, actor: str | None, action: str, detail: str = "", ip: str = ""
    ) -> None:
        con = self.connect()
        try:
            con.execute(
                "INSERT INTO audit(ts, actor, action, detail, ip) VALUES(?,?,?,?,?)",
                (iso(utcnow()), (actor or "anonymous")[:64], action[:64], detail[:2000], ip[:64]),
            )
            con.commit()
        finally:
            con.close()

    def list_audit(self, limit: int = 200) -> list[sqlite3.Row]:
        con = self.connect()
        try:
            return list(
                con.execute(
                    "SELECT ts, actor, action, detail, ip FROM audit ORDER BY id DESC LIMIT ?",
                    (max(1, min(limit, 1000)),),
                ).fetchall()
            )
        finally:
            con.close()

    def stats(self) -> dict[str, int]:
        con = self.connect()
        try:
            def count(table: str) -> int:
                return con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

            return {
                "instances": count("instances"),
                "running": con.execute(
                    "SELECT COUNT(*) FROM instances WHERE status = 'running'"
                ).fetchone()[0],
                "solves": count("solves"),
                "audit": count("audit"),
            }
        finally:
            con.close()
