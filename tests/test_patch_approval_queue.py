import asyncio
import importlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path


if "app" not in sys.modules:
    TEST_DATA_DIR = tempfile.TemporaryDirectory()
    os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
    os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
    SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
    sys.path.insert(0, str(SERVER_DIR))
app = importlib.import_module("app")


class JsonRequest:
    def __init__(self, body=None, query_params=None):
        self._body = body or {}
        self.query_params = query_params or {}

    async def json(self):
        return self._body


def reset_db():
    with app.db() as conn:
        conn.execute("DELETE FROM jobs")
        conn.execute("DELETE FROM updates")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM orgs")


def seed_offline_agent_with_updates():
    now = time.time()
    with app.db() as conn:
        org_id = conn.execute(
            "INSERT INTO orgs(name,created_at) VALUES(?,?)", ("Patch Test", now)
        ).lastrowid
        conn.execute(
            """INSERT INTO agents
               (id,hostname,token_hash,org_id,created_at,last_seen,os_version)
               VALUES(?,?,?,?,?,?,?)""",
            ("offline-agent", "OFFLINE-PC", "hash", org_id, now, now - 3600, "Windows 11"),
        )
        for update_id, kb in (("update-a", "KB100001"), ("update-b", "KB100002")):
            conn.execute(
                """INSERT INTO updates
                   (agent_id,update_id,kb,title,severity,status,detected_at)
                   VALUES(?,?,?,?,?,'pending',?)""",
                ("offline-agent", update_id, kb, f"Security Update {kb}", "Critical", now),
            )


def approve(update_id):
    return asyncio.run(
        app.patching_approve_update(JsonRequest({"update_id": update_id, "update_ids": [update_id]}))
    )


def test_bulk_approval_persists_every_decision_for_an_offline_device(monkeypatch):
    reset_db()
    seed_offline_agent_with_updates()
    monkeypatch.setattr(app, "require_admin", lambda _request: {"u": "tester"})
    monkeypatch.setattr(app, "audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)

    first = approve("update-a")
    second = approve("update-b")

    assert first["devices"] == 1
    assert second["devices"] == 1
    with app.db() as conn:
        statuses = dict(
            conn.execute(
                "SELECT update_id,status FROM updates WHERE agent_id='offline-agent'"
            ).fetchall()
        )
        jobs = conn.execute(
            "SELECT payload FROM jobs WHERE agent_id='offline-agent' "
            "AND type='install_updates' AND status='pending'"
        ).fetchall()
    assert statuses == {"update-a": "approved", "update-b": "approved"}
    queued_ids = {
        update_id
        for job in jobs
        for update_id in json.loads(job["payload"])["update_ids"]
    }
    assert queued_ids == {"update-a", "update-b"}

    pending = app.patching_pending(JsonRequest(query_params={"status": "actionable"}))
    assert pending["updates"] == []
