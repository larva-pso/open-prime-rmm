"""One request/transaction for selected patch groups, preserving scope and conflicts."""
import asyncio
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

if "app" not in sys.modules:
    TEST_DATA_DIR = tempfile.TemporaryDirectory()
    os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
    os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
app = importlib.import_module("app")


def test_platform_release_version_is_1316():
    assert app.PLATFORM_VERSION == "1.31.6"


class JsonRequest:
    def __init__(self, payload):
        self.payload = payload
    async def json(self):
        return self.payload


def seed(agents, updates):
    with app.db() as conn:
        for aid in agents:
            conn.execute(
                "INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) "
                "VALUES (?,?,?,?,?)", (aid, aid, "hash", time.time(), time.time() - 3600)
            )
        for aid, uid, kb in updates:
            conn.execute(
                "INSERT INTO updates (agent_id,update_id,kb,title,severity,status,detected_at) "
                "VALUES (?,?,?,?,?,'pending',?)",
                (aid, uid, kb, f"Update {kb}", "Critical", time.time()),
            )


def clean(agents):
    with app.db() as conn:
        for aid in agents:
            conn.execute("DELETE FROM jobs WHERE agent_id=?", (aid,))
            conn.execute("DELETE FROM updates WHERE agent_id=?", (aid,))
            conn.execute("DELETE FROM agents WHERE id=?", (aid,))


def test_bulk_approve_merges_groups_once_and_respects_device_scope():
    a, b = str(uuid4()), str(uuid4())
    seed([a, b], [(a, "one", "KB1"), (a, "two", "KB2"), (b, "one", "KB1")])
    groups = [
        {"update_id": "one", "update_ids": ["one"], "agent_ids": [a]},
        {"update_id": "two", "update_ids": ["two"], "agent_ids": [a]},
    ]
    try:
        with patch.object(app, "require_admin", return_value={"u": "tester"}), \
                patch.object(app, "audit") as audit, patch.object(app, "_wake_agent") as wake:
            result = asyncio.run(app.patching_bulk_decision(
                JsonRequest({"action": "approve", "groups": groups})
            ))
            assert result["groups"] == 2
            assert result["devices"] == 1
            audit.assert_called_once()
            wake.assert_called_once_with(a)
        with app.db() as conn:
            assert dict(conn.execute(
                "SELECT update_id,status FROM updates WHERE agent_id=?", (a,)
            ).fetchall()) == {"one": "approved", "two": "approved"}
            assert conn.execute("SELECT status FROM updates WHERE agent_id=?", (b,)).fetchone()[0] == "pending"
            jobs = conn.execute(
                "SELECT payload FROM jobs WHERE agent_id=? AND type='install_updates' AND status='pending'",
                (a,),
            ).fetchall()
            assert len(jobs) == 1
            assert set(json.loads(jobs[0]["payload"])["update_ids"]) == {"one", "two"}
    finally:
        clean([a, b])


def test_empty_device_scope_never_expands_single_group_approval_to_fleet():
    agent_id = str(uuid4())
    seed([agent_id], [(agent_id, "one", "KB1")])
    try:
        with patch.object(app, "require_admin", return_value={"u": "tester"}), \
                patch.object(app, "audit"), patch.object(app, "_wake_agent"):
            result = asyncio.run(app.patching_approve_update(
                JsonRequest({"update_id": "one", "agent_ids": []})
            ))
            assert result["devices"] == 0
        with app.db() as conn:
            assert conn.execute(
                "SELECT status FROM updates WHERE agent_id=?", (agent_id,)
            ).fetchone()[0] == "pending"
    finally:
        clean([agent_id])


def test_bulk_deny_reports_running_conflict_without_denial_or_cross_customer_write():
    a, b, c = (str(uuid4()) for _ in range(3))
    seed([a, b, c], [(a, "one", "KB1"), (b, "one", "KB1"), (c, "one", "KB1")])
    job_id = str(uuid4())
    with app.db() as conn:
        conn.execute(
            "INSERT INTO jobs (id,agent_id,type,payload,status,created_at,started_at) "
            "VALUES (?,?,?,'{\"update_ids\":[\"one\"]}','running',?,?)",
            (job_id, b, "install_updates", time.time(), time.time()),
        )
    try:
        with patch.object(app, "require_admin", return_value={"u": "tester"}), \
                patch.object(app, "audit") as audit, patch.object(app, "_wake_agent") as wake:
            result = asyncio.run(app.patching_bulk_decision(JsonRequest({
                "action": "deny", "groups": [
                    {"update_id": "one", "kb": "KB1", "title": "Update KB1", "agent_ids": [a, b]}
                ],
            })))
            assert result["devices"] == 1
            assert result["remaining_actionable"] == 1
            assert result["running_conflicts"][0]["agent_id"] == b
            audit.assert_called_once()
            wake.assert_called_once_with(a)
        with app.db() as conn:
            statuses = [conn.execute(
                "SELECT status FROM updates WHERE agent_id=?", (aid,)
            ).fetchone()[0] for aid in (a, b, c)]
            assert statuses == ["denied", "pending", "pending"]
    finally:
        clean([a, b, c])


def test_dashboard_submits_selected_groups_in_one_scoped_request_and_reports_conflicts():
    if not shutil.which("node"):
        pytest.skip("Node.js unavailable")
    dashboard = (Path(__file__).resolve().parents[1] / "server" / "dashboard.html").read_text()
    function = "async function bulkPatch(action){" + dashboard.split(
        "async function bulkPatch(action){", 1
    )[1].split("\n}\n", 1)[0] + "\n}"
    harness = """
const vm = require('node:vm');
const groups = [
  {update_id:'one', update_ids:['one'], device_count:1, devices:[{agent_id:'agent-a'}]},
  {update_id:'two', update_ids:['two'], device_count:1, devices:[{agent_id:'agent-a'}]}
];
const calls = [], messages = [];
const ctx = {selectedPatchGroups:()=>groups, confirm:()=>true,
  api:async (url, options)=>{calls.push({url, body:JSON.parse(options.body)});
    return {ok:true, groups:2, devices:1, remaining_actionable:1,
      running_conflicts:[{agent_id:'agent-a',job_ids:['running-job']}]};},
  toast:(message)=>messages.push(message), loadPatchPending:()=>{}};
vm.createContext(ctx);
vm.runInContext(process.argv[1], ctx);
ctx.bulkPatch('deny').then(()=>console.log(JSON.stringify({calls, messages})));
"""
    run = subprocess.run(["node", "-e", harness, function], capture_output=True, text=True, check=True)
    outcome = json.loads(run.stdout)
    assert len(outcome["calls"]) == 1
    assert outcome["calls"][0]["url"] == "/api/patching/bulk-decision"
    assert len(outcome["calls"][0]["body"]["groups"]) == 2
    assert all(g["agent_ids"] == ["agent-a"] for g in outcome["calls"][0]["body"]["groups"])
    assert "running" in outcome["messages"][0].lower()
