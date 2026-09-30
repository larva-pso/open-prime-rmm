"""Opt-in forced reboot must never change existing protected power actions."""
import importlib
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

if "app" not in sys.modules:
    TEST_DATA_DIR = tempfile.TemporaryDirectory()
    os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
    os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
app = importlib.import_module("app")
ROOT = Path(__file__).resolve().parents[1]


def test_force_reboot_payload_is_explicit_and_short_lived():
    now = time.time()
    safe = app.build_power_job_payload("reboot", "test", "manual", now)
    forced = app.build_power_job_payload("reboot", "test", "manual", now, force_reboot=True)
    assert safe["force_reboot"] is False
    assert forced["force_reboot"] is True
    assert forced["suppress_if_user_logged_in"] is True
    assert app.power_job_expired(forced, forced["expires_at"] + 1)
    assert not app.power_job_expired(forced, now)
    with pytest.raises(ValueError):
        app.build_power_job_payload("shutdown", "test", "manual", now, force_reboot=True)


def test_force_option_validates_boolean_and_reboot_only():
    schedule = {"name": "Forced pilot", "action_type": "reboot", "force_reboot": True}
    assert app._validate_schedule_body(schedule)["force_reboot"] == 1
    assert app._validate_schedule_body({"name": "Safe", "action_type": "reboot"})["force_reboot"] == 0
    with pytest.raises(app.HTTPException):
        app._validate_schedule_body({**schedule, "force_reboot": "true"})
    with pytest.raises(app.HTTPException):
        app._validate_schedule_body({**schedule, "action_type": "shutdown"})
    rule = {"name": "Forced pilot", "trigger_type": "reboot_pending_days", "action_type": "reboot", "force_reboot": True}
    assert app._validate_automation_rule(rule)["force_reboot"] == 1
    with pytest.raises(app.HTTPException):
        app._validate_automation_rule({**rule, "action_type": "install_updates"})


def test_existing_rules_default_safe_and_force_flows_to_jobs():
    now = time.time()
    with app.db() as conn:
        conn.execute("DELETE FROM jobs")
        conn.execute("DELETE FROM automation_rules")
        conn.execute("DELETE FROM schedules")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM orgs")
        org = conn.execute("INSERT INTO orgs(name,created_at) VALUES(?,?)", (f"Force test {now}", now)).lastrowid
        conn.execute("INSERT INTO agents(id,hostname,token_hash,org_id,created_at,last_seen) VALUES(?,?,?,?,?,?)", ("force-pilot", "PILOT", "hash", org, now, now))
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(schedules)")}
        assert "force_reboot" in cols
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(automation_rules)")}
        assert "force_reboot" in cols
        sid = conn.execute("""INSERT INTO schedules(name,script_id,mode,target_type,target_ids,created_at,action_type)
                              VALUES(?,?,?,?,?,?,?)""", ("Old task", 0, "daily", "machines", json.dumps(["force-pilot"]), now, "reboot")).lastrowid
        old = conn.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
        assert old["force_reboot"] == 0
        assert app.fire_schedule(conn, old, now) == 1
        old_job = conn.execute("SELECT payload FROM jobs WHERE schedule_id=?", (sid,)).fetchone()
        assert json.loads(old_job["payload"])["force_reboot"] is False
        conn.execute("UPDATE schedules SET force_reboot=1 WHERE id=?", (sid,))
        conn.execute("DELETE FROM jobs WHERE schedule_id=?", (sid,))
        forced = conn.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
        assert app.fire_schedule(conn, forced, now) == 1
        job = conn.execute("SELECT payload FROM jobs WHERE schedule_id=?", (sid,)).fetchone()
        assert json.loads(job["payload"])["force_reboot"] is True
        rid = conn.execute("""INSERT INTO automation_rules(name,trigger_type,script_id,target_type,target_ids,created_at,updated_at,action_type,force_reboot)
                              VALUES(?,?,?,?,?,?,?,?,?)""", ("Forced rule", "reboot_pending_days", 0, "machines", json.dumps(["force-pilot"]), now, now, "reboot", 1)).lastrowid
        rule = conn.execute("SELECT * FROM automation_rules WHERE id=?", (rid,)).fetchone()
        agent = conn.execute("SELECT * FROM agents WHERE id=?", ("force-pilot",)).fetchone()
        app._queue_automation_script(conn, rule, agent, "test", now)
        job = conn.execute("SELECT payload FROM jobs WHERE label=?", ("Automation: Forced rule",)).fetchone()
        assert json.loads(job["payload"])["force_reboot"] is True


def test_agent_force_path_is_opt_in_and_never_affects_shutdown():
    agent = (ROOT / "agent" / "agent.ps1").read_text(encoding="utf-8-sig")
    reboot = agent.split("function Invoke-RebootJob", 1)[1].split("function Invoke-JobList", 1)[0]
    assert "force_reboot" in reboot
    assert "(-not $forceReboot) -and (Test-InteractiveUserLoggedOn)" in reboot
    assert "if ($isShutdown) { $forceReboot = $false }" in reboot
    assert "'/f'" in reboot
    assert "forceReboot" in reboot.split('$worker = @"', 1)[1]
    assert "expires_at" in reboot


def test_delayed_power_worker_uses_initialized_log_path():
    agent = (ROOT / "agent" / "agent.ps1").read_text(encoding="utf-8-sig")
    reboot = agent.split("function Invoke-RebootJob", 1)[1].split("function Invoke-JobList", 1)[0]
    assert "$LogPath" in agent.split("function Write-Log", 1)[0]
    assert "$unicode.GetBytes($LogPath)" in reboot
    assert "$unicode.GetBytes($LogFile)" not in reboot


def test_dashboard_has_explicit_opt_in_everywhere():
    dashboard = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
    for marker in ("id=\"dsForceReboot\"", "id=\"scForceReboot\"", "id=\"tbForceReboot\"", "force_reboot:forceReboot"):
        assert marker in dashboard
    assert "Force reboot" in dashboard
    assert "Unsaved work" in dashboard


class RequestBody:
    def __init__(self, body):
        self.body = body
        self.headers = {"content-length": "1"}

    async def json(self):
        return self.body


def test_manual_reboot_api_requires_explicit_force(monkeypatch):
    now = time.time()
    with app.db() as conn:
        conn.execute("DELETE FROM jobs")
        conn.execute("DELETE FROM agents")
        conn.execute("INSERT INTO agents(id,hostname,token_hash,created_at,last_seen) VALUES(?,?,?,?,?)",
                     ("force-manual", "PILOT", "hash", now, now))
    monkeypatch.setattr(app, "require_admin", lambda request: None)
    monkeypatch.setattr(app, "require_admin_role", lambda request: None)
    monkeypatch.setattr(app, "audit", lambda *args: None)
    monkeypatch.setattr(app, "_wake_agent", lambda agent_id: None)
    for flag in (False, True):
        result = asyncio.run(app.reboot_machine("force-manual", RequestBody({"delay_sec": 60, "force_reboot": flag})))
        with app.db() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (result["job_id"],)).fetchone()
        assert json.loads(job["payload"])["force_reboot"] is flag
        assert ("Force" in job["label"]) is flag
    with pytest.raises(app.HTTPException):
        asyncio.run(app.reboot_machine("force-manual", RequestBody({"force_reboot": "yes"})))
    result = asyncio.run(app.reboot_machine("force-manual", RequestBody({"force_reboot": True, "delay_sec": 0})))
    with app.db() as conn:
        payload = json.loads(conn.execute("SELECT payload FROM jobs WHERE id=?", (result["job_id"],)).fetchone()[0])
    assert payload["delay_sec"] == 0


def test_force_schedule_and_rule_persist_via_api(monkeypatch):
    monkeypatch.setattr(app, "require_admin", lambda request: None)
    monkeypatch.setattr(app, "require_admin_role", lambda request: None)
    monkeypatch.setattr(app, "audit", lambda *args: None)
    schedule = {"name": "Forced canary", "mode": "daily", "daily_time": "02:00",
                "action_type": "reboot", "target_type": "machines", "target_ids": [], "force_reboot": True}
    result = asyncio.run(app.create_schedule(RequestBody(schedule)))
    sid = result["id"]
    with app.db() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (result["id"],)).fetchone()
        assert row["force_reboot"] == 1
        assert app._schedule_dict(conn, row)["force_reboot"] == 1
    rule = {"name": "Force after deadline", "trigger_type": "reboot_pending_days",
            "action_type": "reboot", "force_reboot": True, "target_type": "machines", "target_ids": []}
    result = asyncio.run(app.api_create_automation_rule(RequestBody(rule)))
    rid = result["id"]
    with app.db() as conn:
        row = conn.execute("SELECT * FROM automation_rules WHERE id=?", (result["id"],)).fetchone()
        assert row["force_reboot"] == 1
        assert app._automation_rule_dict(conn, row)["force_reboot"] == 1
    asyncio.run(app.update_schedule(sid, RequestBody({**schedule, "force_reboot": False})))
    asyncio.run(app.api_update_automation_rule(rid, RequestBody({**rule, "force_reboot": False})))
    with app.db() as conn:
        assert conn.execute("SELECT force_reboot FROM schedules WHERE id=?", (sid,)).fetchone()[0] == 0
        assert conn.execute("SELECT force_reboot FROM automation_rules WHERE id=?", (rid,)).fetchone()[0] == 0


def test_forced_actions_require_admin_role(monkeypatch):
    monkeypatch.setattr(app, "require_admin", lambda request: None)

    def deny(request):
        raise app.HTTPException(status_code=403, detail="Admin access required")

    monkeypatch.setattr(app, "require_admin_role", deny)
    with pytest.raises(app.HTTPException) as exc:
        asyncio.run(app.reboot_machine("force-manual", RequestBody({"force_reboot": True})))
    assert exc.value.status_code == 403
    body = {"name": "Forced test", "action_type": "reboot", "force_reboot": True}
    with pytest.raises(app.HTTPException) as exc:
        asyncio.run(app.create_schedule(RequestBody(body)))
    assert exc.value.status_code == 403
