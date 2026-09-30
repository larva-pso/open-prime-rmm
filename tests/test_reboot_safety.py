import importlib
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
    SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
    sys.path.insert(0, str(SERVER_DIR))
app = importlib.import_module("app")

ROOT = Path(__file__).resolve().parents[1]
AGENT = (ROOT / "agent" / "agent.ps1").read_text(encoding="utf-8-sig")


def reset_db():
    with app.db() as conn:
        conn.execute("DELETE FROM automation_runs")
        conn.execute("DELETE FROM automation_rules")
        conn.execute("DELETE FROM schedules")
        conn.execute("DELETE FROM jobs")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM orgs")


def seed_agent(conn, now):
    org_id = conn.execute("INSERT INTO orgs(name,created_at) VALUES(?,?)", ("Safety Test", now)).lastrowid
    conn.execute(
        "INSERT INTO agents(id,hostname,token_hash,org_id,created_at,last_seen,os_version) VALUES(?,?,?,?,?,?,?)",
        ("agent-safe", "SAFE-PC", "hash", org_id, now, now, "Windows 11"),
    )
    return org_id


def assert_safe_power_payload(payload, source, now):
    assert payload["source"] == source
    assert payload["suppress_if_user_logged_in"] is True
    assert payload["expires_at"] > now
    assert payload["expires_at"] <= now + app.POWER_JOB_TTL_SECONDS + 1
    assert app.power_job_expired(payload, payload["expires_at"] + 0.1)
    assert not app.power_job_expired(payload, now)


def test_scheduled_reboot_is_session_guarded_and_short_lived():
    reset_db()
    now = time.time()
    with app.db() as conn:
        seed_agent(conn, now)
        schedule_id = conn.execute(
            """INSERT INTO schedules
               (name,script_id,mode,interval_minutes,daily_time,target_type,target_ids,
                variables,enabled,last_run_at,next_run_at,created_at,action_type,weekdays)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("Night reboot", 0, "daily", 60, "21:00", "machines", json.dumps(["agent-safe"]),
             "{}", 1, None, now, now, "reboot", "[]"),
        ).lastrowid
        schedule = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        assert app.fire_schedule(conn, schedule, now) == 1
        job = conn.execute("SELECT * FROM jobs WHERE schedule_id=?", (schedule_id,)).fetchone()
    assert_safe_power_payload(json.loads(job["payload"]), "schedule", now)


def test_reboot_automation_is_session_guarded_and_short_lived(monkeypatch):
    reset_db()
    now = time.time()
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)
    with app.db() as conn:
        seed_agent(conn, now)
        rule_id = conn.execute(
            """INSERT INTO automation_rules
               (name,enabled,trigger_type,threshold,window_minutes,cooldown_minutes,script_id,
                target_type,target_ids,variables,last_run_at,created_at,updated_at,action_type)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("Reboot pending", 1, "reboot_pending_days", 1, 1, 1440, 0,
             "machines", json.dumps(["agent-safe"]), "{}", None, now, now, "reboot"),
        ).lastrowid
        rule = conn.execute("SELECT * FROM automation_rules WHERE id=?", (rule_id,)).fetchone()
        agent = conn.execute("SELECT * FROM agents WHERE id='agent-safe'").fetchone()
        job_id = app._queue_automation_script(conn, rule, agent, "pending", now)
        job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    assert_safe_power_payload(json.loads(job["payload"]), "automation", now)


def test_stale_power_payload_is_fail_closed():
    now = time.time()
    payload = app.build_power_job_payload("reboot", "test", "schedule", now - 3600)
    assert app.power_job_expired(payload, now)
    # Missing/malformed expiry must not allow a disruptive queued action through.
    assert app.power_job_expired({"mode": "reboot"}, now)
    assert app.power_job_expired({"expires_at": "bad"}, now)


def test_agent_reboot_path_is_fail_closed_for_interactive_sessions():
    assert "function Test-InteractiveUserLoggedOn" in AGENT
    assert "WTSEnumerateSessions" in AGENT
    start = AGENT.index("function Invoke-RebootJob")
    end = AGENT.index("function Invoke-JobList", start)
    reboot = AGENT[start:end]
    guard = reboot.index("Test-InteractiveUserLoggedOn")
    launch = reboot.index("Start-Process -FilePath 'shutdown.exe'")
    assert guard < launch
    assert "suppressed because an interactive user is logged in" in reboot
    assert "suppress_if_user_logged_in" in reboot
    assert "expires_at" in reboot


def test_agent_suppresses_reboot_capable_scripts_for_logged_in_users():
    assert "function Test-ScriptMayReboot" in AGENT
    assert "Restart-Computer" in AGENT
    assert "shutdown(?:\\.exe)?" in AGENT
    run_list = AGENT[AGENT.index("function Invoke-JobList"):]
    assert "Test-ScriptMayReboot $job.payload" in run_list
    assert "Automation/script suppressed because it can reboot" in run_list
