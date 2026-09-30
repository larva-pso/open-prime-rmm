import json
import sqlite3
import time
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import app

DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
AGENT = (ROOT / "agent" / "agent.ps1").read_text(encoding="utf-8")


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(app.SCHEMA)
    return conn


def add_org_agent(conn, agent_id="a1", created_at=None, os_version="Windows 11 Pro"):
    now = time.time()
    created_at = now if created_at is None else created_at
    cur = conn.execute("INSERT INTO orgs(name,created_at) VALUES(?,?)", (f"Org-{agent_id}", now))
    org_id = cur.lastrowid
    conn.execute(
        "INSERT INTO agents(id,hostname,os_version,token_hash,org_id,created_at,last_seen) VALUES(?,?,?,?,?,?,?)",
        (agent_id, f"PC-{agent_id}", os_version, "hash", org_id, created_at, now),
    )
    return org_id


def add_script(conn, name):
    cur = conn.execute(
        "INSERT INTO scripts(name,description,content,shell,timeout_sec,variables,updated_at) VALUES(?,?,?,?,?,?,?)",
        (name, "", f"Write-Output '{name}'", "powershell", 120, "[]", time.time()),
    )
    return cur.lastrowid


def add_application(conn, name="Chrome", installer_type="msi"):
    now = time.time()
    cur = conn.execute(
        """INSERT INTO applications(name,description,operating_system,architecture,installer_type,run_as,parameters,
           categories,success_codes,timeout_sec,reboot_behavior,detection_type,detection_value,stop_on_pre_failure,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (name, "", "windows", "x64", installer_type, "system", "/qn /norestart", "[]", "[0,3010]",
         1800, "never", "none", "", 1, now, now),
    )
    app_id = cur.lastrowid
    conn.execute(
        "INSERT INTO application_files(application_id,kind,original_name,stored_name,size_bytes,sha256,active,created_at) VALUES(?,?,?,?,?,?,1,?)",
        (app_id, "installer", f"{name}.{'msi' if installer_type == 'msi' else 'exe'}", "stored-installer", 1234, "a" * 64, now),
    )
    return app_id


def add_stack(conn, org_id, steps, *, name="Onboarding", failure="continue", retries=0, retry_delay=0):
    now = time.time()
    cur = conn.execute(
        "INSERT INTO automation_stacks(org_id,name,description,version,failure_policy,retry_count,retry_delay_sec,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (org_id, name, "", 1, failure, retries, retry_delay, now, now),
    )
    stack_id = cur.lastrowid
    for pos, (kind, action_id) in enumerate(steps, 1):
        conn.execute(
            "INSERT INTO automation_stack_steps(stack_id,position,action_type,action_id,variables,failure_policy,retry_count,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (stack_id, pos, kind, action_id, "{}", "", None, now),
        )
    return stack_id


def test_application_job_reuses_existing_run_script_protocol(monkeypatch):
    conn = make_db()
    org_id = add_org_agent(conn)
    application_id = add_application(conn, "Google Chrome")
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)

    snapshot = app._application_snapshot(conn, application_id)
    job_id = app._queue_application_job(conn, application_snapshot=snapshot, agent_id="a1", now=time.time())
    job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    payload = json.loads(job["payload"])

    assert job["type"] == "run_script"
    assert payload["origin"] == "application"
    assert payload["application_id"] == application_id
    assert "/api/agent/application-files/" in payload["content"]
    assert "Get-FileHash" in payload["content"]
    assert "SHA256 mismatch" in payload["content"]
    assert "Application requires x64 Windows" in payload["content"]
    assert "token" not in payload["content"].lower()
    assert org_id


def test_application_step_in_stack_is_still_a_run_script_job(monkeypatch):
    conn = make_db()
    org_id = add_org_agent(conn)
    application_id = add_application(conn, "Firefox", "exe")
    stack_id = add_stack(conn, org_id, [("application", application_id)])
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)

    agent = conn.execute("SELECT * FROM agents WHERE id='a1'").fetchone()
    stack = conn.execute("SELECT * FROM automation_stacks WHERE id=?", (stack_id,)).fetchone()
    run_id = app._start_onboarding_run(conn, agent, stack, "manual", time.time())

    step = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=?", (run_id,)).fetchone()
    job = conn.execute("SELECT * FROM jobs WHERE id=?", (step["job_id"],)).fetchone()
    payload = json.loads(job["payload"])
    assert step["action_type"] == "application"
    assert job["type"] == "run_script"
    assert payload["origin"] == "application"


def test_onboarding_executes_steps_strictly_in_order(monkeypatch):
    conn = make_db()
    org_id = add_org_agent(conn)
    s1, s2 = add_script(conn, "Step One"), add_script(conn, "Step Two")
    stack_id = add_stack(conn, org_id, [("script", s1), ("script", s2)])
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)

    agent = conn.execute("SELECT * FROM agents WHERE id='a1'").fetchone()
    stack = conn.execute("SELECT * FROM automation_stacks WHERE id=?", (stack_id,)).fetchone()
    run_id = app._start_onboarding_run(conn, agent, stack, "manual", time.time())

    rows = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? ORDER BY position", (run_id,)).fetchall()
    assert [r["status"] for r in rows] == ["running", "pending"]
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1

    app._process_onboarding_job_result(conn, rows[0]["job_id"], True, "ok", time.time())
    rows = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? ORDER BY position", (run_id,)).fetchall()
    assert [r["status"] for r in rows] == ["done", "running"]
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 2

    app._process_onboarding_job_result(conn, rows[1]["job_id"], True, "ok", time.time())
    run = conn.execute("SELECT * FROM onboarding_runs WHERE id=?", (run_id,)).fetchone()
    state = conn.execute("SELECT * FROM device_onboarding_state WHERE agent_id='a1'").fetchone()
    assert run["status"] == "completed"
    assert state["status"] == "completed"


def test_delayed_retry_blocks_later_steps_until_retry_is_due(monkeypatch):
    conn = make_db()
    org_id = add_org_agent(conn)
    s1, s2 = add_script(conn, "Retry First"), add_script(conn, "Must Wait")
    stack_id = add_stack(conn, org_id, [("script", s1), ("script", s2)], retries=1, retry_delay=60)
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)
    start = time.time()
    agent = conn.execute("SELECT * FROM agents WHERE id='a1'").fetchone()
    stack = conn.execute("SELECT * FROM automation_stacks WHERE id=?", (stack_id,)).fetchone()
    run_id = app._start_onboarding_run(conn, agent, stack, "manual", start)
    first = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? AND position=1", (run_id,)).fetchone()

    # An in-progress run must retain the retry delay it started with even if a
    # technician edits the source stack while this device is onboarding.
    conn.execute("UPDATE automation_stacks SET retry_delay_sec=0 WHERE id=?", (stack_id,))
    app._process_onboarding_job_result(conn, first["job_id"], False, "failed", start + 1)
    rows = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? ORDER BY position", (run_id,)).fetchall()
    assert [r["status"] for r in rows] == ["pending", "pending"]
    assert rows[0]["next_attempt_at"] > start + 1
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1

    # A normal check-in before the retry delay expires must not skip to step 2.
    app._maybe_advance_onboarding(conn, "a1", start + 30)
    rows = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? ORDER BY position", (run_id,)).fetchall()
    assert [r["status"] for r in rows] == ["pending", "pending"]
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1

    app._maybe_advance_onboarding(conn, "a1", start + 62)
    rows = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? ORDER BY position", (run_id,)).fetchall()
    assert [r["status"] for r in rows] == ["running", "pending"]
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 2


def test_automatic_onboarding_never_retrofits_existing_fleet_and_runs_once(monkeypatch):
    conn = make_db()
    now = time.time()
    org_id = add_org_agent(conn, "old", created_at=now - 3600)
    # Put a second, newly-enrolled device in the same organization.
    conn.execute(
        "INSERT INTO agents(id,hostname,os_version,token_hash,org_id,created_at,last_seen) VALUES(?,?,?,?,?,?,?)",
        ("new", "PC-new", "Windows 11 Pro", "hash", org_id, now + 10, now + 10),
    )
    script_id = add_script(conn, "Baseline")
    stack_id = add_stack(conn, org_id, [("script", script_id)])
    conn.execute(
        "INSERT INTO org_onboarding_settings(org_id,active_stack_id,enabled,enabled_at,target_workstations,target_servers,updated_at) VALUES(?,?,?,?,?,?,?)",
        (org_id, stack_id, 1, now, 1, 0, now),
    )
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)

    assert app._maybe_start_automatic_onboarding(conn, "old", now + 20) is None
    assert conn.execute("SELECT COUNT(*) FROM onboarding_runs WHERE agent_id='old'").fetchone()[0] == 0

    run_id = app._maybe_start_automatic_onboarding(conn, "new", now + 20)
    assert run_id
    assert conn.execute("SELECT COUNT(*) FROM onboarding_runs WHERE agent_id='new'").fetchone()[0] == 1
    assert app._maybe_start_automatic_onboarding(conn, "new", now + 30) is None
    assert conn.execute("SELECT COUNT(*) FROM onboarding_runs WHERE agent_id='new'").fetchone()[0] == 1


def test_onboarding_preflight_failure_leaves_no_partial_run(monkeypatch):
    conn = make_db()
    org_id = add_org_agent(conn)
    stack_id = add_stack(conn, org_id, [("application", 999999)])
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)
    agent = conn.execute("SELECT * FROM agents WHERE id='a1'").fetchone()
    stack = conn.execute("SELECT * FROM automation_stacks WHERE id=?", (stack_id,)).fetchone()

    with pytest.raises(Exception):
        app._start_onboarding_run(conn, agent, stack, "manual", time.time())
    assert conn.execute("SELECT COUNT(*) FROM onboarding_runs").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM onboarding_run_steps").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM device_onboarding_state").fetchone()[0] == 0


def test_dashboard_exposes_application_library_and_customer_onboarding_builder():
    assert 'data-view="applications"' in DASHBOARD
    assert 'id="view-applications"' in DASHBOARD
    assert 'id="onboardingModal"' in DASHBOARD
    assert 'openOnboardingManager(${o.id})' in DASHBOARD
    assert 'Automatically run on newly enrolled devices' in DASHBOARD
    assert "function onboardingDrop(i,event)" in DASHBOARD
    assert "function runDeviceOnboarding()" in DASHBOARD


def test_agent_protocol_was_not_extended_for_application_installation():
    # Compatibility guard: application jobs are compiled to the known run_script
    # path. Old 1.13.4 endpoints must never receive an unknown install job type.
    assert "install_application" not in AGENT
    assert '"run_script"' in AGENT or "'run_script'" in AGENT
