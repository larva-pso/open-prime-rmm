import json
import sqlite3
import time
from pathlib import Path
import sys

SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import app


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            content TEXT NOT NULL,
            shell TEXT NOT NULL DEFAULT 'powershell',
            timeout_sec INTEGER DEFAULT 900,
            variables TEXT DEFAULT '[]',
            safety_class TEXT DEFAULT 'unclassified',
            ai_auto_allowed INTEGER DEFAULT 0,
            changes_system INTEGER DEFAULT 1,
            reboot_impact TEXT DEFAULT 'possible',
            updated_at REAL NOT NULL
        );
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            os_version TEXT,
            ext_inventory TEXT DEFAULT '{}',
            disk_health TEXT DEFAULT '[]',
            smart_failures INTEGER DEFAULT 0,
            disk_events TEXT DEFAULT '{}',
            reboot_required INTEGER DEFAULT 0,
            last_seen REAL,
            org_id INTEGER
        );
        CREATE TABLE monitor_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dedupe_key TEXT UNIQUE,
            agent_id TEXT,
            org_id INTEGER,
            incident_type TEXT,
            severity TEXT,
            status TEXT,
            message TEXT,
            value_text TEXT,
            threshold_text TEXT,
            first_seen REAL,
            last_seen REAL,
            resolved_at REAL,
            remediation_job_id TEXT DEFAULT ''
        );
        CREATE TABLE jobs (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            type TEXT,
            label TEXT,
            payload TEXT,
            status TEXT DEFAULT 'pending',
            output TEXT DEFAULT '',
            exit_code INTEGER,
            created_at REAL,
            finished_at REAL
        );
        CREATE TABLE ai_remediation_runs (
            job_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            script_id INTEGER NOT NULL,
            source_type TEXT DEFAULT '',
            source_key TEXT DEFAULT '',
            source_context TEXT DEFAULT '{}',
            created_at REAL NOT NULL,
            assessed_at REAL,
            assessment TEXT DEFAULT ''
        );
        """
    )
    return conn


def add_script(conn, name, safety="diagnostic", auto=1, changes=0):
    conn.execute(
        """INSERT INTO scripts(name,description,content,shell,timeout_sec,variables,
           safety_class,ai_auto_allowed,changes_system,reboot_impact,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (name, "desc", "Write-Output ok", "powershell", 120, "[]", safety,
         auto, changes, "no", time.time()),
    )


def test_recent_storage_health_gets_disk_diagnostic_candidates():
    conn = make_db()
    add_script(conn, "[MSP] Disk & SMART Health")
    add_script(conn, "[MSP] Recent Critical Event Log Summary")
    rows = app._ai_candidate_scripts(conn, ["disk_io_events"])
    assert [r["name"] for r in rows][:2] == [
        "[MSP] Disk & SMART Health",
        "[MSP] Recent Critical Event Log Summary",
    ]


def test_auto_collection_queues_only_diagnostic_opted_in_script(monkeypatch):
    conn = make_db()
    now = time.time()
    conn.execute(
        "INSERT INTO agents(id,hostname,os_version,last_seen) VALUES (?,?,?,?)",
        ("a1", "PC1", "Windows 11", now),
    )
    add_script(conn, "[MSP] Disk & SMART Health", "diagnostic", 1, 0)
    conn.execute(
        "INSERT INTO settings(key,value) VALUES ('ai',?)",
        (json.dumps({"auto_diagnostics": True, "enabled": False}),),
    )
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)
    agent = conn.execute("SELECT * FROM agents WHERE id='a1'").fetchone()
    job_id = app._auto_queue_diagnostic_for_incident(
        conn, agent, incident_type="disk_io_events", source_key="disk_io:a1",
        message="Disk I/O errors", value_text="1 event", threshold_text="0", now=now,
    )
    assert job_id
    job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    assert job["type"] == "run_script"
    assert "Disk & SMART Health" in job["label"]
    run = conn.execute("SELECT * FROM ai_remediation_runs WHERE job_id=?", (job_id,)).fetchone()
    assert run["source_type"] == "monitor_auto"


def test_auto_collection_refuses_remediation_even_if_opted_in_flag_is_set(monkeypatch):
    conn = make_db()
    now = time.time()
    conn.execute(
        "INSERT INTO agents(id,hostname,os_version,last_seen) VALUES (?,?,?,?)",
        ("a1", "PC1", "Windows 11", now),
    )
    # The mapped first script is deliberately misclassified as remediation.
    add_script(conn, "[MSP] Disk & SMART Health", "safe_remediation", 1, 1)
    conn.execute(
        "INSERT INTO settings(key,value) VALUES ('ai',?)",
        (json.dumps({"auto_diagnostics": True, "enabled": False}),),
    )
    monkeypatch.setattr(app, "_wake_agent", lambda _agent_id: None)
    agent = conn.execute("SELECT * FROM agents WHERE id='a1'").fetchone()
    job_id = app._auto_queue_diagnostic_for_incident(
        conn, agent, incident_type="disk_io_events", source_key="disk_io:a1",
        message="Disk I/O errors", value_text="1 event", threshold_text="0", now=now,
    )
    assert job_id is None
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0


def test_ai_health_context_includes_resolved_storage_history_without_open_incident():
    conn = make_db()
    now = time.time()
    conn.execute(
        "INSERT INTO agents(id,hostname,os_version,last_seen) VALUES (?,?,?,?)",
        ("a1", "PC1", "Windows 11", now),
    )
    conn.execute(
        """INSERT INTO monitor_incidents(dedupe_key,agent_id,incident_type,severity,status,message,
           value_text,threshold_text,first_seen,last_seen,resolved_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        ("disk_io:a1", "a1", "disk_io_events", "critical", "resolved", "Disk I/O errors",
         "Event 51", "0", now - 2*86400, now - 86400, now - 86400),
    )
    ctx = app._ai_health_context(conn, "a1")
    assert ctx is not None
    assert ctx["incidents"] == []
    assert ctx["recent_storage"] is not None
    assert "disk_io_events" in ctx["incident_types"]
