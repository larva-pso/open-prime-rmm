import importlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient


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


def reset_monitoring_data():
    with app.db() as conn:
        conn.execute("DELETE FROM monitor_incidents")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM orgs")
        conn.execute("DELETE FROM settings WHERE key='monitor_policy'")


def add_agent(agent_id, hostname, os_version, memory_used_pct):
    now = time.time()
    with app.db() as conn:
        conn.execute(
            """INSERT INTO agents
               (id,hostname,os_version,token_hash,last_seen,created_at,memory_used_pct)
               VALUES(?,?,?,?,?,?,?)""",
            (agent_id, hostname, os_version, "hash", now, now, memory_used_pct),
        )


def save_memory_policy(**overrides):
    policy = {
        **app.DEFAULT_MONITOR_POLICY,
        "memory_alert_enabled": True,
        "workstation_memory_pct": 80,
        "server_memory_pct": 90,
        **overrides,
    }
    with app.db() as conn:
        conn.execute(
            """INSERT INTO settings(key,value) VALUES('monitor_policy',?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (json.dumps(policy),),
        )


def memory_incidents():
    with app.db() as conn:
        return conn.execute(
            "SELECT agent_id,status,value_text,threshold_text FROM monitor_incidents "
            "WHERE incident_type='high_memory' ORDER BY agent_id"
        ).fetchall()


def test_memory_policy_is_disabled_by_default_and_clamps_class_thresholds():
    assert app.DEFAULT_MONITOR_POLICY["memory_alert_enabled"] is False
    policy = app.sanitize_monitor_policy({
        "memory_alert_enabled": True,
        "workstation_memory_pct": 15,
        "server_memory_pct": 150,
    })
    assert policy["memory_alert_enabled"] is True
    assert policy["workstation_memory_pct"] == 50
    assert policy["server_memory_pct"] == 99


def test_monitoring_uses_separate_workstation_and_server_memory_thresholds():
    reset_monitoring_data()
    save_memory_policy()
    add_agent("server-1", "SERVER-1", "Windows Server 2022", 85)
    add_agent("workstation-1", "PC-1", "Windows 11 Pro", 85)

    app.evaluate_monitoring()

    rows = memory_incidents()
    assert [(r["agent_id"], r["status"]) for r in rows] == [("workstation-1", "open")]
    assert rows[0]["value_text"] == "85.0% RAM used"
    assert rows[0]["threshold_text"] == ">= 80% (workstation)"


def test_high_memory_incident_resolves_after_usage_recovers():
    reset_monitoring_data()
    save_memory_policy()
    add_agent("server-1", "SERVER-1", "Windows Server 2022", 95)
    app.evaluate_monitoring()
    with app.db() as conn:
        conn.execute("UPDATE agents SET memory_used_pct=70 WHERE id='server-1'")

    app.evaluate_monitoring()

    rows = memory_incidents()
    assert len(rows) == 1
    assert rows[0]["status"] == "resolved"


def test_disabling_monitoring_resolves_an_existing_high_memory_incident():
    reset_monitoring_data()
    save_memory_policy()
    add_agent("server-1", "SERVER-1", "Windows Server 2022", 95)
    app.evaluate_monitoring()
    save_memory_policy(enabled=False)

    app.evaluate_monitoring()

    rows = memory_incidents()
    assert len(rows) == 1
    assert rows[0]["status"] == "resolved"


def test_agent_reports_guarded_current_memory_usage():
    assert "$AgentVersion = '1.13.7'" in AGENT
    assert "$inv.memory_used_pct" in AGENT
    assert "TotalVisibleMemorySize" in AGENT
    assert "FreePhysicalMemory" in AGENT


def test_agent_checkin_persists_memory_usage_for_fleet_and_monitoring():
    reset_monitoring_data()
    token = "test-agent-token"
    now = time.time()
    with app.db() as conn:
        conn.execute(
            """INSERT INTO agents(id,hostname,token_hash,last_seen,created_at)
               VALUES(?,?,?,?,?)""",
            ("checkin-1", "CHECKIN-PC", app.hash_token(token), now, now),
        )
    response = TestClient(app.app).post(
        "/api/agent/checkin",
        headers={"X-Agent-Id": "checkin-1", "X-Agent-Token": token},
        json={
            "hostname": "CHECKIN-PC",
            "os_version": "Windows 11 Pro",
            "agent_version": "1.13.6",
            "updates": [],
            "inventory": {"memory_used_pct": 73.4, "disks": []},
        },
    )
    assert response.status_code == 200
    with app.db() as conn:
        row = conn.execute(
            "SELECT memory_used_pct FROM agents WHERE id='checkin-1'"
        ).fetchone()
    assert row["memory_used_pct"] == 73.4


def test_dynamic_group_resolves_the_new_fleet_filters_without_broadening():
    reset_monitoring_data()
    add_agent("matching", "SERVER-A", "Windows Server 2022", 95)
    add_agent("wrong-os", "LINUX-A", "Ubuntu Linux", 95)
    with app.db() as conn:
        conn.execute("UPDATE agents SET bdgz_protected=0 WHERE id IN ('matching','wrong-os')")
        conn.execute(
            """INSERT INTO monitor_incidents
               (dedupe_key,agent_id,incident_type,severity,status,message,
                value_text,threshold_text,first_seen,last_seen,consecutive_count)
               VALUES('high_memory:matching','matching','high_memory','warning','open',
                      'High RAM','95%','90%',?,?,1)""",
            (time.time(), time.time()),
        )
        filters = app.sanitize_group_filters({
            "device_class": "server",
            "os_family": "windows_server",
            "protection_status": "missing",
            "memory_status": "high",
        })
        assert filters == {
            "device_class": "server",
            "os_family": "windows_server",
            "protection_status": "missing",
            "memory_status": "high",
        }
        assert app.resolve_group_filters(conn, filters) == ["matching"]


def test_dynamic_group_treats_stale_memory_telemetry_as_unknown():
    reset_monitoring_data()
    add_agent("stale", "STALE-PC", "Windows 11 Pro", 72)
    with app.db() as conn:
        conn.execute(
            "UPDATE agents SET last_seen=? WHERE id='stale'",
            (time.time() - 600,),
        )
        assert app.resolve_group_filters(conn, {"memory_status": "normal"}) == []
        assert app.resolve_group_filters(conn, {"memory_status": "unknown"}) == ["stale"]
