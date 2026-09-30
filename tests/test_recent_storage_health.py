import sqlite3
import time
from pathlib import Path
import sys

SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import app


def make_incident_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE monitor_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            incident_type TEXT,
            severity TEXT,
            status TEXT,
            message TEXT,
            value_text TEXT,
            threshold_text TEXT,
            first_seen REAL,
            last_seen REAL,
            resolved_at REAL
        );
        """
    )
    return conn


def add_disk_incident(conn, agent_id, age_days, status="resolved", value="disk event"):
    now = time.time()
    first = now - age_days * 86400
    conn.execute(
        """INSERT INTO monitor_incidents
           (agent_id,incident_type,severity,status,message,value_text,threshold_text,
            first_seen,last_seen,resolved_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (agent_id, "disk_io_events", "critical", status, "Disk I/O errors detected",
         value, "0 disk I/O events in the last 24h", first, first + 3600,
         first + 86400 if status == "resolved" else None),
    )


def test_recent_storage_map_keeps_resolved_disk_incidents_for_seven_days_only():
    conn = make_incident_db()
    add_disk_incident(conn, "recent", 2, value="recent")
    add_disk_incident(conn, "old", 8, value="old")
    add_disk_incident(conn, "still-open", 1, status="open", value="open")

    result = app._recent_storage_warning_map(conn)

    assert "recent" in result
    assert result["recent"]["value_text"] == "recent"
    assert "old" not in result
    assert "still-open" not in result


def test_recent_storage_map_uses_latest_resolved_occurrence():
    conn = make_incident_db()
    add_disk_incident(conn, "pc1", 5, value="older")
    add_disk_incident(conn, "pc1", 1, value="newer")

    result = app._recent_storage_warning_map(conn)

    assert result["pc1"]["value_text"] == "newer"


def test_active_disk_or_smart_fault_supersedes_recent_warning():
    recent = {"first_seen": time.time() - 86400, "value_text": "recent"}

    machine = {"disk_io_warning": False, "hw_warning": False}
    app._apply_recent_storage_warning(machine, recent)
    assert machine["recent_storage_warning"] is True
    assert machine["storage_health_state"] == "recent"

    machine = {"disk_io_warning": True, "hw_warning": False}
    app._apply_recent_storage_warning(machine, recent)
    assert machine["recent_storage_warning"] is False
    assert machine["storage_health_state"] == "critical"

    machine = {"disk_io_warning": False, "hw_warning": True}
    app._apply_recent_storage_warning(machine, recent)
    assert machine["recent_storage_warning"] is False
    assert machine["storage_health_state"] == "critical"


def test_healthy_storage_state_when_no_current_or_recent_fault():
    machine = {"disk_io_warning": False, "hw_warning": False}
    app._apply_recent_storage_warning(machine, None)
    assert machine["recent_storage_warning"] is False
    assert machine["recent_storage_event"] is None
    assert machine["storage_health_state"] == "healthy"
