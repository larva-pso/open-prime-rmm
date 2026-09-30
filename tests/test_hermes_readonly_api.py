import importlib
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest
from fastapi import HTTPException


if "app" not in sys.modules:
    TEST_DATA_DIR = tempfile.TemporaryDirectory()
    os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
    os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
    os.environ["OUTPOST_HERMES_API_TOKEN"] = "test-hermes-token"
    SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
    sys.path.insert(0, str(SERVER_DIR))
app = importlib.import_module("app")


class DummyRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}


def hermes_request(token="test-hermes-token"):
    return DummyRequest({"Authorization": f"Bearer {token}"})


@pytest.fixture(autouse=True)
def clean_db_and_token():
    app.HERMES_API_TOKEN = "test-hermes-token"
    with app.db() as conn:
        conn.execute("DELETE FROM jobs")
        conn.execute("DELETE FROM updates")
        conn.execute("DELETE FROM monitor_incidents")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM locations")
        conn.execute("DELETE FROM orgs")
    yield


def seed_device(hostname="PC-ALIVE", last_seen=None):
    now = time.time()
    if last_seen is None:
        last_seen = now
    agent_id = "agent-" + hostname.lower().replace("_", "-")
    with app.db() as conn:
        org = conn.execute("SELECT id FROM orgs WHERE name=?", ("OpenPrime",)).fetchone()
        org_id = org["id"] if org else conn.execute(
            "INSERT INTO orgs(name,created_at) VALUES(?,?)",
            ("OpenPrime", now),
        ).lastrowid
        conn.execute(
            """INSERT INTO agents
               (id,hostname,token_hash,org_id,created_at,last_seen,reboot_required,os_version,
                ip,public_ip,local_ip,agent_version,serial,model,cpu,ram_gb,disks,last_user,device_class)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                agent_id, hostname, "hash", org_id, now, last_seen, 1, "Windows 11 Pro",
                "10.0.0.5", "203.0.113.10", "10.0.0.5", "1.13.4", "SN123",
                "OptiPlex", "Intel", 16, '[{"name":"C:","free_gb":42,"total_gb":256}]',
                "prime\\tech", "workstation",
            ),
        )
        conn.execute(
            "INSERT INTO updates(agent_id,update_id,kb,title,severity,status,detected_at) VALUES(?,?,?,?,?,?,?)",
            (agent_id, "upd-1", "KB123", "Security Update", "Critical", "pending", now),
        )
        conn.execute(
            "INSERT INTO jobs(id,agent_id,type,label,payload,status,exit_code,created_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("job-" + hostname.lower(), agent_id, "run_script", "Inventory", "{}", "completed", 0, now - 30, now - 20),
        )
    return agent_id


def test_hermes_api_requires_bearer_token():
    seed_device()
    with pytest.raises(HTTPException) as missing:
        app.hermes_fleet_summary(DummyRequest())
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as wrong:
        app.hermes_fleet_summary(hermes_request("wrong-token"))
    assert wrong.value.status_code == 401


def test_hermes_device_search_returns_read_only_alive_status_without_agent_secret():
    agent_id = seed_device()
    response = app.hermes_device_search(hermes_request(), q="alive")
    assert response["count"] == 1
    device = response["devices"][0]
    assert device["id"] == agent_id
    assert device["hostname"] == "PC-ALIVE"
    assert device["online"] is True
    assert device["org_name"] == "OpenPrime"
    assert device["last_seen_age_seconds"] < 60
    assert "token_hash" not in device
    assert "AgentToken" not in str(device)


def test_hermes_device_detail_includes_inventory_updates_and_job_metadata_only():
    agent_id = seed_device()
    detail = app.hermes_device_detail(agent_id, hermes_request())
    assert detail["device"]["hostname"] == "PC-ALIVE"
    assert detail["device"]["reboot_required"] is True
    assert detail["device"]["agent_version"] == "1.13.4"
    assert detail["updates"][0]["kb"] == "KB123"
    assert detail["jobs"][0]["id"].startswith("job-")
    assert detail["jobs"][0]["status"] == "completed"
    assert "output" not in detail["jobs"][0]


def test_hermes_fleet_summary_counts_online_and_offline_devices():
    seed_device("PC-ONLINE", last_seen=time.time())
    seed_device("PC-OFFLINE", last_seen=time.time() - 3600)
    summary = app.hermes_fleet_summary(hermes_request())
    assert summary["overview"]["total"] == 2
    assert summary["overview"]["online"] == 1
    assert summary["overview"]["offline"] == 1
    assert summary["overview"]["reboot_required"] == 2
