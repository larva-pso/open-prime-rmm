import asyncio
import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Reuse an already-loaded app module when the full suite is running. When this
# file runs alone, provide its own isolated test data directory.
if "app" not in sys.modules:
    TEST_DATA_DIR = tempfile.TemporaryDirectory()
    os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
    os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
    SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
    sys.path.insert(0, str(SERVER_DIR))
app = importlib.import_module("app")


class JsonRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


class AutomationWorkspaceTests(unittest.TestCase):
    def setUp(self):
        with app.db() as conn:
            conn.execute("DELETE FROM automation_rule_state")
            conn.execute("DELETE FROM automation_runs")
            conn.execute("DELETE FROM automation_rules")
            conn.execute("DELETE FROM schedules")
            conn.execute("DELETE FROM device_groups")
            conn.execute("DELETE FROM jobs")
            conn.execute("DELETE FROM scripts")
            conn.execute("DELETE FROM agents")
            conn.execute("DELETE FROM orgs")
        self.original_require_admin_role = app.require_admin_role
        self.original_audit = app.audit
        app.require_admin_role = lambda request: {"username": "tester", "role": "admin"}
        app.audit = lambda *args, **kwargs: None

    def tearDown(self):
        app.require_admin_role = self.original_require_admin_role
        app.audit = self.original_audit

    def seed_group_target(self):
        now = time.time()
        with app.db() as conn:
            org_id = conn.execute(
                "INSERT INTO orgs(name,created_at) VALUES(?,?)", ("Test Customer", now)
            ).lastrowid
            conn.execute(
                """INSERT INTO agents
                   (id,hostname,token_hash,org_id,created_at,last_seen,reboot_required,os_version)
                   VALUES(?,?,?,?,?,?,?,?)""",
                ("agent-1", "PC-1", "hash", org_id, now, now, 1, "Windows 11"),
            )
            group_id = conn.execute(
                "INSERT INTO device_groups(name,filters,created_at) VALUES(?,?,?)",
                ("Needs Restart", json.dumps({"reboot_required": True}), now),
            ).lastrowid
        return group_id

    def test_schedule_dict_parses_weekdays_and_live_target_count(self):
        group_id = self.seed_group_target()
        now = time.time()
        with app.db() as conn:
            schedule_id = conn.execute(
                """INSERT INTO schedules
                   (name,script_id,mode,interval_minutes,daily_time,target_type,target_ids,
                    variables,enabled,last_run_at,next_run_at,created_at,action_type,weekdays)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("Windows Needs Restart", 0, "daily", 60, "02:00", "group",
                 json.dumps([group_id]), "{}", 1, None, now + 3600, now,
                 "reboot", json.dumps([1, 3, 6])),
            ).lastrowid
            row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
            result = app._schedule_dict(conn, row)
        self.assertEqual([1, 3, 6], result["weekdays"])
        self.assertEqual(1, result["target_count"])
        self.assertEqual("Reboot machine", result["script_name"])

    def test_non_script_condition_rule_has_live_target_count_without_deleted_script(self):
        group_id = self.seed_group_target()
        now = time.time()
        with app.db() as conn:
            rule_id = conn.execute(
                """INSERT INTO automation_rules
                   (name,enabled,trigger_type,threshold,window_minutes,cooldown_minutes,
                    script_id,target_type,target_ids,variables,last_run_at,created_at,updated_at,action_type)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("Reboot stale machines", 1, "reboot_pending_days", 2, 1, 1440,
                 0, "group", json.dumps([group_id]), "{}", None, now, now, "reboot"),
            ).lastrowid
            row = conn.execute("SELECT * FROM automation_rules WHERE id=?", (rule_id,)).fetchone()
            result = app._automation_rule_dict(conn, row)
        self.assertEqual(1, result["target_count"])
        self.assertEqual("", result["script_name"])
        self.assertEqual("", result["script_shell"])

    def test_non_script_rule_can_be_edited_without_script_id(self):
        now = time.time()
        with app.db() as conn:
            rule_id = conn.execute(
                """INSERT INTO automation_rules
                   (name,enabled,trigger_type,threshold,window_minutes,cooldown_minutes,
                    script_id,target_type,target_ids,variables,last_run_at,created_at,updated_at,action_type)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("Reboot condition", 1, "reboot_pending_days", 1, 1, 60,
                 0, "all", "[]", "{}", None, now, now, "reboot"),
            ).lastrowid
        req = JsonRequest({
            "name": "Reboot condition edited",
            "enabled": True,
            "trigger_type": "reboot_pending_days",
            "threshold": 2,
            "window_minutes": 1,
            "cooldown_minutes": 120,
            "script_id": 0,
            "action_type": "reboot",
            "target_type": "all",
            "target_ids": [],
            "variables": {},
        })
        result = asyncio.run(app.api_update_automation_rule(rule_id, req))
        self.assertTrue(result["ok"])
        with app.db() as conn:
            row = conn.execute("SELECT * FROM automation_rules WHERE id=?", (rule_id,)).fetchone()
        self.assertEqual("Reboot condition edited", row["name"])
        self.assertEqual("reboot", row["action_type"])
        self.assertEqual(0, row["script_id"])

    def test_condition_rule_toggle_works_before_first_run(self):
        now = time.time()
        with app.db() as conn:
            rule_id = conn.execute(
                """INSERT INTO automation_rules
                   (name,enabled,trigger_type,threshold,window_minutes,cooldown_minutes,
                    script_id,target_type,target_ids,variables,last_run_at,created_at,updated_at,action_type)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("Never run yet", 1, "antivirus_missing", 0, 1, 60,
                 0, "all", "[]", "{}", None, now, now, "reboot"),
            ).lastrowid
        response = app.api_toggle_automation_rule(rule_id, object())
        self.assertFalse(response["enabled"])
        with app.db() as conn:
            row = conn.execute("SELECT enabled,last_run_at FROM automation_rules WHERE id=?", (rule_id,)).fetchone()
        self.assertEqual(0, row["enabled"])
        self.assertIsNone(row["last_run_at"])


if __name__ == "__main__":
    unittest.main()
