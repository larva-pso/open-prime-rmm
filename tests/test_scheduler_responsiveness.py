"""The scheduler must not delay unrelated requests while doing blocking I/O."""
import asyncio
import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
import threading
from unittest.mock import patch
from uuid import uuid4

from starlette.requests import Request

if "app" not in sys.modules:
    TEST_DATA_DIR = tempfile.TemporaryDirectory()
    os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
    os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
    os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
app = importlib.import_module("app")


class SchedulerResponsivenessTests(unittest.IsolatedAsyncioTestCase):
    async def test_manual_automation_wakes_only_after_job_commit(self):
        agent_id = str(uuid4())
        with app.db() as conn:
            conn.execute("INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) "
                         "VALUES (?,?,?,?,?)",
                         (agent_id, "AUTOMATION-TEST", "hash", time.time(), time.time()))
            agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            rule_id = conn.execute(
                "INSERT INTO automation_rules (name,trigger_type,script_id,action_type,created_at,updated_at) "
                "VALUES ('wake-test','low_disk_gb',0,'reboot',?,?)",
                (time.time(), time.time()),
            ).lastrowid
        observed = []
        def verify_wake(aid):
            with app.db() as conn:
                observed.append(conn.execute(
                    "SELECT COUNT(*) FROM jobs WHERE agent_id=? AND status='pending'", (aid,)
                ).fetchone()[0])
        try:
            with patch.object(app, "require_admin_role"), patch.object(app, "audit"), \
                    patch.object(app, "_automation_targets", return_value=[agent]), \
                    patch.object(app, "_wake_agent", side_effect=verify_wake):
                result = await asyncio.to_thread(app.api_run_automation_rule, rule_id, object())
            self.assertEqual(1, result["jobs_created"])
            self.assertEqual([1], observed)
        finally:
            with app.db() as conn:
                conn.execute("DELETE FROM automation_runs WHERE rule_id=?", (rule_id,))
                conn.execute("DELETE FROM jobs WHERE agent_id=?", (agent_id,))
                conn.execute("DELETE FROM automation_rules WHERE id=?", (rule_id,))
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    async def test_auto_approve_wakes_only_after_decision_is_committed(self):
        agent_id = str(uuid4())
        with app.db() as conn:
            conn.execute("INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) "
                         "VALUES (?,?,?,?,?)",
                         (agent_id, "AUTO-TEST", "hash", time.time(), time.time()))
            conn.execute(
                "INSERT INTO updates (agent_id,update_id,kb,title,severity,status,detected_at) "
                "VALUES (?,?,?,?,?,'pending',?)",
                (agent_id, "auto-perf", "KB987654", "Auto test", "Critical", time.time() - 86400),
            )
        observed = []
        def verify_wake(aid):
            with app.db() as conn:
                observed.append(conn.execute(
                    "SELECT status FROM updates WHERE agent_id=?", (aid,)
                ).fetchone()[0])
        try:
            with patch.object(app, "get_policy", return_value={"enabled": True,
                    "severities": ["Critical"], "delay_days": 0}), \
                    patch.object(app, "get_org_policy", return_value=None), \
                    patch.object(app, "policy_in_maintenance_window", return_value=True), \
                    patch.object(app, "policy_category_stance", return_value="auto"), \
                    patch.object(app, "_wake_agent", side_effect=verify_wake):
                await asyncio.to_thread(app.run_auto_approve)
            self.assertEqual(["approved"], observed)
        finally:
            with app.db() as conn:
                conn.execute("DELETE FROM jobs WHERE agent_id=?", (agent_id,))
                conn.execute("DELETE FROM updates WHERE agent_id=?", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    async def test_job_result_commits_without_freezing_other_requests(self):
        agent_id, job_id = str(uuid4()), str(uuid4())
        with app.db() as conn:
            conn.execute(
                "INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) VALUES (?,?,?,?,?)",
                (agent_id, "RESULT-TEST", "hash", time.time(), time.time()),
            )
            agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            conn.execute(
                "INSERT INTO jobs (id,agent_id,type,payload,status,created_at,started_at) "
                "VALUES (?,?,?,'{}','running',?,?)",
                (job_id, agent_id, "run_script", time.time(), time.time()),
            )
        payload = json.dumps({"ok": True, "output": "complete", "exit_code": 0}).encode()
        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}
        request = Request({"type": "http", "method": "POST", "path": "/api/agent/jobs/result",
                           "headers": [], "client": ("127.0.0.1", 1234)}, receive)
        real_db = app.db
        @contextmanager
        def slow_db():
            time.sleep(0.2)
            with real_db() as conn:
                yield conn
        try:
            with patch.object(app, "require_agent", return_value=agent), patch.object(app, "db", slow_db):
                task = asyncio.create_task(app.agent_job_result(job_id, request))
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                self.assertEqual({"ok": True}, await task)
                self.assertLess(elapsed, 0.12, "job-result write blocked the API event loop")
            with real_db() as conn:
                self.assertEqual("done", conn.execute(
                    "SELECT status FROM jobs WHERE id=?", (job_id,)
                ).fetchone()[0])
        finally:
            with real_db() as conn:
                conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    async def test_patch_deny_remains_responsive_and_preserves_running_conflicts(self):
        agents = [str(uuid4()) for _ in range(3)]
        job_id = str(uuid4())
        with app.db() as conn:
            for aid in agents:
                conn.execute(
                    "INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) "
                    "VALUES (?,?,?,?,?)", (aid, aid, "hash", time.time(), time.time())
                )
                conn.execute(
                    "INSERT INTO updates (agent_id,update_id,kb,title,severity,status,detected_at) "
                    "VALUES (?,?,?,?,?,'pending',?)",
                    (aid, "deny-perf", "KB654321", "Deny test", "Critical", time.time()),
                )
            conn.execute(
                "INSERT INTO jobs (id,agent_id,type,payload,status,created_at,started_at) "
                "VALUES (?,?,?,'{\"update_ids\":[\"deny-perf\"]}','running',?,?)",
                (job_id, agents[1], "install_updates", time.time(), time.time()),
            )
        class JsonRequest:
            async def json(self):
                return {"update_id": "deny-perf", "agent_ids": agents[:2]}
        real_db = app.db
        @contextmanager
        def slow_db():
            time.sleep(0.2)
            with real_db() as conn:
                yield conn
        try:
            with patch.object(app, "require_admin", return_value={"u": "test"}), \
                    patch.object(app, "audit"), patch.object(app, "db", slow_db):
                task = asyncio.create_task(app.patching_deny_update(JsonRequest()))
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                result = await task
                self.assertLess(elapsed, 0.12, "patch denial blocked the API event loop")
                self.assertEqual(1, result["devices"])
                self.assertEqual(1, len(result["running_conflicts"]))
                self.assertEqual(1, result["remaining_actionable"])
            with real_db() as conn:
                statuses = [conn.execute(
                    "SELECT status FROM updates WHERE agent_id=?", (aid,)
                ).fetchone()[0] for aid in agents]
                self.assertEqual(["denied", "pending", "pending"], statuses)
        finally:
            with real_db() as conn:
                conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                for aid in agents:
                    conn.execute("DELETE FROM updates WHERE agent_id=?", (aid,))
                    conn.execute("DELETE FROM agents WHERE id=?", (aid,))

    async def test_patch_approval_does_not_freeze_other_requests(self):
        agent_id = str(uuid4())
        with app.db() as conn:
            conn.execute(
                "INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) VALUES (?,?,?,?,?)",
                (agent_id, "PATCH-TEST", "hash", time.time(), time.time()),
            )
            conn.execute(
                "INSERT INTO updates (agent_id,update_id,kb,title,severity,status,detected_at) "
                "VALUES (?,?,?,?,?,'pending',?)",
                (agent_id, "perf-patch", "KB123456", "Performance test", "Critical", time.time()),
            )
        class JsonRequest:
            async def json(self):
                return {"update_id": "perf-patch", "agent_ids": [agent_id]}
        real_db = app.db
        @contextmanager
        def slow_db():
            time.sleep(0.2)
            with real_db() as conn:
                yield conn
        try:
            with patch.object(app, "require_admin", return_value={"u": "test"}), \
                    patch.object(app, "audit"), patch.object(app, "db", slow_db):
                task = asyncio.create_task(app.patching_approve_update(JsonRequest()))
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                result = await task
                self.assertLess(elapsed, 0.12, "patch approval blocked the API event loop")
                self.assertEqual(1, result["devices"])
            with real_db() as conn:
                self.assertEqual("approved", conn.execute(
                    "SELECT status FROM updates WHERE agent_id=?", (agent_id,)
                ).fetchone()[0])
        finally:
            with real_db() as conn:
                conn.execute("DELETE FROM jobs WHERE agent_id=?", (agent_id,))
                conn.execute("DELETE FROM updates WHERE agent_id=?", (agent_id,))
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    async def test_poll_db_lookup_does_not_freeze_other_requests(self):
        agent_id = str(uuid4())
        with app.db() as conn:
            conn.execute(
                "INSERT INTO agents (id,hostname,token_hash,live_mode,created_at,last_seen) "
                "VALUES (?,?,?,0,?,?)",
                (agent_id, "POLL-TEST", "test-hash", time.time(), time.time()),
            )
        real_db = app.db
        @contextmanager
        def slow_db():
            time.sleep(0.2)
            with real_db() as conn:
                yield conn
        try:
            with patch.object(app, "require_agent", return_value={"id": agent_id}), \
                    patch.object(app, "db", slow_db):
                task = asyncio.create_task(app.agent_poll(object()))
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                self.assertEqual({"jobs": [], "live_mode": False}, await task)
                self.assertLess(elapsed, 0.12, "long-poll authentication blocked the API loop")
        finally:
            with real_db() as conn:
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    async def test_checkin_write_does_not_freeze_other_requests(self):
        agent_id = str(uuid4())
        with app.db() as conn:
            conn.execute(
                "INSERT INTO agents (id,hostname,token_hash,created_at,last_seen) "
                "VALUES (?,?,?,?,?)",
                (agent_id, "CHECKIN-TEST", "test-hash", time.time(), time.time() - 60),
            )
            agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        payload = json.dumps({"inventory": {}, "updates": []}).encode()
        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}
        request = Request({"type": "http", "method": "POST", "path": "/api/agent/checkin",
                           "headers": [], "client": ("127.0.0.1", 1234)}, receive)
        real_db = app.db
        @contextmanager
        def slow_db():
            time.sleep(0.2)
            with real_db() as conn:
                yield conn
        try:
            with patch.object(app, "require_agent", return_value=agent), patch.object(app, "db", slow_db):
                task = asyncio.create_task(app.agent_checkin(request))
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                result = await task
                self.assertLess(elapsed, 0.12, "check-in blocked the API event loop")
                self.assertIn("jobs", result)
            with real_db() as conn:
                self.assertGreater(conn.execute("SELECT last_seen FROM agents WHERE id=?",
                                                (agent_id,)).fetchone()[0], agent["last_seen"])
        finally:
            with real_db() as conn:
                conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))

    async def test_worker_thread_signals_event_on_its_owner_loop(self):
        agent_id = "wake-thread-test"
        owner_thread = threading.get_ident()
        signal_threads = []
        class TrackingEvent:
            def set(self):
                signal_threads.append(threading.get_ident())

        app._live_events[agent_id] = TrackingEvent()
        try:
            app._register_live_event_loop(agent_id, asyncio.get_running_loop())
            await asyncio.to_thread(app._wake_agent, agent_id)
            await asyncio.sleep(0.02)
            self.assertEqual([owner_thread], signal_threads)
        finally:
            app._live_events.pop(agent_id, None)
            getattr(app, "_live_event_loops", {}).pop(agent_id, None)

    async def test_bdgz_config_lookup_does_not_block_event_loop(self):
        @contextmanager
        def slow_db():
            time.sleep(0.2)
            yield object()

        workers = (
            "run_due_schedules", "run_auto_approve", "run_offline_alerts",
            "reap_stale_jobs", "evaluate_monitoring", "evaluate_automation_rules",
            "run_scheduled_maintenance", "_maybe_send_daily_digest",
        )
        with patch.multiple(app, **{name: lambda: None for name in workers}), \
                patch.object(app, "db", slow_db), \
                patch.object(app, "get_bdgz", return_value={"enabled": False}), \
                patch.object(app, "_bdgz_last_sync", 0):
            task = asyncio.create_task(app.scheduler_loop())
            try:
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 0.12, "BDGZ config I/O blocked the API event loop")
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

    async def test_slow_scheduler_job_does_not_block_event_loop(self):
        def slow_job():
            time.sleep(0.2)

        with patch.object(app, "run_due_schedules", slow_job):
            task = asyncio.create_task(app.scheduler_loop())
            try:
                start = time.monotonic()
                await asyncio.sleep(0.03)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 0.12, "scheduler job blocked the API event loop")
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task


if __name__ == "__main__":
    unittest.main()
