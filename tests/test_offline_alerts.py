import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


TEST_DATA_DIR = tempfile.TemporaryDirectory()
os.environ["OUTPOST_ADMIN_PASSWORD"] = "test-admin-password"
os.environ["OUTPOST_ENROLL_KEY"] = "test-enroll-key"
os.environ["OUTPOST_DATA_DIR"] = TEST_DATA_DIR.name
SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
sys.path.insert(0, str(SERVER_DIR))
app = importlib.import_module("app")


class OfflineAlertTests(unittest.TestCase):
    def setUp(self):
        with app.db() as conn:
            conn.execute("DELETE FROM monitor_incidents")
            conn.execute("DELETE FROM agents")
            conn.execute("DELETE FROM orgs")
            conn.execute("DELETE FROM settings WHERE key IN ('alerts', 'alert_state', 'monitor_policy')")
        self.sent = []
        self.original_send_discord = app.send_discord
        self.original_monitor_alert = app._monitor_alert
        app.send_discord = lambda *args, **kwargs: self.sent.append((args, kwargs))

    def tearDown(self):
        app.send_discord = self.original_send_discord
        app._monitor_alert = self.original_monitor_alert

    def save_alerts(self, config):
        with app.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('alerts', ?)",
                (json.dumps(config),),
            )

    def add_agent(self, agent_id, hostname, os_version, offline_hours):
        with app.db() as conn:
            conn.execute(
                """INSERT INTO agents
                   (id, hostname, os_version, token_hash, last_seen, created_at)
                   VALUES (?, ?, ?, 'test-token-hash', ?, ?)""",
                (agent_id, hostname, os_version,
                 time.time() - offline_hours * 3600, time.time()),
            )

    def test_server_and_workstation_alert_switches_are_independent(self):
        self.save_alerts({
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/test/test",
            "on_offline_workstations": False,
            "offline_workstation_hours": 1,
            "on_offline_servers": True,
            "offline_server_hours": 1,
        })
        self.add_agent("server-1", "SERVER-1", "Microsoft Windows Server 2022", 2)
        self.add_agent("workstation-1", "PC-1", "Microsoft Windows 11 Pro", 2)

        app.run_offline_alerts()

        self.assertEqual(1, len(self.sent))
        self.assertIn("SERVER-1", self.sent[0][0][1])
        self.assertIn("**Device type:** Server", self.sent[0][0][2])

    def test_server_and_workstation_thresholds_are_independent(self):
        self.save_alerts({
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/test/test",
            "on_offline_workstations": True,
            "offline_workstation_hours": 2,
            "on_offline_servers": True,
            "offline_server_hours": 4,
        })
        self.add_agent("server-2", "SERVER-2", "Windows Server 2019 Standard", 3)
        self.add_agent("workstation-2", "PC-2", "Windows 10 Pro", 3)

        app.run_offline_alerts()

        self.assertEqual(1, len(self.sent))
        self.assertIn("PC-2", self.sent[0][0][1])
        self.assertIn("**Device type:** Workstation", self.sent[0][0][2])

    def test_legacy_offline_setting_applies_to_both_device_types(self):
        self.save_alerts({
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/test/test",
            "on_offline": False,
            "offline_hours": 6,
        })

        with app.db() as conn:
            config = app.get_alerts(conn)

        self.assertFalse(config["on_offline_workstations"])
        self.assertFalse(config["on_offline_servers"])
        self.assertEqual(6, config["offline_workstation_hours"])
        self.assertEqual(6, config["offline_server_hours"])

    def test_central_monitor_does_not_send_a_duplicate_offline_discord_alert(self):
        self.save_alerts({
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/test/test",
            "on_monitoring": True,
            "on_offline_workstations": True,
            "offline_workstation_hours": 2,
            "on_offline_servers": True,
            "offline_server_hours": 2,
        })
        self.add_agent("server-3", "SERVER-3", "Windows Server 2022", 3)
        monitoring_alerts = []
        app._monitor_alert = lambda title, *args, **kwargs: monitoring_alerts.append(title)

        app.evaluate_monitoring()

        self.assertFalse(any("has not checked in" in title for title in monitoring_alerts))


if __name__ == "__main__":
    unittest.main()
