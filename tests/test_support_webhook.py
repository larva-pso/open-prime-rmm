import asyncio
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
TEST_DATA_DIR = tempfile.TemporaryDirectory()
os.environ.setdefault("OUTPOST_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("OUTPOST_ENROLL_KEY", "test-enroll-key")
os.environ.setdefault("OUTPOST_DATA_DIR", TEST_DATA_DIR.name)
sys.path.insert(0, str(ROOT / "server"))
app = importlib.import_module("app")


class JsonRequest:
    def __init__(self, body):
        self.body = body

    async def json(self):
        return self.body


class SupportWebhookTests(unittest.TestCase):
    def setUp(self):
        with app.db() as conn:
            conn.execute("DELETE FROM settings WHERE key='alerts'")
        self.original_require_admin_role = app.require_admin_role
        self.original_send_discord_strict = app.send_discord_strict
        app.require_admin_role = lambda request: {"username": "tester", "role": "admin"}

    def tearDown(self):
        app.require_admin_role = self.original_require_admin_role
        app.send_discord_strict = self.original_send_discord_strict

    def test_alert_settings_save_dedicated_support_webhook(self):
        self.assertIn(
            "support_webhook_url: (qs('#alSupportWebhook') ? qs('#alSupportWebhook').value : '').trim()",
            DASHBOARD,
        )
        self.assertIn(
            "keep_support_webhook: (qs('#alSupportWebhook') ? qs('#alSupportWebhook').value.trim() === '' : true)",
            DASHBOARD,
        )

    def test_alert_settings_load_dedicated_support_webhook_state(self):
        self.assertTrue("qs('#alSupportWebhook').value = '';" in DASHBOARD)
        self.assertTrue(
            "qs('#alSupportWebhookSet').textContent = a.support_webhook_set" in DASHBOARD
        )

    def test_support_channel_button_uses_support_alert_route(self):
        self.assertTrue("async function testSupportAlert(){" in DASHBOARD)
        self.assertTrue("JSON.stringify({ webhook_url: url, route: 'support' })" in DASHBOARD)

    def test_support_channel_test_falls_back_to_main_webhook(self):
        main_webhook = "https://discord.com/api/webhooks/test/main"
        with app.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('alerts', ?)",
                (json.dumps({"webhook_url": main_webhook, "support_webhook_url": ""}),),
            )
        sent = []
        app.send_discord_strict = lambda url, *args, **kwargs: (sent.append(url) or (True, "sent"))

        result = asyncio.run(app.test_alert(JsonRequest({"route": "support"})))

        self.assertTrue(result["ok"])
        self.assertEqual([main_webhook], sent)

    def test_alert_api_saves_but_does_not_echo_support_webhook(self):
        support_webhook = "https://discord.com/api/webhooks/test/support"
        asyncio.run(app.write_alerts(JsonRequest({
            "enabled": True,
            "support_webhook_url": support_webhook,
        })))

        safe = app.read_alerts(object())

        self.assertTrue(safe["support_webhook_set"])
        self.assertEqual("", safe["support_webhook_url"])

    def test_blank_support_webhook_preserves_saved_value(self):
        support_webhook = "https://discord.com/api/webhooks/test/support"
        with app.db() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('alerts', ?)",
                (json.dumps({"support_webhook_url": support_webhook}),),
            )

        asyncio.run(app.write_alerts(JsonRequest({
            "support_webhook_url": "",
            "keep_support_webhook": True,
        })))

        with app.db() as conn:
            self.assertEqual(support_webhook, app.get_alerts(conn)["support_webhook_url"])


if __name__ == "__main__":
    unittest.main()
