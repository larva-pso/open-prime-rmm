import sqlite3
from pathlib import Path
import sys

SERVER_DIR = Path(__file__).resolve().parents[1] / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from msp_script_pack import (MSP_SCRIPTS, MSP_SCRIPT_SAFETY, PACK_SETTING_KEY, PACK_VERSION,
                             apply_msp_script_metadata, seed_msp_script_pack)


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
        """
    )
    return conn


def test_pack_has_expected_shape_and_unique_names():
    assert len(MSP_SCRIPTS) >= 20
    names = [s["name"].lower() for s in MSP_SCRIPTS]
    assert len(names) == len(set(names))
    for script in MSP_SCRIPTS:
        assert script["name"].startswith("[MSP] ")
        assert script["shell"] in {"powershell", "cmd", "bash"}
        assert script["content"].strip()
        assert 5 <= int(script["timeout_sec"]) <= 86400
        assert isinstance(script.get("variables", []), list)
        calcs = []
        for var in script.get("variables", []):
            assert var["type"] in {"text", "integer", "checkbox", "dropdown"}
            assert var["calc"] and (var["calc"][0].isalpha() or var["calc"][0] == "_")
            assert all(ch.isalnum() or ch == "_" for ch in var["calc"])
            calcs.append(var["calc"])
            if var["type"] == "dropdown":
                assert var.get("options")
        assert len(calcs) == len(set(calcs))


def test_seed_is_idempotent_and_does_not_overwrite_existing_script():
    conn = make_db()
    first_name = MSP_SCRIPTS[0]["name"]
    conn.execute(
        "INSERT INTO scripts (name,description,content,shell,timeout_sec,variables,updated_at) VALUES (?,?,?,?,?,?,?)",
        (first_name, "custom", "Write-Output 'custom'", "powershell", 60, "[]", 1.0),
    )

    result = seed_msp_script_pack(conn)
    assert result["seeded"] == len(MSP_SCRIPTS) - 1
    assert result["skipped"] == 1
    assert conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0] == len(MSP_SCRIPTS)
    assert conn.execute("SELECT content FROM scripts WHERE name=?", (first_name,)).fetchone()[0] == "Write-Output 'custom'"
    marker = conn.execute("SELECT value FROM settings WHERE key=?", (PACK_SETTING_KEY,)).fetchone()[0]
    assert marker == PACK_VERSION

    second = seed_msp_script_pack(conn)
    assert second["seeded"] == 0
    assert conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0] == len(MSP_SCRIPTS)


def test_scripts_do_not_embed_secrets_or_destructive_reboot_commands():
    corpus = "\n".join(s["content"].lower() for s in MSP_SCRIPTS)
    assert 'write-output "$($c.agent_token' not in corpus
    assert 'write-output $c.agent_token' not in corpus
    assert "enroll_key" not in corpus
    assert "shutdown.exe /r" not in corpus
    assert "restart-computer" not in corpus


def test_builtin_safety_metadata_is_complete_and_diagnostics_are_only_auto_allowed_class():
    names = {s["name"] for s in MSP_SCRIPTS}
    assert names == set(MSP_SCRIPT_SAFETY)
    for name, (safety, auto_allowed, changes_system, reboot_impact) in MSP_SCRIPT_SAFETY.items():
        assert safety in {"diagnostic", "safe_remediation", "disruptive", "high_impact"}
        assert reboot_impact in {"no", "possible", "yes"}
        if auto_allowed:
            assert safety == "diagnostic"
            assert changes_system is False


def test_metadata_upgrade_does_not_touch_script_content():
    conn = make_db()
    name = "[MSP] Disk & SMART Health"
    conn.execute(
        "INSERT INTO scripts (name,description,content,shell,timeout_sec,variables,updated_at) VALUES (?,?,?,?,?,?,?)",
        (name, "edited", "Write-Output edited", "powershell", 60, "[]", 1.0),
    )
    apply_msp_script_metadata(conn)
    row = conn.execute("SELECT * FROM scripts WHERE name=?", (name,)).fetchone()
    assert row["content"] == "Write-Output edited"
    assert row["safety_class"] == "diagnostic"
    assert row["ai_auto_allowed"] == 1
    assert row["changes_system"] == 0
    assert row["reboot_impact"] == "no"


def test_metadata_marker_preserves_technician_reclassification_on_restart():
    conn = make_db()
    name = "[MSP] Disk & SMART Health"
    conn.execute(
        "INSERT INTO scripts (name,description,content,shell,timeout_sec,variables,updated_at) VALUES (?,?,?,?,?,?,?)",
        (name, "edited", "Write-Output edited", "powershell", 60, "[]", 1.0),
    )
    assert apply_msp_script_metadata(conn) == 1
    conn.execute("UPDATE scripts SET safety_class='high_impact', ai_auto_allowed=0 WHERE name=?", (name,))
    assert apply_msp_script_metadata(conn) == 0
    row = conn.execute("SELECT safety_class,ai_auto_allowed FROM scripts WHERE name=?", (name,)).fetchone()
    assert row["safety_class"] == "high_impact"
    assert row["ai_auto_allowed"] == 0
