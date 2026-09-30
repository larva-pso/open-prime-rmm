"""
OpenPrime RMM — self-hosted server
--------------------------------
Single-file FastAPI app providing:
  * Agent API   : enroll, check-in (inventory + pending Windows Updates), job pickup, job results
  * Dashboard   : fleet view, update approval, script library, remote script execution, job history
  * Auth        : admin password (dashboard, signed session cookie) + per-agent bearer tokens

Environment variables (see README):
  OUTPOST_ADMIN_PASSWORD   required  — dashboard login password
  OUTPOST_ENROLL_KEY       required  — shared key new agents must present once to enroll
  OUTPOST_READONLY_API_TOKEN optional — read-only bearer token for fleet queries
  OUTPOST_DATA_DIR         optional  — where the SQLite DB + secret live (default ./data)
  OUTPOST_SESSION_HOURS    optional  — dashboard session lifetime (default 12)

Run:  uvicorn app:app --host 127.0.0.1 --port 8420
(Front with Caddy/nginx for TLS — agents connect over HTTPS.)
"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
import zipfile
import urllib.parse
import uuid
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from msp_script_pack import seed_msp_script_pack, apply_msp_script_metadata

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("OUTPOST_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "outpost.db"
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
DIAGNOSTIC_DIR = DATA_DIR / "diagnostics"
DIAGNOSTIC_DIR.mkdir(parents=True, exist_ok=True)
APPLICATION_DIR = DATA_DIR / "applications"
APPLICATION_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_PASSWORD = os.environ.get("OUTPOST_ADMIN_PASSWORD", "")
ENROLL_KEY = os.environ.get("OUTPOST_ENROLL_KEY", "")
HERMES_API_TOKEN = os.environ.get("OUTPOST_READONLY_API_TOKEN", os.environ.get("OUTPOST_HERMES_API_TOKEN", ""))
SESSION_HOURS = int(os.environ.get("OUTPOST_SESSION_HOURS", "12"))
PLATFORM_VERSION = "1.31.6"

OFFLINE_AFTER_SECONDS = 15 * 60      # no check-in for 15 min => offline
MAX_JOB_OUTPUT = 120_000             # chars of job output stored
AGENT_VERSION = "1.0.0"
POWER_JOB_TTL_SECONDS = 15 * 60       # never deliver an old reboot/shutdown after the window


def build_power_job_payload(mode: str, message: str, source: str, now: float,
                            delay_sec: int = 60, force_reboot: bool = False) -> dict:
    """Build a short-lived power job; only explicit reboot may override sessions.

    Shutdown and ordinary reboot stay session-guarded on the endpoint, including
    an immediate re-check after the countdown. Force reboot still expires.
    """
    mode = "shutdown" if str(mode).lower() == "shutdown" else "reboot"
    if force_reboot and mode != "reboot":
        raise ValueError("Force reboot is available only for reboot jobs")
    delay = max(0, min(3600, int(delay_sec or 0)))
    return {
        "delay_sec": delay,
        "mode": mode,
        "message": str(message or f"OpenPrimeRMM managed {mode}"),
        "source": str(source or "managed"),
        "suppress_if_user_logged_in": True,
        "force_reboot": force_reboot is True,
        "created_at": float(now),
        "expires_at": float(now) + max(POWER_JOB_TTL_SECONDS, delay + 60),
    }


def power_job_expired(payload: dict, now: float) -> bool:
    """Return True for expired *or malformed* disruptive job payloads."""
    try:
        expires_at = float(payload.get("expires_at"))
    except (AttributeError, TypeError, ValueError):
        return True
    return not (expires_at > float(now))


def validate_force_reboot(body: dict, action: str) -> int:
    """Require explicit JSON true; never override non-reboot actions."""
    force = body.get("force_reboot", False)
    if type(force) is not bool or (force and action != "reboot"):
        raise HTTPException(status_code=400, detail="Force reboot requires a boolean and a reboot action")
    return int(force)

if not ADMIN_PASSWORD or not ENROLL_KEY:
    raise SystemExit(
        "Refusing to start: set OUTPOST_ADMIN_PASSWORD and OUTPOST_ENROLL_KEY "
        "environment variables first (see README)."
    )

# Persistent secret for signing session cookies
_secret_file = DATA_DIR / "secret.key"
if not _secret_file.exists():
    _secret_file.write_bytes(secrets.token_bytes(32))
    try:
        os.chmod(_secret_file, 0o600)
    except OSError:
        pass
SECRET_KEY = _secret_file.read_bytes()

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS locations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL,
    name        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    UNIQUE(org_id, name)
);
CREATE TABLE IF NOT EXISTS agents (
    id              TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    machine_guid    TEXT DEFAULT '',
    os_version      TEXT DEFAULT '',
    ip              TEXT DEFAULT '',
    public_ip       TEXT DEFAULT '',
    local_ip        TEXT DEFAULT '',
    agent_version   TEXT DEFAULT '',
    token_hash      TEXT NOT NULL,
    reboot_required INTEGER DEFAULT 0,
    last_seen       REAL DEFAULT 0,
    org_id          INTEGER,
    location_id     INTEGER,
    created_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS updates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL,
    update_id   TEXT NOT NULL,
    kb          TEXT DEFAULT '',
    title       TEXT DEFAULT '',
    severity    TEXT DEFAULT '',
    size_mb     REAL DEFAULT 0,
    status      TEXT DEFAULT 'pending',      -- pending | approved | failed | denied
    denied_by   TEXT DEFAULT '',
    denied_at   REAL,
    detected_at REAL NOT NULL,
    UNIQUE(agent_id, update_id)
);
CREATE TABLE IF NOT EXISTS org_policies (
    org_id      INTEGER PRIMARY KEY,
    policy      TEXT NOT NULL,               -- JSON, same shape as global policy
    updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scripts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    content         TEXT NOT NULL,
    shell           TEXT NOT NULL DEFAULT 'powershell', -- powershell | cmd | bash
    timeout_sec     INTEGER DEFAULT 900,
    variables       TEXT DEFAULT '[]',            -- JSON list of variable definitions
    safety_class    TEXT DEFAULT 'unclassified', -- diagnostic | safe_remediation | disruptive | high_impact | unclassified
    ai_auto_allowed INTEGER DEFAULT 0,
    changes_system  INTEGER DEFAULT 1,
    reboot_impact   TEXT DEFAULT 'possible',      -- no | possible | yes
    updated_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS applications (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,
    description         TEXT DEFAULT '',
    operating_system    TEXT DEFAULT 'windows',
    architecture        TEXT DEFAULT 'all',
    installer_type      TEXT DEFAULT 'msi',
    run_as              TEXT DEFAULT 'system',
    parameters          TEXT DEFAULT '',
    categories          TEXT DEFAULT '[]',
    success_codes       TEXT DEFAULT '[0,3010]',
    timeout_sec         INTEGER DEFAULT 1800,
    reboot_behavior     TEXT DEFAULT 'never',
    detection_type      TEXT DEFAULT 'none',
    detection_value     TEXT DEFAULT '',
    pre_script_id       INTEGER,
    post_script_id      INTEGER,
    stop_on_pre_failure INTEGER DEFAULT 1,
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS application_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id  INTEGER NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'helper', -- installer | helper | icon
    original_name   TEXT NOT NULL,
    stored_name     TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    sha256          TEXT NOT NULL DEFAULT '',
    active          INTEGER DEFAULT 1,
    created_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_application_files_app ON application_files(application_id, kind, active);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    pw_hash       TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'tech',   -- admin | tech
    created_at    REAL NOT NULL,
    last_login    REAL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    filters     TEXT NOT NULL DEFAULT '{}',   -- JSON criteria, evaluated at run time
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    script_id        INTEGER NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'interval',   -- interval | daily
    interval_minutes INTEGER DEFAULT 60,
    daily_time       TEXT DEFAULT '03:00',               -- HH:MM, server local time
    target_type      TEXT NOT NULL DEFAULT 'all',        -- all | orgs | machines
    target_ids       TEXT DEFAULT '[]',                  -- JSON list of org ids or machine ids
    variables        TEXT DEFAULT '{}',                  -- JSON {calculatedName: value}
    enabled          INTEGER DEFAULT 1,
    last_run_at      REAL,
    next_run_at      REAL,
    created_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    type        TEXT NOT NULL,               -- run_script | install_updates
    label       TEXT DEFAULT '',
    payload     TEXT NOT NULL,               -- JSON
    status      TEXT DEFAULT 'pending',      -- pending | running | done | failed
    output      TEXT DEFAULT '',
    exit_code   INTEGER,
    schedule_id INTEGER,
    archived    INTEGER DEFAULT 0,
    created_at  REAL NOT NULL,
    started_at  REAL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS monitor_incidents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key        TEXT NOT NULL UNIQUE,
    agent_id          TEXT,
    org_id            INTEGER,
    incident_type     TEXT NOT NULL,
    severity          TEXT DEFAULT 'warning',
    status            TEXT DEFAULT 'open',
    message           TEXT DEFAULT '',
    value_text        TEXT DEFAULT '',
    threshold_text    TEXT DEFAULT '',
    first_seen        REAL NOT NULL,
    last_seen         REAL NOT NULL,
    resolved_at       REAL,
    consecutive_count INTEGER DEFAULT 1,
    last_alert_at     REAL,
    remediation_job_id TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_monitor_incidents_status ON monitor_incidents(status, last_seen);
CREATE TABLE IF NOT EXISTS ai_remediation_runs (
    job_id         TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    script_id      INTEGER NOT NULL,
    source_type    TEXT DEFAULT '',
    source_key     TEXT DEFAULT '',
    source_context TEXT DEFAULT '{}',
    created_at     REAL NOT NULL,
    assessed_at    REAL,
    assessment     TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_remediation_agent ON ai_remediation_runs(agent_id, created_at);
CREATE TABLE IF NOT EXISTS org_monitor_policies (
    org_id      INTEGER PRIMARY KEY,
    policy      TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS automation_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    enabled          INTEGER DEFAULT 1,
    trigger_type     TEXT NOT NULL,
    threshold        REAL DEFAULT 0,
    window_minutes   INTEGER DEFAULT 1,
    cooldown_minutes INTEGER DEFAULT 1440,
    script_id        INTEGER NOT NULL,
    target_type      TEXT NOT NULL DEFAULT 'all',
    target_ids       TEXT DEFAULT '[]',
    variables        TEXT DEFAULT '{}',
    last_run_at      REAL,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS automation_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL,
    agent_id    TEXT NOT NULL,
    job_id      TEXT NOT NULL,
    trigger_key TEXT DEFAULT '',
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS automation_rule_state (
    rule_id       INTEGER NOT NULL,
    agent_id      TEXT NOT NULL,
    first_true_at REAL NOT NULL,
    last_true_at  REAL NOT NULL,
    PRIMARY KEY(rule_id, agent_id)
);
CREATE TABLE IF NOT EXISTS automation_stacks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id           INTEGER NOT NULL,
    name             TEXT NOT NULL,
    description      TEXT DEFAULT '',
    version          INTEGER DEFAULT 1,
    failure_policy   TEXT DEFAULT 'continue', -- continue | stop
    retry_count      INTEGER DEFAULT 1,
    retry_delay_sec  INTEGER DEFAULT 60,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS automation_stack_steps (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    stack_id        INTEGER NOT NULL,
    position        INTEGER NOT NULL,
    action_type     TEXT NOT NULL, -- script | application
    action_id       INTEGER NOT NULL,
    variables       TEXT DEFAULT '{}',
    failure_policy  TEXT DEFAULT '',
    retry_count     INTEGER,
    created_at      REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stack_steps_position ON automation_stack_steps(stack_id, position);
CREATE TABLE IF NOT EXISTS org_onboarding_settings (
    org_id               INTEGER PRIMARY KEY,
    active_stack_id      INTEGER,
    enabled              INTEGER DEFAULT 0,
    enabled_at           REAL,
    target_workstations  INTEGER DEFAULT 1,
    target_servers       INTEGER DEFAULT 0,
    updated_at           REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS device_onboarding_state (
    agent_id        TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'pending',
    stack_id        INTEGER,
    stack_version   INTEGER,
    last_run_id     TEXT DEFAULT '',
    started_at      REAL,
    completed_at    REAL,
    updated_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS onboarding_runs (
    id             TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL,
    org_id         INTEGER,
    stack_id       INTEGER NOT NULL,
    stack_name     TEXT NOT NULL,
    stack_version  INTEGER NOT NULL,
    trigger_type   TEXT DEFAULT 'automatic', -- automatic | manual | retry
    status         TEXT DEFAULT 'pending',   -- pending | running | completed | completed_with_errors | failed | cancelled
    current_step   INTEGER DEFAULT 0,
    total_steps    INTEGER DEFAULT 0,
    retry_delay_sec INTEGER DEFAULT 60,
    created_at     REAL NOT NULL,
    started_at     REAL,
    finished_at    REAL
);
CREATE TABLE IF NOT EXISTS onboarding_run_steps (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    position        INTEGER NOT NULL,
    action_type     TEXT NOT NULL,
    action_id       INTEGER NOT NULL,
    action_name     TEXT NOT NULL,
    action_snapshot TEXT NOT NULL DEFAULT '{}',
    status          TEXT DEFAULT 'pending', -- pending | running | done | failed | skipped | cancelled
    job_id          TEXT DEFAULT '',
    attempt         INTEGER DEFAULT 0,
    retry_count     INTEGER DEFAULT 0,
    failure_policy  TEXT DEFAULT 'continue',
    last_error      TEXT DEFAULT '',
    next_attempt_at REAL DEFAULT 0,
    created_at      REAL NOT NULL,
    started_at      REAL,
    finished_at     REAL
);
CREATE INDEX IF NOT EXISTS idx_onboarding_runs_agent ON onboarding_runs(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_onboarding_steps_run ON onboarding_run_steps(run_id, position);
CREATE INDEX IF NOT EXISTS idx_onboarding_steps_job ON onboarding_run_steps(job_id);
CREATE INDEX IF NOT EXISTS idx_automation_runs_rule_agent ON automation_runs(rule_id, agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_updates_agent ON updates(agent_id);
CREATE INDEX IF NOT EXISTS idx_jobs_agent    ON jobs(agent_id, status);
"""


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


with db() as conn:
    conn.executescript(SCHEMA)
    # Migration for databases created before organizations/device identity existed
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(agents)")]
    if "org_id" not in cols:
        conn.execute("ALTER TABLE agents ADD COLUMN org_id INTEGER")
    if "machine_guid" not in cols:
        conn.execute("ALTER TABLE agents ADD COLUMN machine_guid TEXT DEFAULT ''")
    # Enrollment identity lookups are tenant-scoped. These indexes are deliberately
    # non-unique so an existing database containing legacy duplicates can still
    # start; enrollment detects ambiguity and refuses to overwrite either record.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_org_hostname_ci "
                 "ON agents(org_id, hostname COLLATE NOCASE)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_machine_guid_ci "
                 "ON agents(machine_guid COLLATE NOCASE)")
    # Migration for databases created before schedules existed
    jcols = [r["name"] for r in conn.execute("PRAGMA table_info(jobs)")]
    if "schedule_id" not in jcols:
        conn.execute("ALTER TABLE jobs ADD COLUMN schedule_id INTEGER")
    # Migration for databases created before hardware inventory existed
    for col, decl in [("serial", "TEXT DEFAULT ''"), ("model", "TEXT DEFAULT ''"),
                      ("cpu", "TEXT DEFAULT ''"), ("ram_gb", "REAL DEFAULT 0"),
                      ("memory_used_pct", "REAL"),
                      ("disks", "TEXT DEFAULT '[]'"), ("last_user", "TEXT DEFAULT ''"),
                      ("disk_health", "TEXT DEFAULT '[]'"), ("smart_failures", "INTEGER DEFAULT 0"),
                      ("bdgz_protected", "INTEGER"), ("disk_events", "TEXT DEFAULT '{}'")]:
        if col not in cols:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {decl}")
    # Migration for databases created before update deny existed
    ucols = [r["name"] for r in conn.execute("PRAGMA table_info(updates)")]
    if "denied_by" not in ucols:
        conn.execute("ALTER TABLE updates ADD COLUMN denied_by TEXT DEFAULT ''")
    # Migration for rich Windows Update inventory (server companion phase 1).
    # Capable agents send category/browse_only/revision per update; older
    # agents simply leave the defaults in place.
    for col, decl in [("category", "TEXT DEFAULT ''"),
                      ("browse_only", "INTEGER DEFAULT 0"),
                      ("revision", "INTEGER DEFAULT 0")]:
        if col not in ucols:
            conn.execute(f"ALTER TABLE updates ADD COLUMN {col} {decl}")
    # Windows Update worker run history. worker-report.json is last-run-wins on
    # the endpoint, so the server keeps each distinct run (deduped by the
    # report's checked_at) or transitions between check-ins become invisible.
    conn.executescript("""CREATE TABLE IF NOT EXISTS wu_runs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT NOT NULL,
        started_at  REAL DEFAULT 0,
        checked_at  REAL NOT NULL,
        phase       TEXT DEFAULT '',
        status      TEXT DEFAULT '',
        mode        TEXT DEFAULT '',
        lab_build   TEXT DEFAULT '',
        compliant   INTEGER DEFAULT 0,
        hidden_count INTEGER DEFAULT 0,
        visible_count INTEGER DEFAULT 0,
        counters    TEXT DEFAULT '{}',
        errors      TEXT DEFAULT '[]',
        warnings    TEXT DEFAULT '[]',
        created_at  REAL NOT NULL,
        UNIQUE(agent_id, checked_at)
    );""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wu_runs_agent_time "
                 "ON wu_runs(agent_id, checked_at DESC)")
    acols_wu = [r["name"] for r in conn.execute("PRAGMA table_info(agents)")]
    if "wu_capable" not in acols_wu:
        conn.execute("ALTER TABLE agents ADD COLUMN wu_capable INTEGER DEFAULT 0")
    if "denied_at" not in ucols:
        conn.execute("ALTER TABLE updates ADD COLUMN denied_at REAL")
    # Migration for databases created before public/local IP + locations existed
    for col, decl in [("public_ip", "TEXT DEFAULT ''"), ("local_ip", "TEXT DEFAULT ''"),
                      ("location_id", "INTEGER")]:
        if col not in cols:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {decl}")
    # Migration for databases created before script variables existed
    scols = [r["name"] for r in conn.execute("PRAGMA table_info(scripts)")]
    if "variables" not in scols:
        conn.execute("ALTER TABLE scripts ADD COLUMN variables TEXT DEFAULT '[]'")
    if "shell" not in scols:
        conn.execute("ALTER TABLE scripts ADD COLUMN shell TEXT NOT NULL DEFAULT 'powershell'")
        # One-time, conservative migration for unmistakable legacy scripts that
        # were saved before the Script Library exposed a language selector.
        conn.execute("UPDATE scripts SET shell='cmd' WHERE lower(ltrim(content)) LIKE '@echo off%'")
        conn.execute("UPDATE scripts SET shell='bash' WHERE ltrim(content) LIKE '#!/bin/bash%' OR ltrim(content) LIKE '#!/usr/bin/env bash%'")
    conn.execute("UPDATE scripts SET shell='powershell' WHERE shell IS NULL OR shell NOT IN ('powershell','cmd','bash')")
    # 1.29.5: additive script safety metadata used only by AI-assisted remediation.
    # Existing technician automations continue to behave exactly as before.
    scols = [r["name"] for r in conn.execute("PRAGMA table_info(scripts)")]
    for col, decl in [
        ("safety_class", "TEXT DEFAULT 'unclassified'"),
        ("ai_auto_allowed", "INTEGER DEFAULT 0"),
        ("changes_system", "INTEGER DEFAULT 1"),
        ("reboot_impact", "TEXT DEFAULT 'possible'"),
    ]:
        if col not in scols:
            conn.execute(f"ALTER TABLE scripts ADD COLUMN {col} {decl}")
    conn.execute("UPDATE scripts SET safety_class='unclassified' WHERE safety_class IS NULL OR safety_class='' ")
    conn.execute("UPDATE scripts SET reboot_impact='possible' WHERE reboot_impact IS NULL OR reboot_impact NOT IN ('no','possible','yes')")
    # 1.29.2: seed a curated MSP Windows workstation script pack once.
    # Existing scripts with the same names are never overwritten; a settings
    # marker prevents deleted built-ins from being recreated every restart.
    seed_msp_script_pack(conn)
    apply_msp_script_metadata(conn)
    # Existing same-name scripts are preserved, except exact Base64 transport
    # blobs shipped by 1.30.3, which are safely repaired by known content hashes.
    # Proprietary/tenant-specific script seed packs are not included in OpenPrimeRMM.
    sccols = [r["name"] for r in conn.execute("PRAGMA table_info(schedules)")]
    if "variables" not in sccols:
        conn.execute("ALTER TABLE schedules ADD COLUMN variables TEXT DEFAULT '{}'")
    if "action_type" not in sccols:
        conn.execute("ALTER TABLE schedules ADD COLUMN action_type TEXT DEFAULT 'script'")
    if "weekdays" not in sccols:
        conn.execute("ALTER TABLE schedules ADD COLUMN weekdays TEXT DEFAULT '[]'")
    if "force_reboot" not in sccols:
        conn.execute("ALTER TABLE schedules ADD COLUMN force_reboot INTEGER NOT NULL DEFAULT 0")
    arcols = [r["name"] for r in conn.execute("PRAGMA table_info(automation_rules)")]
    if "action_type" not in arcols:
        conn.execute("ALTER TABLE automation_rules ADD COLUMN action_type TEXT DEFAULT 'script'")
    if "force_reboot" not in arcols:
        conn.execute("ALTER TABLE automation_rules ADD COLUMN force_reboot INTEGER NOT NULL DEFAULT 0")
    # Migration for databases created before job archiving existed
    if "archived" not in jcols:
        conn.execute("ALTER TABLE jobs ADD COLUMN archived INTEGER DEFAULT 0")
    # Migrations: Bitdefender GravityZone integration
    ocols = [r["name"] for r in conn.execute("PRAGMA table_info(orgs)")]
    for col in ("bdgz_company_id", "bdgz_company_name"):
        if col not in ocols:
            conn.execute(f"ALTER TABLE orgs ADD COLUMN {col} TEXT DEFAULT ''")
    conn.executescript("""CREATE TABLE IF NOT EXISTS av_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, received_at REAL NOT NULL,
        module TEXT DEFAULT '', computer_name TEXT DEFAULT '', computer_ip TEXT DEFAULT '',
        threat TEXT DEFAULT '', file_path TEXT DEFAULT '', action TEXT DEFAULT '',
        agent_id TEXT, org_id INTEGER, raw TEXT DEFAULT '',
        archived INTEGER DEFAULT 0, archived_at REAL, archived_by TEXT DEFAULT '')""")
    evcols = [r["name"] for r in conn.execute("PRAGMA table_info(av_events)")]
    for col, decl in [("archived", "INTEGER DEFAULT 0"),
                      ("archived_at", "REAL"),
                      ("archived_by", "TEXT DEFAULT ''")]:
        if col not in evcols:
            conn.execute(f"ALTER TABLE av_events ADD COLUMN {col} {decl}")
    ucols = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
    for col, decl in [("totp_secret", "TEXT DEFAULT ''"), ("totp_enabled", "INTEGER DEFAULT 0")]:
        if col not in ucols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")
    acols = [r["name"] for r in conn.execute("PRAGMA table_info(agents)")]
    for col, decl in [("device_class", "TEXT DEFAULT ''"),
                      ("ext_inventory", "TEXT DEFAULT '{}'"),
                      ("software", "TEXT DEFAULT '[]'"), ("rd_id", "TEXT DEFAULT ''"),
                      ("macs", "TEXT DEFAULT '[]'")]:
        if col not in acols:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {decl}")
    conn.executescript("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        username TEXT DEFAULT '', ip TEXT DEFAULT '', action TEXT DEFAULT '',
        target TEXT DEFAULT '', detail TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS service_monitors (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL,
        service_name TEXT NOT NULL, auto_restart INTEGER DEFAULT 1,
        last_state TEXT DEFAULT '', created_at REAL NOT NULL)""")
    conn.executescript("""CREATE TABLE IF NOT EXISTS support_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        agent_id TEXT, hostname TEXT DEFAULT '', org_id INTEGER,
        first_name TEXT DEFAULT '', last_name TEXT DEFAULT '',
        email TEXT DEFAULT '', phone TEXT DEFAULT '',
        subject TEXT DEFAULT '', body TEXT DEFAULT '',
        username TEXT DEFAULT '', status TEXT DEFAULT 'new')""")
    srcols = [r["name"] for r in conn.execute("PRAGMA table_info(support_requests)")]
    for col, decl in [("attach_name", "TEXT DEFAULT ''"), ("attach_mime", "TEXT DEFAULT ''")]:
        if col not in srcols:
            conn.execute(f"ALTER TABLE support_requests ADD COLUMN {col} {decl}")
    # Migration: persistent long-poll ("live mode") gating. Per-machine override
    # (NULL = follow org/global default) and per-org default. -1/NULL semantics:
    #   agents.live_mode: NULL=inherit, 0=force off, 1=force on
    #   orgs.live_mode_default: 0=off (default), 1=on
    acols = [r["name"] for r in conn.execute("PRAGMA table_info(agents)")]
    if "live_mode" not in acols:
        conn.execute("ALTER TABLE agents ADD COLUMN live_mode INTEGER")   # NULL = inherit
    ocols2 = [r["name"] for r in conn.execute("PRAGMA table_info(orgs)")]
    if "live_mode_default" not in ocols2:
        conn.execute("ALTER TABLE orgs ADD COLUMN live_mode_default INTEGER DEFAULT 0")
    # 1.13.0 migrations: recovery, monitoring, patching, automation
    acols = [r["name"] for r in conn.execute("PRAGMA table_info(agents)")]
    for col, decl in [
        ("reboot_since", "REAL"),
        ("last_update_scan", "REAL"),
        ("screenconnect_session_id", "TEXT DEFAULT ''"),
        ("screenconnect_service_name", "TEXT DEFAULT ''"),
        ("wu_management", "TEXT DEFAULT '{}'"),
    ]:
        if col not in acols:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {decl}")
    ucols = [r["name"] for r in conn.execute("PRAGMA table_info(updates)")]
    if "status_changed_at" not in ucols:
        conn.execute("ALTER TABLE updates ADD COLUMN status_changed_at REAL")
        conn.execute("UPDATE updates SET status_changed_at=COALESCE(detected_at, ?)", (time.time(),))


def get_latest_agent_version() -> str:
    """The agent.ps1 file we serve is the source of truth for the agent version."""
    try:
        text = (BASE_DIR.parent / "agent" / "agent.ps1").read_text(errors="ignore")
        import re as _re
        m = _re.search(r"\$AgentVersion\s*=\s*'([^']+)'", text)
        return m.group(1) if m else ""
    except OSError:
        return ""


LATEST_AGENT_VERSION = get_latest_agent_version()

# Platform version shown in the dashboard. Kept in lockstep with the agent
# version ($AgentVersion in agent.ps1) — one number for the whole release.
SERVER_VERSION = PLATFORM_VERSION


DEFAULT_SCREENCONNECT_SETTINGS = {
    "enabled": False,
    "base_url": "",
    "session_group": "All Machines",
    "join_mode": "Join",
}


def get_screenconnect_settings(conn: sqlite3.Connection) -> dict:
    cfg = dict(DEFAULT_SCREENCONNECT_SETTINGS)
    row = conn.execute("SELECT value FROM settings WHERE key='screenconnect'").fetchone()
    if row:
        try:
            cfg.update(json.loads(row["value"]))
        except (ValueError, TypeError):
            pass
    cfg["base_url"] = str(cfg.get("base_url") or "").strip().rstrip("/")
    cfg["session_group"] = str(cfg.get("session_group") or "All Machines").strip()
    cfg["join_mode"] = "JoinWithOptions" if str(cfg.get("join_mode")) == "JoinWithOptions" else "Join"
    cfg["enabled"] = bool(cfg.get("enabled") and cfg["base_url"])
    return cfg


def sanitize_screenconnect_settings(body: dict) -> dict:
    base_url = str(body.get("base_url") or "").strip().rstrip("/")
    if base_url and not base_url.lower().startswith(("https://", "http://")):
        raise HTTPException(status_code=400, detail="ScreenConnect URL must begin with https:// or http://")
    return {
        "enabled": bool(body.get("enabled") and base_url),
        "base_url": base_url[:512],
        "session_group": str(body.get("session_group") or "All Machines").strip()[:128],
        "join_mode": "JoinWithOptions" if str(body.get("join_mode")) == "JoinWithOptions" else "Join",
    }


def screenconnect_url(cfg: dict, session_id: str, join_mode: str | None = None) -> str:
    sid = str(session_id or "").strip()
    try:
        uuid.UUID(sid)
    except (ValueError, AttributeError):
        return ""
    if not cfg.get("enabled") or not cfg.get("base_url"):
        return ""
    group = urllib.parse.quote(str(cfg.get("session_group") or ""), safe="")
    action = "JoinWithOptions" if (join_mode or cfg.get("join_mode")) == "JoinWithOptions" else "Join"
    if group:
        return f"{cfg['base_url']}/Host#Access/{group}//{urllib.parse.quote(sid)}/{action}"
    return f"{cfg['base_url']}/Host#Access///{urllib.parse.quote(sid)}/{action}"


def apply_screenconnect_links(machine: dict, cfg: dict) -> None:
    sid = machine.get("screenconnect_session_id") or ""
    machine["screenconnect_enabled"] = bool(cfg.get("enabled"))
    machine["screenconnect_join_url"] = screenconnect_url(cfg, sid, "Join")
    machine["screenconnect_options_url"] = screenconnect_url(cfg, sid, "JoinWithOptions")
    machine["screenconnect_default_url"] = screenconnect_url(cfg, sid, cfg.get("join_mode"))


DEFAULT_POLICY = {
    "enabled": False,
    "defender": True,          # approve Defender definition updates immediately
    "severities": ["Critical"],
    "delay_days": 3,           # wait this long after first detection before approving
    "include_preview": False,  # whether to auto-approve Preview/Optional updates
    "excluded_kbs": [],        # KBs/update IDs that must never auto-approve
    "maintenance_enabled": False,
    "maintenance_days": [0, 1, 2, 3, 4, 5, 6],  # Monday=0
    "maintenance_start": "00:00",
    "maintenance_end": "23:59",
    "auto_retry_failed": False,
    "retry_failed_after_hours": 24,
    "backup_stale_days": 3,
    "reboot_after_install": False,
    "reboot_delay_minutes": 15,
    # Per-category stance. auto = eligible for the severity/delay auto-approval
    # rules above; manual = shows as pending and requires a human approval;
    # report = report only, never queued by policy (manual approval still works
    # for a deliberate technician action). Standard/security updates are always
    # governed by the severity rules and have no stance knob on purpose.
    "category_stances": {
        "driver": "report",
        "firmware": "report",
        "feature": "manual",
        "optional": "manual",
    },
    # Endpoint enforcement is opt-in. When enabled OpenPrimeRMM owns the user-facing
    # Windows Update controls, leaves the Windows Update service running, sets
    # Automatic Updates to notify-only, and hides denied updates through WUA.
    "manage_windows_update": False,
    "block_user_update_access": True,
    "block_pause_updates": True,
    "hide_denied_updates": True,
}


def get_policy(conn: sqlite3.Connection) -> dict:
    """Global (default) policy."""
    row = conn.execute("SELECT value FROM settings WHERE key='policy'").fetchone()
    if not row:
        return dict(DEFAULT_POLICY)
    try:
        pol = dict(DEFAULT_POLICY)
        pol.update(json.loads(row["value"]))
        return pol
    except (ValueError, TypeError):
        return dict(DEFAULT_POLICY)


def get_org_policy(conn: sqlite3.Connection, org_id) -> dict | None:
    """Per-org policy override, or None if the org uses the global policy."""
    if org_id is None:
        return None
    row = conn.execute(
        "SELECT policy FROM org_policies WHERE org_id=?", (org_id,)
    ).fetchone()
    if not row:
        return None
    try:
        pol = dict(DEFAULT_POLICY)
        pol.update(json.loads(row["policy"]))
        return pol
    except (ValueError, TypeError):
        return None


def effective_policy(conn: sqlite3.Connection, org_id) -> dict:
    """The policy that actually applies to a machine: its org's override if set,
    otherwise the global policy."""
    return get_org_policy(conn, org_id) or get_policy(conn)


DEFENDER_MARKERS = ("security intelligence update", "defender antivirus")


def _parse_hhmm(value: str, default=(0, 0)) -> tuple[int, int]:
    try:
        hh, mm = (int(x) for x in str(value).split(":")[:2])
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            return hh, mm
    except (TypeError, ValueError):
        pass
    return default


def policy_in_maintenance_window(pol: dict, when: float | None = None) -> bool:
    if not pol.get("maintenance_enabled"):
        return True
    dt = datetime.datetime.fromtimestamp(when or time.time())
    days = {int(x) for x in (pol.get("maintenance_days") or []) if str(x).isdigit()}
    if days and dt.weekday() not in days:
        # An overnight window belongs to the day on which it started.
        sh, sm = _parse_hhmm(pol.get("maintenance_start"), (0, 0))
        eh, em = _parse_hhmm(pol.get("maintenance_end"), (23, 59))
        if (sh, sm) > (eh, em):
            prev_day = (dt.weekday() - 1) % 7
            if prev_day in days and (dt.hour, dt.minute) <= (eh, em):
                return True
        return False
    sh, sm = _parse_hhmm(pol.get("maintenance_start"), (0, 0))
    eh, em = _parse_hhmm(pol.get("maintenance_end"), (23, 59))
    now_min = dt.hour * 60 + dt.minute
    start_min = sh * 60 + sm
    end_min = eh * 60 + em
    if start_min <= end_min:
        return start_min <= now_min <= end_min
    return now_min >= start_min or now_min <= end_min


def update_is_excluded(pol: dict, update_row) -> bool:
    excluded = {str(x).strip().upper() for x in (pol.get("excluded_kbs") or []) if str(x).strip()}
    if not excluded:
        return False
    kb = str(update_row["kb"] or "").strip().upper()
    uid = str(update_row["update_id"] or "").strip().upper()
    title = str(update_row["title"] or "").upper()
    return kb in excluded or uid in excluded or any(x and x in title for x in excluded)


def run_auto_approve():
    """Policy engine for automatic patch approval and controlled retry.

    The engine never changes the endpoint architecture. It only creates the same
    install_updates jobs technicians create manually, and honors customer policy,
    exclusions, maintenance windows, approval delay, and failed-update retry.
    """
    now = time.time()
    wake_after_commit = set()
    with db() as conn:
        global_pol = get_policy(conn)
        org_pol_cache: dict = {}

        def policy_for(org_id):
            if org_id not in org_pol_cache:
                org_pol_cache[org_id] = get_org_policy(conn, org_id) or global_pol
            return org_pol_cache[org_id]

        rows = conn.execute(
            """SELECT u.*, a.org_id AS agent_org FROM updates u
               JOIN agents a ON a.id = u.agent_id
               WHERE u.status IN ('pending','failed')"""
        ).fetchall()

        by_agent: dict[str, list] = {}
        for u in rows:
            pol = policy_for(u["agent_org"])
            if not pol.get("enabled") or not policy_in_maintenance_window(pol, now):
                continue
            if update_is_excluded(pol, u):
                continue
            # Per-category stance: only 'auto' categories are eligible for
            # policy-driven approval. Manual/report categories always wait
            # for a technician. Legacy rows without categories behave as
            # standard updates, exactly as before 1.17.0.
            if policy_category_stance(pol, u) != "auto":
                continue
            if u["status"] == "failed":
                if not pol.get("auto_retry_failed"):
                    continue
                changed = float(u["status_changed_at"] or u["detected_at"] or now)
                retry_after = max(1, int(pol.get("retry_failed_after_hours") or 24)) * 3600
                if now - changed < retry_after:
                    continue
            cutoff = now - max(0, int(pol.get("delay_days") or 0)) * 86400
            severities = {str(s).lower() for s in pol.get("severities", [])}
            title = (u["title"] or "").lower()
            is_defender = pol.get("defender") and any(m in title for m in DEFENDER_MARKERS)
            is_severity = (u["severity"] or "").lower() in severities and u["detected_at"] <= cutoff
            if is_defender or is_severity:
                by_agent.setdefault(u["agent_id"], []).append(u["update_id"])

        for agent_id, ids in by_agent.items():
            result = _approve_and_queue_updates(
                conn, agent_id, ids, now, label_prefix="Policy install"
            )
            if result["approved"]:
                wake_after_commit.add(agent_id)
    for agent_id in wake_after_commit:
        _wake_agent(agent_id)


def _sched_weekdays(row) -> list:
    try:
        if "weekdays" in row.keys():
            return json.loads(row["weekdays"] or "[]")
    except (ValueError, TypeError, AttributeError):
        pass
    return []


def compute_next_run(mode: str, interval_minutes, daily_time: str, from_ts: float | None = None,
                     weekdays: list | None = None):
    """Next run timestamp. 'daily' uses the server's local clock.
    'once' returns None after it has fired (handled by the caller).
    weekdays (optional): list of ints 0=Mon..6=Sun — daily runs only on those
    days, so "reboot workstations Tue+Thu at 02:00" is expressible."""
    now = from_ts if from_ts is not None else time.time()
    if mode == "once":
        # A one-time schedule runs on the next scheduler tick, then disables itself.
        return now
    if mode == "daily":
        try:
            hh, mm = (int(x) for x in str(daily_time).split(":")[:2])
        except (ValueError, TypeError):
            hh, mm = 3, 0
        days = sorted({int(d) for d in (weekdays or []) if 0 <= int(d) <= 6})
        dt = datetime.datetime.fromtimestamp(now)
        run = dt.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if run.timestamp() <= now:
            run += datetime.timedelta(days=1)
        if days:
            for _ in range(8):
                if run.weekday() in days:
                    break
                run += datetime.timedelta(days=1)
        return run.timestamp()
    return now + max(5, int(interval_minutes or 60)) * 60


def resolve_group_filters(conn: sqlite3.Connection, filters: dict) -> list[str]:
    """Evaluate a dynamic group's criteria NOW and return matching agent ids.

    Criteria (all optional, ANDed):
      device_class        'workstation' | 'server' (manual override wins)
      os_family           windows_11 | windows_10 | windows_server | linux | macos | other
      protection_status   protected | missing | unknown
      memory_status       high | normal | unknown
      status              'online' | 'offline'
      reboot_required     True
      has_pending_updates True
      missing_av          True (Bitdefender not confirmed protected)
      has_open_incidents  True
      org_ids             [int, ...]
      hostname_contains   substring (case-insensitive)
      os_contains         substring of os_version
      domain_contains     substring of the reported AD domain
      software_contains   substring of any installed program's name
      free_gb_below       number — any fixed disk with less free space than this
    Evaluated fresh at run/preview time — never a stored device list."""
    now = time.time()
    rows = conn.execute(
        """SELECT a.id, a.org_id, a.last_seen, a.reboot_required, a.os_version,
                  a.hostname, a.device_class, a.bdgz_protected, a.disks,
                  a.software, a.ext_inventory, a.memory_used_pct,
                  (SELECT COUNT(*) FROM updates u
                   WHERE u.agent_id=a.id AND u.status IN ('pending','failed')) AS pending_cnt,
                  (SELECT COUNT(*) FROM monitor_incidents i
                   WHERE i.agent_id=a.id AND i.status='open') AS open_inc,
                  (SELECT COUNT(*) FROM monitor_incidents i
                   WHERE i.agent_id=a.id AND i.status='open'
                     AND i.incident_type='high_memory') AS high_memory_inc
           FROM agents a"""
    ).fetchall()
    org_ids = {int(x) for x in (filters.get("org_ids") or []) if str(x).isdigit()}
    want_class = str(filters.get("device_class") or "").strip().lower()
    want_os_family = str(filters.get("os_family") or "").strip().lower()
    protection_status = str(filters.get("protection_status") or "").strip().lower()
    memory_status = str(filters.get("memory_status") or "").strip().lower()
    status = str(filters.get("status") or "").strip().lower()
    host_q = str(filters.get("hostname_contains") or "").strip().lower()
    os_q = str(filters.get("os_contains") or "").strip().lower()
    dom_q = str(filters.get("domain_contains") or "").strip().lower()
    sw_q = str(filters.get("software_contains") or "").strip().lower()
    try:
        free_below = float(filters.get("free_gb_below")) if filters.get("free_gb_below") not in (None, "", 0) else None
    except (TypeError, ValueError):
        free_below = None
    out = []
    for r in rows:
        memory_fresh = bool(r["last_seen"] and now - float(r["last_seen"]) <= 300)
        if want_class in ("server", "workstation") and device_class_of(r) != want_class:
            continue
        if want_os_family and os_family_of(r["os_version"]) != want_os_family:
            continue
        if protection_status == "protected" and r["bdgz_protected"] != 1:
            continue
        if protection_status == "missing" and r["bdgz_protected"] != 0:
            continue
        if protection_status == "unknown" and r["bdgz_protected"] is not None:
            continue
        if memory_status == "high" and (not memory_fresh or not (r["high_memory_inc"] or 0)):
            continue
        if memory_status == "normal" and (not memory_fresh or r["memory_used_pct"] is None or (r["high_memory_inc"] or 0)):
            continue
        if memory_status == "unknown" and memory_fresh and r["memory_used_pct"] is not None:
            continue
        is_online = (now - float(r["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS
        if filters.get("online") and not is_online:
            continue
        if status == "online" and not is_online:
            continue
        if status == "offline" and is_online:
            continue
        if filters.get("reboot_required") and not r["reboot_required"]:
            continue
        if org_ids and (r["org_id"] not in org_ids):
            continue
        if filters.get("missing_av") and r["bdgz_protected"] == 1:
            continue
        if filters.get("has_pending_updates") and not (r["pending_cnt"] or 0):
            continue
        if filters.get("has_open_incidents") and not (r["open_inc"] or 0):
            continue
        if host_q and host_q not in (r["hostname"] or "").lower():
            continue
        if os_q and os_q not in (r["os_version"] or "").lower():
            continue
        if dom_q:
            try:
                dom = str(json.loads(r["ext_inventory"] or "{}").get("domain") or "")
            except (ValueError, TypeError):
                dom = ""
            if dom_q not in dom.lower():
                continue
        if sw_q:
            try:
                sw = json.loads(r["software"] or "[]")
            except (ValueError, TypeError):
                sw = []
            if not any(sw_q in str(s.get("name") or "").lower() for s in sw if isinstance(s, dict)):
                continue
        if free_below is not None:
            try:
                disks = json.loads(r["disks"] or "[]")
            except (ValueError, TypeError):
                disks = []
            hit = any(isinstance(d, dict) and float(d.get("free_gb") or 1e9) < free_below for d in disks)
            if not hit:
                continue
        out.append(r["id"])
    return out


def sanitize_group_filters(body: dict) -> dict:
    f = {}
    dc = str(body.get("device_class") or "").strip().lower()
    if dc in ("server", "workstation"):
        f["device_class"] = dc
    os_family = str(body.get("os_family") or "").strip().lower()
    if os_family in ("windows_11", "windows_10", "windows_server", "linux", "macos", "other"):
        f["os_family"] = os_family
    protection_status = str(body.get("protection_status") or "").strip().lower()
    if protection_status in ("protected", "missing", "unknown"):
        f["protection_status"] = protection_status
    memory_status = str(body.get("memory_status") or "").strip().lower()
    if memory_status in ("high", "normal", "unknown"):
        f["memory_status"] = memory_status
    st = str(body.get("status") or "").strip().lower()
    if st in ("online", "offline"):
        f["status"] = st
    if body.get("online"):        # back-compat with 1.27.0 groups
        f["status"] = "online"
    for flag in ("reboot_required", "missing_av", "has_pending_updates", "has_open_incidents"):
        if body.get(flag):
            f[flag] = True
    for txt in ("hostname_contains", "os_contains", "domain_contains", "software_contains"):
        v = str(body.get(txt) or "").strip()[:120]
        if v:
            f[txt] = v
    try:
        fb = float(body.get("free_gb_below"))
        if 0 < fb <= 10000:
            f["free_gb_below"] = fb
    except (TypeError, ValueError):
        pass
    orgs = [int(x) for x in (body.get("org_ids") or []) if str(x).isdigit()]
    if orgs:
        f["org_ids"] = orgs[:100]
    return f


def resolve_targets(conn: sqlite3.Connection, target_type: str, target_ids: list) -> list[str]:
    """Expand a schedule target into concrete agent ids."""
    if target_type == "group":
        # Dynamic group: re-evaluated on every run, so the machine list is
        # always current (this is the point of groups).
        gid = int(target_ids[0]) if target_ids else 0
        row = conn.execute("SELECT filters FROM device_groups WHERE id=?", (gid,)).fetchone()
        if not row:
            return []
        try:
            filters = json.loads(row["filters"] or "{}")
        except (ValueError, TypeError):
            filters = {}
        return resolve_group_filters(conn, filters)
    if target_type == "all":
        return [r["id"] for r in conn.execute("SELECT id FROM agents")]
    if target_type == "orgs":
        ids = [int(x) for x in target_ids]
        if not ids:
            return []
        qmarks = ",".join("?" for _ in ids)
        return [r["id"] for r in conn.execute(
            f"SELECT id FROM agents WHERE org_id IN ({qmarks})", ids)]
    # machines
    out = []
    for mid in target_ids:
        if conn.execute("SELECT 1 FROM agents WHERE id=?", (str(mid),)).fetchone():
            out.append(str(mid))
    return out


def get_or_create_org(conn: sqlite3.Connection, name: str) -> int | None:
    name = (name or "").strip()[:128]
    if not name:
        return None
    row = conn.execute(
        "SELECT id FROM orgs WHERE name=? COLLATE NOCASE", (name,)
    ).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO orgs (name, created_at) VALUES (?,?)", (name, time.time())
    )
    return cur.lastrowid

# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------


def _sign(data: bytes) -> str:
    return hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2$200000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def bootstrap_admin():
    """Ensure at least one admin exists. On first run, create 'admin' from the
    env password so there's always a way in; after that the DB is authoritative."""
    with db() as conn:
        has_admin = conn.execute(
            "SELECT 1 FROM users WHERE role='admin' LIMIT 1"
        ).fetchone()
        if not has_admin:
            conn.execute(
                "INSERT INTO users (username, pw_hash, role, created_at)"
                " VALUES ('admin', ?, 'admin', ?) "
                " ON CONFLICT(username) DO NOTHING",
                (hash_password(ADMIN_PASSWORD), time.time()),
            )


bootstrap_admin()


def audit(request, action: str, target: str = "", detail: str = "", user=None):
    """Record an admin action. Best-effort; never breaks the request."""
    try:
        if user is None:
            try:
                user = current_user(request)
            except Exception:
                user = {}
        with db() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, username, ip, action, target, detail)"
                " VALUES (?,?,?,?,?,?)",
                (time.time(), user.get("u", "?"), client_ip(request),
                 action, str(target)[:200], str(detail)[:500]))
            conn.execute("""DELETE FROM audit_log WHERE id NOT IN
                            (SELECT id FROM audit_log ORDER BY id DESC LIMIT 20000)""")
    except Exception:
        pass


# --- TOTP (RFC 6238), dependency-free ---
def _totp_now(secret: str, when: float = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int((when if when is not None else time.time()) // step)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = ((h[off] & 0x7F) << 24 | h[off + 1] << 16 | h[off + 2] << 8 | h[off + 3]) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return False
    now = time.time()
    # accept the current and adjacent windows for clock drift
    return any(hmac.compare_digest(_totp_now(secret, now + off * 30), code)
               for off in (-1, 0, 1))


def make_session_cookie(user_id: int, username: str, role: str) -> str:
    payload = json.dumps({
        "exp": time.time() + SESSION_HOURS * 3600,
        "uid": user_id, "u": username, "r": role,
    }).encode()
    b64 = base64.urlsafe_b64encode(payload).decode()
    return f"{b64}.{_sign(payload)}"


LOGIN_CHALLENGE_SECONDS = 5 * 60


def make_login_challenge(user_id: int, username: str, role: str, ip: str) -> str:
    """Create a short-lived signed credential-stage token for the 2FA step.

    The challenge is stored only in an HttpOnly cookie, expires after five
    minutes, and is bound to the source IP that completed the password step.
    It is not a dashboard session and cannot authorize any other API route.
    """
    payload = json.dumps({
        "purpose": "dashboard-2fa",
        "exp": time.time() + LOGIN_CHALLENGE_SECONDS,
        "uid": user_id, "u": username, "r": role,
        "ip": hashlib.sha256((ip or "").encode()).hexdigest(),
        "nonce": secrets.token_hex(12),
    }).encode()
    b64 = base64.urlsafe_b64encode(payload).decode()
    return f"{b64}.{_sign(payload)}"


def login_challenge_data(cookie: str | None, ip: str) -> dict | None:
    if not cookie or "." not in cookie:
        return None
    b64, sig = cookie.rsplit(".", 1)
    try:
        payload = base64.urlsafe_b64decode(b64.encode())
    except Exception:
        return None
    if not hmac.compare_digest(_sign(payload), sig):
        return None
    try:
        data = json.loads(payload)
        if data.get("purpose") != "dashboard-2fa" or data.get("exp", 0) <= time.time():
            return None
        ip_hash = hashlib.sha256((ip or "").encode()).hexdigest()
        if not hmac.compare_digest(str(data.get("ip", "")), ip_hash):
            return None
        if not data.get("uid") or not data.get("u"):
            return None
        return data
    except Exception:
        return None


def session_data(cookie: str | None) -> dict | None:
    if not cookie or "." not in cookie:
        return None
    b64, sig = cookie.rsplit(".", 1)
    try:
        payload = base64.urlsafe_b64decode(b64.encode())
    except Exception:
        return None
    if not hmac.compare_digest(_sign(payload), sig):
        return None
    try:
        data = json.loads(payload)
        if data["exp"] <= time.time():
            return None
        # Cookies minted before the user system have no uid/role — force re-login
        if "uid" not in data or "r" not in data:
            return None
        return data
    except Exception:
        return None


def session_valid(cookie: str | None) -> bool:
    return session_data(cookie) is not None


def current_user(request: Request) -> dict:
    data = session_data(request.cookies.get("outpost_session"))
    if not data:
        raise HTTPException(status_code=401, detail="Not signed in")
    return data


def require_admin(request: Request) -> dict:
    """Any signed-in user may use most endpoints; some require the admin role."""
    return current_user(request)


def require_admin_role(request: Request) -> dict:
    data = current_user(request)
    if data.get("r") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return data


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ----- TOTP two-factor auth (RFC 6238), pure stdlib, no dependencies -----
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def totp_new_secret() -> str:
    return "".join(secrets.choice(_B32) for _ in range(32))


def _b32decode(s: str) -> bytes:
    s = s.strip().replace(" ", "").upper()
    bits = ""
    for c in s:
        if c in _B32:
            bits += bin(_B32.index(c))[2:].zfill(5)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out)


def totp_now(secret: str, when=None) -> str:
    key = _b32decode(secret)
    counter = int((when or time.time()) // 30)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = ((h[off] & 0x7F) << 24 | h[off + 1] << 16 | h[off + 2] << 8 | h[off + 3]) % 1_000_000
    return str(code).zfill(6)


def totp_verify(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if len(code) != 6 or not secret:
        return False
    now = time.time()
    return any(hmac.compare_digest(totp_now(secret, now + d * 30), code) for d in (-1, 0, 1))


def totp_uri(secret: str, username: str) -> str:
    label = urllib.parse.quote(f"OpenPrime-RMM:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer=OpenPrime-RMM"


def require_agent(request: Request) -> sqlite3.Row:
    agent_id = request.headers.get("X-Agent-Id", "")
    token = request.headers.get("X-Agent-Token", "")
    if not agent_id or not token:
        raise HTTPException(status_code=401, detail="Missing agent credentials")
    with db() as conn:
        row = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not row or not hmac.compare_digest(row["token_hash"], hash_token(token)):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")
    return row


def client_ip(request: Request) -> str:
    """Best-effort real client (device WAN) IP behind proxy chains.

    Preference order: X-Real-IP (set it on the outermost proxy), then
    X-Forwarded-For. If OUTPOST_TRUSTED_PROXIES (comma-separated IPs) is
    set, walk the XFF chain right-to-left and return the first hop that is
    not a trusted proxy; otherwise use the leftmost entry. Falls back to
    the TCP peer. NOTE: the outermost proxy must overwrite/strip
    client-supplied X-Real-IP for this to be trustworthy."""
    real = request.headers.get("X-Real-IP", "").strip()
    if real:
        return real[:64]
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        hops = [h.strip() for h in fwd.split(",") if h.strip()]
        trusted = {p.strip() for p in os.environ.get("OUTPOST_TRUSTED_PROXIES", "").split(",") if p.strip()}
        if hops:
            if trusted:
                for hop in reversed(hops):
                    if hop not in trusted:
                        return hop[:64]
            return hops[0][:64]
    return (request.client.host if request.client else "")[:64]


# Very small in-memory brake on login brute force
_login_fail: dict[str, list[float]] = {}


def login_throttled(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _login_fail.get(ip, []) if now - t < 600]
    _login_fail[ip] = hits
    return len(hits) >= 8


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

app = FastAPI(title="OpenPrime-RMM RMM", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def disable_api_caching(request: Request, call_next):
    """Dashboard API responses are operational state and must never be stale.

    In particular, patch approve/deny actions are followed immediately by GETs
    for the pending list and machine details.  Explicit no-store headers prevent
    a browser, reverse proxy, or intermediary from showing the pre-action state.
    """
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "dashboard.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico():
    return FileResponse(BASE_DIR / "favicon.ico", media_type="image/x-icon")


@app.get("/favicon.svg", include_in_schema=False)
def favicon_svg():
    return FileResponse(BASE_DIR / "favicon.svg", media_type="image/svg+xml")


@app.get("/downloads/agent.ps1")
def download_agent():
    return FileResponse(BASE_DIR.parent / "agent" / "agent.ps1", media_type="text/plain")


@app.get("/downloads/tray.ps1")
def download_tray():
    path = BASE_DIR.parent / "agent" / "tray.ps1"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="tray.ps1 is missing on the server — copy the whole agent "
                                   "folder: sudo cp -r outpost/agent/* /opt/open-prime-rmm/agent/")
    return FileResponse(path, media_type="text/plain")


@app.get("/downloads/tray.ico")
def download_tray_icon():
    path = BASE_DIR.parent / "agent" / "tray.ico"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No icon")
    return FileResponse(path, media_type="image/x-icon")


def get_latest_tray_version() -> str:
    try:
        txt = (BASE_DIR.parent / "agent" / "tray.ps1").read_text(encoding="utf-8", errors="replace")
        for line in txt.splitlines():
            if line.startswith("$TrayVersion"):
                return line.split("'")[1]
    except Exception:
        pass
    return ""


LATEST_TRAY_VERSION = get_latest_tray_version()
try:
    _TRAY_MTIME = (BASE_DIR.parent / "agent" / "tray.ps1").stat().st_mtime
except OSError:
    _TRAY_MTIME = 0.0


def current_tray_version() -> str:
    """Re-read tray.ps1 on demand so dropping a new one onto the server starts
    advertising it without a service restart. Re-reads only when the file's
    modification time changes, so it's cheap on every check-in."""
    global LATEST_TRAY_VERSION, _TRAY_MTIME
    try:
        p = BASE_DIR.parent / "agent" / "tray.ps1"
        mtime = p.stat().st_mtime
        if mtime != _TRAY_MTIME:
            LATEST_TRAY_VERSION = get_latest_tray_version()
            _TRAY_MTIME = mtime
    except OSError:
        pass
    return LATEST_TRAY_VERSION


@app.get("/downloads/Install-Agent.ps1")
def download_installer():
    return FileResponse(BASE_DIR.parent / "agent" / "Install-Agent.ps1", media_type="text/plain")


@app.get("/downloads/Install-Agent.cmd")
def download_cmd_installer():
    path = BASE_DIR.parent / "agent" / "Install-Agent.cmd"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Install-Agent.cmd is missing on the server")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename="Install-Agent.cmd",
        headers={"Cache-Control": "no-store"},
    )


RECOVERY_DIR = BASE_DIR.parent / "agent" / "recovery"
RECOVERY_DOWNLOADS = {
    "OpenPrimeRMM-Recover-Stable-Agent.cmd": ("application/octet-stream", "Stable agent recovery"),
    "OpenPrimeRMM-Repair-Agent-Task.cmd": ("application/octet-stream", "Scheduled task repair"),
    "OpenPrimeRMM-Collect-Diagnostics.cmd": ("application/octet-stream", "Endpoint diagnostics collector"),
    "RECOVERY_GUIDE.md": ("text/markdown", "Recovery guide"),
    "SHA256SUMS.txt": ("text/plain", "Recovery-tool checksums"),
    "agent-stable-1.12.6.ps1": ("text/plain", "Pinned stable agent 1.12.6"),
}


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _agent_version_from_file(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"\$AgentVersion\s*=\s*'([^']+)'", text)
    return match.group(1) if match else ""


@app.get("/downloads/OpenPrimeRMMAgent-x64.msi")
def download_msi():
    """Serve the operator-built agent MSI. Build it with the OpenPrimeRMM MSI
    project, then place it at /opt/open-prime-rmm/agent/msi-dist/ with this exact
    filename (a stable name keeps every deployment command valid across MSI
    versions; just overwrite the file when you build a new one)."""
    msi_path = BASE_DIR.parent / "agent" / "msi-dist" / "OpenPrimeRMMAgent-x64.msi"
    if not msi_path.exists():
        raise HTTPException(
            status_code=404,
            detail="MSI not uploaded yet. Place your built MSI at "
                   "/opt/open-prime-rmm/agent/msi-dist/OpenPrimeRMMAgent-x64.msi",
        )
    return FileResponse(msi_path, media_type="application/octet-stream",
                        filename="OpenPrimeRMMAgent-x64.msi")


@app.get("/downloads/recovery/{filename}")
def download_recovery_file(filename: str):
    entry = RECOVERY_DOWNLOADS.get(filename)
    if not entry:
        raise HTTPException(status_code=404, detail="Recovery file not found")
    path = RECOVERY_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Recovery file is missing on the server: {filename}")
    media_type, _label = entry
    inline_text = filename in {"RECOVERY_GUIDE.md", "SHA256SUMS.txt", "agent-stable-1.12.6.ps1"}
    return FileResponse(
        path,
        media_type=media_type,
        filename=None if inline_text else filename,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/recovery/status")
def recovery_status(request: Request):
    require_admin(request)
    active_agent = BASE_DIR.parent / "agent" / "agent.ps1"
    stable_agent = RECOVERY_DIR / "agent-stable-1.12.6.ps1"
    tools = []
    for filename, (_media_type, label) in RECOVERY_DOWNLOADS.items():
        if filename == "agent-stable-1.12.6.ps1":
            continue
        path = RECOVERY_DIR / filename
        tools.append({
            "filename": filename,
            "label": label,
            "available": path.is_file(),
            "size_bytes": path.stat().st_size if path.is_file() else 0,
            "sha256": _file_sha256(path) if path.is_file() else "",
            "url": f"/downloads/recovery/{filename}",
        })
    return {
        "platform_version": PLATFORM_VERSION,
        "active_agent_version": _agent_version_from_file(active_agent),
        "stable_agent_version": _agent_version_from_file(stable_agent),
        "stable_agent_sha256": _file_sha256(stable_agent) if stable_agent.is_file() else "",
        "tools": tools,
    }


# ------------------------------ Agent API ---------------------------------


async def read_agent_json(request: Request) -> dict:
    """Tolerant JSON body reader for agent-facing endpoints. Old agents encode
    bodies as Latin-1, and script output can contain raw binary bytes; a strict
    UTF-8 decode would 500 and (for job results) strand the job at 'running'.
    Invalid bytes are replaced instead of rejected."""
    raw = await request.body()
    if len(raw) > 32 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Body too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")      # what PS 5.1 Invoke-RestMethod actually sends
        except (UnicodeDecodeError, ValueError):
            text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object")
    return data


def enroll_agent_record(request: Request, body: dict) -> dict:
    """Shared enrollment implementation for JSON/PowerShell and form/CMD installers.

    Device identity is tenant-safe:
      * A preserved AgentId repairs that exact device record.
      * Otherwise legacy/reinstall matching is customer + hostname only.
      * MachineGuid acts as a collision guard, never as a global hostname substitute.
      * Ambiguous/conflicting identity is rejected instead of overwriting a record.
    """
    if not hmac.compare_digest(str(body.get("enroll_key", "")), ENROLL_KEY):
        raise HTTPException(status_code=403, detail="Bad enroll key")

    hostname = str(body.get("hostname", "")).strip()[:128] or "unknown"
    machine_guid = str(body.get("machine_guid", "")).strip().strip("{}")[:128]
    existing_agent_id = str(body.get("existing_agent_id", "")).strip()[:64]
    os_version = str(body.get("os_version", ""))[:256]
    org_name = str(body.get("org", "")).strip()
    # Deployment commands templated without a selected customer should never
    # mint a literal placeholder customer; such devices land in "Unassigned"
    # and get reassigned from the Fleet page.
    if org_name.lower() in ("", "customer name", "unassigned", "org name"):
        org_name = "Unassigned"
    token = secrets.token_urlsafe(32)
    now = time.time()

    with db() as conn:
        org_id = get_or_create_org(conn, org_name) if org_name else None
        existing = None

        # A reinstall/repair normally still has config.json. Its AgentId is the
        # safest possible pointer and permits hostname changes without relying on
        # a globally unique computer name.
        if existing_agent_id:
            candidate = conn.execute(
                "SELECT id, org_id, hostname, machine_guid FROM agents WHERE id=?",
                (existing_agent_id,),
            ).fetchone()
            if candidate:
                saved_guid = str(candidate["machine_guid"] or "").strip()
                if machine_guid and saved_guid and saved_guid.lower() != machine_guid.lower():
                    raise HTTPException(
                        status_code=409,
                        detail=("The preserved OpenPrimeRMM AgentId belongs to a different "
                                "Windows installation. Remove the copied/stale configuration "
                                "before enrolling this computer."),
                    )
                if (org_id is not None and candidate["org_id"] is not None
                        and candidate["org_id"] != org_id):
                    current = conn.execute(
                        "SELECT name FROM orgs WHERE id=?", (candidate["org_id"],)
                    ).fetchone()
                    current_name = current["name"] if current else "another customer"
                    raise HTTPException(
                        status_code=409,
                        detail=(f"This device record belongs to '{current_name}'. Move or "
                                f"delete it in OpenPrimeRMM before enrolling under '{org_name}'."),
                    )
                existing = candidate

        if existing is None:
            # Never search hostname globally. Computer names are only unique inside
            # the selected customer, and separate customers may use identical naming.
            if org_id is None:
                host_matches = conn.execute(
                    "SELECT id, org_id, hostname, machine_guid FROM agents "
                    "WHERE hostname=? COLLATE NOCASE AND org_id IS NULL "
                    "ORDER BY created_at",
                    (hostname,),
                ).fetchall()
            else:
                host_matches = conn.execute(
                    "SELECT id, org_id, hostname, machine_guid FROM agents "
                    "WHERE hostname=? COLLATE NOCASE AND org_id=? "
                    "ORDER BY created_at",
                    (hostname, org_id),
                ).fetchall()

            if len(host_matches) > 1:
                raise HTTPException(
                    status_code=409,
                    detail=("More than one device with this hostname already exists inside "
                            "the selected customer. Resolve the duplicate records first."),
                )
            if host_matches:
                candidate = host_matches[0]
                saved_guid = str(candidate["machine_guid"] or "").strip()
                if machine_guid and saved_guid and saved_guid.lower() != machine_guid.lower():
                    raise HTTPException(
                        status_code=409,
                        detail=("A different Windows device already uses this hostname inside "
                                "the selected customer. Delete/rename the old record or confirm "
                                "the correct device before re-enrolling."),
                    )
                existing = candidate

        if existing:
            # Deliberate repair/re-enrollment of the exact or tenant-scoped record.
            # An explicitly selected customer may claim an Unassigned record, but an
            # assigned record is never silently moved between customers.
            agent_id = existing["id"]
            effective_org_id = existing["org_id"] if existing["org_id"] is not None else org_id
            conn.execute(
                "UPDATE agents SET token_hash=?, hostname=?, machine_guid=?, "
                "os_version=?, ip=?, org_id=? WHERE id=?",
                (hash_token(token), hostname, machine_guid or existing["machine_guid"] or "",
                 os_version, client_ip(request), effective_org_id, agent_id),
            )
        else:
            agent_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO agents (id, hostname, machine_guid, os_version, ip, "
                "token_hash, org_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (agent_id, hostname, machine_guid, os_version, client_ip(request),
                 hash_token(token), org_id, now),
            )
    return {"agent_id": agent_id, "agent_token": token, "checkin_path": "/api/agent/checkin"}


@app.post("/api/agent/enroll")
async def agent_enroll(request: Request):
    body = await read_agent_json(request)
    return enroll_agent_record(request, body)


@app.post("/api/agent/enroll-cmd")
async def agent_enroll_cmd(request: Request):
    """Native-CMD enrollment endpoint.

    curl.exe submits URL-encoded fields and receives batch-safe KEY=VALUE lines,
    avoiding PowerShell and fragile JSON parsing in Install-Agent.cmd.
    """
    raw = await request.body()
    if len(raw) > 64 * 1024:
        raise HTTPException(status_code=413, detail="Body too large")
    try:
        parsed = urllib.parse.parse_qs(
            raw.decode("utf-8"), keep_blank_values=True, strict_parsing=False
        )
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid form body")
    body = {key: values[-1] if values else "" for key, values in parsed.items()}
    result = enroll_agent_record(request, body)
    # IDs/tokens are generated from UUID and token_urlsafe, so they cannot inject
    # additional batch commands or line breaks.
    return PlainTextResponse(
        f"AGENT_ID={result['agent_id']}\r\n"
        f"AGENT_TOKEN={result['agent_token']}\r\n"
        f"CHECKIN_PATH={result['checkin_path']}\r\n",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/agent/checkin")
async def agent_checkin(request: Request):
    agent = await asyncio.to_thread(require_agent, request)
    body = await read_agent_json(request)
    return await asyncio.to_thread(_process_agent_checkin, request, agent, body)


def _process_agent_checkin(request: Request, agent: sqlite3.Row, body: dict):
    """Commit inventory, job pickup and optional alerts without blocking the API loop."""
    now = time.time()
    _mon_alerts = []
    centralized_monitoring = False

    reported = body.get("updates", []) or []
    reported_ids = {str(u.get("update_id", "")) for u in reported if u.get("update_id")}

    inv = body.get("inventory") or {}
    wu_management = inv.get("windows_update_management") or {}
    if not isinstance(wu_management, dict):
        wu_management = {}
    disks = inv.get("disks") or []
    if not isinstance(disks, list):
        disks = []
    try:
        memory_used_pct = float(inv.get("memory_used_pct"))
        if not 0 <= memory_used_pct <= 100:
            memory_used_pct = None
    except (TypeError, ValueError):
        memory_used_pct = None
    with db() as conn:
        pub_ip = client_ip(request)
        loc_ip = str(inv.get("local_ip", agent["local_ip"] or ""))[:64]
        reboot_now = bool(body.get("reboot_required"))
        reboot_since = agent["reboot_since"] if "reboot_since" in agent.keys() else None
        if reboot_now and not reboot_since:
            reboot_since = now
        if not reboot_now:
            reboot_since = None
        conn.execute(
            "UPDATE agents SET last_seen=?, ip=?, public_ip=?, local_ip=?, os_version=?,"
            " agent_version=?, reboot_required=?, reboot_since=?, last_update_scan=?,"
            " serial=?, model=?, cpu=?, ram_gb=?, memory_used_pct=?, disks=?, last_user=?, wu_management=? WHERE id=?",
            (
                now,
                pub_ip,          # keep legacy 'ip' populated for compatibility
                pub_ip,
                loc_ip,
                str(body.get("os_version", agent["os_version"]))[:256],
                str(body.get("agent_version", ""))[:32],
                1 if reboot_now else 0,
                reboot_since,
                now,
                str(inv.get("serial", agent["serial"] or ""))[:128],
                str(inv.get("model", agent["model"] or ""))[:256],
                str(inv.get("cpu", agent["cpu"] or ""))[:256],
                float(inv.get("ram_gb") or agent["ram_gb"] or 0),
                memory_used_pct,
                json.dumps(disks[:12]),
                str(inv.get("last_user", agent["last_user"] or ""))[:128],
                json.dumps(wu_management),
                agent["id"],
            ),
        )
        # Server companion: harvest the worker report into run history. The
        # endpoint report is last-run-wins, so each distinct checked_at is a
        # run the server must remember. UNIQUE(agent_id, checked_at) makes
        # this idempotent across repeated check-ins carrying the same report.
        try:
            _wu_checked = float(wu_management.get("checked_at") or 0)
        except (TypeError, ValueError):
            _wu_checked = 0
        if _wu_checked > 0:
            _counter_keys = (
                "deny_rules_received", "deny_matches_found", "deny_not_found",
                "hide_attempted", "hide_succeeded", "hide_verified",
                "hide_direct", "hide_fallback", "hide_setter_failed",
                "unhide_attempted", "unhide_succeeded", "unhide_verified",
                "unhide_direct", "unhide_fallback", "unhide_setter_failed",
                "pending_count", "excluded_count",
                "scan_standard_count", "scan_optional_count",
                "scan_driver_count", "scan_firmware_count", "scan_feature_count",
            )
            _counters = {}
            for k in _counter_keys:
                try:
                    _counters[k] = int(wu_management.get(k) or 0)
                except (TypeError, ValueError):
                    _counters[k] = 0
            try:
                _wu_started = float(wu_management.get("started_at") or 0)
            except (TypeError, ValueError):
                _wu_started = 0
            conn.execute(
                "INSERT OR IGNORE INTO wu_runs (agent_id, started_at, checked_at,"
                " phase, status, mode, lab_build, compliant, hidden_count,"
                " visible_count, counters, errors, warnings, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    agent["id"], _wu_started, _wu_checked,
                    str(wu_management.get("phase") or "")[:32],
                    str(wu_management.get("worker_status") or wu_management.get("status") or "")[:32],
                    str(wu_management.get("mode") or "")[:32],
                    str(wu_management.get("lab_build") or "")[:64],
                    1 if wu_management.get("compliant") else 0,
                    int(wu_management.get("hidden_count") or 0),
                    int(wu_management.get("visible_count") or 0),
                    json.dumps(_counters),
                    json.dumps((wu_management.get("errors") or [])[:20]),
                    json.dumps((wu_management.get("warnings") or [])[:20]),
                    now,
                ),
            )
            # A device that sends a worker report has the isolated Windows
            # Update architecture; remember that so policy enforcement and
            # dashboards can distinguish capable agents from legacy 1.12.6.
            conn.execute("UPDATE agents SET wu_capable=1 WHERE id=?", (agent["id"],))
            # Keep run history bounded per device.
            conn.execute(
                "DELETE FROM wu_runs WHERE agent_id=? AND id NOT IN ("
                " SELECT id FROM wu_runs WHERE agent_id=?"
                " ORDER BY checked_at DESC LIMIT 500)",
                (agent["id"], agent["id"]),
            )
        _hw_alert = None
        dh = inv.get("disk_health") or []
        if isinstance(dh, list):
            try:
                smart = int(inv.get("smart_failures") or 0)
            except (TypeError, ValueError):
                smart = 0
            conn.execute("UPDATE agents SET disk_health=?, smart_failures=? WHERE id=?",
                         (json.dumps(dh[:12]), smart, agent["id"]))
            bad = [d for d in dh if isinstance(d, dict)
                   and str(d.get("health", "")).lower() not in ("healthy", "")]
            dev = inv.get("disk_events") or {}
            dev = dev if isinstance(dev, dict) else {}
            ev_count = int(dev.get("count") or 0)
            conn.execute("UPDATE agents SET disk_events=? WHERE id=?",
                         (json.dumps({"count": ev_count,
                                      "last": str(dev.get("last") or "")[:400],
                                      "last_time": str(dev.get("last_time") or "")[:40]}),
                          agent["id"]))
            if (bad or smart or ev_count) and not _alert_already_sent(conn, f"hw:{agent['id']}", 24 * 3600):
                org = conn.execute(
                    "SELECT o.name FROM agents a LEFT JOIN orgs o ON o.id=a.org_id WHERE a.id=?",
                    (agent["id"],)).fetchone()
                parts = []
                if bad:
                    parts.append(", ".join(f"{d.get('name','disk')}: {d.get('health','?')}" for d in bad))
                if smart:
                    parts.append(f"{smart} disk(s) predicting SMART failure")
                if ev_count:
                    parts.append(f"{ev_count} disk error event(s) in the last 24h "
                                 f"(bad blocks / IO failures). Last: {str(dev.get('last') or '')[:200]}")
                _hw_alert = (agent["hostname"], org["name"] if org else None, " | ".join(parts))
        else:
            _hw_alert = None

        # Updates no longer reported were installed or superseded - drop them,
        # EXCEPT denied ones (keep the deny record even after the agent hides them).
        # Keep enough identity metadata to carry a denial across Windows Update ID
        # changes for the same KB/title.
        rows = conn.execute(
            "SELECT update_id, kb, title, status, denied_by, denied_at "
            "FROM updates WHERE agent_id=?", (agent["id"],)
        ).fetchall()
        denied_rows = [r for r in rows if r["status"] == "denied"]
        for r in rows:
            if r["update_id"] not in reported_ids and r["status"] != "denied":
                conn.execute(
                    "DELETE FROM updates WHERE agent_id=? AND update_id=?",
                    (agent["id"], r["update_id"]),
                )

        # Upsert what the machine reports now, preserving approval/deny status.
        # If Windows exposes the same patch under a new UpdateID, inherit the
        # existing denial by normalized KB or exact normalized title.
        for u in reported:
            uid = str(u.get("update_id", "")).strip()
            if not uid:
                continue
            kb_value = str(u.get("kb", ""))[:64]
            title_value = str(u.get("title", ""))[:512]
            uid_norm = _patch_normalize_text(uid)
            kb_norm = _patch_normalize_kb(kb_value) if kb_value else ""
            title_norm = _patch_normalize_text(title_value) if title_value else ""
            inherited = None
            for denied_row in denied_rows:
                if (uid_norm and _patch_normalize_text(denied_row["update_id"]) == uid_norm):
                    inherited = denied_row
                    break
                if (kb_norm and _patch_normalize_kb(denied_row["kb"]) == kb_norm):
                    inherited = denied_row
                    break
                if (title_norm and _patch_normalize_text(denied_row["title"]) == title_norm):
                    inherited = denied_row
                    break
            incoming_status = "denied" if inherited else "pending"
            inherited_by = str(inherited["denied_by"] or "") if inherited else ""
            inherited_at = float(inherited["denied_at"] or now) if inherited else None
            try:
                revision_value = int(u.get("revision") or 0)
            except (TypeError, ValueError):
                revision_value = 0
            conn.execute(
                """INSERT INTO updates
                     (agent_id, update_id, kb, title, severity, size_mb, detected_at,
                      status, denied_by, denied_at, status_changed_at,
                      category, browse_only, revision)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(agent_id, update_id) DO UPDATE SET
                     kb=excluded.kb, title=excluded.title,
                     severity=excluded.severity, size_mb=excluded.size_mb,
                     category=excluded.category, browse_only=excluded.browse_only,
                     revision=excluded.revision,
                     status=CASE WHEN excluded.status='denied' THEN 'denied' ELSE updates.status END,
                     denied_by=CASE WHEN excluded.status='denied' THEN excluded.denied_by ELSE updates.denied_by END,
                     denied_at=CASE WHEN excluded.status='denied' THEN excluded.denied_at ELSE updates.denied_at END,
                     status_changed_at=CASE WHEN excluded.status='denied' AND updates.status!='denied'
                                            THEN excluded.status_changed_at ELSE updates.status_changed_at END""",
                (
                    agent["id"], uid, kb_value, title_value,
                    str(u.get("severity", ""))[:32],
                    float(u.get("size_mb") or 0), now, incoming_status,
                    inherited_by, inherited_at, now,
                    str(u.get("category", ""))[:32],
                    1 if u.get("browse_only") else 0,
                    revision_value,
                ),
            )

        # Extended inventory (agent 1.13.2+). Stored as one JSON blob: these
        # fields are for display, not querying, and keeping them together
        # avoids a schema migration every time a collector is added. Older
        # agents simply send none of it and the column keeps its default.
        _ext_keys = ("last_boot", "uptime_hours", "os_install_date", "os_arch",
                     "domain", "domain_joined", "bios_version", "bios_date",
                     "timezone", "bitlocker", "firewall", "adapters",
                     "hotfixes", "local_admins", "backup")
        _ext = {}
        for _k in _ext_keys:
            if _k in inv and inv[_k] not in (None, "", [], {}):
                _ext[_k] = inv[_k]
        if _ext:
            _ext["_updated_at"] = now
            conn.execute("UPDATE agents SET ext_inventory=? WHERE id=?",
                         (json.dumps(_ext)[:60000], agent["id"]))

        # Store software inventory if the agent sent it
        sw = inv.get("software")
        if isinstance(sw, list):
            conn.execute("UPDATE agents SET software=? WHERE id=?",
                         (json.dumps(sw[:600]), agent["id"]))
        macs = inv.get("macs")
        if isinstance(macs, list) and macs:
            norm = []
            for m in macs[:8]:
                c = "".join(ch for ch in str(m) if ch in "0123456789abcdefABCDEF")
                if len(c) == 12:
                    norm.append(":".join(c[i:i+2].upper() for i in range(0, 12, 2)))
            if norm:
                conn.execute("UPDATE agents SET macs=? WHERE id=?",
                             (json.dumps(norm), agent["id"]))

        # ScreenConnect / ConnectWise Control session discovery. Do not clear a
        # manually saved mapping when a client reports no installed service.
        sc_sid = str(inv.get("screenconnect_session_id") or "").strip()
        sc_service = str(inv.get("screenconnect_service_name") or "").strip()
        if sc_sid:
            try:
                sc_sid = str(uuid.UUID(sc_sid))
                conn.execute(
                    "UPDATE agents SET screenconnect_session_id=?, screenconnect_service_name=? WHERE id=?",
                    (sc_sid, sc_service[:256], agent["id"]),
                )
            except ValueError:
                pass

        # Service monitors the agent should enforce, and process any restart reports
        mons = conn.execute(
            "SELECT id, service_name, auto_restart, last_state FROM service_monitors WHERE agent_id=?",
            (agent["id"],)).fetchall()
        monitors_out = [{"service": m["service_name"], "auto_restart": bool(m["auto_restart"])}
                        for m in mons]
        mon_report = inv.get("service_monitor_report") or {}
        if isinstance(mon_report, dict):
            for m in mons:
                st = mon_report.get(m["service_name"])
                if st and st != m["last_state"]:
                    conn.execute("UPDATE service_monitors SET last_state=? WHERE id=?",
                                 (str(st)[:32], m["id"]))
                    if st in ("stopped", "restarted-failed"):
                        _mon_alerts.append((agent["hostname"], m["service_name"], st))

        # Organization onboarding is intentionally checked only after a normal
        # inventory/check-in transaction has succeeded. Automatic onboarding is
        # disabled by default and has a creation-time safety gate so enabling it
        # cannot retrofit the existing fleet. Existing/running stacks may also
        # advance a delayed retry here without touching the heartbeat protocol.
        _maybe_start_automatic_onboarding(conn, agent["id"], now)
        _maybe_advance_onboarding(conn, agent["id"], now)

        # Hand out queued jobs
        job_rows = conn.execute(
            "SELECT id, type, payload FROM jobs WHERE agent_id=? AND status='pending'"
            " ORDER BY created_at LIMIT 5",
            (agent["id"],),
        ).fetchall()
        jobs = []
        for j in job_rows:
            payload = json.loads(j["payload"])
            # Reboots and shutdowns are deliberately ephemeral. A computer that
            # was asleep/offline during a maintenance schedule must not execute
            # yesterday's queued power action when it checks in during work hours.
            # Legacy/malformed power payloads have no expiry and fail closed.
            if j["type"] == "reboot" and power_job_expired(payload, now):
                conn.execute(
                    "UPDATE jobs SET status='cancelled', output=?, exit_code=0, finished_at=? WHERE id=?",
                    ("Cancelled: reboot/shutdown window expired before endpoint pickup.", now, j["id"]),
                )
                continue
            # Final safety gate: a deny can race with a queued patch job. Never hand
            # a now-denied update to the endpoint, even if an older pending job escaped
            # the API-side cancellation path.
            if j["type"] == "install_updates":
                requested = [str(x) for x in (payload.get("update_ids") or []) if str(x)]
                if requested:
                    qmarks = ",".join("?" for _ in requested)
                    denied_now = {r["update_id"] for r in conn.execute(
                        f"SELECT update_id FROM updates WHERE agent_id=? AND status='denied' "
                        f"AND update_id IN ({qmarks})",
                        (agent["id"], *requested),
                    ).fetchall()}
                    requested = [uid for uid in requested if uid not in denied_now]
                    payload["update_ids"] = requested
                if not payload.get("update_ids"):
                    conn.execute(
                        "UPDATE jobs SET status='cancelled', output=?, exit_code=0, finished_at=? WHERE id=?",
                        ("Cancelled because all requested updates are denied.", now, j["id"]),
                    )
                    continue
                conn.execute("UPDATE jobs SET payload=? WHERE id=?", (json.dumps(payload), j["id"]))
            conn.execute(
                "UPDATE jobs SET status='running', started_at=? WHERE id=?", (now, j["id"])
            )
            jobs.append({"id": j["id"], "type": j["type"], "payload": payload})

        # Tell the agent which updates are denied so it can hide them locally
        denied = conn.execute(
            "SELECT update_id, kb FROM updates WHERE agent_id=? AND status='denied'",
            (agent["id"],),
        ).fetchall()
        denied_ids = [r["update_id"] for r in denied]
        denied_kbs = [r["kb"] for r in denied if r["kb"]]
        denied_details = [dict(r) for r in conn.execute(
            "SELECT update_id, kb, title FROM updates WHERE agent_id=? AND status='denied'",
            (agent["id"],),
        ).fetchall()]
        # Whether this machine's effective policy wants preview/optional updates
        eff = effective_policy(conn, agent["org_id"])
        include_preview = bool(eff.get("include_preview"))
        update_management = {
            "managed": bool(eff.get("manage_windows_update")),
            "block_user_update_access": bool(eff.get("block_user_update_access", True)),
            "block_pause_updates": bool(eff.get("block_pause_updates", True)),
            "hide_denied_updates": bool(eff.get("hide_denied_updates", True)),
            "automatic_updates_mode": "notify",
        }
        centralized_monitoring = bool(effective_monitor_policy(conn, agent["org_id"]).get("enabled"))
        # Resolve persistent long-poll ("live mode") for this agent
        live_mode = effective_live_mode(conn, agent)

    if _hw_alert and not centralized_monitoring:
        try:
            alert_hardware(*_hw_alert)
        except Exception:
            pass
    for host, svc, st in (_mon_alerts if not centralized_monitoring else []):
        try:
            with db() as conn:
                acfg = get_alerts(conn)
            if acfg.get("enabled") and acfg.get("webhook_url"):
                verb = "is stopped" if st == "stopped" else "failed to restart"
                send_discord(acfg["webhook_url"], f"⚙️ Service {verb} on {host}",
                             f"**Service:** {svc}\n**Machine:** {host}\n"
                             f"**When:** {time.strftime('%Y-%m-%d %H:%M %Z')}", color=0xB7791F)
        except Exception:
            pass
    # Fast re-check: if an ad-hoc command was just queued for this machine, tell
    # it to poll again in a few seconds so output comes back near-instantly.
    recheck = 0
    exp = _nudge_agents.get(agent["id"])
    if exp and exp > time.time():
        recheck = 3
    elif exp:
        _nudge_agents.pop(agent["id"], None)

    return {"jobs": jobs, "interval_hint_minutes": 1,
            "recheck_seconds": recheck,
            "latest_agent_version": LATEST_AGENT_VERSION,
            "denied_update_ids": denied_ids,
            "denied_kbs": denied_kbs,
            "denied_updates": denied_details,
            "update_management": update_management,
            "service_monitors": monitors_out,
            "latest_tray_version": current_tray_version(),
            "brand": COMPANY_NAME,
            "live_mode": live_mode,
            "include_preview": include_preview}


@app.post("/api/agent/poll")
async def agent_poll(request: Request):
    """Persistent long-poll channel for live-mode agents. Holds the request open
    up to ~25s waiting on an in-memory asyncio.Event; returns instantly when a
    job is queued for this agent (run_command sets the event). Claims and returns
    pending jobs exactly like checkin does. Holds NO DB connection while parked,
    so a single worker scales to the whole fleet."""
    agent = await asyncio.to_thread(require_agent, request)
    aid = agent["id"]

    # Confirm this agent is actually allowed in live mode; if not, tell it to
    # fall back to interval check-ins (handles a mid-session toggle-off).
    if not await asyncio.to_thread(_poll_live_enabled, aid):
        return {"jobs": [], "live_mode": False}

    ev = _live_events.get(aid)
    if ev is None:
        ev = asyncio.Event()
        _live_events[aid] = ev
    _register_live_event_loop(aid, asyncio.get_running_loop())
    _live_connected[aid] = time.time()

    # Fast path: a job may already be waiting (queued before we connected).
    def _claim_jobs():
        now = time.time()
        with db() as conn:
            conn.execute("UPDATE agents SET last_seen=? WHERE id=?", (now, aid))
            rows = conn.execute(
                "SELECT id, type, payload FROM jobs WHERE agent_id=? AND status='pending'"
                " ORDER BY created_at LIMIT 5", (aid,)).fetchall()
            out = []
            for j in rows:
                try:
                    payload = json.loads(j["payload"] or "{}")
                except (ValueError, TypeError):
                    payload = {}
                # Live Mode must honor the same last-moment denial gate as the
                # regular check-in path. Otherwise a queued update could escape
                # through long-poll seconds after an administrator denied it.
                if j["type"] == "install_updates":
                    requested = [str(x) for x in (payload.get("update_ids") or []) if str(x)]
                    if requested:
                        qmarks = ",".join("?" for _ in requested)
                        denied_now = {r["update_id"] for r in conn.execute(
                            f"SELECT update_id FROM updates WHERE agent_id=? AND status='denied' "
                            f"AND update_id IN ({qmarks})",
                            (aid, *requested),
                        ).fetchall()}
                        requested = [uid for uid in requested if uid not in denied_now]
                        payload["update_ids"] = requested
                    if not payload.get("update_ids"):
                        conn.execute(
                            "UPDATE jobs SET status='cancelled', output=?, exit_code=0, finished_at=? WHERE id=?",
                            ("Cancelled because all requested updates are denied.", now, j["id"]),
                        )
                        continue
                    conn.execute("UPDATE jobs SET payload=? WHERE id=?", (json.dumps(payload), j["id"]))
                conn.execute("UPDATE jobs SET status='running', started_at=? WHERE id=?", (now, j["id"]))
                out.append({"id": j["id"], "type": j["type"], "payload": payload})
        return out

    jobs = await asyncio.to_thread(_claim_jobs)
    if jobs:
        ev.clear()
        return {"jobs": jobs, "live_mode": True}

    # Park: wait for a wake signal or time out at 25s. No DB connection held here.
    try:
        await asyncio.wait_for(ev.wait(), timeout=25.0)
    except asyncio.TimeoutError:
        pass
    finally:
        ev.clear()

    jobs = await asyncio.to_thread(_claim_jobs)
    return {"jobs": jobs, "live_mode": True}


def _poll_live_enabled(agent_id: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT id, live_mode, org_id FROM agents WHERE id=?", (agent_id,)
        ).fetchone()
        return bool(row and effective_live_mode(conn, row))


@app.post("/api/agent/jobs/{job_id}/result")
async def agent_job_result(job_id: str, request: Request):
    agent = await asyncio.to_thread(require_agent, request)
    body = await read_agent_json(request)
    return await asyncio.to_thread(_process_agent_job_result, job_id, agent, body)


def _process_agent_job_result(job_id: str, agent: sqlite3.Row, body: dict):
    """Commit the result before best-effort follow-up work, off the API loop."""
    ok = bool(body.get("ok"))
    output = str(body.get("output") or "")[:MAX_JOB_OUTPUT]
    try:
        exit_code = int(body.get("exit_code"))
    except (TypeError, ValueError):
        exit_code = None
    now = time.time()

    # Transaction 1: record the result. This must ALWAYS commit — nothing
    # optional (alerting etc.) is allowed to fail it, or the job would show
    # 'running' forever while the agent gives up retrying against a 500.
    with db() as conn:
        job = conn.execute(
            "SELECT * FROM jobs WHERE id=? AND agent_id=?", (job_id, agent["id"])
        ).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Unknown job")
        conn.execute(
            "UPDATE jobs SET status=?, output=?, exit_code=?, finished_at=? WHERE id=?",
            ("done" if ok else "failed", output, exit_code, now, job_id),
        )
        if job["type"] == "install_updates":
            failed_ids = [str(x) for x in (body.get("failed_update_ids", []) or [])]
            for uid in failed_ids:
                conn.execute(
                    "UPDATE updates SET status='failed', status_changed_at=? WHERE agent_id=? AND update_id=?",
                    (now, agent["id"], uid),
                )
            if body.get("reboot_required"):
                conn.execute(
                    "UPDATE agents SET reboot_required=1, reboot_since=COALESCE(reboot_since, ?) WHERE id=?",
                    (now, agent["id"]),
                )
            # Optional controlled reboot after a successful patch job. This uses
            # the existing reboot job type and never changes the agent runtime.
            if ok and not failed_ids and body.get("reboot_required"):
                arow = conn.execute("SELECT org_id FROM agents WHERE id=?", (agent["id"],)).fetchone()
                pol = effective_policy(conn, arow["org_id"] if arow else None)
                if pol.get("reboot_after_install") and policy_in_maintenance_window(pol, now) and not conn.execute(
                    "SELECT 1 FROM jobs WHERE agent_id=? AND type='reboot' AND status IN ('pending','running')",
                    (agent["id"],),
                ).fetchone():
                    delay = max(0, min(86400, int(pol.get("reboot_delay_minutes") or 15) * 60))
                    conn.execute(
                        "INSERT INTO jobs (id, agent_id, type, label, payload, created_at) VALUES (?,?,?,?,?,?)",
                        (str(uuid.uuid4()), agent["id"], "reboot",
                         "Policy reboot after Windows Updates",
                         json.dumps(build_power_job_payload(
                             "reboot", "OpenPrime-RMM: maintenance reboot after Windows Updates",
                             "patching", now, delay)),
                         now),
                    )

    # Advance a sequential organization onboarding stack only after the exact
    # endpoint job has committed its result. This bookkeeping is separate from
    # ordinary script jobs and may never turn a successful result POST into 500.
    try:
        with db() as conn:
            _process_onboarding_job_result(conn, job_id, ok, output, now)
    except Exception:
        pass

    # Best-effort alerting AFTER the result is committed. Never let it 500.
    try:
        update_failures = bool(body.get("failed_update_ids"))
        if not ok or (job["type"] == "install_updates" and update_failures):
            with db() as conn:
                org = conn.execute(
                    "SELECT o.name FROM agents a LEFT JOIN orgs o ON o.id=a.org_id WHERE a.id=?",
                    (agent["id"],),
                ).fetchone()
            alert_failed_job(agent["hostname"], org["name"] if org else None,
                             job["label"] or job["type"], job["type"])
    except Exception:
        pass
    if job["type"] == "uninstall_agent" and ok:
        # The endpoint acknowledged full removal and will delete itself in
        # ~2 minutes; retire the record now so the console reflects reality.
        with db() as conn:
            conn.execute("DELETE FROM updates WHERE agent_id=?", (agent["id"],))
            conn.execute("DELETE FROM wu_runs WHERE agent_id=?", (agent["id"],))
            conn.execute("DELETE FROM jobs WHERE agent_id=?", (agent["id"],))
            for r in conn.execute("SELECT id FROM onboarding_runs WHERE agent_id=?", (agent["id"],)).fetchall():
                conn.execute("DELETE FROM onboarding_run_steps WHERE run_id=?", (r["id"],))
            conn.execute("DELETE FROM onboarding_runs WHERE agent_id=?", (agent["id"],))
            conn.execute("DELETE FROM device_onboarding_state WHERE agent_id=?", (agent["id"],))
            conn.execute("DELETE FROM agents WHERE id=?", (agent["id"],))
    return {"ok": True}


import urllib.request
import urllib.error


DEFAULT_ALERTS = {
    "enabled": False,
    "webhook_url": "",
    "support_webhook_url": "",
    "on_offline_workstations": True,
    "offline_workstation_hours": 2,
    "on_offline_servers": True,
    "offline_server_hours": 2,
    "on_failed_job": True,       # a script/update job failed
    "on_failed_updates": True,   # an update install reported failures
    "on_login": False,           # successful dashboard sign-in
    "on_login_fail": True,       # failed dashboard sign-in attempt
    "on_hardware": True,         # disk health / SMART / bad blocks
    "on_monitoring": True,       # centralized monitoring incidents
}


def get_alerts(conn: sqlite3.Connection) -> dict:
    row = conn.execute("SELECT value FROM settings WHERE key='alerts'").fetchone()
    cfg = dict(DEFAULT_ALERTS)
    stored = {}
    if row:
        try:
            stored = json.loads(row["value"])
            cfg.update(stored)
        except (ValueError, TypeError):
            pass
    # Preserve the previous single offline-alert setting by applying it to both
    # device classes until the administrator saves the new separate controls.
    if "on_offline_workstations" not in stored:
        cfg["on_offline_workstations"] = bool(stored.get("on_offline", True))
    if "on_offline_servers" not in stored:
        cfg["on_offline_servers"] = bool(stored.get("on_offline", True))
    if "offline_workstation_hours" not in stored:
        cfg["offline_workstation_hours"] = stored.get("offline_hours", 2)
    if "offline_server_hours" not in stored:
        cfg["offline_server_hours"] = stored.get("offline_hours", 2)
    return cfg


def send_discord_strict(webhook_url: str, title: str, description: str,
                        color: int = 0xC43D3D) -> tuple:
    """POST to a Discord webhook and report honestly: (ok, detail)."""
    url = (webhook_url or "").strip()
    if not url.startswith("https://"):
        return False, "Webhook URL must start with https:// (paste the full URL from Discord)"
    if "discord.com/api/webhooks/" not in url and "discordapp.com/api/webhooks/" not in url:
        return False, "That doesn't look like a Discord webhook URL (expected …discord.com/api/webhooks/…)"
    payload = {
        "username": "OpenPrime-RMM",
        "embeds": [{
            "title": title,
            "description": description,
            "color": color,
            "footer": {"text": "OpenPrime-RMM RMM"},
            # Discord requires ISO8601 WITH timezone; a naive timestamp gets
            # the whole request rejected with 400 Invalid Form Body.
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }],
    }
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     # Cloudflare in front of Discord rejects the default
                     # Python-urllib user agent with 403.
                     "User-Agent": "OpenPrime-RMM RMM (webhook)"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return False, f"Discord returned HTTP {e.code}: {body or e.reason}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"Could not reach Discord: {e}"


def send_discord(webhook_url: str, title: str, description: str, color: int = 0xC43D3D):
    """Fire-and-forget wrapper. Never raises; logs failures to journalctl."""
    try:
        ok, detail = send_discord_strict(webhook_url, title, description, color)
        if not ok:
            print(f"[alerts] Discord send failed: {detail}", flush=True)
    except Exception as e:
        print(f"[alerts] Discord send crashed: {e}", flush=True)


def _looks_like_discord_webhook(webhook_url: str) -> bool:
    url = (webhook_url or "").strip()
    return url.startswith("https://discord.com/api/webhooks/") \
        or url.startswith("https://discordapp.com/api/webhooks/")


def _alert_already_sent(conn: sqlite3.Connection, key: str, within_sec: float) -> bool:
    """Dedupe: returns True if we alerted on this key recently (stored in settings)."""
    row = conn.execute("SELECT value FROM settings WHERE key='alert_state'").fetchone()
    state = {}
    if row:
        try:
            state = json.loads(row["value"])
        except (ValueError, TypeError):
            state = {}
    now = time.time()
    last = state.get(key, 0)
    if now - last < within_sec:
        return True
    state[key] = now
    # prune old entries
    state = {k: v for k, v in state.items() if now - v < 7 * 86400}
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('alert_state', ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (json.dumps(state),),
    )
    return False


def alert_hardware(hostname: str, org, detail: str):
    """Discord alert for failing hardware (best-effort, never raises)."""
    try:
        with db() as conn:
            cfg = get_alerts(conn)
        if not cfg.get("enabled") or not cfg.get("webhook_url"):
            return
        send_discord(cfg["webhook_url"], f"\U0001F4BD Hardware warning on {hostname}",
                     f"**Device:** {hostname}\n"
                     f"**Customer:** {org or 'Unassigned'}\n"
                     f"**When:** {time.strftime('%Y-%m-%d %H:%M %Z')}\n"
                     f"**Detail:** {detail}\n"
                     f"Back up this machine and plan a drive replacement.",
                     color=0xC43D3D)
    except Exception:
        pass


def run_offline_alerts():
    """Check for machines that have gone silent and fire a Discord alert once each.
    Webhook calls happen AFTER the DB transaction closes — a slow/unreachable
    Discord must never hold the SQLite write lock (it blocks every other writer,
    including agents posting job results)."""
    to_send = []
    with db() as conn:
        cfg = get_alerts(conn)
        if not cfg.get("enabled") or not cfg.get("webhook_url"):
            return
        workstation_enabled = bool(cfg.get("on_offline_workstations"))
        server_enabled = bool(cfg.get("on_offline_servers"))
        if not workstation_enabled and not server_enabled:
            return
        now = time.time()
        rows = conn.execute(
            """SELECT a.hostname, a.os_version, a.last_seen, o.name AS org FROM agents a
               LEFT JOIN orgs o ON o.id=a.org_id
               WHERE a.last_seen>0""",
        ).fetchall()
        for r in rows:
            is_server = "windows server" in (r["os_version"] or "").lower()
            device_type = "Server" if is_server else "Workstation"
            alert_enabled = server_enabled if is_server else workstation_enabled
            offline_hours = max(1, int(cfg.get(
                "offline_server_hours" if is_server else "offline_workstation_hours"
            ) or 2))
            if not alert_enabled or r["last_seen"] >= now - offline_hours * 3600:
                continue
            # re-alert at most once per 24h per machine
            if _alert_already_sent(conn, f"offline:{r['hostname']}", 24 * 3600):
                continue
            hrs = round((now - r["last_seen"]) / 3600, 1)
            to_send.append((r["hostname"], r["org"], device_type, hrs))
    for hostname, org, device_type, hrs in to_send:
        send_discord(
            cfg["webhook_url"],
            f"⚠️ {hostname} is offline",
            f"**Customer:** {org or 'Unassigned'}\n"
            f"**Device type:** {device_type}\n"
            f"**Last check-in:** {hrs} hours ago",
            color=0xB7791F,
        )


def alert_failed_job(agent_hostname: str, org: str, label: str, kind: str):
    """Called when a job comes back failed. Fires immediately (already deduped by job)."""
    with db() as conn:
        cfg = get_alerts(conn)
        if not cfg.get("enabled") or not cfg.get("webhook_url"):
            return
        if kind == "install_updates" and not cfg.get("on_failed_updates"):
            return
        if kind != "install_updates" and not cfg.get("on_failed_job"):
            return
    send_discord(
        cfg["webhook_url"],
        f"❌ Task failed on {agent_hostname}",
        f"**Customer:** {org or 'Unassigned'}\n**Task:** {label}",
        color=0xC43D3D,
    )


@app.get("/api/alerts")
def read_alerts(request: Request):
    require_admin_role(request)
    with db() as conn:
        cfg = get_alerts(conn)
    # Don't echo the full webhook back — just whether one is set
    safe = dict(cfg)
    safe["webhook_set"] = bool(cfg.get("webhook_url"))
    safe["webhook_url"] = ""
    safe["support_webhook_set"] = bool(cfg.get("support_webhook_url"))
    safe["support_webhook_url"] = ""
    return safe


@app.put("/api/alerts")
async def write_alerts(request: Request):
    require_admin_role(request)
    body = await request.json()
    with db() as conn:
        cur = get_alerts(conn)
        webhook = str(body.get("webhook_url", "")).strip()
        support_webhook = str(body.get("support_webhook_url", "")).strip()
        # Keep existing webhook if the field was left blank (not re-entered)
        if not webhook and body.get("keep_webhook"):
            webhook = cur.get("webhook_url", "")
        if not support_webhook and body.get("keep_support_webhook"):
            support_webhook = cur.get("support_webhook_url", "")
        if webhook and not _looks_like_discord_webhook(webhook):
            raise HTTPException(status_code=400,
                                detail="That doesn't look like a Discord webhook URL")
        if support_webhook and not _looks_like_discord_webhook(support_webhook):
            raise HTTPException(status_code=400,
                                detail="That doesn't look like a Discord support webhook URL")
        workstation_enabled = bool(body.get("on_offline_workstations"))
        server_enabled = bool(body.get("on_offline_servers"))
        workstation_hours = max(1, min(168, int(body.get("offline_workstation_hours") or 2)))
        server_hours = max(1, min(168, int(body.get("offline_server_hours") or 2)))
        cfg = {
            "enabled": bool(body.get("enabled")),
            "webhook_url": webhook,
            "support_webhook_url": support_webhook,
            "on_offline_workstations": workstation_enabled,
            "offline_workstation_hours": workstation_hours,
            "on_offline_servers": server_enabled,
            "offline_server_hours": server_hours,
            # Keep rollback compatibility with the v1.15.2 dashboard/server.
            "on_offline": workstation_enabled or server_enabled,
            "offline_hours": min(workstation_hours, server_hours),
            "on_failed_job": bool(body.get("on_failed_job")),
            "on_failed_updates": bool(body.get("on_failed_updates")),
            "on_hardware": bool(body.get("on_hardware")),
            "on_monitoring": bool(body.get("on_monitoring", True)),
            "on_login": bool(body.get("on_login")),
            "on_login_fail": bool(body.get("on_login_fail")),
            "digest_daily": bool(body.get("digest_daily")),
        }
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('alerts', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(cfg),),
        )
    return {"ok": True}


@app.post("/api/alerts/test")
async def test_alert(request: Request):
    require_admin_role(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    url = str(body.get("webhook_url") or "").strip()
    route = str(body.get("route") or "alerts").strip().lower()
    if not url:
        with db() as conn:
            cfg = get_alerts(conn)
        url = (cfg.get("support_webhook_url") or cfg.get("webhook_url", "")) \
            if route == "support" else cfg.get("webhook_url", "")
    if not url:
        raise HTTPException(status_code=400, detail="Enter a webhook URL first")
    ok, detail = send_discord_strict(
        url,
        "✅ OpenPrime-RMM support Discord test" if route == "support" else "✅ OpenPrime-RMM test alert",
        "Support requests will post to this dedicated Discord channel."
        if route == "support" else "If you can read this in Discord, alerts are configured correctly.",
        color=0x1F8A4C)
    if not ok:
        raise HTTPException(status_code=502, detail=detail)
    return {"ok": True, "detail": detail}


# ---------------------------- Dashboard API --------------------------------


@app.post("/api/login")
async def login(request: Request, response: Response):
    """Password stage of dashboard authentication.

    Users without TOTP receive a normal session immediately. Users with TOTP
    receive only a short-lived HttpOnly verification challenge; no dashboard
    session exists until /api/login/verify succeeds.
    """
    ip = client_ip(request)
    if login_throttled(ip):
        raise HTTPException(status_code=429, detail="Too many attempts — wait 10 minutes")
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone()
    if not user or not verify_password(password, user["pw_hash"]):
        _login_fail.setdefault(ip, []).append(time.time())
        try:
            with db() as c2:
                acfg = get_alerts(c2)
            if acfg.get("enabled") and acfg.get("webhook_url") and acfg.get("on_login_fail", True):
                send_discord(acfg["webhook_url"], "🔐 Failed dashboard login",
                             f"**Username tried:** {username or '(blank)'}\n**From IP:** {ip}\n"
                             f"**When:** {time.strftime('%Y-%m-%d %H:%M %Z')}",
                             color=0xB7791F)
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Wrong username or password")

    if user["totp_enabled"]:
        response.set_cookie(
            "outpost_login_challenge",
            make_login_challenge(user["id"], user["username"], user["role"], ip),
            httponly=True, samesite="strict", secure=True,
            max_age=LOGIN_CHALLENGE_SECONDS, path="/",
        )
        return {"ok": True, "requires_totp": True, "username": user["username"]}

    return _complete_dashboard_login(request, response, user, ip)


@app.post("/api/login/verify")
async def login_verify(request: Request, response: Response):
    """Second dashboard authentication step for TOTP-enabled users."""
    ip = client_ip(request)
    if login_throttled(ip):
        raise HTTPException(status_code=429, detail="Too many attempts — wait 10 minutes")
    challenge = login_challenge_data(
        request.cookies.get("outpost_login_challenge"), ip
    )
    if not challenge:
        response.delete_cookie("outpost_login_challenge", path="/")
        raise HTTPException(status_code=401, detail="Verification expired — sign in again")
    body = await request.json()
    code = str(body.get("totp", "")).strip()
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (challenge["uid"],)).fetchone()
    if (not user or not user["totp_enabled"] or
            not totp_verify(user["totp_secret"], code)):
        _login_fail.setdefault(ip, []).append(time.time())
        try:
            with db() as c2:
                acfg = get_alerts(c2)
            if acfg.get("enabled") and acfg.get("webhook_url") and acfg.get("on_login_fail", True):
                send_discord(acfg["webhook_url"], "🔐 Failed dashboard 2FA",
                             f"**User:** {challenge.get('u', '?')}\n**From IP:** {ip}\n"
                             f"**When:** {time.strftime('%Y-%m-%d %H:%M %Z')}",
                             color=0xB7791F)
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid verification code")
    response.delete_cookie("outpost_login_challenge", path="/")
    return _complete_dashboard_login(request, response, user, ip)


@app.post("/api/login/cancel")
def login_cancel(response: Response):
    """Discard an unfinished second-factor challenge."""
    response.delete_cookie("outpost_login_challenge", path="/")
    return {"ok": True}


def _complete_dashboard_login(request: Request, response: Response, user, ip: str) -> dict:
    """Mint the dashboard session only after every required factor succeeds."""
    with db() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), user["id"]))
    try:
        with db() as c2:
            acfg = get_alerts(c2)
        if acfg.get("enabled") and acfg.get("webhook_url") and acfg.get("on_login"):
            send_discord(acfg["webhook_url"], "🔓 Dashboard sign-in",
                         f"**User:** {user['username']}\n**From IP:** {ip}\n"
                         f"**When:** {time.strftime('%Y-%m-%d %H:%M %Z')}", color=0x1F8A4C)
    except Exception:
        pass
    audit(request, "login", user["username"], f"from {ip}",
          user={"u": user["username"]})
    response.set_cookie(
        "outpost_session",
        make_session_cookie(user["id"], user["username"], user["role"]),
        httponly=True, samesite="strict", secure=True, max_age=SESSION_HOURS * 3600,
        path="/",
    )
    response.delete_cookie("outpost_login_challenge", path="/")
    return {"ok": True, "requires_totp": False,
            "username": user["username"], "role": user["role"]}


@app.get("/api/me")
def whoami(request: Request):
    data = current_user(request)
    with db() as conn:
        row = conn.execute("SELECT totp_enabled FROM users WHERE id=?", (data.get("uid"),)).fetchone()
    return {"username": data.get("u"), "role": data.get("r"), "uid": data.get("uid"),
            "totp_enabled": bool(row["totp_enabled"]) if row else False,
            "version": SERVER_VERSION}


def derive_server_url(request: Request) -> str:
    """Best-effort public URL of this server. Prefers an explicit env override,
    else reconstructs from the proxy's forwarded headers."""
    override = os.environ.get("OUTPOST_PUBLIC_URL", "").strip()
    if override:
        return override.rstrip("/")
    # Behind Apache -> Caddy, the original host/scheme arrive as forwarded headers
    host = (request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host") or "")
    proto = request.headers.get("X-Forwarded-Proto", "https")
    host = host.split(",")[0].strip()
    if not host:
        return ""
    return f"{proto}://{host}".rstrip("/")


@app.get("/api/deploy-info")
def deploy_info(request: Request):
    """Everything the dashboard needs to render a copy-paste enroll command.
    Admin-only: the enroll key is sensitive."""
    require_admin_role(request)
    with db() as conn:
        orgs = [dict(r) for r in conn.execute(
            "SELECT id, name FROM orgs ORDER BY name COLLATE NOCASE"
        )]
    return {
        "server_url": derive_server_url(request),
        "enroll_key": ENROLL_KEY,
        "orgs": orgs,
    }


# User management (admin only, except self password change) --------------------


@app.get("/api/users")
def list_users(request: Request):
    require_admin_role(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at, last_login FROM users"
            " ORDER BY role, username COLLATE NOCASE"
        ).fetchall()
    return {"users": [dict(r) for r in rows]}


@app.post("/api/users")
async def create_user(request: Request):
    require_admin_role(request)
    body = await request.json()
    username = str(body.get("username", "")).strip()[:64]
    password = str(body.get("password", ""))
    role = body.get("role", "tech")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    if role not in ("admin", "tech"):
        raise HTTPException(status_code=400, detail="Bad role")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",
                        (username,)).fetchone():
            raise HTTPException(status_code=400, detail="That username already exists")
        conn.execute(
            "INSERT INTO users (username, pw_hash, role, created_at) VALUES (?,?,?,?)",
            (username, hash_password(password), role, time.time()),
        )
    return {"ok": True}


@app.post("/api/users/{user_id}/password")
async def admin_reset_password(user_id: int, request: Request):
    require_admin_role(request)
    body = await request.json()
    password = str(body.get("password", ""))
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown user")
        conn.execute("UPDATE users SET pw_hash=? WHERE id=?",
                     (hash_password(password), user_id))
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, request: Request):
    data = require_admin_role(request)
    if data.get("uid") == user_id:
        raise HTTPException(status_code=400, detail="You can't delete your own account")
    with db() as conn:
        # Never remove the last admin
        row = conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown user")
        if row["role"] == "admin":
            n = conn.execute("SELECT COUNT(*) n FROM users WHERE role='admin'").fetchone()["n"]
            if n <= 1:
                raise HTTPException(status_code=400, detail="Can't delete the last admin")
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    return {"ok": True}


@app.post("/api/change-password")
async def change_own_password(request: Request):
    """Any signed-in user changing their own password (needs current password)."""
    data = current_user(request)
    body = await request.json()
    current = str(body.get("current_password", ""))
    new = str(body.get("new_password", ""))
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (data["uid"],)).fetchone()
        if not user or not verify_password(current, user["pw_hash"]):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        conn.execute("UPDATE users SET pw_hash=? WHERE id=?",
                     (hash_password(new), data["uid"]))
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("outpost_session", path="/")
    response.delete_cookie("outpost_login_challenge", path="/")
    return {"ok": True}


RECENT_STORAGE_WARNING_DAYS = 7


def _recent_storage_warning_map(conn: sqlite3.Connection, days: int = RECENT_STORAGE_WARNING_DAYS) -> dict:
    """Return the latest resolved disk-I/O incident detected within the recent-history window.

    The endpoint intentionally reports disk_events only for the last 24 hours.  We keep a
    longer MSP-visible warning without touching the agent by using the monitoring incident
    history that OpenPrimeRMM already persists.  first_seen is used as the event-detection
    anchor so the yellow state expires seven days after the original detection, not seven
    days after the incident finally aged out of the 24-hour endpoint window.
    """
    cutoff = time.time() - max(1, int(days)) * 86400
    rows = conn.execute(
        """SELECT agent_id, id, severity, message, value_text, threshold_text,
                  first_seen, last_seen, resolved_at
           FROM monitor_incidents
           WHERE incident_type='disk_io_events'
             AND status='resolved'
             AND agent_id IS NOT NULL
             AND first_seen >= ?
           ORDER BY first_seen DESC, id DESC""",
        (cutoff,),
    ).fetchall()
    recent = {}
    for row in rows:
        agent_id = row["agent_id"]
        if agent_id in recent:
            continue
        recent[agent_id] = {
            "incident_id": row["id"],
            "first_seen": float(row["first_seen"] or 0),
            "last_seen": float(row["last_seen"] or 0),
            "resolved_at": float(row["resolved_at"] or 0),
            "message": row["message"] or "Disk I/O error",
            "value_text": row["value_text"] or "",
        }
    return recent


def _apply_recent_storage_warning(machine: dict, recent_event: dict | None) -> None:
    """Attach seven-day storage history, unless an active disk/SMART fault supersedes it."""
    active_storage_fault = bool(machine.get("disk_io_warning") or machine.get("hw_warning"))
    recent = bool(recent_event and not active_storage_fault)
    machine["recent_storage_warning"] = recent
    machine["recent_storage_event"] = recent_event if recent else None
    machine["storage_health_state"] = (
        "critical" if active_storage_fault else ("recent" if recent else "healthy")
    )


def _machine_dict(row: sqlite3.Row, pending: int, approved: int, failed: int = 0, desired_managed: bool | None = None) -> dict:
    online = bool(row["last_seen"]) and (time.time() - row["last_seen"]) < OFFLINE_AFTER_SECONDS
    keys = row.keys()
    try:
        disks = json.loads(row["disks"] or "[]")
    except (ValueError, TypeError):
        disks = []
    try:
        ext_inventory = json.loads(row["ext_inventory"] or "{}") if "ext_inventory" in keys else {}
    except (ValueError, TypeError):
        ext_inventory = {}
    try:
        disk_health = json.loads(row["disk_health"] or "[]") if "disk_health" in keys else []
    except (ValueError, TypeError):
        disk_health = []
    try:
        disk_events = json.loads(row["disk_events"] or "{}") if "disk_events" in keys else {}
    except (ValueError, TypeError):
        disk_events = {}
    if not isinstance(disk_events, dict):
        disk_events = {}
    try:
        wu_management = json.loads(row["wu_management"] or "{}") if "wu_management" in keys else {}
    except (ValueError, TypeError):
        wu_management = {}
    if not isinstance(wu_management, dict):
        wu_management = {}
    else:
        wu_management = dict(wu_management)
    if desired_managed is not None:
        wu_management["desired_managed"] = bool(desired_managed)
    low_disk = any(
        d.get("total_gb", 0) > 0 and
        (d.get("free_gb", 0) < 10 or d.get("free_gb", 0) / d["total_gb"] < 0.10)
        for d in disks if isinstance(d, dict)
    )
    smart_failures = (row["smart_failures"] if "smart_failures" in keys else 0) or 0
    physical_warning = bool([
        d for d in disk_health
        if isinstance(d, dict) and str(d.get("health", "")).lower() not in ("healthy", "")
    ] or smart_failures)
    disk_event_count = int(disk_events.get("count") or 0)
    disk_io_warning = disk_event_count > 0
    return {
        "id": row["id"],
        "hostname": row["hostname"],
        "os_version": row["os_version"],
        "ip": row["ip"],
        "public_ip": (row["public_ip"] if "public_ip" in keys else "") or "",
        "local_ip": (row["local_ip"] if "local_ip" in keys else "") or "",
        "macs": (json.loads(row["macs"] or "[]") if "macs" in keys else []),
        "agent_version": row["agent_version"],
        "reboot_required": bool(row["reboot_required"]),
        "last_seen": row["last_seen"],
        "online": online,
        "pending_updates": pending,
        "approved_updates": approved,
        "failed_updates": failed,
        "org_id": row["org_id"],
        "org_name": row["org_name"] if "org_name" in keys else None,
        "location_id": (row["location_id"] if "location_id" in keys else None),
        "location_name": (row["location_name"] if "location_name" in keys else None),
        "disk_health": disk_health,
        "ext_inventory": ext_inventory,
        "device_class": (row["device_class"] if "device_class" in keys else "") or "",
        "device_class_effective": device_class_of(row),
        "smart_failures": smart_failures,
        "hw_warning": physical_warning,
        "disk_io_warning": disk_io_warning,
        "disk_event_count": disk_event_count,
        "health_warning": bool(physical_warning or disk_io_warning or low_disk),
        "bdgz_protected": row["bdgz_protected"] if "bdgz_protected" in keys else None,
        "disk_events": disk_events,
        "serial": row["serial"] or "",
        "model": row["model"] or "",
        "cpu": row["cpu"] or "",
        "ram_gb": row["ram_gb"] or 0,
        "memory_used_pct": (row["memory_used_pct"] if "memory_used_pct" in keys else None),
        "last_user": row["last_user"] or "",
        "disks": disks,
        "low_disk": low_disk,
        "screenconnect_session_id": (row["screenconnect_session_id"] if "screenconnect_session_id" in keys else "") or "",
        "screenconnect_service_name": (row["screenconnect_service_name"] if "screenconnect_service_name" in keys else "") or "",
        "windows_update_management": wu_management,
    }


def require_hermes_api(request: Request) -> None:
    """Authenticate the read-only Hermes integration API.

    This is intentionally separate from dashboard cookies and agent tokens. It
    allows a locally stored integration token to ask factual fleet questions
    without granting write endpoints or exposing endpoint secrets.
    """
    expected = HERMES_API_TOKEN.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Read-only API token is not configured")
    auth = request.headers.get("Authorization", "").strip()
    token = request.headers.get("X-Hermes-Token", "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid read-only API token")


def _machine_for_hermes(machine: dict) -> dict:
    last_seen = float(machine.get("last_seen") or 0)
    age = max(0, int(time.time() - last_seen)) if last_seen else None
    return {
        "id": machine.get("id"),
        "hostname": machine.get("hostname"),
        "org_id": machine.get("org_id"),
        "org_name": machine.get("org_name"),
        "location_id": machine.get("location_id"),
        "location_name": machine.get("location_name"),
        "online": bool(machine.get("online")),
        "last_seen": last_seen,
        "last_seen_age_seconds": age,
        "os_version": machine.get("os_version"),
        "device_class": machine.get("device_class"),
        "device_class_effective": machine.get("device_class_effective"),
        "agent_version": machine.get("agent_version"),
        "reboot_required": bool(machine.get("reboot_required")),
        "pending_updates": int(machine.get("pending_updates") or 0),
        "approved_updates": int(machine.get("approved_updates") or 0),
        "failed_updates": int(machine.get("failed_updates") or 0),
        "health_status": machine.get("health_status"),
        "open_incidents": int(machine.get("open_incidents") or 0),
        "critical_incidents": int(machine.get("critical_incidents") or 0),
        "health_warning": bool(machine.get("health_warning")),
        "storage_health_state": machine.get("storage_health_state"),
        "low_disk": bool(machine.get("low_disk")),
        "public_ip": machine.get("public_ip") or "",
        "local_ip": machine.get("local_ip") or "",
        "serial": machine.get("serial") or "",
        "model": machine.get("model") or "",
        "cpu": machine.get("cpu") or "",
        "ram_gb": machine.get("ram_gb") or 0,
        "memory_used_pct": machine.get("memory_used_pct"),
        "memory_alert": bool(machine.get("memory_alert")),
        "last_user": machine.get("last_user") or "",
        "disks": machine.get("disks") or [],
        "ext_inventory": machine.get("ext_inventory") or {},
        "windows_update_management": machine.get("windows_update_management") or {},
    }


def _hermes_machines(conn) -> list[dict]:
    agents = conn.execute(
        """SELECT a.*, o.name AS org_name, l.name AS location_name FROM agents a
           LEFT JOIN orgs o ON o.id = a.org_id
           LEFT JOIN locations l ON l.id = a.location_id
           ORDER BY o.name IS NULL, o.name COLLATE NOCASE,
                    l.name IS NULL, l.name COLLATE NOCASE, a.hostname"""
    ).fetchall()
    counts = {
        (r["agent_id"], r["status"]): r["n"]
        for r in conn.execute(
            "SELECT agent_id, status, COUNT(*) n FROM updates GROUP BY agent_id, status"
        )
    }
    desired_managed = {
        a["id"]: bool(effective_policy(conn, a["org_id"]).get("manage_windows_update"))
        for a in agents
    }
    machines = [
        _machine_for_hermes(_machine_dict(
            a,
            counts.get((a["id"], "pending"), 0) + counts.get((a["id"], "failed"), 0),
            counts.get((a["id"], "approved"), 0),
            counts.get((a["id"], "failed"), 0),
            desired_managed.get(a["id"]),
        ))
        for a in agents
    ]
    return machines


def _matches_hermes_query(machine: dict, query: str) -> bool:
    if not query:
        return True
    haystack = " ".join(str(machine.get(k) or "") for k in (
        "id", "hostname", "org_name", "location_name", "os_version", "public_ip",
        "local_ip", "serial", "model", "last_user", "device_class_effective",
    )).lower()
    return query.lower() in haystack


@app.get("/api/hermes/fleet/summary")
def hermes_fleet_summary(request: Request):
    require_hermes_api(request)
    with db() as conn:
        machines = _hermes_machines(conn)
    overview = {
        "total": len(machines),
        "online": sum(1 for m in machines if m["online"]),
        "offline": sum(1 for m in machines if not m["online"]),
        "reboot_required": sum(1 for m in machines if m["reboot_required"]),
        "needs_attention": sum(1 for m in machines if m.get("health_status") != "healthy"),
        "with_pending_updates": sum(1 for m in machines if m["pending_updates"] > 0),
        "failed_update_devices": sum(1 for m in machines if m["failed_updates"] > 0),
        "critical_incident_devices": sum(1 for m in machines if m["critical_incidents"] > 0),
    }
    return {"overview": overview, "generated_at": time.time()}


@app.get("/api/hermes/devices")
def hermes_device_search(request: Request, q: str = "", status: str = "", limit: int = 25):
    require_hermes_api(request)
    query = (q or "").strip()[:120]
    status = (status or "").strip().lower()
    limit = max(1, min(int(limit or 25), 100))
    with db() as conn:
        machines = _hermes_machines(conn)
    if status in ("online", "offline"):
        want_online = status == "online"
        machines = [m for m in machines if bool(m["online"]) == want_online]
    machines = [m for m in machines if _matches_hermes_query(m, query)]
    return {"count": len(machines), "devices": machines[:limit]}


@app.get("/api/hermes/devices/{agent_id}")
def hermes_device_detail(agent_id: str, request: Request):
    require_hermes_api(request)
    with db() as conn:
        row = conn.execute(
            """SELECT a.*, o.name AS org_name, l.name AS location_name FROM agents a
               LEFT JOIN orgs o ON o.id = a.org_id
               LEFT JOIN locations l ON l.id = a.location_id
               WHERE a.id=?""",
            (agent_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown machine")
        counts = {
            r["status"]: r["n"]
            for r in conn.execute(
                "SELECT status, COUNT(*) n FROM updates WHERE agent_id=? GROUP BY status",
                (agent_id,),
            )
        }
        machine = _machine_for_hermes(_machine_dict(
            row,
            counts.get("pending", 0) + counts.get("failed", 0),
            counts.get("approved", 0),
            counts.get("failed", 0),
            bool(effective_policy(conn, row["org_id"]).get("manage_windows_update")),
        ))
        updates = [dict(u) for u in conn.execute(
            """SELECT update_id, kb, title, severity, size_mb, status, denied_by,
                      denied_at, detected_at
               FROM updates WHERE agent_id=? ORDER BY severity DESC, title LIMIT 100""",
            (agent_id,),
        )]
        jobs = [dict(j) for j in conn.execute(
            """SELECT id, type, label, status, exit_code, schedule_id, created_at,
                      finished_at
               FROM jobs WHERE agent_id=? ORDER BY created_at DESC LIMIT 25""",
            (agent_id,),
        )]
        incidents = [dict(i) for i in conn.execute(
            """SELECT id, severity, message, value_text, threshold_text, first_seen,
                      last_seen, status
               FROM monitor_incidents WHERE agent_id=? AND status='open'
               ORDER BY severity DESC, last_seen DESC LIMIT 25""",
            (agent_id,),
        )]
    return {"device": machine, "updates": updates, "jobs": jobs, "open_incidents": incidents}


@app.get("/api/machines")
def list_machines(request: Request):
    require_admin(request)
    with db() as conn:
        agents = conn.execute(
            """SELECT a.*, o.name AS org_name, l.name AS location_name FROM agents a
               LEFT JOIN orgs o ON o.id = a.org_id
               LEFT JOIN locations l ON l.id = a.location_id
               ORDER BY o.name IS NULL, o.name COLLATE NOCASE,
                        l.name IS NULL, l.name COLLATE NOCASE, a.hostname"""
        ).fetchall()
        counts = {
            (r["agent_id"], r["status"]): r["n"]
            for r in conn.execute(
                "SELECT agent_id, status, COUNT(*) n FROM updates GROUP BY agent_id, status"
            )
        }
        orgs = [dict(r) for r in conn.execute(
            "SELECT id, name FROM orgs ORDER BY name COLLATE NOCASE"
        )]
        locations = [dict(r) for r in conn.execute(
            "SELECT id, org_id, name FROM locations ORDER BY name COLLATE NOCASE"
        )]
        av_counts = {
            r["agent_id"]: r["n"] for r in conn.execute(
                """SELECT agent_id, COUNT(*) n FROM av_events
                   WHERE agent_id IS NOT NULL AND received_at > ?
                   GROUP BY agent_id""", (time.time() - 7 * 86400,))
        }
        monitor_counts = {
            r["agent_id"]: {"open": r["n"], "critical": r["critical_n"]}
            for r in conn.execute(
                """SELECT agent_id, COUNT(*) n,
                          SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) critical_n
                   FROM monitor_incidents
                   WHERE status='open' AND agent_id IS NOT NULL
                   GROUP BY agent_id"""
            )
        }
        memory_incidents = {
            r["agent_id"] for r in conn.execute(
                """SELECT agent_id FROM monitor_incidents
                   WHERE status='open' AND incident_type='high_memory'
                     AND agent_id IS NOT NULL"""
            )
        }
        recent_storage = _recent_storage_warning_map(conn)
        sc_cfg = get_screenconnect_settings(conn)
        desired_managed = {
            a["id"]: bool(effective_policy(conn, a["org_id"]).get("manage_windows_update"))
            for a in agents
        }
    machines = [
        _machine_dict(a, counts.get((a["id"], "pending"), 0) + counts.get((a["id"], "failed"), 0),
                      counts.get((a["id"], "approved"), 0),
                      counts.get((a["id"], "failed"), 0), desired_managed.get(a["id"]))
        for a in agents
    ]
    for m in machines:
        apply_screenconnect_links(m, sc_cfg)
        m["av_incidents"] = av_counts.get(m["id"], 0)
        mc = monitor_counts.get(m["id"], {"open": 0, "critical": 0})
        m["open_incidents"] = int(mc.get("open") or 0)
        m["critical_incidents"] = int(mc.get("critical") or 0)
        m["memory_alert"] = m["id"] in memory_incidents
        _apply_recent_storage_warning(m, recent_storage.get(m["id"]))
        m["health_status"] = "critical" if (m["critical_incidents"] or m["disk_io_warning"] or m["hw_warning"] or m["av_incidents"]) else (
            "warning" if (m["recent_storage_warning"] or m["open_incidents"] or m["health_warning"] or m["failed_updates"] or m["reboot_required"] or m["bdgz_protected"] == 0) else "healthy"
        )
    total = len(machines)
    overview = {
        "total": total,
        "online": sum(1 for m in machines if m["online"]),
        "with_pending": sum(1 for m in machines if m["pending_updates"] > 0),
        "pending_total": sum(m["pending_updates"] for m in machines),
        "reboot_required": sum(1 for m in machines if m["reboot_required"]),
        "with_failed": sum(1 for m in machines if m["failed_updates"] > 0),
        "installing": sum(1 for m in machines if m["approved_updates"] > 0),
        "hw_warnings": sum(1 for m in machines if m["health_warning"]),
        "with_incidents": sum(1 for m in machines if m["open_incidents"] > 0 or m["av_incidents"] > 0),
        "needs_attention": sum(1 for m in machines if m["health_status"] != "healthy"),
    }
    return {"machines": machines, "overview": overview, "orgs": orgs, "locations": locations}


@app.get("/api/machines/{agent_id}")
def machine_detail(agent_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        a = conn.execute(
            """SELECT a.*, o.name AS org_name, l.name AS location_name FROM agents a
               LEFT JOIN orgs o ON o.id = a.org_id
               LEFT JOIN locations l ON l.id = a.location_id
               WHERE a.id=?""",
            (agent_id,),
        ).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        updates = conn.execute(
            "SELECT update_id, kb, title, severity, size_mb, status, denied_by, denied_at, category, browse_only FROM updates"
            " WHERE agent_id=? ORDER BY severity DESC, title",
            (agent_id,),
        ).fetchall()
        jobs = conn.execute(
            "SELECT id, type, label, status, exit_code, schedule_id, created_at, finished_at"
            " FROM jobs WHERE agent_id=? ORDER BY created_at DESC LIMIT 100",
            (agent_id,),
        ).fetchall()
        pending = sum(1 for u in updates if u["status"] in ("pending", "failed"))
        approved = sum(1 for u in updates if u["status"] == "approved")
        failed = sum(1 for u in updates if u["status"] == "failed")
        incidents = conn.execute(
            """SELECT id, incident_type, severity, message, value_text, threshold_text,
                      first_seen, last_seen
               FROM monitor_incidents
               WHERE agent_id=? AND status='open'
               ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, last_seen DESC""",
            (agent_id,),
        ).fetchall()
        recent_storage_event = _recent_storage_warning_map(conn).get(agent_id)
        eff_live = effective_live_mode(conn, a)
        desired_managed = bool(effective_policy(conn, a["org_id"]).get("manage_windows_update"))
        sc_cfg = get_screenconnect_settings(conn)
        onboarding = _device_onboarding_dict(conn, agent_id)
    ov = a["live_mode"]
    live_override = "on" if ov == 1 else ("off" if ov == 0 else "inherit")
    conn_ts = _live_connected.get(agent_id)
    live_connected = bool(conn_ts and (time.time() - conn_ts) < 70)
    machine = _machine_dict(a, pending, approved, failed, desired_managed)
    apply_screenconnect_links(machine, sc_cfg)
    machine["open_incidents"] = len(incidents)
    machine["critical_incidents"] = sum(1 for i in incidents if i["severity"] == "critical")
    machine["memory_alert"] = any(i["incident_type"] == "high_memory" for i in incidents)
    _apply_recent_storage_warning(machine, recent_storage_event)
    machine["health_status"] = "critical" if (machine["critical_incidents"] or machine["disk_io_warning"] or machine["hw_warning"]) else (
        "warning" if (machine["recent_storage_warning"] or machine["open_incidents"] or machine["health_warning"] or machine["failed_updates"] or machine["reboot_required"] or machine["bdgz_protected"] == 0) else "healthy"
    )
    return {
        "machine": machine,
        "updates": [dict(u) for u in updates],
        "jobs": [dict(j) for j in jobs],
        "incidents": [dict(i) for i in incidents],
        "live_mode": {"effective": eff_live, "override": live_override,
                      "connected": live_connected},
        "onboarding": onboarding,
    }


@app.delete("/api/machines/{agent_id}")
def delete_machine(agent_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        conn.execute("DELETE FROM updates WHERE agent_id=?", (agent_id,))
        conn.execute("DELETE FROM jobs WHERE agent_id=?", (agent_id,))
        conn.execute("DELETE FROM wu_runs WHERE agent_id=?", (agent_id,))
        for r in conn.execute("SELECT id FROM onboarding_runs WHERE agent_id=?", (agent_id,)).fetchall():
            conn.execute("DELETE FROM onboarding_run_steps WHERE run_id=?", (r["id"],))
        conn.execute("DELETE FROM onboarding_runs WHERE agent_id=?", (agent_id,))
        conn.execute("DELETE FROM device_onboarding_state WHERE agent_id=?", (agent_id,))
        conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
    return {"ok": True}


@app.post("/api/machines/{agent_id}/class")
async def set_machine_class(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json()
    value = str(body.get("device_class") or "").strip().lower()
    if value not in ("", "server", "workstation"):
        raise HTTPException(status_code=400, detail="device_class must be '', 'server' or 'workstation'")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute("UPDATE agents SET device_class=? WHERE id=?", (value, agent_id))
    audit(request, "machine_class", agent_id, value or "auto")
    return {"ok": True}


@app.post("/api/machines/{agent_id}/uninstall")
async def machine_full_uninstall(agent_id: str, request: Request):
    """Order FULL removal of OpenPrimeRMM from the endpoint (agent 1.13.1+).

    Queues an uninstall_agent job carrying the MSI uninstall token. The agent
    acknowledges, then removes itself detached ~2 minutes later (authorized
    MSI uninstall with Windows Update restore, or script cleanup). When the
    acknowledgement result arrives, the device record is deleted
    automatically. If the endpoint never picks the job up (offline), nothing
    happens until it returns."""
    admin = require_admin(request)
    body = await request.json()
    token = str(body.get("uninstall_token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="uninstall_token required")
    now = time.time()
    with db() as conn:
        a = conn.execute("SELECT id, hostname, agent_version FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), agent_id, "uninstall_agent", "Full agent removal",
             json.dumps({"uninstall_token": token}), now),
        )
    audit(request, "machine_full_uninstall", agent_id, a["hostname"])
    return {"ok": True, "note": "Removal ordered; the record deletes itself when the endpoint acknowledges."}


@app.post("/api/machines/{agent_id}/updates/approve")
async def approve_updates(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json()
    with db() as conn:
        a = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        if body.get("all"):
            rows = conn.execute(
                "SELECT update_id, title FROM updates WHERE agent_id=?"
                " AND status NOT IN ('approved','denied')",
                (agent_id,),
            ).fetchall()
            ids = [r["update_id"] for r in rows]
        else:
            ids = [str(x) for x in body.get("update_ids", [])]
        if not ids:
            raise HTTPException(status_code=400, detail="No updates selected")
        result = _approve_and_queue_updates(conn, agent_id, ids, time.time())
        if not result["approved"]:
            raise HTTPException(status_code=400, detail="No pending updates selected")
    _nudge_agents[agent_id] = time.time() + 180
    _wake_agent(agent_id)
    return {"ok": True, "job_id": result["job_id"], "count": result["approved"]}


@app.post("/api/machines/{agent_id}/updates/deny")
async def deny_updates(agent_id: str, request: Request):
    """Deny selected updates, cancel queued installs, and refuse a misleading
    deny when Windows has already started installing that update."""
    user = require_admin(request)
    body = await request.json()
    ids = [str(x) for x in body.get("update_ids", []) if str(x)]
    if not ids:
        raise HTTPException(status_code=400, detail="No updates selected")
    now = time.time()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        conflicts = _running_update_conflicts(conn, agent_id, set(ids))
        if conflicts:
            raise HTTPException(
                status_code=409,
                detail="One or more selected updates are already installing and cannot be denied until that job finishes.",
            )
        job_changes = _cancel_pending_update_jobs(conn, agent_id, set(ids), now)
        qmarks = ",".join("?" for _ in ids)
        cur = conn.execute(
            f"UPDATE updates SET status='denied', denied_by=?, denied_at=?, status_changed_at=?"
            f" WHERE agent_id=? AND update_id IN ({qmarks}) AND status IN ('pending','failed','approved')",
            (user.get("u", ""), now, now, agent_id, *ids),
        )
    _nudge_agents[agent_id] = time.time() + 180
    _wake_agent(agent_id)
    audit(request, "patch_deny_device", agent_id,
          f"{cur.rowcount} update(s); {job_changes['cancelled']} job(s) cancelled; {job_changes['trimmed']} trimmed", user=user)
    return {"ok": True, "count": cur.rowcount, **job_changes}


@app.post("/api/machines/{agent_id}/updates/undeny")
async def undeny_updates(agent_id: str, request: Request):
    """Un-deny: return updates to pending so they can be approved again."""
    require_admin(request)
    body = await request.json()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        ids = [str(x) for x in body.get("update_ids", [])]
        if not ids:
            raise HTTPException(status_code=400, detail="No updates selected")
        qmarks = ",".join("?" for _ in ids)
        conn.execute(
            f"UPDATE updates SET status='pending', denied_by='', denied_at=NULL, status_changed_at=?"
            f" WHERE agent_id=? AND update_id IN ({qmarks}) AND status='denied'",
            (time.time(), agent_id, *ids),
        )
    _nudge_agents[agent_id] = time.time() + 180
    _wake_agent(agent_id)
    return {"ok": True, "count": len(ids)}


@app.get("/api/denied-updates")
def list_denied_updates(request: Request):
    """Fleet-wide view of everything that's been denied and on which machines."""
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            """SELECT u.update_id, u.kb, u.title, u.severity, u.denied_by, u.denied_at,
                      a.hostname, a.id AS agent_id, o.name AS org_name
               FROM updates u
               JOIN agents a ON a.id = u.agent_id
               LEFT JOIN orgs o ON o.id = a.org_id
               WHERE u.status='denied'
               ORDER BY u.denied_at DESC"""
        ).fetchall()
    return {"denied": [dict(r) for r in rows]}


# Patching (fleet-wide, NinjaOne-style) --------------------------------------

def _install_job_ids(row) -> list[str]:
    try:
        payload = json.loads(row["payload"] or "{}")
        return [str(x) for x in (payload.get("update_ids") or []) if str(x)]
    except (ValueError, TypeError):
        return []


def _approve_and_queue_updates(conn: sqlite3.Connection, agent_id: str,
                               update_ids: list[str], now: float,
                               label_prefix: str = "Install") -> dict:
    """Persist approval independently from endpoint availability.

    A technician may approve several patch groups in succession. Reuse an
    existing pending install job instead of treating it as a reason to skip the
    later decisions. IDs already present in a running job are not queued twice;
    other approved IDs are placed in a follow-up job.
    """
    requested = list(dict.fromkeys(str(uid) for uid in update_ids if str(uid)))
    if not requested:
        return {"approved": 0, "job_id": "", "jobs_created": 0, "jobs_merged": 0}
    placeholders = ",".join("?" for _ in requested)
    rows = conn.execute(
        f"SELECT update_id FROM updates WHERE agent_id=? "
        f"AND update_id IN ({placeholders}) AND status IN ('pending','failed')",
        (agent_id, *requested),
    ).fetchall()
    approved_ids = [row["update_id"] for row in rows]
    if not approved_ids:
        return {"approved": 0, "job_id": "", "jobs_created": 0, "jobs_merged": 0}

    approved_ph = ",".join("?" for _ in approved_ids)
    conn.execute(
        f"UPDATE updates SET status='approved', status_changed_at=? "
        f"WHERE agent_id=? AND update_id IN ({approved_ph})",
        (now, agent_id, *approved_ids),
    )

    active_jobs = conn.execute(
        "SELECT id, payload, status FROM jobs WHERE agent_id=? "
        "AND type='install_updates' AND status IN ('pending','running') ORDER BY created_at",
        (agent_id,),
    ).fetchall()
    already_queued = {uid for job in active_jobs for uid in _install_job_ids(job)}
    missing_ids = [uid for uid in approved_ids if uid not in already_queued]
    pending_job = next((job for job in active_jobs if job["status"] == "pending"), None)
    if missing_ids and pending_job:
        merged_ids = list(dict.fromkeys([*_install_job_ids(pending_job), *missing_ids]))
        conn.execute(
            "UPDATE jobs SET payload=?, label=? WHERE id=? AND status='pending'",
            (json.dumps({"update_ids": merged_ids}),
             f"{label_prefix} {len(merged_ids)} update(s)", pending_job["id"]),
        )
        return {"approved": len(approved_ids), "job_id": pending_job["id"],
                "jobs_created": 0, "jobs_merged": 1}
    if missing_ids:
        job_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (job_id, agent_id, "install_updates",
             f"{label_prefix} {len(missing_ids)} update(s)",
             json.dumps({"update_ids": missing_ids}), now),
        )
        return {"approved": len(approved_ids), "job_id": job_id,
                "jobs_created": 1, "jobs_merged": 0}
    return {"approved": len(approved_ids),
            "job_id": active_jobs[0]["id"] if active_jobs else "",
            "jobs_created": 0, "jobs_merged": 0}

def _running_update_conflicts(conn: sqlite3.Connection, agent_id: str, update_ids: set[str]) -> list[str]:
    conflicts = []
    for job in conn.execute(
        "SELECT id, payload FROM jobs WHERE agent_id=? AND type='install_updates' AND status='running'",
        (agent_id,),
    ).fetchall():
        if update_ids.intersection(_install_job_ids(job)):
            conflicts.append(job["id"])
    return conflicts

def _cancel_pending_update_jobs(conn: sqlite3.Connection, agent_id: str, update_ids: set[str], now: float) -> dict:
    """Remove denied updates from queued install jobs. Empty jobs become cancelled.

    This is deliberately server-side and runs before an endpoint can claim the job.
    """
    cancelled = 0
    trimmed = 0
    for job in conn.execute(
        "SELECT id, payload FROM jobs WHERE agent_id=? AND type='install_updates' AND status='pending'",
        (agent_id,),
    ).fetchall():
        old_ids = _install_job_ids(job)
        new_ids = [uid for uid in old_ids if uid not in update_ids]
        if len(new_ids) == len(old_ids):
            continue
        if not new_ids:
            conn.execute(
                "UPDATE jobs SET status='cancelled', output=?, exit_code=0, finished_at=? WHERE id=? AND status='pending'",
                ("Cancelled because the update was denied before installation started.", now, job["id"]),
            )
            cancelled += 1
        else:
            conn.execute(
                "UPDATE jobs SET payload=?, label=? WHERE id=? AND status='pending'",
                (json.dumps({"update_ids": new_ids}), f"Install {len(new_ids)} update(s)", job["id"]),
            )
            trimmed += 1
    return {"cancelled": cancelled, "trimmed": trimmed}

def _patch_normalize_text(value) -> str:
    """Stable comparison form for Windows Update identifiers and titles."""
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def _patch_normalize_kb(value) -> str:
    """Normalize the many KB formats PSWindowsUpdate can return.

    Examples such as ``KB5095093``, ``5095093`` and arrays stringified with
    punctuation all resolve to the same key when a KB number is present.
    """
    text = str(value or "").strip().upper()
    match = re.search(r"\bKB\s*[-:]?\s*(\d{4,})\b", text)
    if not match:
        match = re.search(r"\b(\d{6,})\b", text)
    return f"KB{match.group(1)}" if match else _patch_normalize_text(text).upper()


_WORKER_CLASS_LABELS = {
    "driver": "Driver updates",
    "firmware": "Firmware updates",
    "feature": "Feature updates",
    "optional": "Preview / optional",
}


def _patch_display_category(worker_class: str, title: str, kb: str = "") -> str:
    """Prefer the category the Windows Update worker reported; refine
    'standard' (and legacy rows without a class) with the title heuristic."""
    label = _WORKER_CLASS_LABELS.get(str(worker_class or "").lower())
    if label:
        return label
    return _patch_category(title, kb)


def _patch_category(title: str, kb: str = "") -> str:
    """Best-effort display category derived from Windows Update metadata."""
    text = (title or "").lower()
    kb_upper = (kb or "").upper()
    if "driver" in text:
        return "Driver updates"
    if any(x in text for x in ("defender", "security intelligence", "definition update")):
        return "Definition updates"
    if ".net" in text:
        return ".NET updates"
    if any(x in text for x in ("feature update", "enablement package")):
        return "Feature updates"
    if any(x in text for x in ("preview", "optional update")):
        return "Preview / optional"
    if any(x in text for x in ("security update", "cumulative update")) or kb_upper.startswith("KB"):
        return "Security updates"
    return "Other"


def _patch_severity_rank(severity: str) -> int:
    value = (severity or "").strip().lower()
    if value == "critical":
        return 0
    if value == "important":
        return 1
    if value in ("moderate", "recommended"):
        return 2
    return 3


@app.get("/api/patching/overview")
def patching_overview(request: Request):
    """Visual fleet patch summary. Existing response fields are retained for
    compatibility, with richer data added for the dashboard."""
    require_admin(request)
    now = time.time()
    with db() as conn:
        agent_rows = conn.execute(
            """SELECT a.id, a.hostname, a.os_version, a.last_seen,
                      a.reboot_required, o.name AS org_name
               FROM agents a
               LEFT JOIN orgs o ON o.id=a.org_id
               ORDER BY a.hostname COLLATE NOCASE"""
        ).fetchall()
        update_rows = conn.execute(
            """SELECT u.agent_id, u.update_id, u.kb, u.title, u.severity,
                      u.size_mb, u.status, u.detected_at,
                      a.hostname, a.os_version, a.last_seen,
                      o.name AS org_name
               FROM updates u
               JOIN agents a ON a.id=u.agent_id
               LEFT JOIN orgs o ON o.id=a.org_id
               ORDER BY LOWER(u.title), LOWER(a.hostname)"""
        ).fetchall()

    status_counts = {"pending": 0, "approved": 0, "failed": 0, "denied": 0}
    per_agent = {}
    for row in update_rows:
        status = row["status"] or "pending"
        status_counts[status] = status_counts.get(status, 0) + 1
        counts = per_agent.setdefault(row["agent_id"], {
            "pending": 0, "approved": 0, "failed": 0, "denied": 0,
        })
        counts[status] = counts.get(status, 0) + 1

    total_devices = len(agent_rows)
    outstanding_ids = {
        aid for aid, values in per_agent.items()
        if values.get("pending", 0) or values.get("approved", 0) or values.get("failed", 0)
    }
    compliant_devices = max(0, total_devices - len(outstanding_ids))
    compliance_pct = round(
        100.0 * compliant_devices / total_devices, 2
    ) if total_devices else 100.0

    os_counts = {}
    top_devices = []
    online_devices = 0
    reboot_required = 0
    for agent in agent_rows:
        os_name = (agent["os_version"] or "Unspecified").strip() or "Unspecified"
        os_counts[os_name] = os_counts.get(os_name, 0) + 1
        is_online = (now - float(agent["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS
        if is_online:
            online_devices += 1
        if agent["reboot_required"]:
            reboot_required += 1
        counts = per_agent.get(agent["id"], {})
        pending = counts.get("pending", 0)
        failed = counts.get("failed", 0)
        approved = counts.get("approved", 0)
        outstanding = pending + failed + approved
        if outstanding:
            top_devices.append({
                "agent_id": agent["id"],
                "hostname": agent["hostname"],
                "org_name": agent["org_name"] or "Unassigned",
                "os_version": agent["os_version"] or "",
                "online": is_online,
                "reboot_required": bool(agent["reboot_required"]),
                "pending": pending,
                "failed": failed,
                "approved": approved,
                "n": outstanding,  # old UI compatibility
            })
    top_devices.sort(key=lambda x: (-x["n"], -x["failed"], x["hostname"].lower()))

    age_buckets = {"0-29": 0, "30-59": 0, "60-89": 0, "90+": 0}
    category_counts = {}
    grouped_updates = {}
    for row in update_rows:
        if row["status"] not in ("pending", "failed"):
            continue
        detected_at = float(row["detected_at"] or now)
        age_days = max(0, int((now - detected_at) // 86400))
        if age_days < 30:
            age_buckets["0-29"] += 1
        elif age_days < 60:
            age_buckets["30-59"] += 1
        elif age_days < 90:
            age_buckets["60-89"] += 1
        else:
            age_buckets["90+"] += 1

        category = _patch_category(row["title"], row["kb"])
        category_counts[category] = category_counts.get(category, 0) + 1
        key = row["update_id"]
        group = grouped_updates.setdefault(key, {
            "update_id": row["update_id"],
            "kb": row["kb"] or "",
            "title": row["title"] or row["update_id"],
            "severity": row["severity"] or "",
            "category": category,
            "size_mb": row["size_mb"] or 0,
            "first_seen": detected_at,
            "latest_seen": detected_at,
            "pending_count": 0,
            "failed_count": 0,
            "devices": [],
        })
        group["first_seen"] = min(group["first_seen"], detected_at)
        group["latest_seen"] = max(group["latest_seen"], detected_at)
        if row["status"] == "failed":
            group["failed_count"] += 1
        else:
            group["pending_count"] += 1
        group["devices"].append({
            "agent_id": row["agent_id"],
            "hostname": row["hostname"],
            "org_name": row["org_name"] or "Unassigned",
            "os_version": row["os_version"] or "",
            "status": row["status"],
            "online": (now - float(row["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS,
            "age_days": age_days,
        })

    top_pending_updates = list(grouped_updates.values())
    for group in top_pending_updates:
        group["device_count"] = len(group["devices"])
        group["sample_devices"] = group["devices"][:8]
    top_pending_updates.sort(
        key=lambda x: (-x["device_count"], -x["failed_count"],
                       _patch_severity_rank(x["severity"]), x["title"].lower())
    )

    failed_devices = sum(1 for c in per_agent.values() if c.get("failed", 0))
    devices_with_pending = sum(
        1 for c in per_agent.values() if c.get("pending", 0) or c.get("failed", 0)
    )
    os_breakdown = [
        {"os": name, "n": count}
        for name, count in sorted(os_counts.items(), key=lambda item: (-item[1], item[0].lower()))
    ]
    category_breakdown = [
        {"category": name, "n": count}
        for name, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0].lower()))
    ]

    return {
        # Existing fields retained
        "total_devices": total_devices,
        "compliant_devices": compliant_devices,
        "compliance_pct": compliance_pct,
        "failed_devices": failed_devices,
        "counts": status_counts,
        "os_breakdown": os_breakdown,
        "top_devices": top_devices[:10],
        "age_buckets": age_buckets,
        # Rich visual dashboard fields
        "online_devices": online_devices,
        "devices_with_pending": devices_with_pending,
        "reboot_required": reboot_required,
        "category_breakdown": category_breakdown,
        "top_pending_updates": top_pending_updates[:10],
    }


@app.get("/api/backups")
def backups_overview(request: Request):
    """Fleet backup posture from the agents' Macrium/Veeam event-log reports.

    States: ok (recent success), stale (no success within the customer's
    backup_stale_days), failing (latest failure is newer than the latest
    success), none (no backup product events detected on the device)."""
    require_admin(request)
    now = time.time()
    out = []
    with db() as conn:
        global_pol = get_policy(conn)
        org_pol: dict = {}
        rows = conn.execute(
            """SELECT a.id, a.hostname, a.org_id, a.last_seen, a.ext_inventory,
                      a.software, o.name AS org_name
               FROM agents a LEFT JOIN orgs o ON o.id=a.org_id
               ORDER BY LOWER(a.hostname)"""
        ).fetchall()
        for r in rows:
            if r["org_id"] not in org_pol:
                org_pol[r["org_id"]] = effective_policy(conn, r["org_id"]) if r["org_id"] else global_pol
            threshold = max(1, int(org_pol[r["org_id"]].get("backup_stale_days") or 3))
            try:
                ext = json.loads(r["ext_inventory"] or "{}")
            except (ValueError, TypeError):
                ext = {}
            products = ext.get("backup") if isinstance(ext.get("backup"), list) else []
            # Installed backup software (name + version) from the software
            # inventory — richer than the event-derived product name alone.
            installed = []
            try:
                for s in json.loads(r["software"] or "[]"):
                    n = str(s.get("name") or "")
                    if re.search(r"macrium|veeam|reflect", n, re.I):
                        v = str(s.get("version") or "").strip()
                        installed.append(f"{n} {v}".strip())
            except (ValueError, TypeError, AttributeError):
                pass
            best_success = None
            latest_failure = None
            names = []
            failure_note = ""
            for p in products:
                if not isinstance(p, dict):
                    continue
                names.append(str(p.get("product") or "?"))
                ls = str(p.get("last_success") or "")
                lf = str(p.get("last_failure") or "")
                if ls and (best_success is None or ls > best_success):
                    best_success = ls
                if lf and (latest_failure is None or lf > latest_failure):
                    latest_failure = lf
                    failure_note = str(p.get("failure_note") or "")[:160]
            age_days = None
            if best_success:
                try:
                    age_days = round((now - time.mktime(time.strptime(best_success, "%Y-%m-%d %H:%M"))) / 86400, 1)
                except (ValueError, OverflowError):
                    age_days = None
            if not products:
                state = "none"
            elif latest_failure and (not best_success or latest_failure > best_success):
                state = "failing"
            elif best_success is None or (age_days is not None and age_days > threshold):
                state = "stale"
            else:
                state = "ok"
            out.append({
                "agent_id": r["id"], "hostname": r["hostname"],
                "org_name": r["org_name"] or "Unassigned",
                "online": (now - float(r["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS,
                "products": names, "installed": installed[:3],
                "last_success": best_success,
                "last_failure": latest_failure, "failure_note": failure_note,
                "age_days": age_days, "threshold_days": threshold, "state": state,
            })
    rank = {"failing": 0, "stale": 1, "none": 2, "ok": 3}
    out.sort(key=lambda x: (rank.get(x["state"], 9),
                            -(x["age_days"] if x["age_days"] is not None else 9999),
                            x["org_name"].lower(), x["hostname"].lower()))
    counts = {"ok": 0, "stale": 0, "failing": 0, "none": 0}
    for d in out:
        counts[d["state"]] = counts.get(d["state"], 0) + 1
    return {"devices": out, "summary": counts}


@app.get("/api/patching/pending")
def patching_pending(request: Request):
    """Fleet update list grouped by update ID, including the matching devices
    so the dashboard can expand a row without an extra round trip."""
    require_admin(request)
    status = request.query_params.get("status", "pending")
    if status not in ("pending", "approved", "failed", "denied", "outstanding", "actionable"):
        status = "pending"
    allowed = (("pending", "approved", "failed") if status == "outstanding"
               else (("pending", "failed") if status == "actionable" else (status,)))
    placeholders = ",".join("?" for _ in allowed)
    now = time.time()
    with db() as conn:
        rows = conn.execute(
            f"""SELECT u.agent_id, u.update_id, u.kb, u.title, u.severity,
                       u.size_mb, u.status, u.detected_at,
                       u.category AS worker_class, u.browse_only,
                       a.hostname, a.os_version, a.last_seen,
                       o.name AS org_name
                FROM updates u
                JOIN agents a ON a.id=u.agent_id
                LEFT JOIN orgs o ON o.id=a.org_id
                WHERE u.status IN ({placeholders})
                ORDER BY LOWER(u.title), LOWER(a.hostname)""",
            allowed,
        ).fetchall()
        global_pol = get_policy(conn)

    grouped = {}
    for row in rows:
        detected_at = float(row["detected_at"] or now)
        age_days = max(0, int((now - detected_at) // 86400))
        # Windows publishes drivers as multiple catalog entries (distinct
        # UpdateIDs) with identical titles. Group by KB when present,
        # otherwise by normalized title, so visually identical updates
        # stack into one row; per-variant IDs are kept for actions.
        merge_key = ("kb:" + row["kb"].strip().upper()) if (row["kb"] or "").strip() else ("t:" + (row["title"] or row["update_id"]).strip().lower())
        group = grouped.setdefault(merge_key, {
            "update_id": row["update_id"],
            "kb": row["kb"] or "",
            "title": row["title"] or row["update_id"],
            "severity": row["severity"] or "",
            "category": _patch_display_category(row["worker_class"], row["title"], row["kb"]),
            "category_class": str(row["worker_class"] or "").lower(),
            "browse_only": bool(row["browse_only"]),
            "stance": policy_category_stance(global_pol, {"category": row["worker_class"], "browse_only": row["browse_only"]}),
            "size_mb": row["size_mb"] or 0,
            "first_seen": detected_at,
            "latest_seen": detected_at,
            "pending_count": 0,
            "failed_count": 0,
            "approved_count": 0,
            "denied_count": 0,
            "devices": [],
        })
        group["first_seen"] = min(group["first_seen"], detected_at)
        group["latest_seen"] = max(group["latest_seen"], detected_at)
        count_key = f"{row['status']}_count"
        group[count_key] = group.get(count_key, 0) + 1
        ids = group.setdefault("update_ids", [])
        if row["update_id"] not in ids:
            ids.append(row["update_id"])
        devmap = group.setdefault("_devmap", {})
        existing = devmap.get(row["agent_id"])
        if existing:
            existing["instances"] += 1
            # surface the most actionable status for the device row
            order = {"failed": 3, "pending": 2, "approved": 1, "denied": 0}
            if order.get(row["status"], 0) > order.get(existing["status"], 0):
                existing["status"] = row["status"]
            existing["age_days"] = max(existing["age_days"], age_days)
        else:
            devmap[row["agent_id"]] = {
                "agent_id": row["agent_id"],
                "hostname": row["hostname"],
                "org_name": row["org_name"] or "Unassigned",
                "os_version": row["os_version"] or "",
                "status": row["status"],
                "online": (now - float(row["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS,
                "age_days": age_days,
                "instances": 1,
            }

    updates = list(grouped.values())
    for group in updates:
        group["devices"] = list(group.pop("_devmap", {}).values())
        group["variant_count"] = len(group.get("update_ids") or [group["update_id"]])
        group["device_count"] = len(group["devices"])
        ages = [device["age_days"] for device in group["devices"]]
        group["avg_age_days"] = round(sum(ages) / len(ages)) if ages else 0
        group["max_age_days"] = max(ages) if ages else 0
        group["devices"].sort(key=lambda x: (x["org_name"].lower(), x["hostname"].lower()))
    updates.sort(
        key=lambda x: (-x["device_count"], -x["failed_count"],
                       _patch_severity_rank(x["severity"]), x["title"].lower())
    )
    summary = {"groups": len(updates), "instances": len(rows),
               "actionable": 0, "manual": 0, "report_only": 0}
    for group in updates:
        stance = group.get("stance") or "auto"
        if stance == "report":
            summary["report_only"] += 1
        elif stance == "manual":
            summary["manual"] += 1
        else:
            summary["actionable"] += 1
    return {"status": status, "updates": updates, "summary": summary}


@app.get("/api/patching/update/{update_id}")
def patching_update_devices(update_id: str, request: Request):
    """Which devices are affected by one update, retained for compatibility."""
    require_admin(request)
    now = time.time()
    with db() as conn:
        meta = conn.execute(
            "SELECT update_id, MAX(kb) kb, MAX(title) title, MAX(severity) severity,"
            " MAX(size_mb) size_mb FROM updates WHERE update_id=?", (update_id,)
        ).fetchone()
        devices = conn.execute(
            """SELECT a.id AS agent_id, a.hostname, a.os_version, a.last_seen,
                      o.name AS org_name, u.status, u.detected_at
               FROM updates u JOIN agents a ON a.id=u.agent_id
               LEFT JOIN orgs o ON o.id=a.org_id
               WHERE u.update_id=? ORDER BY a.hostname""", (update_id,)
        ).fetchall()
    output = []
    for device in devices:
        item = dict(device)
        item["age_days"] = max(0, int((now - float(item.get("detected_at") or now)) // 86400))
        item["online"] = (now - float(item.get("last_seen") or 0)) < OFFLINE_AFTER_SECONDS
        output.append(item)
    return {"update": dict(meta) if meta else {}, "devices": output}


@app.post("/api/patching/approve")
async def patching_approve_update(request: Request):
    """Approve one update across all matching pending/failed devices."""
    user = await asyncio.to_thread(require_admin, request)
    body = await request.json()
    return await asyncio.to_thread(_patching_approve_sync, request, body, user)


def _patching_approve_sync(request: Request, body: dict, user: dict):
    update_id = str(body.get("update_id", ""))
    update_ids = [str(u) for u in (body.get("update_ids") or []) if str(u)]
    if update_id and update_id not in update_ids:
        update_ids.append(update_id)
    if not update_ids:
        raise HTTPException(status_code=400, detail="update_id required")
    limit_ids = body.get("agent_ids")
    if limit_ids is not None and not isinstance(limit_ids, list):
        raise HTTPException(status_code=400, detail="agent_ids must be a list")
    now = time.time()
    approved_devices = 0
    jobs_created = 0
    jobs_merged = 0
    targets = []
    with db() as conn:
        placeholders = ",".join("?" for _ in update_ids)
        rows = conn.execute(
            f"SELECT DISTINCT agent_id FROM updates WHERE update_id IN ({placeholders})"
            " AND status IN ('pending','failed')", update_ids
        ).fetchall()
        targets = [row["agent_id"] for row in rows]
        if limit_ids is not None:
            allowed_ids = set(limit_ids)
            targets = [target for target in targets if target in allowed_ids]
        for agent_id in targets:
            agent_ids_for_update = [
                r["update_id"] for r in conn.execute(
                    f"SELECT update_id FROM updates WHERE agent_id=?"
                    f" AND update_id IN ({placeholders})"
                    " AND status IN ('pending','failed')",
                    [agent_id, *update_ids],
                )
            ]
            if not agent_ids_for_update:
                continue
            result = _approve_and_queue_updates(conn, agent_id, agent_ids_for_update, now)
            if result["approved"]:
                approved_devices += 1
                jobs_created += result["jobs_created"]
                jobs_merged += result["jobs_merged"]
    for agent_id in targets:
        _nudge_agents[agent_id] = time.time() + 180
        _wake_agent(agent_id)
    audit(request, "patch_approve", update_ids[0],
          f"{approved_devices} device decision(s), {len(update_ids)} variant(s); "
          f"{jobs_created} job(s) created, {jobs_merged} merged", user=user)
    return {"ok": True, "devices": approved_devices,
            "jobs_created": jobs_created, "jobs_merged": jobs_merged}


@app.post("/api/patching/deny")
async def patching_deny_update(request: Request):
    """Deny an update across every matching actionable device.

    Windows Update can occasionally expose the same patch with different
    UpdateID values while retaining the same KB/title.  The original endpoint
    matched only the exact UpdateID, which could leave a visually identical row
    pending.  This implementation matches the exact ID first and also matches a
    supplied normalized KB or exact normalized title.  The dashboard supplies
    the affected agent IDs from the expanded patch group as an additional scope.
    """
    user = await asyncio.to_thread(require_admin, request)
    body = await request.json()
    return await asyncio.to_thread(_patching_deny_sync, request, body, user)


def _patching_deny_sync(request: Request, body: dict, user: dict):
    update_id = str(body.get("update_id", "")).strip()
    kb = str(body.get("kb", "")).strip()
    title = str(body.get("title", "")).strip()
    if not update_id and not kb and not title:
        raise HTTPException(status_code=400, detail="update_id, kb, or title required")

    limit_ids = body.get("agent_ids")
    allowed_ids = {str(x) for x in limit_ids if str(x)} if isinstance(limit_ids, list) else None
    uid_norm = _patch_normalize_text(update_id)
    kb_norm = _patch_normalize_kb(kb) if kb else ""
    title_norm = _patch_normalize_text(title) if title else ""
    now = time.time()

    matched_rows = []
    with db() as conn:
        scope_sql = ""
        scope_args = []
        if allowed_ids is not None:
            if len(allowed_ids) > 500:
                raise HTTPException(status_code=400, detail="Too many target devices")
            if allowed_ids:
                scope_sql = f" AND agent_id IN ({','.join('?' for _ in allowed_ids)})"
                scope_args = list(allowed_ids)
        rows = conn.execute(
            "SELECT id, agent_id, update_id, kb, title, status FROM updates "
            "WHERE status IN ('pending','failed','approved','denied')" + scope_sql,
            scope_args,
        ).fetchall() if allowed_ids is None or allowed_ids else []
        for row in rows:
            if allowed_ids is not None and row["agent_id"] not in allowed_ids:
                continue
            exact_id = bool(uid_norm and _patch_normalize_text(row["update_id"]) == uid_norm)
            same_kb = bool(kb_norm and _patch_normalize_kb(row["kb"]) == kb_norm)
            same_title = bool(title_norm and _patch_normalize_text(row["title"]) == title_norm)
            if exact_id or same_kb or same_title:
                matched_rows.append(row)

        actionable = [row for row in matched_rows if row["status"] in ("pending", "failed", "approved")]
        by_agent = {}
        for row in actionable:
            by_agent.setdefault(row["agent_id"], []).append(row)
        running_conflicts = []
        cancelled_jobs = 0
        trimmed_jobs = 0
        denied_rows = []
        for agent_id, agent_rows in by_agent.items():
            row_ids = {row["update_id"] for row in agent_rows}
            conflicts = _running_update_conflicts(conn, agent_id, row_ids)
            if conflicts:
                running_conflicts.append({"agent_id": agent_id, "job_ids": conflicts})
                continue
            changes = _cancel_pending_update_jobs(conn, agent_id, row_ids, now)
            cancelled_jobs += changes["cancelled"]
            trimmed_jobs += changes["trimmed"]
            for row in agent_rows:
                cur = conn.execute(
                    "UPDATE updates SET status='denied', denied_by=?, denied_at=?, "
                    "status_changed_at=? WHERE id=? AND status IN ('pending','failed','approved')",
                    (user.get("u", ""), now, now, row["id"]),
                )
                if cur.rowcount:
                    denied_rows.append(row)

        still_actionable = len(actionable) - len(denied_rows)

    denied = len(denied_rows)
    already_denied = sum(1 for row in matched_rows if row["status"] == "denied")
    for agent_id in {row["agent_id"] for row in denied_rows}:
        _nudge_agents[agent_id] = time.time() + 180
        _wake_agent(agent_id)
    basis = []
    if uid_norm:
        basis.append("update_id")
    if kb_norm:
        basis.append("kb")
    if title_norm:
        basis.append("title")
    audit(
        request, "patch_deny", update_id or kb or title,
        f"{denied} denied; {already_denied} already denied; "
        f"{cancelled_jobs} job(s) cancelled; {len(running_conflicts)} running conflict(s); "
        f"matched by {','.join(basis)}",
        user=user,
    )
    return {
        "ok": True,
        "devices": denied,
        "matched": len(matched_rows),
        "already_denied": already_denied,
        "remaining_actionable": int(still_actionable or 0),
        "match_basis": basis,
        "cancelled_jobs": cancelled_jobs,
        "trimmed_jobs": trimmed_jobs,
        "running_conflicts": running_conflicts,
    }


@app.post("/api/patching/bulk-decision")
async def patching_bulk_decision(request: Request):
    """Persist selected patch groups together; wake each affected agent once."""
    user = await asyncio.to_thread(require_admin, request)
    body = await request.json()
    return await asyncio.to_thread(_patching_bulk_sync, request, body, user)


def _bulk_row_matches(row, group: dict) -> bool:
    return row["agent_id"] in group["agents"] and bool(
        (group["uid"] and _patch_normalize_text(row["update_id"]) == group["uid"]) or
        (group["kb"] and _patch_normalize_kb(row["kb"]) == group["kb"]) or
        (group["title"] and _patch_normalize_text(row["title"]) == group["title"])
    )


def _patching_bulk_sync(request: Request, body: dict, user: dict):
    if not isinstance(body, dict) or body.get("action") not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="Invalid patch action")
    raw_groups = body.get("groups")
    if not isinstance(raw_groups, list) or not 1 <= len(raw_groups) <= 50:
        raise HTTPException(status_code=400, detail="Select 1 to 50 patch groups")
    action = body["action"]
    groups, all_agents, all_updates = [], set(), set()
    for raw in raw_groups:
        if not isinstance(raw, dict) or not isinstance(raw.get("agent_ids"), list):
            raise HTTPException(status_code=400, detail="Each group requires device IDs")
        agents = {a for a in raw["agent_ids"] if isinstance(a, str) and a}
        if not agents or len(agents) > 500 or any(len(a) > 128 for a in agents):
            raise HTTPException(status_code=400, detail="Invalid group device scope")
        update_id = str(raw.get("update_id") or "").strip()
        kb = str(raw.get("kb") or "").strip()
        title = str(raw.get("title") or "").strip()
        ids_raw = raw.get("update_ids") or []
        if not isinstance(ids_raw, list) or len(ids_raw) > 400:
            raise HTTPException(status_code=400, detail="Too many update variants")
        ids = {uid.strip() for uid in ids_raw if isinstance(uid, str) and uid.strip()}
        if update_id:
            ids.add(update_id)
        if len(ids) > 400 or any(len(uid) > 256 for uid in ids):
            raise HTTPException(status_code=400, detail="Invalid update variants")
        if (action == "approve" and not ids) or (action == "deny" and not (update_id or kb or title)):
            raise HTTPException(status_code=400, detail="Missing patch identity")
        if len(kb) > 128 or len(title) > 512:
            raise HTTPException(status_code=400, detail="Invalid patch metadata")
        groups.append({"agents": agents, "ids": ids,
                       "uid": _patch_normalize_text(update_id),
                       "kb": _patch_normalize_kb(kb) if kb else "",
                       "title": _patch_normalize_text(title)})
        all_agents.update(agents)
        all_updates.update(ids)
    if len(all_agents) > 500 or len(all_updates) > 400:
        raise HTTPException(status_code=400, detail="Too many selected devices or updates")

    now = time.time()
    touched, jobs_created, jobs_merged = set(), 0, 0
    denied_rows, cancelled_jobs, trimmed_jobs = 0, 0, 0
    conflicts_by_agent = {}
    with db() as conn:
        agent_scope = ",".join("?" for _ in all_agents)
        if action == "approve":
            update_scope = ",".join("?" for _ in all_updates)
            rows = conn.execute(
                "SELECT agent_id, update_id FROM updates WHERE status IN ('pending','failed') "
                f"AND agent_id IN ({agent_scope}) AND update_id IN ({update_scope})",
                (*all_agents, *all_updates),
            ).fetchall()
            by_agent = {}
            for row in rows:
                if any(row["agent_id"] in g["agents"] and row["update_id"] in g["ids"]
                       for g in groups):
                    by_agent.setdefault(row["agent_id"], set()).add(row["update_id"])
            for agent_id, ids in by_agent.items():
                result = _approve_and_queue_updates(conn, agent_id, sorted(ids), now)
                if result["approved"]:
                    touched.add(agent_id)
                    jobs_created += result["jobs_created"]
                    jobs_merged += result["jobs_merged"]
        else:
            rows = conn.execute(
                "SELECT id, agent_id, update_id, kb, title, status FROM updates "
                "WHERE status IN ('pending','failed','approved','denied') "
                f"AND agent_id IN ({agent_scope})", tuple(all_agents),
            ).fetchall()
            states = {row["id"]: row["status"] for row in rows}
            for group in groups:
                by_agent = {}
                for row in rows:
                    if states[row["id"]] in ("pending", "failed", "approved") and _bulk_row_matches(row, group):
                        by_agent.setdefault(row["agent_id"], []).append(row)
                for agent_id, agent_rows in by_agent.items():
                    ids = {row["update_id"] for row in agent_rows}
                    conflicts = _running_update_conflicts(conn, agent_id, ids)
                    if conflicts:
                        conflicts_by_agent.setdefault(agent_id, set()).update(conflicts)
                        continue
                    changes = _cancel_pending_update_jobs(conn, agent_id, ids, now)
                    cancelled_jobs += changes["cancelled"]
                    trimmed_jobs += changes["trimmed"]
                    for row in agent_rows:
                        cur = conn.execute(
                            "UPDATE updates SET status='denied', denied_by=?, denied_at=?, "
                            "status_changed_at=? WHERE id=? AND status IN ('pending','failed','approved')",
                            (user.get("u", ""), now, now, row["id"]),
                        )
                        if cur.rowcount:
                            states[row["id"]] = "denied"
                            denied_rows += 1
                            touched.add(agent_id)
            remaining = sum(1 for row in rows if states[row["id"]] in
                            ("pending", "failed", "approved") and any(
                                _bulk_row_matches(row, group) for group in groups))
    for agent_id in touched:
        _nudge_agents[agent_id] = time.time() + 180
        _wake_agent(agent_id)
    audit(request, "patch_bulk_" + action, str(len(groups)),
          f"{len(touched)} device(s); {denied_rows} denied; {jobs_created} job(s) created; "
          f"{jobs_merged} merged; {len(conflicts_by_agent)} running conflict(s)", user=user)
    return {"ok": True, "groups": len(groups),
            "devices": len(touched) if action == "approve" else denied_rows,
            "jobs_created": jobs_created, "jobs_merged": jobs_merged,
            "cancelled_jobs": cancelled_jobs, "trimmed_jobs": trimmed_jobs,
            "remaining_actionable": remaining if action == "deny" else 0,
            "running_conflicts": [
                {"agent_id": agent_id, "job_ids": sorted(ids)}
                for agent_id, ids in sorted(conflicts_by_agent.items())
            ]}


# Organizations (customers) -------------------------------------------------


@app.get("/api/orgs")
def list_orgs(request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            """SELECT o.id, o.name, COUNT(a.id) AS machine_count
               FROM orgs o LEFT JOIN agents a ON a.org_id = o.id
               GROUP BY o.id ORDER BY o.name COLLATE NOCASE"""
        ).fetchall()
        unassigned = conn.execute(
            "SELECT COUNT(*) n FROM agents WHERE org_id IS NULL"
        ).fetchone()["n"]
    return {"orgs": [dict(r) for r in rows], "unassigned": unassigned}


@app.post("/api/orgs")
async def create_org(request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:128]
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    with db() as conn:
        if conn.execute("SELECT 1 FROM orgs WHERE name=? COLLATE NOCASE", (name,)).fetchone():
            raise HTTPException(status_code=400, detail="An organization with that name already exists")
        org_id = get_or_create_org(conn, name)
    return {"ok": True, "id": org_id}


@app.put("/api/orgs/{org_id}")
async def rename_org(org_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:128]
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    with db() as conn:
        dup = conn.execute(
            "SELECT 1 FROM orgs WHERE name=? COLLATE NOCASE AND id!=?", (name, org_id)
        ).fetchone()
        if dup:
            raise HTTPException(status_code=400, detail="An organization with that name already exists")
        conn.execute("UPDATE orgs SET name=? WHERE id=?", (name, org_id))
    return {"ok": True}


@app.delete("/api/orgs/{org_id}")
def delete_org(org_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        # Do not orphan a live onboarding execution by deleting its organization.
        # The run snapshots action contents, but application files are still
        # intentionally protected by their owning application record. Require a
        # technician to cancel/finish active onboarding before customer removal.
        active_runs = conn.execute(
            "SELECT COUNT(*) n FROM onboarding_runs WHERE org_id=? AND status IN ('pending','running')",
            (org_id,),
        ).fetchone()["n"]
        if active_runs:
            raise HTTPException(status_code=409, detail=f"Customer has {active_runs} onboarding run(s) still active; cancel or finish them first")
        # Machines are kept — they move to "Unassigned" and lose their location
        conn.execute("UPDATE agents SET org_id=NULL, location_id=NULL WHERE org_id=?", (org_id,))
        conn.execute("DELETE FROM locations WHERE org_id=?", (org_id,))
        conn.execute("DELETE FROM org_policies WHERE org_id=?", (org_id,))
        stack_ids = [r["id"] for r in conn.execute("SELECT id FROM automation_stacks WHERE org_id=?", (org_id,)).fetchall()]
        for sid in stack_ids:
            conn.execute("DELETE FROM automation_stack_steps WHERE stack_id=?", (sid,))
        conn.execute("DELETE FROM automation_stacks WHERE org_id=?", (org_id,))
        conn.execute("DELETE FROM org_onboarding_settings WHERE org_id=?", (org_id,))
        conn.execute("DELETE FROM orgs WHERE id=?", (org_id,))
    return {"ok": True}


@app.post("/api/machines/{agent_id}/live-mode")
async def set_machine_live_mode(agent_id: str, request: Request):
    """Set the per-machine live-mode override. mode: 'on' | 'off' | 'inherit'.
    'inherit' clears the override so the org/global default applies."""
    require_admin(request)
    body = await request.json()
    mode = str(body.get("mode", "inherit")).lower()
    val = {"on": 1, "off": 0, "inherit": None}.get(mode, None)
    with db() as conn:
        a = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute("UPDATE agents SET live_mode=? WHERE id=?", (val, agent_id))
    # If turning off, wake any parked poll so it re-evaluates and drops to interval.
    _wake_agent(agent_id)
    audit(request, "live_mode", a["hostname"], mode)
    return {"ok": True, "mode": mode}


@app.post("/api/orgs/{org_id}/live-mode")
async def set_org_live_mode(org_id: int, request: Request):
    """Set the per-org default live mode (applies to machines set to 'inherit')."""
    require_admin(request)
    body = await request.json()
    on = 1 if body.get("on") else 0
    with db() as conn:
        o = conn.execute("SELECT name FROM orgs WHERE id=?", (org_id,)).fetchone()
        if not o:
            raise HTTPException(status_code=404, detail="Unknown organization")
        conn.execute("UPDATE orgs SET live_mode_default=? WHERE id=?", (on, org_id))
        # Wake parked polls for inheriting machines in this org so an off-toggle
        # takes effect promptly.
        if not on:
            for r in conn.execute(
                "SELECT id FROM agents WHERE org_id=? AND live_mode IS NULL", (org_id,)):
                _wake_agent(r["id"])
    audit(request, "live_mode_org", o["name"], "on" if on else "off")
    return {"ok": True, "on": bool(on)}


@app.post("/api/machines/{agent_id}/org")
async def set_machine_org(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json()
    org_id = body.get("org_id")   # int or None to unassign
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        if org_id is not None and not conn.execute(
            "SELECT 1 FROM orgs WHERE id=?", (int(org_id),)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Unknown organization")
        # Changing org clears any location (locations belong to one org)
        conn.execute(
            "UPDATE agents SET org_id=?, location_id=NULL WHERE id=?",
            (int(org_id) if org_id is not None else None, agent_id),
        )
    return {"ok": True}


# Locations (sites within a customer) ----------------------------------------


@app.get("/api/orgs/{org_id}/locations")
def list_locations(org_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            """SELECT l.id, l.name, COUNT(a.id) AS machine_count
               FROM locations l LEFT JOIN agents a ON a.location_id = l.id
               WHERE l.org_id=? GROUP BY l.id ORDER BY l.name COLLATE NOCASE""",
            (org_id,),
        ).fetchall()
    return {"locations": [dict(r) for r in rows]}


@app.post("/api/orgs/{org_id}/locations")
async def create_location(org_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:128]
    if not name:
        raise HTTPException(status_code=400, detail="Location name is required")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        if conn.execute(
            "SELECT 1 FROM locations WHERE org_id=? AND name=? COLLATE NOCASE", (org_id, name)
        ).fetchone():
            raise HTTPException(status_code=400, detail="That location already exists for this customer")
        cur = conn.execute(
            "INSERT INTO locations (org_id, name, created_at) VALUES (?,?,?)",
            (org_id, name, time.time()),
        )
        new_id = cur.lastrowid
    return {"ok": True, "id": new_id}


@app.put("/api/locations/{location_id}")
async def rename_location(location_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:128]
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    with db() as conn:
        loc = conn.execute("SELECT org_id FROM locations WHERE id=?", (location_id,)).fetchone()
        if not loc:
            raise HTTPException(status_code=404, detail="Unknown location")
        dup = conn.execute(
            "SELECT 1 FROM locations WHERE org_id=? AND name=? COLLATE NOCASE AND id!=?",
            (loc["org_id"], name, location_id),
        ).fetchone()
        if dup:
            raise HTTPException(status_code=400, detail="That location name already exists")
        conn.execute("UPDATE locations SET name=? WHERE id=?", (name, location_id))
    return {"ok": True}


@app.delete("/api/locations/{location_id}")
def delete_location(location_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        # Machines keep their org, just lose the location assignment
        conn.execute("UPDATE agents SET location_id=NULL WHERE location_id=?", (location_id,))
        conn.execute("DELETE FROM locations WHERE id=?", (location_id,))
    return {"ok": True}


@app.post("/api/machines/{agent_id}/location")
async def set_machine_location(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json()
    location_id = body.get("location_id")   # int or None
    with db() as conn:
        a = conn.execute("SELECT org_id FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        if location_id is not None:
            loc = conn.execute(
                "SELECT org_id FROM locations WHERE id=?", (int(location_id),)
            ).fetchone()
            if not loc:
                raise HTTPException(status_code=404, detail="Unknown location")
            # A location must belong to the machine's own org
            if loc["org_id"] != a["org_id"]:
                raise HTTPException(status_code=400,
                                    detail="That location belongs to a different customer")
        conn.execute(
            "UPDATE agents SET location_id=? WHERE id=?",
            (int(location_id) if location_id is not None else None, agent_id),
        )
    return {"ok": True}


# Update auto-approval policy -------------------------------------------------


@app.get("/api/patching/enforcement")
def patching_enforcement(request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT a.id, a.hostname, a.last_seen, a.wu_management, a.org_id, "
            "a.wu_capable, o.name org_name "
            "FROM agents a LEFT JOIN orgs o ON o.id=a.org_id ORDER BY o.name, a.hostname"
        ).fetchall()
        output = []
        for row in rows:
            try:
                report = json.loads(row["wu_management"] or "{}")
            except (ValueError, TypeError):
                report = {}
            if not isinstance(report, dict):
                report = {}
            desired_managed = bool(effective_policy(conn, row["org_id"]).get("manage_windows_update"))
            capable = bool(row["wu_capable"])
            mode = report.get("mode", "unknown")
            verified = mode == "managed" if desired_managed else mode == "observe"
            output.append({
                "agent_id": row["id"], "hostname": row["hostname"],
                "org_name": row["org_name"], "last_seen": row["last_seen"],
                "desired_managed": desired_managed,
                "capable": capable,
                "mode": mode,
                "verified": verified,
                "compliant": bool(report.get("compliant")) if verified else False,
                "checked_at": report.get("checked_at"),
                "hidden_count": int(report.get("hidden_count") or 0),
                "worker_status": str(report.get("worker_status") or ""),
                "lab_build": str(report.get("lab_build") or ""),
                "errors": report.get("errors") or [],
            })
    managed = [x for x in output if x["desired_managed"]]
    capable_managed = [x for x in managed if x["capable"]]
    return {
        "devices": output,
        "summary": {
            "managed": len(managed),
            "compliant": sum(1 for x in capable_managed if x["verified"] and x["compliant"]),
            "noncompliant": sum(1 for x in capable_managed if x["verified"] and not x["compliant"]),
            "unknown": sum(1 for x in capable_managed if not x["verified"]),
            # Devices whose policy wants management but whose agent does not
            # yet have the isolated Windows Update architecture. These are not
            # failures; they are awaiting the capable production agent.
            "awaiting_agent": sum(1 for x in managed if not x["capable"]),
            "capable": sum(1 for x in output if x["capable"]),
        },
    }


@app.get("/api/patching/runs/{agent_id}")
def patching_runs(agent_id: str, request: Request, limit: int = 50):
    """Windows Update worker run history for one device. The endpoint report
    is last-run-wins, so this table is the only server-side record of
    transitions (hides, unhides, installs) between check-ins."""
    require_admin(request)
    limit = max(1, min(int(limit or 50), 500))
    with db() as conn:
        rows = conn.execute(
            "SELECT started_at, checked_at, phase, status, mode, lab_build,"
            " compliant, hidden_count, visible_count, counters, errors, warnings"
            " FROM wu_runs WHERE agent_id=? ORDER BY checked_at DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
    runs = []
    for r in rows:
        item = dict(r)
        for key in ("counters", "errors", "warnings"):
            try:
                item[key] = json.loads(item[key] or ("{}" if key == "counters" else "[]"))
            except (ValueError, TypeError):
                item[key] = {} if key == "counters" else []
        item["compliant"] = bool(item["compliant"])
        runs.append(item)
    return {"agent_id": agent_id, "runs": runs}


@app.get("/api/policy")
def read_policy(request: Request):
    require_admin(request)
    with db() as conn:
        return get_policy(conn)


@app.put("/api/policy")
async def write_policy(request: Request):
    require_admin(request)
    body = await request.json()
    pol = _sanitize_policy(body)
    with db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('policy', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(pol),),
        )
        agent_ids = [r["id"] for r in conn.execute("SELECT id FROM agents").fetchall()]
    for agent_id in agent_ids:
        _nudge_agents[agent_id] = time.time() + 180
        _wake_agent(agent_id)
    return {"ok": True}


_STANCE_CATEGORIES = ("driver", "firmware", "feature", "optional")
_STANCE_VALUES = ("auto", "manual", "report")


def _sanitize_stances(raw) -> dict:
    stances = dict(DEFAULT_POLICY["category_stances"])
    if isinstance(raw, dict):
        for cat in _STANCE_CATEGORIES:
            val = str(raw.get(cat, stances[cat])).lower()
            if val in _STANCE_VALUES:
                stances[cat] = val
    return stances


def policy_category_stance(pol: dict, update_row) -> str:
    """Effective stance for one update row. Standard/security updates are
    always 'auto' (the severity rules decide); rows from legacy agents have
    no category and are treated as standard. BrowseOnly updates without a
    category are treated as optional."""
    category = ""
    try:
        category = str(update_row["category"] or "").lower()
    except (KeyError, IndexError, TypeError):
        category = ""
    browse_only = False
    try:
        browse_only = bool(update_row["browse_only"])
    except (KeyError, IndexError, TypeError):
        browse_only = False
    if not category and browse_only:
        category = "optional"
    if category not in _STANCE_CATEGORIES:
        return "auto"
    stances = pol.get("category_stances") or {}
    val = str(stances.get(category, DEFAULT_POLICY["category_stances"][category])).lower()
    return val if val in _STANCE_VALUES else "auto"


def _sanitize_policy(body: dict) -> dict:
    valid_sev = {"Critical", "Important", "Moderate", "Low"}
    days = []
    for x in body.get("maintenance_days", []):
        try:
            n = int(x)
            if 0 <= n <= 6 and n not in days:
                days.append(n)
        except (TypeError, ValueError):
            pass
    excluded = []
    raw_excluded = body.get("excluded_kbs", [])
    if isinstance(raw_excluded, str):
        raw_excluded = raw_excluded.replace(";", ",").replace("\n", ",").split(",")
    for item in raw_excluded if isinstance(raw_excluded, list) else []:
        val = str(item).strip().upper()[:80]
        if val and val not in excluded:
            excluded.append(val)
    start_h, start_m = _parse_hhmm(body.get("maintenance_start"), (0, 0))
    end_h, end_m = _parse_hhmm(body.get("maintenance_end"), (23, 59))
    return {
        "enabled": bool(body.get("enabled")),
        "defender": bool(body.get("defender")),
        "severities": [s for s in body.get("severities", []) if s in valid_sev],
        "delay_days": max(0, min(60, int(body.get("delay_days") or 0))),
        "include_preview": bool(body.get("include_preview")),
        "excluded_kbs": excluded[:200],
        "maintenance_enabled": bool(body.get("maintenance_enabled")),
        "maintenance_days": days or list(range(7)),
        "maintenance_start": f"{start_h:02d}:{start_m:02d}",
        "maintenance_end": f"{end_h:02d}:{end_m:02d}",
        "auto_retry_failed": bool(body.get("auto_retry_failed")),
        "retry_failed_after_hours": max(1, min(720, int(body.get("retry_failed_after_hours") or 24))),
        "backup_stale_days": max(1, min(60, int(body.get("backup_stale_days") or 3))),
        "reboot_after_install": bool(body.get("reboot_after_install")),
        "reboot_delay_minutes": max(0, min(1440, int(body.get("reboot_delay_minutes") or 15))),
        "category_stances": _sanitize_stances(body.get("category_stances")),
        "manage_windows_update": bool(body.get("manage_windows_update")),
        "block_user_update_access": bool(body.get("block_user_update_access", True)),
        "block_pause_updates": bool(body.get("block_pause_updates", True)),
        "hide_denied_updates": bool(body.get("hide_denied_updates", True)),
    }


@app.get("/api/orgs/{org_id}/policy")
def read_org_policy(org_id: int, request: Request):
    """Returns the org's override plus a flag for whether one exists.
    If none, returns the global policy as the effective baseline."""
    require_admin(request)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        override = get_org_policy(conn, org_id)
        return {
            "has_override": override is not None,
            "policy": override or get_policy(conn),
        }


@app.put("/api/orgs/{org_id}/policy")
async def write_org_policy(org_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        # Setting use_global=true removes the override (org falls back to global)
        if body.get("use_global"):
            conn.execute("DELETE FROM org_policies WHERE org_id=?", (org_id,))
            agent_ids = [r["id"] for r in conn.execute("SELECT id FROM agents WHERE org_id=?", (org_id,)).fetchall()]
            result = {"ok": True, "has_override": False}
        else:
            pol = _sanitize_policy(body)
            conn.execute(
                "INSERT INTO org_policies (org_id, policy, updated_at) VALUES (?,?,?)"
                " ON CONFLICT(org_id) DO UPDATE SET policy=excluded.policy, updated_at=excluded.updated_at",
                (org_id, json.dumps(pol), time.time()),
            )
            agent_ids = [r["id"] for r in conn.execute("SELECT id FROM agents WHERE org_id=?", (org_id,)).fetchall()]
            result = {"ok": True, "has_override": True}
    for agent_id in agent_ids:
        _nudge_agents[agent_id] = time.time() + 180
        _wake_agent(agent_id)
    return result


# Patch report (PDF) ----------------------------------------------------------

COMPANY_NAME = os.environ.get("OUTPOST_COMPANY_NAME", "Your MSP")


@app.get("/api/orgs/{org_id}/report.pdf")
def org_patch_report(org_id: int, request: Request, days: int = 30):
    require_admin(request)
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                        Table, TableStyle)
    except ImportError:
        raise HTTPException(status_code=500,
                            detail="reportlab is not installed — run: pip install reportlab")

    days = max(7, min(days, 90))
    since = time.time() - days * 86400

    with db() as conn:
        org = conn.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="Unknown customer")
        agents = conn.execute(
            "SELECT a.*, NULL AS org_name FROM agents a WHERE a.org_id=? ORDER BY a.hostname",
            (org_id,),
        ).fetchall()
        counts = {
            (r["agent_id"], r["status"]): r["n"]
            for r in conn.execute(
                "SELECT agent_id, status, COUNT(*) n FROM updates GROUP BY agent_id, status"
            )
        }
        machines, installed_by_agent, failed_jobs_by_agent = [], {}, {}
        for a in agents:
            jobs = conn.execute(
                "SELECT status, payload FROM jobs WHERE agent_id=? AND type='install_updates'"
                " AND created_at>=?", (a["id"], since),
            ).fetchall()
            inst = fail = 0
            for j in jobs:
                try:
                    n = len(json.loads(j["payload"]).get("update_ids", []))
                except (ValueError, TypeError):
                    n = 0
                if j["status"] == "done":
                    inst += n
                elif j["status"] == "failed":
                    fail += 1
            installed_by_agent[a["id"]] = inst
            failed_jobs_by_agent[a["id"]] = fail
            machines.append(_machine_dict(
                a, counts.get((a["id"], "pending"), 0) + counts.get((a["id"], "failed"), 0),
                counts.get((a["id"], "approved"), 0), counts.get((a["id"], "failed"), 0)))

    total = len(machines)
    compliant = sum(1 for m in machines if m["pending_updates"] == 0)
    pct = round(compliant / total * 100) if total else 100
    installed_total = sum(installed_by_agent.values())
    failed_total = sum(failed_jobs_by_agent.values())
    low_disk = sum(1 for m in machines if m["low_disk"])
    offline = sum(1 for m in machines if not m["online"])
    hw_warn = sum(1 for m in machines if m.get("hw_warning"))
    protected = sum(1 for m in machines if m.get("bdgz_protected") == 1)
    with db() as conn:
        av_incidents = conn.execute(
            "SELECT COUNT(*) n FROM av_events WHERE org_id=? AND received_at>=?",
            (org_id, since)).fetchone()["n"]

    # ---- build the PDF ----
    import io
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter),
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            title=f"Patch report — {org['name']}")
    styles = getSampleStyleSheet()
    ink, mut, acc = colors.HexColor("#171B21"), colors.HexColor("#66707D"), colors.HexColor("#2450C9")
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=20, textColor=ink,
                        alignment=0, spaceAfter=2)
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=10.5, textColor=mut)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, textColor=mut)
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=8.5, textColor=ink)

    gen = datetime.datetime.now().strftime("%B %d, %Y")
    story = [
        Paragraph(f"Windows Patch Compliance Report", h1),
        Paragraph(f"<b>{org['name']}</b>  ·  prepared by {COMPANY_NAME}  ·  "
                  f"last {days} days  ·  generated {gen}", sub),
        Spacer(1, 14),
    ]

    def stat(label, value, color=ink):
        hexc = "#" + color.hexval()[2:] if hasattr(color, "hexval") else str(color)
        return [Paragraph(f'<font size="16" color="{hexc}"><b>{value}</b></font>', cell),
                Paragraph(label, small)]

    ok_c, warn_c, bad_c = colors.HexColor("#1F8A4C"), colors.HexColor("#B7791F"), colors.HexColor("#C43D3D")
    summary = Table([[
        stat("machines", total),
        stat("patch compliant", f"{pct}%", ok_c if pct >= 90 else warn_c),
        stat("updates installed", installed_total, acc),
        stat("AV protected", f"{protected}/{total}", ok_c if protected == total else warn_c),
        stat("security incidents", av_incidents, bad_c if av_incidents else ok_c),
        stat("disk warnings", hw_warn, bad_c if hw_warn else ok_c),
        stat("offline now", offline, warn_c if offline else ok_c),
    ]], colWidths=[1.4 * inch] * 7)
    summary.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#E1E5EA")),
        ("INNERGRID", (0, 0), (-1, -1), 0.75, colors.HexColor("#E1E5EA")),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story += [summary, Spacer(1, 16)]

    header = ["Machine", "OS", "Serial", "Pending", "Installed", "Reboot", "Last check-in", "Status"]
    rows = [header]
    row_colors = []
    for m in machines:
        status = "Compliant" if m["pending_updates"] == 0 else "Needs attention"
        rows.append([
            Paragraph(f"<b>{m['hostname']}</b>", cell),
            Paragraph(m["os_version"][:44], cell),
            Paragraph(m["serial"][:20] or "—", cell),
            str(m["pending_updates"]),
            str(installed_by_agent.get(m["id"], 0)),
            "yes" if m["reboot_required"] else "—",
            datetime.datetime.fromtimestamp(m["last_seen"]).strftime("%m/%d %H:%M")
                if m["last_seen"] else "never",
            Paragraph(f'<font color="{"#1F8A4C" if status == "Compliant" else "#B7791F"}">'
                      f"<b>{status}</b></font>", cell),
        ])
    tbl = Table(rows, repeatRows=1,
                colWidths=[1.7 * inch, 2.5 * inch, 1.3 * inch, 0.7 * inch,
                           0.8 * inch, 0.65 * inch, 1.1 * inch, 1.25 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#171B21")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F7F9")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E1E5EA")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [tbl, Spacer(1, 14),
              Paragraph("Compliant = no pending Windows Updates at report time. "
                        "Installed = updates deployed via managed approval in the period. "
                        f"Report generated automatically by {COMPANY_NAME} monitoring.",
                        small)]
    if not machines:
        story.append(Paragraph("No machines are assigned to this customer yet.", sub))

    doc.build(story)
    fname = f"patch-report-{org['name'].replace(' ', '-')}-{datetime.date.today().isoformat()}.pdf"
    return Response(content=buf.getvalue(), media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="{fname}"'})


@app.post("/api/machines/{agent_id}/reboot")
async def reboot_machine(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json() if request.headers.get("content-length") else {}
    force_reboot = bool(validate_force_reboot(body, "reboot"))
    if force_reboot:
        require_admin_role(request)
    delay = max(0, min(3600, int(body.get("delay_sec", 60))))
    with db() as conn:
        a = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        job_id = str(uuid.uuid4())
        now = time.time()
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (job_id, agent_id, "reboot", "Force reboot machine" if force_reboot else "Reboot machine",
             json.dumps(build_power_job_payload(
                 "reboot", "OpenPrime-RMM: scheduled maintenance reboot", "manual", now, delay,
                 force_reboot=force_reboot)),
             now),
        )
    audit(request, "force_reboot" if force_reboot else "reboot", a["hostname"], f"delay={delay}s; job={job_id}")
    _wake_agent(agent_id)
    return {"ok": True, "job_id": job_id}


# Scripts CRUD -------------------------------------------------------------

# Script variables (NinjaOne-style). Each script can define variables that
# technicians fill in when running it. Values are injected into the script's
# process as ENVIRONMENT VARIABLES named by the variable's "calculated name",
# exactly like NinjaOne — so scripts written for Ninja (e.g. reading
# $env:configFilePathOrUrlLink) work unmodified. Empty optional variables are
# passed as the literal string "null", matching Ninja; checkboxes as
# "true"/"false".

import re as _vre

VAR_TYPES = ("text", "integer", "checkbox", "dropdown")
SCRIPT_SHELLS = ("powershell", "cmd", "bash")
SCRIPT_SAFETY_CLASSES = ("unclassified", "diagnostic", "safe_remediation", "disruptive", "high_impact")
REBOOT_IMPACTS = ("no", "possible", "yes")
_CALC_RE = _vre.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def normalize_script_shell(raw) -> str:
    shell = str(raw or "powershell").strip().lower()
    if shell not in SCRIPT_SHELLS:
        raise HTTPException(status_code=400, detail="Script language must be PowerShell, CMD / Batch, or Bash")
    return shell


def normalize_script_safety(raw) -> str:
    value = str(raw or "unclassified").strip().lower()
    if value not in SCRIPT_SAFETY_CLASSES:
        raise HTTPException(status_code=400, detail="Unsupported script safety class")
    return value


def normalize_reboot_impact(raw) -> str:
    value = str(raw or "possible").strip().lower()
    return value if value in REBOOT_IMPACTS else "possible"


def _script_public_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["variables"] = script_variables(row)
    d["safety_class"] = d.get("safety_class") or "unclassified"
    d["ai_auto_allowed"] = bool(d.get("ai_auto_allowed"))
    d["changes_system"] = bool(d.get("changes_system"))
    d["reboot_impact"] = d.get("reboot_impact") if d.get("reboot_impact") in REBOOT_IMPACTS else "possible"
    return d


def sanitize_variables(raw) -> list:
    """Validate and normalize a script's variable definitions."""
    if not isinstance(raw, list):
        return []
    out, seen = [], set()
    for item in raw[:30]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()[:80]
        calc = str(item.get("calc", "")).strip()
        vtype = item.get("type", "text")
        if vtype not in VAR_TYPES:
            vtype = "text"
        if not name:
            continue
        if not _CALC_RE.match(calc):
            raise HTTPException(status_code=400,
                                detail=f"Bad calculated name '{calc}' for variable '{name}'"
                                       " (letters, digits, underscore; must not start with a digit)")
        if calc in seen:
            raise HTTPException(status_code=400, detail=f"Duplicate calculated name '{calc}'")
        seen.add(calc)
        options = [str(o).strip()[:200] for o in item.get("options", []) if str(o).strip()] \
            if vtype == "dropdown" else []
        if vtype == "dropdown" and not options:
            raise HTTPException(status_code=400, detail=f"Dropdown '{name}' needs options")
        out.append({
            "name": name, "calc": calc, "type": vtype,
            "description": str(item.get("description", ""))[:500],
            "default": str(item.get("default", ""))[:1000],
            "mandatory": bool(item.get("mandatory")),
            "options": options,
        })
    return out


def resolve_variable_values(defs: list, supplied, strict: bool = True) -> dict:
    """Turn technician-supplied values into the env-var dict for the agent.
    strict=True (interactive run) enforces mandatory variables; strict=False
    (schedules) falls back to defaults / "null" so scheduled runs never stall."""
    supplied = supplied if isinstance(supplied, dict) else {}
    env = {}
    for d in defs:
        val = supplied.get(d["calc"])
        if val is None or str(val).strip() == "":
            val = d.get("default", "")
        if d["type"] == "checkbox":
            env[d["calc"]] = "true" if str(val).lower() in ("1", "true", "yes", "on") else "false"
            continue
        val = str(val).strip()
        if d["type"] == "integer" and val:
            try:
                val = str(int(val))
            except ValueError:
                if strict:
                    raise HTTPException(status_code=400,
                                        detail=f"'{d['name']}' must be a whole number")
                val = ""
        if d["type"] == "dropdown" and val and val not in d.get("options", []):
            if strict:
                raise HTTPException(status_code=400,
                                    detail=f"'{val}' is not an option for '{d['name']}'")
            val = ""
        if not val:
            if d.get("mandatory") and strict:
                raise HTTPException(status_code=400,
                                    detail=f"'{d['name']}' is mandatory")
            val = "null"          # NinjaOne convention for empty variables
        env[d["calc"]] = val[:4000]
    return env


def script_variables(row) -> list:
    try:
        v = json.loads(row["variables"] or "[]")
        return v if isinstance(v, list) else []
    except (ValueError, KeyError, IndexError):
        return []


@app.get("/api/scripts")
def list_scripts(request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute("SELECT * FROM scripts ORDER BY name").fetchall()
    return {"scripts": [_script_public_dict(r) for r in rows]}


@app.post("/api/scripts")
async def create_script(request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()
    content = str(body.get("content", ""))
    if not name or not content:
        raise HTTPException(status_code=400, detail="Name and content are required")
    variables = json.dumps(sanitize_variables(body.get("variables", [])))
    shell = normalize_script_shell(body.get("shell"))
    timeout_sec = max(5, min(86400, int(body.get("timeout_sec") or 900)))
    safety_class = normalize_script_safety(body.get("safety_class"))
    changes_system = False if safety_class == "diagnostic" else bool(body.get("changes_system", True))
    ai_auto_allowed = bool(body.get("ai_auto_allowed")) and safety_class == "diagnostic"
    reboot_impact = normalize_reboot_impact(body.get("reboot_impact", "no" if safety_class == "diagnostic" else "possible"))
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO scripts (name, description, content, shell, timeout_sec, variables, safety_class,"
            " ai_auto_allowed, changes_system, reboot_impact, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (name, str(body.get("description", ""))[:1000], content, shell,
             timeout_sec, variables, safety_class, 1 if ai_auto_allowed else 0,
             1 if changes_system else 0, reboot_impact, time.time()),
        )
        new_id = cur.lastrowid
    return {"ok": True, "id": new_id}


@app.put("/api/scripts/{script_id}")
async def update_script(script_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()
    content = str(body.get("content", ""))
    if not name or not content:
        raise HTTPException(status_code=400, detail="Name and content are required")
    shell = normalize_script_shell(body.get("shell"))
    timeout_sec = max(5, min(86400, int(body.get("timeout_sec") or 900)))
    safety_class = normalize_script_safety(body.get("safety_class"))
    changes_system = False if safety_class == "diagnostic" else bool(body.get("changes_system", True))
    ai_auto_allowed = bool(body.get("ai_auto_allowed")) and safety_class == "diagnostic"
    reboot_impact = normalize_reboot_impact(body.get("reboot_impact", "no" if safety_class == "diagnostic" else "possible"))
    with db() as conn:
        if not conn.execute("SELECT 1 FROM scripts WHERE id=?", (script_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown script")
        conn.execute(
            "UPDATE scripts SET name=?, description=?, content=?, shell=?, timeout_sec=?, variables=?,"
            " safety_class=?, ai_auto_allowed=?, changes_system=?, reboot_impact=?, updated_at=? WHERE id=?",
            (name, str(body.get("description", ""))[:1000], content, shell, timeout_sec,
             json.dumps(sanitize_variables(body.get("variables", []))), safety_class,
             1 if ai_auto_allowed else 0, 1 if changes_system else 0, reboot_impact,
             time.time(), script_id),
        )
    return {"ok": True}


@app.delete("/api/scripts/{script_id}")
def delete_script(script_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        stack_refs = conn.execute("SELECT COUNT(*) n FROM automation_stack_steps WHERE action_type='script' AND action_id=?", (script_id,)).fetchone()["n"]
        hook_refs = conn.execute("SELECT COUNT(*) n FROM applications WHERE pre_script_id=? OR post_script_id=?", (script_id, script_id)).fetchone()["n"]
        if stack_refs or hook_refs:
            parts = []
            if stack_refs:
                parts.append(f"{stack_refs} onboarding stack step(s)")
            if hook_refs:
                parts.append(f"{hook_refs} application pre/post hook(s)")
            raise HTTPException(status_code=409, detail="Script is still used by " + " and ".join(parts))
        conn.execute("DELETE FROM scripts WHERE id=?", (script_id,))
    return {"ok": True}


# Application installer library ---------------------------------------------

APP_ARCHITECTURES = {"all", "x64", "x86", "arm64"}
APP_INSTALLER_TYPES = {"msi", "exe"}
APP_REBOOT_BEHAVIORS = {"never", "if_required", "always"}
APP_DETECTION_TYPES = {"none", "file_exists", "registry_product_code"}
APP_MAX_INSTALLER_BYTES = 1024 * 1024 * 1024
APP_MAX_HELPER_BYTES = 100 * 1024 * 1024
APP_MAX_ICON_BYTES = 2 * 1024 * 1024


def _safe_app_filename(name: str) -> str:
    name = Path(str(name or "")).name.strip()
    name = re.sub(r"[^A-Za-z0-9._() +\-]", "_", name)[:180]
    return name or "file.bin"


def _json_list(value, default=None):
    if default is None:
        default = []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            out = json.loads(value)
            return out if isinstance(out, list) else list(default)
        except (ValueError, TypeError):
            return list(default)
    return list(default)


def _sanitize_success_codes(value) -> list[int]:
    raw = _json_list(value, [0, 3010]) if not isinstance(value, (tuple, set)) else list(value)
    out = []
    for item in raw[:20]:
        try:
            code = int(item)
        except (TypeError, ValueError):
            continue
        if -2147483648 <= code <= 4294967295 and code not in out:
            out.append(code)
    return out or [0]


def _application_files(conn: sqlite3.Connection, application_id: int, active_only: bool = True) -> list[sqlite3.Row]:
    sql = "SELECT * FROM application_files WHERE application_id=?"
    args = [application_id]
    if active_only:
        sql += " AND active=1"
    sql += " ORDER BY CASE kind WHEN 'installer' THEN 0 WHEN 'icon' THEN 1 ELSE 2 END, id"
    return conn.execute(sql, args).fetchall()


def _application_public_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = dict(row)
    d["categories"] = [str(x) for x in _json_list(row["categories"], [])]
    d["success_codes"] = _sanitize_success_codes(row["success_codes"])
    files = _application_files(conn, row["id"], active_only=True)
    d["files"] = [dict(f) for f in files]
    d["installer_file"] = next((dict(f) for f in files if f["kind"] == "installer"), None)
    d["helper_files"] = [dict(f) for f in files if f["kind"] == "helper"]
    d["icon_file"] = next((dict(f) for f in files if f["kind"] == "icon"), None)
    d["pre_script_name"] = ""
    d["post_script_name"] = ""
    if row["pre_script_id"]:
        r = conn.execute("SELECT name FROM scripts WHERE id=?", (row["pre_script_id"],)).fetchone()
        d["pre_script_name"] = r["name"] if r else "(deleted script)"
    if row["post_script_id"]:
        r = conn.execute("SELECT name FROM scripts WHERE id=?", (row["post_script_id"],)).fetchone()
        d["post_script_name"] = r["name"] if r else "(deleted script)"
    return d


def _validate_application_body(body: dict, existing: sqlite3.Row | None = None) -> dict:
    name = str(body.get("name", existing["name"] if existing else "")).strip()[:160]
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    installer_type = str(body.get("installer_type", existing["installer_type"] if existing else "msi")).lower()
    if installer_type not in APP_INSTALLER_TYPES:
        raise HTTPException(status_code=400, detail="Installer type must be MSI or EXE")
    architecture = str(body.get("architecture", existing["architecture"] if existing else "all")).lower()
    if architecture not in APP_ARCHITECTURES:
        raise HTTPException(status_code=400, detail="Unsupported architecture")
    reboot_behavior = str(body.get("reboot_behavior", existing["reboot_behavior"] if existing else "never")).lower()
    if reboot_behavior not in APP_REBOOT_BEHAVIORS:
        reboot_behavior = "never"
    detection_type = str(body.get("detection_type", existing["detection_type"] if existing else "none")).lower()
    if detection_type not in APP_DETECTION_TYPES:
        detection_type = "none"
    def _script_id(key):
        val = body.get(key, existing[key] if existing else None)
        try:
            return int(val) if val not in (None, "", 0, "0") else None
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"Invalid {key}")
    categories = body.get("categories", _json_list(existing["categories"], []) if existing else [])
    if isinstance(categories, str):
        categories = [x.strip() for x in categories.split(",") if x.strip()]
    categories = [str(x)[:80] for x in (categories or [])][:20]
    success = body.get("success_codes", _sanitize_success_codes(existing["success_codes"]) if existing else [0, 3010])
    return {
        "name": name,
        "description": str(body.get("description", existing["description"] if existing else ""))[:2000],
        "operating_system": "windows",
        "architecture": architecture,
        "installer_type": installer_type,
        "run_as": "system",
        "parameters": str(body.get("parameters", existing["parameters"] if existing else ""))[:4000],
        "categories": json.dumps(categories),
        "success_codes": json.dumps(_sanitize_success_codes(success)),
        "timeout_sec": max(30, min(86400, int(body.get("timeout_sec", existing["timeout_sec"] if existing else 1800) or 1800))),
        "reboot_behavior": reboot_behavior,
        "detection_type": detection_type,
        "detection_value": str(body.get("detection_value", existing["detection_value"] if existing else ""))[:1000],
        "pre_script_id": _script_id("pre_script_id"),
        "post_script_id": _script_id("post_script_id"),
        "stop_on_pre_failure": 1 if body.get("stop_on_pre_failure", bool(existing["stop_on_pre_failure"]) if existing else True) else 0,
    }


def _script_snapshot_for_hook(conn: sqlite3.Connection, script_id) -> dict | None:
    if not script_id:
        return None
    row = conn.execute("SELECT * FROM scripts WHERE id=?", (script_id,)).fetchone()
    if not row:
        return None
    return {
        "id": row["id"], "name": row["name"], "content": row["content"],
        "shell": row["shell"] or "powershell", "timeout_sec": int(row["timeout_sec"] or 900),
        "env": resolve_variable_values(script_variables(row), {}, strict=False),
    }


def _application_snapshot(conn: sqlite3.Connection, application_id: int) -> dict:
    row = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Unknown application")
    files = _application_files(conn, application_id, active_only=True)
    installer = next((f for f in files if f["kind"] == "installer"), None)
    if not installer:
        raise HTTPException(status_code=400, detail="Application has no installer file")
    return {
        "id": row["id"], "name": row["name"], "description": row["description"],
        "architecture": row["architecture"], "installer_type": row["installer_type"],
        "parameters": row["parameters"] or "", "success_codes": _sanitize_success_codes(row["success_codes"]),
        "timeout_sec": int(row["timeout_sec"] or 1800), "reboot_behavior": row["reboot_behavior"] or "never",
        "detection_type": row["detection_type"] or "none", "detection_value": row["detection_value"] or "",
        "stop_on_pre_failure": bool(row["stop_on_pre_failure"]),
        "installer": dict(installer),
        "helpers": [dict(f) for f in files if f["kind"] == "helper"],
        "pre_script": _script_snapshot_for_hook(conn, row["pre_script_id"]),
        "post_script": _script_snapshot_for_hook(conn, row["post_script_id"]),
    }


def _app_download_signature(file_id: int, agent_id: str, job_id: str) -> str:
    msg = f"appfile:{int(file_id)}:{agent_id}:{job_id}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()


def _b64_text(value: str) -> str:
    return base64.b64encode(str(value or "").encode("utf-8")).decode("ascii")


def _ps_sq(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _build_application_install_script(snapshot: dict, agent_id: str, job_id: str) -> str:
    """Build a bounded PowerShell wrapper executed by the existing run_script path.

    This deliberately avoids a new agent job type. Agent 1.13.4 therefore remains
    compatible and application installation cannot break the endpoint check-in
    loop. Installer downloads are job-scoped HMAC URLs and are valid only while
    this exact job is pending/running.
    """
    installer = snapshot["installer"]
    files = [installer] + list(snapshot.get("helpers") or [])
    file_specs = []
    for f in files:
        sig = _app_download_signature(int(f["id"]), agent_id, job_id)
        file_specs.append({
            "id": int(f["id"]), "name": _safe_app_filename(f["original_name"]),
            "sha256": str(f["sha256"] or ""), "sig": sig,
        })
    files_json_b64 = _b64_text(json.dumps(file_specs, separators=(",", ":")))
    success_json_b64 = _b64_text(json.dumps(snapshot.get("success_codes") or [0]))
    pre = snapshot.get("pre_script")
    post = snapshot.get("post_script")

    def hook_vars(prefix: str, hook: dict | None) -> str:
        if not hook:
            return f"${prefix}Enabled=$false\n"
        return (
            f"${prefix}Enabled=$true\n"
            f"${prefix}Name={_ps_sq(hook.get('name','hook'))}\n"
            f"${prefix}Shell={_ps_sq(hook.get('shell','powershell'))}\n"
            f"${prefix}ContentB64={_ps_sq(_b64_text(hook.get('content','')))}\n"
            f"${prefix}Timeout={int(hook.get('timeout_sec') or 900)}\n"
            f"${prefix}EnvB64={_ps_sq(_b64_text(json.dumps(hook.get('env') or {}, separators=(',',':'))))}\n"
        )

    default_params = "/qn /norestart" if snapshot.get("installer_type") == "msi" and not str(snapshot.get("parameters") or "").strip() else str(snapshot.get("parameters") or "")
    script = fr'''$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$AppName={_ps_sq(snapshot.get('name','Application'))}
$AppId={int(snapshot['id'])}
$AgentId={_ps_sq(agent_id)}
$JobId={_ps_sq(job_id)}
$InstallerFileId={int(installer['id'])}
$InstallerType={_ps_sq(snapshot.get('installer_type','msi'))}
$Architecture={_ps_sq(snapshot.get('architecture','all'))}
$ParametersB64={_ps_sq(_b64_text(default_params))}
$SuccessCodesB64={_ps_sq(success_json_b64)}
$FilesB64={_ps_sq(files_json_b64)}
$TimeoutSec={int(snapshot.get('timeout_sec') or 1800)}
$DetectionType={_ps_sq(snapshot.get('detection_type','none'))}
$DetectionValueB64={_ps_sq(_b64_text(snapshot.get('detection_value','')))}
$RebootBehavior={_ps_sq(snapshot.get('reboot_behavior','never'))}
$StopOnPreFailure={'$true' if snapshot.get('stop_on_pre_failure', True) else '$false'}
{hook_vars('Pre', pre)}{hook_vars('Post', post)}
function From-B64([string]$s) {{ if(-not $s){{return ''}}; return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }}
function Invoke-Hook([string]$Name,[string]$Shell,[string]$ContentB64,[int]$Timeout,[string]$EnvB64,[string]$WorkDir) {{
  $ext = if($Shell -eq 'cmd'){{'.bat'}} elseif($Shell -eq 'bash'){{'.sh'}} else {{'.ps1'}}
  $path=Join-Path $WorkDir ('hook_'+[guid]::NewGuid().ToString('N')+$ext)
  [IO.File]::WriteAllText($path,(From-B64 $ContentB64),(New-Object Text.UTF8Encoding($false)))
  $old=@{{}}
  try {{
    $envObj=(From-B64 $EnvB64 | ConvertFrom-Json)
    if($envObj){{ foreach($prop in $envObj.PSObject.Properties){{ $old[$prop.Name]=[Environment]::GetEnvironmentVariable($prop.Name,'Process'); [Environment]::SetEnvironmentVariable($prop.Name,[string]$prop.Value,'Process') }} }}
    [Environment]::SetEnvironmentVariable('PNC_APPLICATION_DIR',$WorkDir,'Process')
    if($Shell -eq 'cmd'){{ $exe="$env:SystemRoot\System32\cmd.exe"; $args=@('/c',('"'+$path+'"')) }}
    elseif($Shell -eq 'bash'){{ $exe=(Get-Command bash.exe -ErrorAction SilentlyContinue).Source; if(-not $exe){{throw 'bash is not available'}}; $args=@(('"'+$path+'"')) }}
    else {{ $exe='powershell.exe'; $args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$path+'"')) }}
    Write-Output "[HOOK] Starting $Name"
    $p=Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
    $null=$p.Handle
    if(-not $p.WaitForExit($Timeout*1000)){{ try{{$p.Kill()}}catch{{}}; throw "$Name timed out after $Timeout seconds" }}
    $p.WaitForExit(); $code=$p.ExitCode
    if($code -ne 0){{ throw "$Name failed with exit code $code" }}
    Write-Output "[HOOK] $Name completed"
  }} finally {{ foreach($k in $old.Keys){{[Environment]::SetEnvironmentVariable($k,$old[$k],'Process')}}; [Environment]::SetEnvironmentVariable('PNC_APPLICATION_DIR',$null,'Process'); Remove-Item $path -Force -ErrorAction SilentlyContinue }}
}}
$cfg=Get-Content 'C:\ProgramData\OpenPrime\config.json' -Raw | ConvertFrom-Json
$base=([string]$cfg.ServerUrl).TrimEnd('/')
$stage=Join-Path 'C:\ProgramData\OpenPrime\staging' ('application_'+$JobId)
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {{
  # Enforce installer architecture on the endpoint as a final safety gate. x86
  # installers are allowed on all supported Windows architectures; x64/ARM64
  # must match the native OS architecture.
  $nativeArch=[string][Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE','Machine')
  if(-not $nativeArch){{$nativeArch=[string]$env:PROCESSOR_ARCHITECTURE}}
  if($Architecture -eq 'x64' -and $nativeArch -notmatch 'AMD64|x64'){{throw "Application requires x64 Windows; endpoint architecture is $nativeArch"}}
  if($Architecture -eq 'arm64' -and $nativeArch -notmatch 'ARM64'){{throw "Application requires ARM64 Windows; endpoint architecture is $nativeArch"}}
  # Detection is intentionally evaluated before downloading large installer
  # payloads. Already-compliant endpoints can complete without transferring the
  # MSI/EXE or helper files at all.
  $detect=From-B64 $DetectionValueB64
  $already=$false
  if($DetectionType -eq 'file_exists' -and $detect){{$already=Test-Path $detect}}
  elseif($DetectionType -eq 'registry_product_code' -and $detect){{
    $keys=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$detect","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$detect")
    $already=($keys | Where-Object {{Test-Path $_}} | Measure-Object).Count -gt 0
  }}
  if($already){{ Write-Output "[SKIP] $AppName is already detected as installed."; exit 0 }}

  $files=(From-B64 $FilesB64 | ConvertFrom-Json)
  $installerPath=$null
  foreach($f in @($files)){{
    $dest=Join-Path $stage ([IO.Path]::GetFileName([string]$f.name))
    $uri="$base/api/agent/application-files/$($f.id)/download?agent_id=$([Uri]::EscapeDataString($AgentId))&job_id=$([Uri]::EscapeDataString($JobId))&sig=$($f.sig)"
    Write-Output "[DOWNLOAD] $($f.name)"
    Invoke-WebRequest -Uri $uri -OutFile $dest -UseBasicParsing -TimeoutSec 300
    if($f.sha256){{ $actual=(Get-FileHash -Path $dest -Algorithm SHA256).Hash.ToLowerInvariant(); if($actual -ne ([string]$f.sha256).ToLowerInvariant()){{throw "SHA256 mismatch for $($f.name)"}} }}
    if([int]$f.id -eq $InstallerFileId){{$installerPath=$dest}}
  }}
  if(-not $installerPath -or -not (Test-Path $installerPath)){{throw 'Installer download is missing'}}
  if($PreEnabled){{
    try{{Invoke-Hook $PreName $PreShell $PreContentB64 $PreTimeout $PreEnvB64 $stage}}
    catch{{ if($StopOnPreFailure){{throw}} else{{Write-Output "[HOOK-WARN] $($_.Exception.Message)"}} }}
  }}
  $params=From-B64 $ParametersB64
  $log=Join-Path $stage 'installer.log'; $stdout=Join-Path $stage 'installer.out'; $stderr=Join-Path $stage 'installer.err'
  if($InstallerType -eq 'msi'){{
    $args='/i "'+$installerPath+'" '+$params+' /l*v "'+$log+'"'
    Write-Output "[INSTALL] msiexec.exe $params"
    $proc=Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $args -WorkingDirectory $stage -WindowStyle Hidden -PassThru
  }} else {{
    Write-Output "[INSTALL] $([IO.Path]::GetFileName($installerPath)) $params"
    $proc=Start-Process -FilePath $installerPath -ArgumentList $params -WorkingDirectory $stage -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
  }}
  $null=$proc.Handle
  if(-not $proc.WaitForExit($TimeoutSec*1000)){{ try{{$proc.Kill()}}catch{{}}; throw "Installer timed out after $TimeoutSec seconds" }}
  $proc.WaitForExit(); $actualCode=[int64]$proc.ExitCode
  if(Test-Path $stdout){{Get-Content $stdout -Tail 200 -ErrorAction SilentlyContinue | Write-Output}}
  if(Test-Path $stderr){{Get-Content $stderr -Tail 200 -ErrorAction SilentlyContinue | Write-Output}}
  if(Test-Path $log){{Write-Output '--- MSI log tail ---'; Get-Content $log -Tail 120 -ErrorAction SilentlyContinue | Write-Output}}
  $success=@(From-B64 $SuccessCodesB64 | ConvertFrom-Json | ForEach-Object {{[int64]$_}})
  if($success -notcontains $actualCode){{ Write-Output "[FAIL] Installer exit code $actualCode"; if($actualCode -gt 0 -and $actualCode -lt 2147483647){{exit [int]$actualCode}} else{{exit 1}} }}
  $reboot=($actualCode -eq 3010 -or $actualCode -eq 1641)
  Write-Output "[OK] Installer exit code $actualCode"
  if($reboot){{Write-Output "[REBOOT-REQUIRED] Installer requested a reboot. Policy=$RebootBehavior"}}
  if($PostEnabled){{Invoke-Hook $PostName $PostShell $PostContentB64 $PostTimeout $PostEnvB64 $stage}}
  Write-Output "[APPLICATION-COMPLETE] $AppName"
  exit 0
}} catch {{
  Write-Output "[APPLICATION-FAILED] $($_.Exception.Message)"
  exit 1
}} finally {{
  Start-Sleep -Milliseconds 150
  Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}}
'''
    return script


def _queue_application_job(conn: sqlite3.Connection, *, application_snapshot: dict, agent_id: str,
                           label: str | None = None, now: float | None = None) -> str:
    now = now or time.time()
    job_id = str(uuid.uuid4())
    content = _build_application_install_script(application_snapshot, agent_id, job_id)
    payload = json.dumps({
        "name": application_snapshot["name"], "content": content,
        "timeout_sec": min(86400, int(application_snapshot.get("timeout_sec") or 1800) + 420),
        "shell": "powershell", "env": {}, "origin": "application",
        "application_id": int(application_snapshot["id"]),
    })
    conn.execute(
        "INSERT INTO jobs(id,agent_id,type,label,payload,created_at) VALUES(?,?,?,?,?,?)",
        (job_id, agent_id, "run_script", label or application_snapshot["name"], payload, now),
    )
    _wake_agent(agent_id)
    return job_id


@app.get("/api/applications")
def list_applications(request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute("SELECT * FROM applications ORDER BY name COLLATE NOCASE").fetchall()
        return {"applications": [_application_public_dict(conn, r) for r in rows]}


@app.post("/api/applications")
async def create_application(request: Request):
    user = require_admin(request)
    body = await request.json()
    vals = _validate_application_body(body)
    now = time.time()
    with db() as conn:
        for sid in (vals["pre_script_id"], vals["post_script_id"]):
            if sid and not conn.execute("SELECT 1 FROM scripts WHERE id=?", (sid,)).fetchone():
                raise HTTPException(status_code=400, detail="Selected pre/post script no longer exists")
        cur = conn.execute(
            """INSERT INTO applications
               (name,description,operating_system,architecture,installer_type,run_as,parameters,categories,
                success_codes,timeout_sec,reboot_behavior,detection_type,detection_value,pre_script_id,
                post_script_id,stop_on_pre_failure,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (vals["name"], vals["description"], vals["operating_system"], vals["architecture"],
             vals["installer_type"], vals["run_as"], vals["parameters"], vals["categories"],
             vals["success_codes"], vals["timeout_sec"], vals["reboot_behavior"], vals["detection_type"],
             vals["detection_value"], vals["pre_script_id"], vals["post_script_id"],
             vals["stop_on_pre_failure"], now, now),
        )
        app_id = cur.lastrowid
    audit(request, "application_create", vals["name"], f"application_id={app_id}", user=user)
    return {"ok": True, "id": app_id}


@app.put("/api/applications/{application_id}")
async def update_application(application_id: int, request: Request):
    user = require_admin(request)
    body = await request.json()
    with db() as conn:
        existing = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Unknown application")
        vals = _validate_application_body(body, existing)
        for sid in (vals["pre_script_id"], vals["post_script_id"]):
            if sid and not conn.execute("SELECT 1 FROM scripts WHERE id=?", (sid,)).fetchone():
                raise HTTPException(status_code=400, detail="Selected pre/post script no longer exists")
        conn.execute(
            """UPDATE applications SET name=?,description=?,operating_system=?,architecture=?,installer_type=?,
               run_as=?,parameters=?,categories=?,success_codes=?,timeout_sec=?,reboot_behavior=?,detection_type=?,
               detection_value=?,pre_script_id=?,post_script_id=?,stop_on_pre_failure=?,updated_at=? WHERE id=?""",
            (vals["name"], vals["description"], vals["operating_system"], vals["architecture"],
             vals["installer_type"], vals["run_as"], vals["parameters"], vals["categories"],
             vals["success_codes"], vals["timeout_sec"], vals["reboot_behavior"], vals["detection_type"],
             vals["detection_value"], vals["pre_script_id"], vals["post_script_id"],
             vals["stop_on_pre_failure"], time.time(), application_id),
        )
    audit(request, "application_update", vals["name"], f"application_id={application_id}", user=user)
    return {"ok": True}


@app.put("/api/applications/{application_id}/files")
async def upload_application_file(application_id: int, request: Request):
    user = require_admin(request)
    kind = str(request.query_params.get("kind") or "").lower()
    filename = _safe_app_filename(request.query_params.get("filename") or "")
    if kind not in ("installer", "helper", "icon"):
        raise HTTPException(status_code=400, detail="File kind must be installer, helper, or icon")
    if kind == "icon" and Path(filename).suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp", ".ico"):
        raise HTTPException(status_code=400, detail="Installer icons must be PNG, JPG, WEBP, or ICO")
    max_bytes = APP_MAX_INSTALLER_BYTES if kind == "installer" else (APP_MAX_ICON_BYTES if kind == "icon" else APP_MAX_HELPER_BYTES)
    with db() as conn:
        app_row = conn.execute("SELECT * FROM applications WHERE id=?", (application_id,)).fetchone()
        if not app_row:
            raise HTTPException(status_code=404, detail="Unknown application")
        if kind == "helper":
            n = conn.execute("SELECT COUNT(*) n FROM application_files WHERE application_id=? AND kind='helper' AND active=1", (application_id,)).fetchone()["n"]
            if n >= 5:
                raise HTTPException(status_code=400, detail="Maximum 5 helper files")
        if kind == "installer":
            ext = Path(filename).suffix.lower().lstrip(".")
            if ext != app_row["installer_type"]:
                raise HTTPException(status_code=400, detail=f"This application expects a .{app_row['installer_type']} installer")
        # Installer/helper files are staged together on a case-insensitive Windows
        # filesystem. Reject normalized-name collisions so a helper can never
        # overwrite the installer (or another helper) after download.
        if kind in ("installer", "helper"):
            active_names = conn.execute(
                "SELECT kind,original_name FROM application_files WHERE application_id=? AND active=1 AND kind IN ('installer','helper')",
                (application_id,),
            ).fetchall()
            for existing_file in active_names:
                if kind == "installer" and existing_file["kind"] == "installer":
                    continue  # this is a supported installer replacement
                if str(existing_file["original_name"] or "").lower() == filename.lower():
                    raise HTTPException(status_code=409, detail=f"An active application file already uses the name '{filename}'")
    app_dir = APPLICATION_DIR / str(application_id)
    app_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}-{filename}"
    final_path = app_dir / stored_name
    tmp_path = app_dir / (stored_name + ".upload")
    total = 0
    digest = hashlib.sha256()
    recorded = False
    try:
        with tmp_path.open("wb") as fh:
            async for chunk in request.stream():
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail=f"File exceeds {max_bytes // (1024*1024)} MB limit")
                digest.update(chunk)
                fh.write(chunk)
        if total <= 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        os.replace(tmp_path, final_path)
        with db() as conn:
            if kind in ("installer", "icon"):
                conn.execute("UPDATE application_files SET active=0 WHERE application_id=? AND kind=? AND active=1", (application_id, kind))
            cur = conn.execute(
                "INSERT INTO application_files(application_id,kind,original_name,stored_name,size_bytes,sha256,active,created_at) VALUES(?,?,?,?,?,?,1,?)",
                (application_id, kind, filename, stored_name, total, digest.hexdigest(), time.time()),
            )
            conn.execute("UPDATE applications SET updated_at=? WHERE id=?", (time.time(), application_id))
            file_id = cur.lastrowid
        # Set this only after the DB context has successfully committed. If the
        # insert/commit fails, remove the already-staged file instead of leaving
        # an unreachable orphan on disk.
        recorded = True
    except Exception:
        tmp_path.unlink(missing_ok=True)
        if final_path.exists() and not recorded:
            final_path.unlink(missing_ok=True)
        raise
    audit(request, "application_file_upload", str(application_id), f"{kind}:{filename}:{total}", user=user)
    return {"ok": True, "file_id": file_id, "size_bytes": total, "sha256": digest.hexdigest()}


@app.delete("/api/applications/{application_id}/files/{file_id}")
def delete_application_file(application_id: int, file_id: int, request: Request):
    user = require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM application_files WHERE id=? AND application_id=?", (file_id, application_id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown application file")
        if row["active"] and row["kind"] == "installer":
            refs = conn.execute("SELECT COUNT(*) n FROM automation_stack_steps WHERE action_type='application' AND action_id=?", (application_id,)).fetchone()["n"]
            if refs:
                raise HTTPException(status_code=409, detail=f"Installer is used by {refs} onboarding stack step(s); upload a replacement instead of removing it")
        conn.execute("UPDATE application_files SET active=0 WHERE id=?", (file_id,))
        conn.execute("UPDATE applications SET updated_at=? WHERE id=?", (time.time(), application_id))
    audit(request, "application_file_remove", str(application_id), row["original_name"], user=user)
    return {"ok": True}


@app.delete("/api/applications/{application_id}")
def delete_application(application_id: int, request: Request):
    user = require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT name FROM applications WHERE id=?", (application_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown application")
        refs = conn.execute("SELECT COUNT(*) n FROM automation_stack_steps WHERE action_type='application' AND action_id=?", (application_id,)).fetchone()["n"]
        if refs:
            raise HTTPException(status_code=400, detail=f"Application is used by {refs} onboarding stack step(s)")
        # An installation job snapshots this application's file IDs. Keep those
        # files alive until every queued/running install has finished so deleting
        # an application can never strand an endpoint halfway through a download.
        active_jobs = 0
        for job in conn.execute("SELECT payload FROM jobs WHERE status IN ('pending','running') AND type='run_script'").fetchall():
            try:
                payload = json.loads(job["payload"] or "{}")
            except (ValueError, TypeError):
                continue
            if payload.get("origin") == "application" and int(payload.get("application_id") or -1) == application_id:
                active_jobs += 1
        if active_jobs:
            raise HTTPException(status_code=409, detail=f"Application has {active_jobs} pending/running installation job(s)")
        # A stack is version-snapshotted at run start. The technician may edit
        # the source stack while that run is active, so also protect application
        # files referenced only by a pending/running historical run snapshot.
        active_onboarding = conn.execute(
            """SELECT COUNT(*) n FROM onboarding_run_steps rs
               JOIN onboarding_runs r ON r.id=rs.run_id
               WHERE rs.action_type='application' AND rs.action_id=?
                 AND r.status IN ('pending','running') AND rs.status IN ('pending','running')""",
            (application_id,),
        ).fetchone()["n"]
        if active_onboarding:
            raise HTTPException(status_code=409, detail=f"Application is still required by {active_onboarding} active onboarding step(s)")
        conn.execute("DELETE FROM application_files WHERE application_id=?", (application_id,))
        conn.execute("DELETE FROM applications WHERE id=?", (application_id,))
    shutil.rmtree(APPLICATION_DIR / str(application_id), ignore_errors=True)
    audit(request, "application_delete", row["name"], f"application_id={application_id}", user=user)
    return {"ok": True}


@app.get("/api/applications/{application_id}/icon")
def application_icon(application_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM application_files WHERE application_id=? AND kind='icon' AND active=1 ORDER BY id DESC LIMIT 1",
            (application_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Application has no icon")
    path = APPLICATION_DIR / str(application_id) / row["stored_name"]
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Application icon file is missing")
    ext = Path(row["original_name"]).suffix.lower()
    media = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon"}.get(ext, "application/octet-stream")
    return FileResponse(path, media_type=media, headers={"Cache-Control": "private, no-store"})


@app.get("/api/agent/application-files/{file_id}/download")
def agent_application_file_download(file_id: int, request: Request):
    agent_id = str(request.query_params.get("agent_id") or "")
    job_id = str(request.query_params.get("job_id") or "")
    supplied = str(request.query_params.get("sig") or "")
    if not agent_id or not job_id or not supplied:
        raise HTTPException(status_code=403, detail="Missing download authorization")
    expected = _app_download_signature(file_id, agent_id, job_id)
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Bad download authorization")
    with db() as conn:
        job = conn.execute("SELECT agent_id,status,payload FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["agent_id"] != agent_id or job["status"] not in ("pending", "running"):
            raise HTTPException(status_code=403, detail="Installer download window is closed")
        try:
            payload = json.loads(job["payload"] or "{}")
        except (ValueError, TypeError):
            payload = {}
        if payload.get("origin") != "application":
            raise HTTPException(status_code=403, detail="Job is not an application installation")
        row = conn.execute("SELECT * FROM application_files WHERE id=?", (file_id,)).fetchone()
        if not row or int(row["application_id"]) != int(payload.get("application_id") or -1):
            raise HTTPException(status_code=404, detail="Application file not found")
    path = APPLICATION_DIR / str(row["application_id"]) / row["stored_name"]
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Application file is missing on the server")
    return FileResponse(path, filename=row["original_name"], media_type="application/octet-stream",
                        headers={"Cache-Control": "no-store"})


@app.post("/api/run-application")
async def run_application(request: Request):
    user = require_admin(request)
    body = await request.json()
    try:
        application_id = int(body.get("application_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="application_id is required")
    machine_ids = [str(x) for x in (body.get("machine_ids") or []) if str(x)]
    with db() as conn:
        snapshot = _application_snapshot(conn, application_id)
        if body.get("all_machines"):
            machine_ids = [r["id"] for r in conn.execute("SELECT id FROM agents")]
        elif body.get("org_ids"):
            org_ids = [int(x) for x in body.get("org_ids") or []]
            if org_ids:
                qmarks = ",".join("?" for _ in org_ids)
                machine_ids += [r["id"] for r in conn.execute(f"SELECT id FROM agents WHERE org_id IN ({qmarks})", org_ids)]
        machine_ids = list(dict.fromkeys(machine_ids))
        if not machine_ids:
            raise HTTPException(status_code=400, detail="No machines selected")
        created = 0
        for mid in machine_ids:
            agent = conn.execute("SELECT id,os_version FROM agents WHERE id=?", (mid,)).fetchone()
            if not agent or "windows" not in str(agent["os_version"] or "").lower():
                continue
            _queue_application_job(conn, application_snapshot=snapshot, agent_id=mid, now=time.time())
            created += 1
    audit(request, "application_run", snapshot["name"], f"devices={created}", user=user)
    return {"ok": True, "jobs_created": created}


# Run a script on machines ---------------------------------------------------


@app.post("/api/run-script")
async def run_script(request: Request):
    require_admin(request)
    body = await request.json()
    script_id = body.get("script_id")
    machine_ids = body.get("machine_ids", [])
    with db() as conn:
        s = conn.execute("SELECT * FROM scripts WHERE id=?", (script_id,)).fetchone()
        if not s:
            raise HTTPException(status_code=404, detail="Unknown script")
        if body.get("all_machines"):
            machine_ids = [r["id"] for r in conn.execute("SELECT id FROM agents")]
        elif body.get("org_ids"):
            org_ids = [int(x) for x in body["org_ids"]]
            qmarks = ",".join("?" for _ in org_ids)
            machine_ids = list(machine_ids) + [
                r["id"] for r in conn.execute(
                    f"SELECT id FROM agents WHERE org_id IN ({qmarks})", org_ids
                )
            ]
            machine_ids = list(dict.fromkeys(machine_ids))
        if not machine_ids:
            raise HTTPException(status_code=400, detail="No machines selected")
        env = resolve_variable_values(script_variables(s), body.get("variables"), strict=True)
        payload = json.dumps({
            "name": s["name"], "content": s["content"], "timeout_sec": s["timeout_sec"],
            "shell": s["shell"] or "powershell", "env": env,
        })
        now = time.time()
        created = 0
        for mid in machine_ids:
            if not conn.execute("SELECT 1 FROM agents WHERE id=?", (mid,)).fetchone():
                continue
            conn.execute(
                "INSERT INTO jobs (id, agent_id, type, label, payload, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), mid, "run_script", s["name"], payload, now),
            )
            created += 1
    return {"ok": True, "jobs_created": created}


# Organization onboarding stacks --------------------------------------------

ONBOARDING_FAILURE_POLICIES = {"continue", "stop"}
ONBOARDING_TERMINAL = {"completed", "completed_with_errors", "failed", "cancelled"}


def _stack_action_name(conn: sqlite3.Connection, action_type: str, action_id: int) -> str:
    if action_type == "script":
        row = conn.execute("SELECT name FROM scripts WHERE id=?", (action_id,)).fetchone()
    elif action_type == "application":
        row = conn.execute("SELECT name FROM applications WHERE id=?", (action_id,)).fetchone()
    else:
        row = None
    return row["name"] if row else "(missing action)"


def _sanitize_stack_steps(conn: sqlite3.Connection, raw_steps) -> list[dict]:
    out = []
    for idx, item in enumerate((raw_steps or [])[:100], start=1):
        if not isinstance(item, dict):
            continue
        action_type = str(item.get("action_type") or "").lower()
        if action_type not in ("script", "application"):
            raise HTTPException(status_code=400, detail=f"Step {idx}: unsupported action type")
        try:
            action_id = int(item.get("action_id"))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"Step {idx}: action is required")
        table = "scripts" if action_type == "script" else "applications"
        if not conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (action_id,)).fetchone():
            raise HTTPException(status_code=400, detail=f"Step {idx}: selected {action_type} no longer exists")
        if action_type == "application" and not conn.execute(
            "SELECT 1 FROM application_files WHERE application_id=? AND kind='installer' AND active=1", (action_id,)
        ).fetchone():
            raise HTTPException(status_code=400, detail=f"Step {idx}: selected application has no active installer file")
        failure_policy = str(item.get("failure_policy") or "").lower()
        if failure_policy and failure_policy not in ONBOARDING_FAILURE_POLICIES:
            failure_policy = ""
        retry_count = item.get("retry_count")
        if retry_count in (None, ""):
            retry_count = None
        else:
            try:
                retry_count = max(0, min(5, int(retry_count)))
            except (TypeError, ValueError):
                retry_count = None
        variables = item.get("variables") if isinstance(item.get("variables"), dict) else {}
        out.append({
            "position": idx, "action_type": action_type, "action_id": action_id,
            "variables": json.dumps(variables), "failure_policy": failure_policy,
            "retry_count": retry_count,
        })
    return out


def _stack_public_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = dict(row)
    steps = conn.execute("SELECT * FROM automation_stack_steps WHERE stack_id=? ORDER BY position", (row["id"],)).fetchall()
    d["steps"] = []
    for st in steps:
        item = dict(st)
        try:
            item["variables"] = json.loads(st["variables"] or "{}")
        except (ValueError, TypeError):
            item["variables"] = {}
        item["action_name"] = _stack_action_name(conn, st["action_type"], st["action_id"])
        d["steps"].append(item)
    d["step_count"] = len(d["steps"])
    return d


def _action_snapshot(conn: sqlite3.Connection, action_type: str, action_id: int, variables: dict) -> dict:
    if action_type == "script":
        row = conn.execute("SELECT * FROM scripts WHERE id=?", (action_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Stack script no longer exists")
        return {
            "id": row["id"], "name": row["name"], "content": row["content"],
            "shell": row["shell"] or "powershell", "timeout_sec": int(row["timeout_sec"] or 900),
            "env": resolve_variable_values(script_variables(row), variables, strict=False),
        }
    if action_type == "application":
        return _application_snapshot(conn, action_id)
    raise HTTPException(status_code=400, detail="Unsupported stack action")


def _onboarding_run_dict(conn: sqlite3.Connection, row: sqlite3.Row | None) -> dict | None:
    if not row:
        return None
    d = dict(row)
    steps = conn.execute("SELECT * FROM onboarding_run_steps WHERE run_id=? ORDER BY position", (row["id"],)).fetchall()
    d["steps"] = [dict(st) for st in steps]
    d["completed_steps"] = sum(1 for st in steps if st["status"] == "done")
    d["failed_steps"] = sum(1 for st in steps if st["status"] == "failed")
    return d


def _device_onboarding_dict(conn: sqlite3.Connection, agent_id: str) -> dict:
    state_row = conn.execute("SELECT * FROM device_onboarding_state WHERE agent_id=?", (agent_id,)).fetchone()
    run = conn.execute("SELECT * FROM onboarding_runs WHERE agent_id=? ORDER BY created_at DESC LIMIT 1", (agent_id,)).fetchone()
    return {"state": dict(state_row) if state_row else None, "run": _onboarding_run_dict(conn, run)}


def _finish_onboarding_run(conn: sqlite3.Connection, run_id: str, status: str, now: float):
    run = conn.execute("SELECT * FROM onboarding_runs WHERE id=?", (run_id,)).fetchone()
    if not run:
        return
    conn.execute("UPDATE onboarding_runs SET status=?, finished_at=? WHERE id=?", (status, now, run_id))
    conn.execute(
        """INSERT INTO device_onboarding_state(agent_id,status,stack_id,stack_version,last_run_id,started_at,completed_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(agent_id) DO UPDATE SET status=excluded.status,stack_id=excluded.stack_id,
             stack_version=excluded.stack_version,last_run_id=excluded.last_run_id,
             started_at=excluded.started_at,completed_at=excluded.completed_at,updated_at=excluded.updated_at""",
        (run["agent_id"], status, run["stack_id"], run["stack_version"], run_id,
         run["started_at"] or run["created_at"], now, now),
    )


def _queue_next_onboarding_step(conn: sqlite3.Connection, run_id: str, now: float | None = None) -> str | None:
    now = now or time.time()
    run = conn.execute("SELECT * FROM onboarding_runs WHERE id=?", (run_id,)).fetchone()
    if not run or run["status"] in ONBOARDING_TERMINAL:
        return None
    if conn.execute("SELECT 1 FROM onboarding_run_steps WHERE run_id=? AND status='running'", (run_id,)).fetchone():
        return None
    # Preserve strict list ordering even when a failed step is waiting for a
    # delayed retry. Always inspect the earliest pending position first; never
    # skip ahead to a later step merely because that later step is immediately
    # eligible to run.
    step = conn.execute(
        "SELECT * FROM onboarding_run_steps WHERE run_id=? AND status='pending' ORDER BY position LIMIT 1",
        (run_id,),
    ).fetchone()
    if not step:
        failed = conn.execute("SELECT COUNT(*) n FROM onboarding_run_steps WHERE run_id=? AND status='failed'", (run_id,)).fetchone()["n"]
        _finish_onboarding_run(conn, run_id, "completed_with_errors" if failed else "completed", now)
        return None
    if float(step["next_attempt_at"] or 0) > float(now):
        return None
    try:
        snap = json.loads(step["action_snapshot"] or "{}")
    except (ValueError, TypeError):
        snap = {}
    attempt = int(step["attempt"] or 0) + 1
    label = f"Onboarding: {run['stack_name']} · {step['position']}. {step['action_name']}"
    try:
        if step["action_type"] == "script":
            payload = json.dumps({
                "name": snap.get("name") or step["action_name"], "content": snap.get("content") or "",
                "timeout_sec": int(snap.get("timeout_sec") or 900), "shell": snap.get("shell") or "powershell",
                "env": snap.get("env") if isinstance(snap.get("env"), dict) else {}, "origin": "onboarding",
            })
            job_id = str(uuid.uuid4())
            conn.execute("INSERT INTO jobs(id,agent_id,type,label,payload,created_at) VALUES(?,?,?,?,?,?)",
                         (job_id, run["agent_id"], "run_script", label, payload, now))
            _wake_agent(run["agent_id"])
        elif step["action_type"] == "application":
            job_id = _queue_application_job(conn, application_snapshot=snap, agent_id=run["agent_id"], label=label, now=now)
        else:
            raise ValueError("Unsupported onboarding action")
    except Exception as exc:
        conn.execute("UPDATE onboarding_run_steps SET status='failed',last_error=?,finished_at=? WHERE id=?",
                     (str(exc)[:2000], now, step["id"]))
        if step["failure_policy"] == "stop":
            conn.execute("UPDATE onboarding_run_steps SET status='skipped',finished_at=? WHERE run_id=? AND status='pending'", (now, run_id))
            _finish_onboarding_run(conn, run_id, "failed", now)
        else:
            return _queue_next_onboarding_step(conn, run_id, now)
        return None
    conn.execute(
        "UPDATE onboarding_run_steps SET status='running',job_id=?,attempt=?,started_at=?,next_attempt_at=0,last_error='' WHERE id=?",
        (job_id, attempt, now, step["id"]),
    )
    conn.execute("UPDATE onboarding_runs SET status='running',current_step=?,started_at=COALESCE(started_at,?) WHERE id=?",
                 (step["position"], now, run_id))
    conn.execute("UPDATE device_onboarding_state SET status='running',updated_at=? WHERE agent_id=?", (now, run["agent_id"]))
    return job_id


def _start_onboarding_run(conn: sqlite3.Connection, agent: sqlite3.Row, stack: sqlite3.Row,
                          trigger_type: str, now: float | None = None) -> str:
    now = now or time.time()
    if conn.execute("SELECT 1 FROM onboarding_runs WHERE agent_id=? AND status IN ('pending','running')", (agent["id"],)).fetchone():
        raise HTTPException(status_code=409, detail="An onboarding stack is already running on this device")
    steps = conn.execute("SELECT * FROM automation_stack_steps WHERE stack_id=? ORDER BY position", (stack["id"],)).fetchall()
    if not steps:
        raise HTTPException(status_code=400, detail="Onboarding stack has no steps")

    # Validate and snapshot every action BEFORE writing run state. The shared DB
    # helper commits on context exit, including exception paths used elsewhere in
    # the legacy server, so preflighting here prevents a missing script/installer
    # from leaving a partial onboarding run behind.
    prepared_steps = []
    for st in steps:
        try:
            vars_obj = json.loads(st["variables"] or "{}")
        except (ValueError, TypeError):
            vars_obj = {}
        snapshot = _action_snapshot(conn, st["action_type"], st["action_id"], vars_obj if isinstance(vars_obj, dict) else {})
        policy = st["failure_policy"] or stack["failure_policy"] or "continue"
        retries = int(st["retry_count"] if st["retry_count"] is not None else stack["retry_count"] or 0)
        prepared_steps.append((st, snapshot, policy, retries))

    run_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO onboarding_runs(id,agent_id,org_id,stack_id,stack_name,stack_version,trigger_type,status,current_step,total_steps,retry_delay_sec,created_at,started_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, agent["id"], agent["org_id"], stack["id"], stack["name"], int(stack["version"] or 1),
         trigger_type, "pending", 0, len(prepared_steps), max(0, min(3600, int(stack["retry_delay_sec"] or 0))), now, now),
    )
    for st, snapshot, policy, retries in prepared_steps:
        conn.execute(
            """INSERT INTO onboarding_run_steps
               (run_id,position,action_type,action_id,action_name,action_snapshot,status,attempt,retry_count,failure_policy,created_at,next_attempt_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,0)""",
            (run_id, st["position"], st["action_type"], st["action_id"], snapshot.get("name") or _stack_action_name(conn, st["action_type"], st["action_id"]),
             json.dumps(snapshot), "pending", 0, retries, policy, now),
        )
    conn.execute(
        """INSERT INTO device_onboarding_state(agent_id,status,stack_id,stack_version,last_run_id,started_at,completed_at,updated_at)
           VALUES(?,?,?,?,?,?,NULL,?)
           ON CONFLICT(agent_id) DO UPDATE SET status=excluded.status,stack_id=excluded.stack_id,
             stack_version=excluded.stack_version,last_run_id=excluded.last_run_id,started_at=excluded.started_at,
             completed_at=NULL,updated_at=excluded.updated_at""",
        (agent["id"], "pending", stack["id"], int(stack["version"] or 1), run_id, now, now),
    )
    _queue_next_onboarding_step(conn, run_id, now)
    return run_id


def _process_onboarding_job_result(conn: sqlite3.Connection, job_id: str, ok: bool, output: str, now: float):
    step = conn.execute("SELECT * FROM onboarding_run_steps WHERE job_id=? ORDER BY id DESC LIMIT 1", (job_id,)).fetchone()
    if not step:
        return
    run = conn.execute("SELECT * FROM onboarding_runs WHERE id=?", (step["run_id"],)).fetchone()
    if not run:
        return
    if run["status"] == "cancelled":
        conn.execute("UPDATE onboarding_run_steps SET status='cancelled',finished_at=?,last_error=? WHERE id=?",
                     (now, "Run cancelled while this step was executing.", step["id"]))
        return
    if ok:
        conn.execute("UPDATE onboarding_run_steps SET status='done',finished_at=?,last_error='' WHERE id=?", (now, step["id"]))
        _queue_next_onboarding_step(conn, run["id"], now)
        return
    attempts = int(step["attempt"] or 0)
    retries = int(step["retry_count"] or 0)
    err = (output or "Step failed")[-2000:]
    if attempts <= retries:
        # Retry timing is part of the run snapshot. Editing the source stack
        # while onboarding is in progress must not change execution semantics.
        delay_sec = max(0, min(3600, int(run["retry_delay_sec"] or 0)))
        conn.execute(
            "UPDATE onboarding_run_steps SET status='pending',job_id='',last_error=?,finished_at=NULL,next_attempt_at=? WHERE id=?",
            (err, now + delay_sec, step["id"]),
        )
        if delay_sec == 0:
            _queue_next_onboarding_step(conn, run["id"], now)
        return
    conn.execute("UPDATE onboarding_run_steps SET status='failed',finished_at=?,last_error=? WHERE id=?", (now, err, step["id"]))
    if step["failure_policy"] == "stop":
        conn.execute("UPDATE onboarding_run_steps SET status='skipped',finished_at=? WHERE run_id=? AND status='pending'", (now, run["id"]))
        _finish_onboarding_run(conn, run["id"], "failed", now)
    else:
        _queue_next_onboarding_step(conn, run["id"], now)


def _maybe_advance_onboarding(conn: sqlite3.Connection, agent_id: str, now: float):
    run = conn.execute("SELECT * FROM onboarding_runs WHERE agent_id=? AND status IN ('pending','running') ORDER BY created_at DESC LIMIT 1", (agent_id,)).fetchone()
    if run:
        _queue_next_onboarding_step(conn, run["id"], now)


def _is_server_agent(agent: sqlite3.Row) -> bool:
    cls = str(agent["device_class"] or "").lower() if "device_class" in agent.keys() else ""
    return cls == "server" or "windows server" in str(agent["os_version"] or "").lower()


def _maybe_start_automatic_onboarding(conn: sqlite3.Connection, agent_id: str, now: float):
    agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not agent or not agent["org_id"] or "windows" not in str(agent["os_version"] or "").lower():
        return None
    cfg = conn.execute("SELECT * FROM org_onboarding_settings WHERE org_id=?", (agent["org_id"],)).fetchone()
    if not cfg or not cfg["enabled"] or not cfg["active_stack_id"] or not cfg["enabled_at"]:
        return None
    # Critical safety gate: enabling onboarding must NEVER retrofit the existing
    # fleet. Only devices enrolled after automatic onboarding was enabled qualify.
    if float(agent["created_at"] or 0) < float(cfg["enabled_at"] or 0):
        return None
    if conn.execute("SELECT 1 FROM device_onboarding_state WHERE agent_id=?", (agent_id,)).fetchone():
        return None
    server = _is_server_agent(agent)
    if server and not cfg["target_servers"]:
        return None
    if not server and not cfg["target_workstations"]:
        return None
    stack = conn.execute("SELECT * FROM automation_stacks WHERE id=? AND org_id=?", (cfg["active_stack_id"], agent["org_id"])).fetchone()
    if not stack:
        return None
    try:
        return _start_onboarding_run(conn, agent, stack, "automatic", now)
    except HTTPException:
        return None


@app.get("/api/orgs/{org_id}/onboarding")
def get_org_onboarding(org_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        cfg = conn.execute("SELECT * FROM org_onboarding_settings WHERE org_id=?", (org_id,)).fetchone()
        stacks = conn.execute("SELECT * FROM automation_stacks WHERE org_id=? ORDER BY name COLLATE NOCASE", (org_id,)).fetchall()
        settings = dict(cfg) if cfg else {
            "org_id": org_id, "active_stack_id": None, "enabled": 0, "enabled_at": None,
            "target_workstations": 1, "target_servers": 0,
        }
        return {"settings": settings, "stacks": [_stack_public_dict(conn, st) for st in stacks]}


@app.post("/api/orgs/{org_id}/onboarding/stacks")
async def create_onboarding_stack(org_id: int, request: Request):
    user = require_admin(request)
    body = await request.json()
    name = str(body.get("name") or "").strip()[:160]
    if not name:
        raise HTTPException(status_code=400, detail="Stack name is required")
    failure_policy = str(body.get("failure_policy") or "continue").lower()
    if failure_policy not in ONBOARDING_FAILURE_POLICIES:
        failure_policy = "continue"
    retry_count = max(0, min(5, int(body.get("retry_count") or 0)))
    retry_delay_sec = max(0, min(3600, int(body.get("retry_delay_sec") or 60)))
    now = time.time()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        steps = _sanitize_stack_steps(conn, body.get("steps") or [])
        cur = conn.execute(
            "INSERT INTO automation_stacks(org_id,name,description,version,failure_policy,retry_count,retry_delay_sec,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (org_id, name, str(body.get("description") or "")[:2000], 1, failure_policy, retry_count, retry_delay_sec, now, now),
        )
        stack_id = cur.lastrowid
        for st in steps:
            conn.execute(
                "INSERT INTO automation_stack_steps(stack_id,position,action_type,action_id,variables,failure_policy,retry_count,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (stack_id, st["position"], st["action_type"], st["action_id"], st["variables"], st["failure_policy"], st["retry_count"], now),
            )
    audit(request, "onboarding_stack_create", name, f"org_id={org_id};steps={len(steps)}", user=user)
    return {"ok": True, "id": stack_id}


@app.put("/api/onboarding/stacks/{stack_id}")
async def update_onboarding_stack(stack_id: int, request: Request):
    user = require_admin(request)
    body = await request.json()
    with db() as conn:
        existing = conn.execute("SELECT * FROM automation_stacks WHERE id=?", (stack_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Unknown onboarding stack")
        name = str(body.get("name", existing["name"]) or "").strip()[:160]
        if not name:
            raise HTTPException(status_code=400, detail="Stack name is required")
        failure_policy = str(body.get("failure_policy", existing["failure_policy"]) or "continue").lower()
        if failure_policy not in ONBOARDING_FAILURE_POLICIES:
            failure_policy = "continue"
        retry_count = max(0, min(5, int(body.get("retry_count", existing["retry_count"]) or 0)))
        retry_delay_sec = max(0, min(3600, int(body.get("retry_delay_sec", existing["retry_delay_sec"]) or 60)))
        steps = _sanitize_stack_steps(conn, body.get("steps") or [])
        new_version = int(existing["version"] or 1) + 1
        now = time.time()
        conn.execute(
            "UPDATE automation_stacks SET name=?,description=?,version=?,failure_policy=?,retry_count=?,retry_delay_sec=?,updated_at=? WHERE id=?",
            (name, str(body.get("description", existing["description"]) or "")[:2000], new_version, failure_policy, retry_count, retry_delay_sec, now, stack_id),
        )
        conn.execute("DELETE FROM automation_stack_steps WHERE stack_id=?", (stack_id,))
        for st in steps:
            conn.execute(
                "INSERT INTO automation_stack_steps(stack_id,position,action_type,action_id,variables,failure_policy,retry_count,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (stack_id, st["position"], st["action_type"], st["action_id"], st["variables"], st["failure_policy"], st["retry_count"], now),
            )
    audit(request, "onboarding_stack_update", name, f"stack_id={stack_id};version={new_version};steps={len(steps)}", user=user)
    return {"ok": True, "version": new_version}


@app.delete("/api/onboarding/stacks/{stack_id}")
def delete_onboarding_stack(stack_id: int, request: Request):
    user = require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM automation_stacks WHERE id=?", (stack_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown onboarding stack")
        if conn.execute("SELECT 1 FROM onboarding_runs WHERE stack_id=? AND status IN ('pending','running')", (stack_id,)).fetchone():
            raise HTTPException(status_code=409, detail="Cannot delete a stack while it is running")
        conn.execute("UPDATE org_onboarding_settings SET active_stack_id=NULL,enabled=0,updated_at=? WHERE active_stack_id=?", (time.time(), stack_id))
        conn.execute("DELETE FROM automation_stack_steps WHERE stack_id=?", (stack_id,))
        conn.execute("DELETE FROM automation_stacks WHERE id=?", (stack_id,))
    audit(request, "onboarding_stack_delete", row["name"], f"stack_id={stack_id}", user=user)
    return {"ok": True}


@app.put("/api/orgs/{org_id}/onboarding/settings")
async def save_org_onboarding_settings(org_id: int, request: Request):
    user = require_admin(request)
    body = await request.json()
    enabled = bool(body.get("enabled"))
    active_stack_id = body.get("active_stack_id")
    try:
        active_stack_id = int(active_stack_id) if active_stack_id not in (None, "", 0, "0") else None
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid active stack")
    now = time.time()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        if active_stack_id:
            stack = conn.execute("SELECT * FROM automation_stacks WHERE id=? AND org_id=?", (active_stack_id, org_id)).fetchone()
            if not stack:
                raise HTTPException(status_code=400, detail="Selected stack does not belong to this customer")
            if enabled and not conn.execute("SELECT 1 FROM automation_stack_steps WHERE stack_id=?", (active_stack_id,)).fetchone():
                raise HTTPException(status_code=400, detail="Add at least one step before enabling automatic onboarding")
        elif enabled:
            raise HTTPException(status_code=400, detail="Select an onboarding stack before enabling automatic onboarding")
        old = conn.execute("SELECT * FROM org_onboarding_settings WHERE org_id=?", (org_id,)).fetchone()
        enabled_at = old["enabled_at"] if old else None
        if enabled and (not old or not old["enabled"]):
            enabled_at = now
        conn.execute(
            """INSERT INTO org_onboarding_settings(org_id,active_stack_id,enabled,enabled_at,target_workstations,target_servers,updated_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(org_id) DO UPDATE SET active_stack_id=excluded.active_stack_id,enabled=excluded.enabled,
                 enabled_at=excluded.enabled_at,target_workstations=excluded.target_workstations,
                 target_servers=excluded.target_servers,updated_at=excluded.updated_at""",
            (org_id, active_stack_id, 1 if enabled else 0, enabled_at,
             1 if body.get("target_workstations", True) else 0, 1 if body.get("target_servers", False) else 0, now),
        )
    audit(request, "onboarding_settings", str(org_id), f"enabled={enabled};stack={active_stack_id}", user=user)
    return {"ok": True, "enabled_at": enabled_at}


@app.get("/api/machines/{agent_id}/onboarding")
def get_machine_onboarding(agent_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        return _device_onboarding_dict(conn, agent_id)


@app.post("/api/machines/{agent_id}/onboarding/run")
async def run_machine_onboarding(agent_id: str, request: Request):
    user = require_admin(request)
    body = await request.json()
    with db() as conn:
        agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Unknown machine")
        if "windows" not in str(agent["os_version"] or "").lower():
            raise HTTPException(status_code=400, detail="Organization onboarding currently supports Windows devices only")
        if not agent["org_id"]:
            raise HTTPException(status_code=400, detail="Assign the device to a customer first")
        stack_id = body.get("stack_id")
        if stack_id in (None, "", 0, "0"):
            cfg = conn.execute("SELECT active_stack_id FROM org_onboarding_settings WHERE org_id=?", (agent["org_id"],)).fetchone()
            stack_id = cfg["active_stack_id"] if cfg else None
        try:
            stack_id = int(stack_id)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Select an onboarding stack")
        stack = conn.execute("SELECT * FROM automation_stacks WHERE id=? AND org_id=?", (stack_id, agent["org_id"])).fetchone()
        if not stack:
            raise HTTPException(status_code=400, detail="Stack does not belong to this customer")
        run_id = _start_onboarding_run(conn, agent, stack, "manual", time.time())
    audit(request, "onboarding_manual_run", agent_id, f"stack_id={stack_id};run_id={run_id}", user=user)
    return {"ok": True, "run_id": run_id}


@app.post("/api/machines/{agent_id}/onboarding/retry-failed")
def retry_machine_onboarding(agent_id: str, request: Request):
    user = require_admin(request)
    now = time.time()
    with db() as conn:
        run = conn.execute("SELECT * FROM onboarding_runs WHERE agent_id=? ORDER BY created_at DESC LIMIT 1", (agent_id,)).fetchone()
        if not run or run["status"] not in ("failed", "completed_with_errors"):
            raise HTTPException(status_code=400, detail="There are no failed onboarding steps to retry")
        count = conn.execute("SELECT COUNT(*) n FROM onboarding_run_steps WHERE run_id=? AND status='failed'", (run["id"],)).fetchone()["n"]
        if not count:
            raise HTTPException(status_code=400, detail="There are no failed onboarding steps to retry")
        conn.execute("UPDATE onboarding_run_steps SET status='pending',job_id='',attempt=0,last_error='',finished_at=NULL,next_attempt_at=0 WHERE run_id=? AND status='failed'", (run["id"],))
        conn.execute("UPDATE onboarding_runs SET status='running',finished_at=NULL WHERE id=?", (run["id"],))
        conn.execute("UPDATE device_onboarding_state SET status='running',completed_at=NULL,updated_at=? WHERE agent_id=?", (now, agent_id))
        _queue_next_onboarding_step(conn, run["id"], now)
    audit(request, "onboarding_retry_failed", agent_id, f"run_id={run['id']};steps={count}", user=user)
    return {"ok": True, "steps": count}


@app.post("/api/machines/{agent_id}/onboarding/cancel")
def cancel_machine_onboarding(agent_id: str, request: Request):
    user = require_admin(request)
    now = time.time()
    with db() as conn:
        run = conn.execute("SELECT * FROM onboarding_runs WHERE agent_id=? AND status IN ('pending','running') ORDER BY created_at DESC LIMIT 1", (agent_id,)).fetchone()
        if not run:
            raise HTTPException(status_code=400, detail="No onboarding stack is running")
        pending_jobs = conn.execute("SELECT job_id FROM onboarding_run_steps WHERE run_id=? AND status='running' AND job_id!=''", (run["id"],)).fetchall()
        for r in pending_jobs:
            conn.execute("UPDATE jobs SET status='cancelled',output=?,finished_at=? WHERE id=? AND status='pending'", ("Cancelled from onboarding console before pickup.", now, r["job_id"]))
        conn.execute("UPDATE onboarding_run_steps SET status='cancelled',finished_at=? WHERE run_id=? AND status IN ('pending','running')", (now, run["id"]))
        _finish_onboarding_run(conn, run["id"], "cancelled", now)
    audit(request, "onboarding_cancel", agent_id, f"run_id={run['id']}", user=user)
    return {"ok": True}


@app.post("/api/machines/{agent_id}/onboarding/reset")
def reset_machine_onboarding(agent_id: str, request: Request):
    user = require_admin(request)
    with db() as conn:
        if conn.execute("SELECT 1 FROM onboarding_runs WHERE agent_id=? AND status IN ('pending','running')", (agent_id,)).fetchone():
            raise HTTPException(status_code=409, detail="Cancel the running onboarding stack before resetting status")
        conn.execute("DELETE FROM device_onboarding_state WHERE agent_id=?", (agent_id,))
    audit(request, "onboarding_reset", agent_id, "state cleared; history preserved", user=user)
    return {"ok": True}


# AI-assisted remediation ----------------------------------------------------

AI_REMEDIATION_SCRIPT_MAP = {
    "disk_io_events": [
        "[MSP] Disk & SMART Health",
        "[MSP] Recent Critical Event Log Summary",
        "[MSP] Workstation Health Summary",
    ],
    "hardware": [
        "[MSP] Disk & SMART Health",
        "[MSP] Recent Critical Event Log Summary",
        "[MSP] Workstation Health Summary",
    ],
    "low_disk": [
        "[MSP] User Profile Disk Usage",
        "[MSP] Workstation Health Summary",
        "[MSP] Safe Temporary File Cleanup",
    ],
    "failed_updates": [
        "[MSP] Windows Update History",
        "[MSP] Workstation Health Summary",
        "[MSP] Reset Windows Update Components",
    ],
    "aged_updates": [
        "[MSP] Windows Update History",
        "[MSP] Workstation Health Summary",
    ],
    "stale_patch_scan": [
        "[MSP] Windows Update History",
        "[MSP] OpenPrimeRMM Agent Health Check",
    ],
    "reboot_pending": [
        "[MSP] Pending Reboot Check",
        "[MSP] Workstation Health Summary",
    ],
    "service_stopped": [
        "[MSP] Automatic Services Not Running",
        "[MSP] Restart Service by Name",
    ],
    "antivirus_missing": [
        "[MSP] Security Posture Quick Audit",
        "[MSP] Workstation Health Summary",
    ],
}


def _script_risk_label(script) -> str:
    safety = (script["safety_class"] if "safety_class" in script.keys() else "") or "unclassified"
    return {
        "diagnostic": "Low",
        "safe_remediation": "Low / Medium",
        "disruptive": "Medium / High",
        "high_impact": "High",
    }.get(safety, "Unclassified")


def _ai_script_summary(script) -> dict:
    d = _script_public_dict(script)
    return {
        "script_id": d["id"],
        "name": d["name"],
        "description": d.get("description") or "",
        "shell": d.get("shell") or "powershell",
        "timeout_sec": int(d.get("timeout_sec") or 900),
        "variables": d.get("variables") or [],
        "safety_class": d.get("safety_class") or "unclassified",
        "risk": _script_risk_label(script),
        "ai_auto_allowed": bool(d.get("ai_auto_allowed")),
        "changes_system": bool(d.get("changes_system")),
        "reboot_impact": d.get("reboot_impact") or "possible",
    }


def _ai_health_context(conn: sqlite3.Connection, agent_id: str) -> dict | None:
    agent = conn.execute(
        "SELECT id, hostname, os_version, ext_inventory, disk_health, smart_failures, disk_events, "
        "reboot_required, last_seen, org_id FROM agents WHERE id=?", (agent_id,),
    ).fetchone()
    if not agent:
        return None
    incidents = conn.execute(
        "SELECT id,dedupe_key,incident_type,severity,message,value_text,threshold_text,first_seen,last_seen "
        "FROM monitor_incidents WHERE agent_id=? AND status='open' ORDER BY first_seen DESC LIMIT 20",
        (agent_id,),
    ).fetchall()
    recent = _recent_storage_warning_map(conn).get(agent_id)
    types = [str(r["incident_type"]) for r in incidents]
    if recent and "disk_io_events" not in types:
        types.append("disk_io_events")
    return {"agent": agent, "incidents": incidents, "recent_storage": recent, "incident_types": types}


def _ai_candidate_scripts(conn: sqlite3.Connection, incident_types: list[str]) -> list[sqlite3.Row]:
    names = []
    for incident_type in incident_types:
        for name in AI_REMEDIATION_SCRIPT_MAP.get(incident_type, []):
            if name not in names:
                names.append(name)
    if not names:
        return []
    rows = conn.execute("SELECT * FROM scripts ORDER BY name COLLATE NOCASE").fetchall()
    by_name = {str(r["name"]).lower(): r for r in rows}
    out = []
    for name in names:
        row = by_name.get(name.lower())
        if not row:
            continue
        # Unclassified scripts are not considered AI-approved actions. A tech
        # must explicitly classify them first in the Script Library.
        if (row["safety_class"] or "unclassified") == "unclassified":
            continue
        out.append(row)
    return out


def _queue_ai_remediation_job(conn: sqlite3.Connection, *, agent, script, source_type: str,
                              source_key: str, source_context: dict, variables=None,
                              strict_variables: bool = True, now: float | None = None) -> str:
    now = now or time.time()
    env = resolve_variable_values(script_variables(script), variables, strict=strict_variables)
    payload = json.dumps({
        "name": script["name"], "content": script["content"],
        "timeout_sec": script["timeout_sec"], "shell": script["shell"] or "powershell", "env": env,
    })
    job_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO jobs (id,agent_id,type,label,payload,created_at) VALUES (?,?,?,?,?,?)",
        (job_id, agent["id"], "run_script", f"AI remediation: {script['name']}", payload, now),
    )
    conn.execute(
        "INSERT INTO ai_remediation_runs(job_id,agent_id,script_id,source_type,source_key,source_context,created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, agent["id"], script["id"], source_type, source_key,
         json.dumps(source_context, default=str)[:16000], now),
    )
    _wake_agent(agent["id"])
    return job_id


def _auto_queue_diagnostic_for_incident(conn: sqlite3.Connection, agent, *, incident_type: str,
                                        source_key: str, message: str, value_text: str,
                                        threshold_text: str, now: float) -> str | None:
    """Optionally collect evidence for a newly-opened incident.

    This never executes AI-authored code. It can only queue an existing script
    explicitly classified as diagnostic AND explicitly opted into AI auto-run.
    """
    cfg = get_ai(conn)
    if not cfg.get("auto_diagnostics"):
        return None
    if not agent["last_seen"] or now - float(agent["last_seen"]) > OFFLINE_AFTER_SECONDS:
        return None
    candidates = _ai_candidate_scripts(conn, [incident_type])
    script = next((x for x in candidates
                   if (x["safety_class"] or "") == "diagnostic" and bool(x["ai_auto_allowed"])), None)
    if not script:
        return None
    # One diagnostic per incident key per day is enough even if alert cooldowns
    # cause the same incident to be treated as newly opened again.
    if conn.execute(
        "SELECT 1 FROM ai_remediation_runs WHERE source_type='monitor_auto' AND source_key=? AND created_at>?",
        (source_key, now - 86400),
    ).fetchone():
        return None
    job_id = _queue_ai_remediation_job(
        conn, agent=agent, script=script, source_type="monitor_auto", source_key=source_key,
        source_context={
            "incident_type": incident_type, "message": message,
            "observed": value_text, "threshold": threshold_text,
        }, variables={}, strict_variables=False, now=now,
    )
    conn.execute("UPDATE monitor_incidents SET remediation_job_id=? WHERE dedupe_key=?", (job_id, source_key))
    return job_id


# Schedules ------------------------------------------------------------------


def fire_schedule(conn: sqlite3.Connection, s: sqlite3.Row, now: float) -> int:
    """Create one job per target machine for a schedule run. Skips machines that
    still have a pending/running job from this same schedule (offline pile-up guard)."""
    keys = s.keys()
    action = (s["action_type"] if "action_type" in keys else "") or "script"
    if action in ("reboot", "shutdown", "install_updates"):
        job_type = "install_updates" if action == "install_updates" else "reboot"
        if action == "shutdown":
            payload = json.dumps(build_power_job_payload(
                "shutdown", "OpenPrimeRMM scheduled maintenance shutdown", "schedule", now))
            label = s["name"] or "Scheduled shutdown"
        elif action == "reboot":
            payload = json.dumps(build_power_job_payload(
                "reboot", "OpenPrimeRMM scheduled maintenance reboot", "schedule", now,
                force_reboot=bool(s["force_reboot"])))
            label = ("Force reboot: " if s["force_reboot"] else "") + (s["name"] or "Scheduled reboot")
        else:  # install_updates
            payload = json.dumps({"source": "schedule"})
            label = s["name"] or "Scheduled updates"
        created = 0
        for mid in resolve_targets(conn, s["target_type"], json.loads(s["target_ids"] or "[]")):
            dup = conn.execute(
                "SELECT 1 FROM jobs WHERE agent_id=? AND schedule_id=?"
                " AND status IN ('pending','running')", (mid, s["id"]),
            ).fetchone()
            if dup:
                continue
            conn.execute(
                "INSERT INTO jobs (id, agent_id, type, label, payload, schedule_id, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), mid, job_type, label, payload, s["id"], now),
            )
            created += 1
        return created
    script = conn.execute("SELECT * FROM scripts WHERE id=?", (s["script_id"],)).fetchone()
    if not script:
        return 0
    try:
        stored_vals = json.loads(s["variables"] or "{}")
    except (ValueError, KeyError, IndexError):
        stored_vals = {}
    env = resolve_variable_values(script_variables(script), stored_vals, strict=False)
    payload = json.dumps({
        "name": script["name"], "content": script["content"],
        "timeout_sec": script["timeout_sec"], "shell": script["shell"] or "powershell", "env": env,
    })
    created = 0
    for mid in resolve_targets(conn, s["target_type"], json.loads(s["target_ids"] or "[]")):
        dup = conn.execute(
            "SELECT 1 FROM jobs WHERE agent_id=? AND schedule_id=?"
            " AND status IN ('pending','running')", (mid, s["id"]),
        ).fetchone()
        if dup:
            continue
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, schedule_id, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), mid, "run_script", s["name"], payload, s["id"], now),
        )
        created += 1
    return created


# ---------------------------------------------------------------------------
# Stability, recovery, monitoring, and automation (1.13.0)
# ---------------------------------------------------------------------------

DEFAULT_SYSTEM_SETTINGS = {
    "backup_enabled": True,
    "backup_time": "02:00",
    "backup_days": [0, 1, 2, 3, 4, 5, 6],
    "backup_retention_days": 14,
    "job_autoarchive_days": 7,
    "cleanup_enabled": True,
    "job_retention_days": 180,
    "audit_retention_days": 365,
    "security_event_retention_days": 180,
    "closed_support_retention_days": 365,
}


def get_system_settings(conn: sqlite3.Connection) -> dict:
    cfg = dict(DEFAULT_SYSTEM_SETTINGS)
    row = conn.execute("SELECT value FROM settings WHERE key='system_settings'").fetchone()
    if row:
        try:
            saved = json.loads(row["value"])
            cfg.update(saved)
            # Backward compatibility with the old integer-only backup hour.
            if "backup_time" not in saved and "backup_hour" in saved:
                cfg["backup_time"] = f"{max(0, min(23, int(saved.get('backup_hour') or 2))):02d}:00"
        except (ValueError, TypeError):
            pass
    if not isinstance(cfg.get("backup_days"), list):
        cfg["backup_days"] = [0, 1, 2, 3, 4, 5, 6]
    cfg.pop("backup_hour", None)
    return cfg


def sanitize_system_settings(body: dict) -> dict:
    backup_time = str(body.get("backup_time") or "02:00").strip()
    try:
        hh, mm = [int(x) for x in backup_time.split(":", 1)]
        if hh not in range(24) or mm not in (0, 15, 30, 45):
            raise ValueError
        backup_time = f"{hh:02d}:{mm:02d}"
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Choose a valid backup time")
    raw_days = body.get("backup_days")
    if not isinstance(raw_days, list):
        raw_days = [0, 1, 2, 3, 4, 5, 6]
    backup_days = sorted({int(x) for x in raw_days if str(x).lstrip('-').isdigit() and 0 <= int(x) <= 6})
    if body.get("backup_enabled", True) and not backup_days:
        raise HTTPException(status_code=400, detail="Select at least one backup day")
    return {
        "backup_enabled": bool(body.get("backup_enabled", True)),
        "backup_time": backup_time,
        "backup_days": backup_days,
        "backup_retention_days": max(2, min(365, int(body.get("backup_retention_days") or 14))),
        "job_autoarchive_days": max(0, min(365, int(body.get("job_autoarchive_days") if body.get("job_autoarchive_days") is not None else 7))),
        "cleanup_enabled": bool(body.get("cleanup_enabled", True)),
        "job_retention_days": max(30, min(3650, int(body.get("job_retention_days") or 180))),
        "audit_retention_days": max(30, min(3650, int(body.get("audit_retention_days") or 365))),
        "security_event_retention_days": max(30, min(3650, int(body.get("security_event_retention_days") or 180))),
        "closed_support_retention_days": max(30, min(3650, int(body.get("closed_support_retention_days") or 365))),
    }


def create_database_backup(prefix: str = "outpost") -> Path:
    """Create a consistent SQLite backup using SQLite's online backup API."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"{prefix}-{stamp}.db"
    tmp = target.with_suffix(".db.tmp")
    if tmp.exists():
        tmp.unlink()
    src = sqlite3.connect(DB_PATH, timeout=30)
    dst = sqlite3.connect(tmp)
    try:
        src.execute("PRAGMA busy_timeout=30000")
        src.backup(dst)
        dst.execute("PRAGMA quick_check")
        dst.commit()
    finally:
        dst.close()
        src.close()
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def list_database_backups() -> list[dict]:
    out = []
    for f in sorted(BACKUP_DIR.glob("outpost-*.db"), key=lambda x: x.stat().st_mtime, reverse=True):
        st = f.stat()
        out.append({"name": f.name, "size_bytes": st.st_size, "created_at": st.st_mtime})
    return out


def prune_database_backups(retention_days: int) -> int:
    cutoff = time.time() - max(2, retention_days) * 86400
    removed = 0
    backups = list(BACKUP_DIR.glob("outpost-*.db"))
    # Always retain at least the latest two usable backups.
    keep = {x for x in sorted(backups, key=lambda f: f.stat().st_mtime, reverse=True)[:2]}
    for f in backups:
        if f in keep:
            continue
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except OSError:
            pass
    return removed


def run_data_cleanup(cfg: dict | None = None) -> dict:
    now = time.time()
    with db() as conn:
        cfg = cfg or get_system_settings(conn)
        counts = {}
        cur = conn.execute(
            "DELETE FROM jobs WHERE archived=1 AND created_at<?",
            (now - int(cfg["job_retention_days"]) * 86400,),
        )
        counts["jobs"] = cur.rowcount
        cur = conn.execute(
            "DELETE FROM audit_log WHERE ts<?",
            (now - int(cfg["audit_retention_days"]) * 86400,),
        )
        counts["audit"] = cur.rowcount
        cur = conn.execute(
            "DELETE FROM av_events WHERE received_at<?",
            (now - int(cfg["security_event_retention_days"]) * 86400,),
        )
        counts["security_events"] = cur.rowcount
        support_cutoff = now - int(cfg["closed_support_retention_days"]) * 86400
        old_support = conn.execute(
            "SELECT id,attach_name FROM support_requests WHERE status IN ('resolved','closed') AND ts<?",
            (support_cutoff,),
        ).fetchall()
        cur = conn.execute(
            "DELETE FROM support_requests WHERE status IN ('resolved','closed') AND ts<?",
            (support_cutoff,),
        )
        counts["support_requests"] = cur.rowcount
        conn.execute("PRAGMA optimize")
    removed_files = 0
    adir = DATA_DIR / "support_attachments"
    for row in old_support:
        if row["attach_name"]:
            try:
                (adir / f"{row['id']}_{row['attach_name']}").unlink(missing_ok=True)
                removed_files += 1
            except OSError:
                pass
    counts["support_attachments"] = removed_files
    # Diagnostics are transient support artifacts, not long-term backups.
    diag_removed = 0
    for f in DIAGNOSTIC_DIR.glob("outpost-diagnostics-*.zip"):
        try:
            if f.stat().st_mtime < now - 7 * 86400:
                f.unlink(); diag_removed += 1
        except OSError:
            pass
    counts["diagnostics"] = diag_removed
    counts["backups"] = prune_database_backups(int(cfg["backup_retention_days"]))
    # Auto-archive successful jobs after N days (0 disables). Failed jobs are
    # deliberately left visible until a human archives them.
    autoarch_days = int(cfg.get("job_autoarchive_days") or 0)
    if autoarch_days > 0:
        with db() as conn:
            cur = conn.execute(
                "UPDATE jobs SET archived=1 WHERE archived=0 AND status='done'"
                " AND finished_at IS NOT NULL AND finished_at < ?",
                (now - autoarch_days * 86400,),
            )
        counts["jobs_autoarchived"] = cur.rowcount
    return counts


def database_integrity_status() -> str:
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            row = conn.execute("PRAGMA quick_check").fetchone()
            return str(row[0]) if row else "unknown"
        finally:
            conn.close()
    except Exception as exc:
        return f"error: {exc}"


def next_backup_timestamp(cfg: dict, now_ts: float | None = None) -> float | None:
    if not cfg.get("backup_enabled"):
        return None
    days = set(int(x) for x in (cfg.get("backup_days") or []))
    if not days:
        return None
    try:
        hh, mm = [int(x) for x in str(cfg.get("backup_time") or "02:00").split(":", 1)]
    except (ValueError, TypeError):
        hh, mm = 2, 0
    now_dt = datetime.datetime.fromtimestamp(now_ts or time.time())
    for offset in range(0, 8):
        day = now_dt.date() + datetime.timedelta(days=offset)
        candidate = datetime.datetime.combine(day, datetime.time(hour=hh, minute=mm))
        if candidate.weekday() in days and candidate > now_dt:
            return candidate.timestamp()
    return None


def system_health_snapshot() -> dict:
    disk = shutil.disk_usage(DATA_DIR)
    backups = list_database_backups()
    with db() as conn:
        cfg = get_system_settings(conn)
        counts = {
            "agents": conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0],
            "online_agents": conn.execute(
                "SELECT COUNT(*) FROM agents WHERE last_seen>?", (time.time() - OFFLINE_AFTER_SECONDS,)
            ).fetchone()[0],
            "pending_jobs": conn.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0],
            "running_jobs": conn.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0],
            "failed_jobs_24h": conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status='failed' AND finished_at>?", (time.time() - 86400,)
            ).fetchone()[0],
            "open_incidents": conn.execute(
                "SELECT COUNT(*) FROM monitor_incidents WHERE status='open'"
            ).fetchone()[0],
            "outdated_agents": conn.execute(
                "SELECT COUNT(*) FROM agents WHERE agent_version<>? AND agent_version<>''",
                (LATEST_AGENT_VERSION,),
            ).fetchone()[0],
            "never_seen_agents": conn.execute(
                "SELECT COUNT(*) FROM agents WHERE COALESCE(last_seen,0)=0"
            ).fetchone()[0],
            "stale_patch_scans": conn.execute(
                "SELECT COUNT(*) FROM agents WHERE COALESCE(last_update_scan,0)<?",
                (time.time() - 24 * 3600,),
            ).fetchone()[0],
        }
    return {
        "version": SERVER_VERSION,
        "database": {
            "path": str(DB_PATH),
            "size_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
            "integrity": database_integrity_status(),
        },
        "storage": {
            "data_dir": str(DATA_DIR),
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "used_pct": round((disk.used / disk.total) * 100, 1) if disk.total else 0,
        },
        "backup": {
            "enabled": bool(cfg["backup_enabled"]),
            "latest": backups[0] if backups else None,
            "count": len(backups),
            "retention_days": cfg["backup_retention_days"],
            "backup_time": cfg.get("backup_time", "02:00"),
            "backup_days": cfg.get("backup_days", [0,1,2,3,4,5,6]),
            "next_run_at": next_backup_timestamp(cfg),
        },
        "counts": counts,
        "settings": cfg,
    }


@app.get("/api/system/health")
def api_system_health(request: Request):
    require_admin_role(request)
    return system_health_snapshot()


@app.get("/api/system/settings")
def api_system_settings(request: Request):
    require_admin_role(request)
    with db() as conn:
        return get_system_settings(conn)


@app.put("/api/system/settings")
async def api_write_system_settings(request: Request):
    require_admin_role(request)
    cfg = sanitize_system_settings(await request.json())
    with db() as conn:
        conn.execute(
            "INSERT INTO settings (key,value) VALUES ('system_settings',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(cfg),),
        )
    audit(request, "system_settings", "server", "retention/backup settings updated")
    return cfg


@app.get("/api/system/backups")
def api_list_backups(request: Request):
    require_admin_role(request)
    return {"backups": list_database_backups()}


@app.post("/api/system/backups/run")
def api_run_backup(request: Request):
    require_admin_role(request)
    path = create_database_backup()
    with db() as conn:
        cfg = get_system_settings(conn)
    prune_database_backups(int(cfg["backup_retention_days"]))
    audit(request, "backup_create", path.name, f"{path.stat().st_size} bytes")
    return {"ok": True, "backup": {"name": path.name, "size_bytes": path.stat().st_size,
                                     "created_at": path.stat().st_mtime}}


@app.delete("/api/system/backups/{filename}")
def delete_system_backup(filename: str, request: Request):
    require_admin(request)
    if not re.fullmatch(r"outpost-\d{8}-\d{6}\.db", filename):
        raise HTTPException(status_code=400, detail="Invalid backup filename")
    path = BACKUP_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")
    path.unlink()
    audit(request, "system_backup_delete", filename, "")
    return {"ok": True}


@app.post("/api/system/backups/prune")
def prune_system_backups(request: Request):
    require_admin(request)
    with db() as conn:
        cfg = get_system_settings(conn)
    deleted = prune_database_backups(int(cfg["backup_retention_days"]))
    audit(request, "system_backup_prune", str(deleted), "")
    return {"ok": True, "deleted": deleted, "retention_days": int(cfg["backup_retention_days"])}


@app.get("/api/system/backups/{filename}")
def api_download_backup(filename: str, request: Request):
    require_admin_role(request)
    if not filename.startswith("outpost-") or not filename.endswith(".db") or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid backup filename")
    path = BACKUP_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


@app.post("/api/system/cleanup/run")
def api_run_cleanup(request: Request):
    require_admin_role(request)
    result = run_data_cleanup()
    audit(request, "cleanup_run", "server", json.dumps(result))
    return {"ok": True, "removed": result}


@app.get("/api/system/diagnostics.zip")
def api_system_diagnostics(request: Request):
    require_admin_role(request)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = DIAGNOSTIC_DIR / f"outpost-diagnostics-{stamp}.zip"
    snap = system_health_snapshot()
    with tempfile.TemporaryDirectory(prefix="outpost-diag-") as td:
        root = Path(td)
        (root / "system-health.json").write_text(json.dumps(snap, indent=2), encoding="utf-8")
        with db() as conn:
            recent_failed = [dict(r) for r in conn.execute(
                """SELECT j.id,j.type,j.label,j.status,j.exit_code,j.created_at,j.finished_at,a.hostname
                   FROM jobs j LEFT JOIN agents a ON a.id=j.agent_id
                   WHERE j.status='failed' ORDER BY j.created_at DESC LIMIT 100"""
            )]
            incidents = [dict(r) for r in conn.execute(
                "SELECT * FROM monitor_incidents ORDER BY last_seen DESC LIMIT 200"
            )]
            schema = [dict(r) for r in conn.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY type,name"
            )]
        (root / "recent-failed-jobs.json").write_text(json.dumps(recent_failed, indent=2), encoding="utf-8")
        (root / "monitor-incidents.json").write_text(json.dumps(incidents, indent=2), encoding="utf-8")
        (root / "database-schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")
        (root / "versions.txt").write_text(
            f"Platform: {SERVER_VERSION}\nAgent served: {LATEST_AGENT_VERSION}\nTray served: {current_tray_version()}\n",
            encoding="utf-8",
        )
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in root.iterdir():
                zf.write(f, arcname=f.name)
    return FileResponse(out, filename=out.name, media_type="application/zip")


DEFAULT_MONITOR_POLICY = {
    "enabled": True,
    "offline_minutes": 15,                    # servers: 24/7
    "workstation_offline_minutes": 90,        # workstations
    "workstation_business_hours_only": True,  # evaluate workstations Mon-Fri, window below
    "business_start": "08:00",
    "business_end": "18:00",
    "low_disk_gb": 10,
    "low_disk_pct": 10,
    "memory_alert_enabled": False,
    "workstation_memory_pct": 90,
    "server_memory_pct": 90,
    "failed_updates": True,
    "pending_update_days": 30,
    "reboot_pending_days": 7,
    "stale_scan_hours": 24,
    "hardware_health": True,
    "antivirus_required": False,
    "alert_cooldown_minutes": 120,
    "notify_resolved": True,
}


def _sanitize_hhmm(value, default: str) -> str:
    s = str(value or "").strip()
    if re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", s):
        return s
    return default


def device_class_of(row) -> str:
    """server/workstation: manual override wins, else derived from the OS name."""
    try:
        override = str(row["device_class"] or "").strip().lower()
    except (KeyError, IndexError, TypeError):
        override = ""
    if override in ("server", "workstation"):
        return override
    try:
        osname = str(row["os_version"] or "")
    except (KeyError, IndexError, TypeError):
        osname = ""
    return "server" if "server" in osname.lower() else "workstation"


def os_family_of(os_version) -> str:
    """Normalize an agent OS caption into the Fleet/group filter families."""
    osname = str(os_version or "").lower()
    if "windows server" in osname:
        return "windows_server"
    if "windows 11" in osname:
        return "windows_11"
    if "windows 10" in osname:
        return "windows_10"
    if any(name in osname for name in ("linux", "ubuntu", "debian", "centos", "red hat")):
        return "linux"
    if any(name in osname for name in ("macos", "mac os", "darwin")):
        return "macos"
    return "other"


def _within_business_hours(pol: dict, now: float) -> bool:
    lt = time.localtime(now)
    if lt.tm_wday >= 5:  # Sat/Sun
        return False
    hhmm = f"{lt.tm_hour:02d}:{lt.tm_min:02d}"
    return pol.get("business_start", "08:00") <= hhmm < pol.get("business_end", "18:00")


def sanitize_monitor_policy(body: dict) -> dict:
    return {
        "enabled": bool(body.get("enabled", True)),
        "offline_minutes": max(5, min(10080, int(body.get("offline_minutes") or 15))),
        "workstation_offline_minutes": max(5, min(10080, int(body.get("workstation_offline_minutes") or 90))),
        "workstation_business_hours_only": bool(body.get("workstation_business_hours_only", True)),
        "business_start": _sanitize_hhmm(body.get("business_start"), "08:00"),
        "business_end": _sanitize_hhmm(body.get("business_end"), "18:00"),
        "low_disk_gb": max(1, min(1000, float(body.get("low_disk_gb") or 10))),
        "low_disk_pct": max(1, min(50, float(body.get("low_disk_pct") or 10))),
        "memory_alert_enabled": bool(body.get("memory_alert_enabled", False)),
        "workstation_memory_pct": max(50, min(99, float(body.get("workstation_memory_pct") or 90))),
        "server_memory_pct": max(50, min(99, float(body.get("server_memory_pct") or 90))),
        "failed_updates": bool(body.get("failed_updates", True)),
        "pending_update_days": max(1, min(365, int(body.get("pending_update_days") or 30))),
        "reboot_pending_days": max(1, min(365, int(body.get("reboot_pending_days") or 7))),
        "stale_scan_hours": max(1, min(720, int(body.get("stale_scan_hours") or 24))),
        "hardware_health": bool(body.get("hardware_health", True)),
        "antivirus_required": bool(body.get("antivirus_required", False)),
        "alert_cooldown_minutes": max(15, min(10080, int(body.get("alert_cooldown_minutes") or 120))),
        "notify_resolved": bool(body.get("notify_resolved", True)),
    }


def get_monitor_policy(conn: sqlite3.Connection) -> dict:
    cfg = dict(DEFAULT_MONITOR_POLICY)
    row = conn.execute("SELECT value FROM settings WHERE key='monitor_policy'").fetchone()
    if row:
        try:
            cfg.update(json.loads(row["value"]))
        except (ValueError, TypeError):
            pass
    return cfg


def get_org_monitor_policy(conn: sqlite3.Connection, org_id) -> dict | None:
    if org_id is None:
        return None
    row = conn.execute("SELECT policy FROM org_monitor_policies WHERE org_id=?", (org_id,)).fetchone()
    if not row:
        return None
    try:
        cfg = dict(DEFAULT_MONITOR_POLICY)
        cfg.update(json.loads(row["policy"]))
        return cfg
    except (ValueError, TypeError):
        return None


def effective_monitor_policy(conn: sqlite3.Connection, org_id) -> dict:
    return get_org_monitor_policy(conn, org_id) or get_monitor_policy(conn)


def _monitor_alert(title: str, description: str, color: int = 0xB7791F):
    try:
        with db() as conn:
            cfg = get_alerts(conn)
        if cfg.get("enabled") and cfg.get("webhook_url") and cfg.get("on_monitoring", True):
            send_discord(cfg["webhook_url"], title, description, color=color)
    except Exception:
        pass


def _set_incident(conn: sqlite3.Connection, *, key: str, agent, incident_type: str,
                  severity: str, message: str, value_text: str, threshold_text: str,
                  active: bool, policy: dict, now: float):
    row = conn.execute("SELECT * FROM monitor_incidents WHERE dedupe_key=?", (key,)).fetchone()
    if active:
        if row:
            if row["status"] != "open":
                # A previously-resolved incident flaring again is a NEW
                # occurrence: restart its clock instead of resurrecting a
                # first_seen from days or weeks ago.
                conn.execute(
                    """UPDATE monitor_incidents SET status='open', message=?, value_text=?, threshold_text=?,
                       first_seen=?, last_seen=?, resolved_at=NULL, consecutive_count=1 WHERE id=?""",
                    (message, value_text, threshold_text, now, now, row["id"]),
                )
                last_alert = float(row["last_alert_at"] or 0)
                should_alert = now - last_alert >= int(policy["alert_cooldown_minutes"]) * 60
                incident_id = row["id"]
                if should_alert:
                    conn.execute("UPDATE monitor_incidents SET last_alert_at=? WHERE id=?", (now, incident_id))
                    return "opened"
                return "active"
            count = int(row["consecutive_count"] or 0) + 1
            conn.execute(
                """UPDATE monitor_incidents SET status='open', message=?, value_text=?, threshold_text=?,
                   last_seen=?, resolved_at=NULL, consecutive_count=? WHERE id=?""",
                (message, value_text, threshold_text, now, count, row["id"]),
            )
            last_alert = float(row["last_alert_at"] or 0)
            should_alert = now - last_alert >= int(policy["alert_cooldown_minutes"]) * 60
            incident_id = row["id"]
        else:
            cur = conn.execute(
                """INSERT INTO monitor_incidents
                   (dedupe_key,agent_id,org_id,incident_type,severity,status,message,value_text,
                    threshold_text,first_seen,last_seen,consecutive_count)
                   VALUES (?,?,?,?,?,'open',?,?,?,?,?,1)""",
                (key, agent["id"], agent["org_id"], incident_type, severity, message,
                 value_text, threshold_text, now, now),
            )
            incident_id = cur.lastrowid
            should_alert = True
        if should_alert:
            conn.execute("UPDATE monitor_incidents SET last_alert_at=? WHERE id=?", (now, incident_id))
            return "opened"
        return "active"
    if row and row["status"] == "open":
        conn.execute(
            "UPDATE monitor_incidents SET status='resolved', resolved_at=?, last_seen=? WHERE id=?",
            (now, now, row["id"]),
        )
        return "resolved"
    return "inactive"


def evaluate_monitoring():
    now = time.time()
    notifications = []
    with db() as conn:
        global_policy = get_monitor_policy(conn)
        agents = conn.execute(
            """SELECT a.*, o.name AS org_name FROM agents a
               LEFT JOIN orgs o ON o.id=a.org_id"""
        ).fetchall()
        for a in agents:
            pol = get_org_monitor_policy(conn, a["org_id"]) or global_policy
            if not pol.get("enabled"):
                conn.execute(
                    """UPDATE monitor_incidents
                       SET status='resolved', resolved_at=?, last_seen=?
                       WHERE agent_id=? AND status='open'""",
                    (now, now, a["id"]),
                )
                continue
            host = a["hostname"]
            org = a["org_name"] or "Unassigned"
            last_contact = float(a["last_seen"] or 0)
            contact_reference = last_contact or float(a["created_at"] or now)
            offline_for = max(0, now - contact_reference)
            offline_value = (f"{int(offline_for // 60)} minutes" if last_contact
                             else f"never checked in ({int(offline_for // 60)} minutes since enrollment)")
            checks = []
            dev_class = device_class_of(a)
            if dev_class == "server":
                off_threshold = int(pol["offline_minutes"])
                off_active = offline_for > off_threshold * 60
                off_label = f"> {off_threshold} minutes (server, 24/7)"
            else:
                off_threshold = int(pol.get("workstation_offline_minutes") or 90)
                off_active = offline_for > off_threshold * 60
                if pol.get("workstation_business_hours_only", True):
                    off_active = off_active and _within_business_hours(pol, now)
                    off_label = (f"> {off_threshold} minutes (workstation, business hours "
                                 f"{pol.get('business_start','08:00')}-{pol.get('business_end','18:00')} Mon-Fri)")
                else:
                    off_label = f"> {off_threshold} minutes (workstation)"
            checks.append((
                f"offline:{a['id']}", "offline", "critical",
                f"{host} has not checked in", offline_value,
                off_label, off_active,
            ))
            try:
                disks = json.loads(a["disks"] or "[]")
            except (ValueError, TypeError):
                disks = []
            low = []
            for d in disks if isinstance(disks, list) else []:
                try:
                    free = float(d.get("free_gb") or 0)
                    total = float(d.get("total_gb") or 0)
                    pct = (free / total * 100) if total else 100
                    if free < float(pol["low_disk_gb"]) or pct < float(pol["low_disk_pct"]):
                        low.append(f"{d.get('letter','disk')} {free:.1f} GB ({pct:.1f}%) free")
                except (TypeError, ValueError):
                    continue
            checks.append((
                f"lowdisk:{a['id']}", "low_disk", "warning",
                f"Low disk space on {host}", "; ".join(low) or "healthy",
                f"< {pol['low_disk_gb']} GB or < {pol['low_disk_pct']}%", bool(low),
            ))
            try:
                memory_used_pct = float(a["memory_used_pct"])
            except (TypeError, ValueError):
                memory_used_pct = None
            memory_threshold = float(
                pol["server_memory_pct"] if dev_class == "server"
                else pol["workstation_memory_pct"]
            )
            memory_fresh = bool(last_contact and now - last_contact <= 300)
            memory_active = bool(
                pol.get("memory_alert_enabled") and memory_fresh and
                memory_used_pct is not None and memory_used_pct >= memory_threshold
            )
            checks.append((
                f"high_memory:{a['id']}", "high_memory", "warning",
                f"High RAM usage on {host}",
                f"{memory_used_pct:.1f}% RAM used" if memory_used_pct is not None else "no current reading",
                f">= {memory_threshold:g}% ({dev_class})", memory_active,
            ))
            failed_count = conn.execute(
                "SELECT COUNT(*) FROM updates WHERE agent_id=? AND status='failed'", (a["id"],)
            ).fetchone()[0]
            checks.append((
                f"failed_updates:{a['id']}", "failed_updates", "warning",
                f"Windows Updates failed on {host}", f"{failed_count} failed update(s)", "0",
                bool(pol.get("failed_updates") and failed_count > 0),
            ))
            old_cutoff = now - int(pol["pending_update_days"]) * 86400
            old_pending = conn.execute(
                "SELECT COUNT(*) FROM updates WHERE agent_id=? AND status IN ('pending','failed') AND detected_at<?",
                (a["id"], old_cutoff),
            ).fetchone()[0]
            checks.append((
                f"old_updates:{a['id']}", "aged_updates", "warning",
                f"Updates have been pending too long on {host}", f"{old_pending} old update(s)",
                f"> {pol['pending_update_days']} days", old_pending > 0,
            ))
            reboot_since = float(a["reboot_since"] or 0)
            reboot_days = (now - reboot_since) / 86400 if reboot_since else 0
            checks.append((
                f"reboot:{a['id']}", "reboot_pending", "warning",
                f"Reboot has been pending on {host}", f"{reboot_days:.1f} days",
                f"> {pol['reboot_pending_days']} days",
                bool(a["reboot_required"] and reboot_since and reboot_days >= int(pol["reboot_pending_days"])),
            ))
            scan_age_h = (now - float(a["last_update_scan"] or 0)) / 3600 if a["last_update_scan"] else 999999
            checks.append((
                f"stale_scan:{a['id']}", "stale_patch_scan", "warning",
                f"Windows Update scan is stale on {host}", f"{scan_age_h:.1f} hours",
                f"> {pol['stale_scan_hours']} hours",
                bool(a["last_seen"] and scan_age_h > int(pol["stale_scan_hours"])),
            ))
            hardware_active = False
            if pol.get("hardware_health"):
                try:
                    dh = json.loads(a["disk_health"] or "[]")
                except (ValueError, TypeError):
                    dh = []
                hardware_active = bool(int(a["smart_failures"] or 0) or any(
                    isinstance(d, dict) and str(d.get("health", "")).lower() not in ("", "healthy")
                    for d in dh
                ))
            checks.append((
                f"hardware:{a['id']}", "hardware", "critical",
                f"Disk health warning on {host}", "SMART/physical disk warning", "healthy",
                hardware_active,
            ))
            try:
                disk_events = json.loads(a["disk_events"] or "{}")
            except (ValueError, TypeError):
                disk_events = {}
            if not isinstance(disk_events, dict):
                disk_events = {}
            disk_event_count = int(disk_events.get("count") or 0)
            disk_event_last = str(disk_events.get("last") or "").strip()
            disk_event_time = str(disk_events.get("last_time") or "").strip()
            disk_event_value = f"{disk_event_count} disk I/O event(s) in the last 24h"
            if disk_event_time:
                disk_event_value += f"; last {disk_event_time}"
            if disk_event_last:
                disk_event_value += f" — {disk_event_last[:220]}"
            checks.append((
                f"disk_io:{a['id']}", "disk_io_events", "critical",
                f"Disk I/O errors detected on {host}", disk_event_value,
                "0 disk I/O events in the last 24h",
                bool(pol.get("hardware_health") and disk_event_count > 0),
            ))
            checks.append((
                f"av:{a['id']}", "antivirus_missing", "critical",
                f"Bitdefender is not confirmed on {host}", "not protected", "protected",
                bool(pol.get("antivirus_required") and a["bdgz_protected"] != 1),
            ))
            service_rows = conn.execute(
                "SELECT id,service_name,last_state FROM service_monitors WHERE agent_id=?",
                (a["id"],),
            ).fetchall()
            for svc in service_rows:
                stopped = svc["last_state"] in ("stopped", "restarted-failed")
                checks.append((
                    f"service:{a['id']}:{svc['id']}", "service_stopped", "warning",
                    f"Monitored service {svc['service_name']} is not healthy on {host}",
                    svc["last_state"] or "unknown", "running", stopped,
                ))
            for key, itype, sev, msg, val, threshold, active in checks:
                result = _set_incident(
                    conn, key=key, agent=a, incident_type=itype, severity=sev,
                    message=msg, value_text=val, threshold_text=threshold,
                    active=active, policy=pol, now=now,
                )
                if result == "opened":
                    notifications.append(("open", itype, sev, msg, host, org, val, threshold))
                    try:
                        _auto_queue_diagnostic_for_incident(
                            conn, a, incident_type=itype, source_key=key, message=msg,
                            value_text=val, threshold_text=threshold, now=now,
                        )
                    except Exception:
                        # Monitoring must never fail because optional AI-assisted
                        # evidence collection could not be queued.
                        pass
                elif result == "resolved" and pol.get("notify_resolved"):
                    notifications.append(("resolved", itype, sev, msg, host, org, val, threshold))
    for action, incident_type, severity, msg, host, org, val, threshold in notifications:
        # Offline Discord notifications use the separate workstation/server
        # switches and timers in Settings. Monitoring still tracks the incident.
        if incident_type == "offline":
            continue
        if action == "open":
            color = 0xC43D3D if severity == "critical" else 0xB7791F
            _monitor_alert(f"⚠️ {msg}", f"**Machine:** {host}\n**Customer:** {org}\n"
                           f"**Observed:** {val}\n**Threshold:** {threshold}", color)
        else:
            _monitor_alert(f"✅ Resolved: {msg}", f"**Machine:** {host}\n**Customer:** {org}", 0x1F8A4C)


@app.get("/api/monitoring/incidents")
def api_monitoring_incidents(request: Request, status: str = "open"):
    require_admin(request)
    where = "" if status == "all" else "WHERE i.status=?"
    params = () if status == "all" else (status,)
    with db() as conn:
        rows = conn.execute(
            f"""SELECT i.*, a.hostname, o.name AS org_name
                FROM monitor_incidents i
                LEFT JOIN agents a ON a.id=i.agent_id
                LEFT JOIN orgs o ON o.id=i.org_id
                {where} ORDER BY CASE i.severity WHEN 'critical' THEN 0 ELSE 1 END,
                i.last_seen DESC LIMIT 1000""", params
        ).fetchall()
    return {"incidents": [dict(r) for r in rows]}


@app.post("/api/monitoring/incidents/{incident_id}/resolve")
def api_resolve_incident(incident_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        conn.execute(
            "UPDATE monitor_incidents SET status='resolved', resolved_at=?, last_seen=? WHERE id=?",
            (time.time(), time.time(), incident_id),
        )
    audit(request, "incident_resolve", str(incident_id), "manual")
    return {"ok": True}


@app.get("/api/monitoring/policy")
def api_monitoring_policy(request: Request):
    require_admin(request)
    with db() as conn:
        return get_monitor_policy(conn)


@app.put("/api/monitoring/policy")
async def api_write_monitoring_policy(request: Request):
    require_admin_role(request)
    cfg = sanitize_monitor_policy(await request.json())
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('monitor_policy',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(cfg),)
        )
    audit(request, "monitor_policy", "global", "updated")
    return cfg


@app.get("/api/orgs/{org_id}/monitoring-policy")
def api_org_monitoring_policy(org_id: int, request: Request):
    require_admin_role(request)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        override = get_org_monitor_policy(conn, org_id)
        return {"has_override": override is not None,
                "policy": override or get_monitor_policy(conn)}


@app.put("/api/orgs/{org_id}/monitoring-policy")
async def api_write_org_monitoring_policy(org_id: int, request: Request):
    require_admin_role(request)
    body = await request.json()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        if body.get("use_global"):
            conn.execute("DELETE FROM org_monitor_policies WHERE org_id=?", (org_id,))
            return {"ok": True, "has_override": False}
        cfg = sanitize_monitor_policy(body)
        conn.execute(
            "INSERT INTO org_monitor_policies(org_id,policy,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(org_id) DO UPDATE SET policy=excluded.policy,updated_at=excluded.updated_at",
            (org_id, json.dumps(cfg), time.time()),
        )
    audit(request, "monitor_policy", f"org:{org_id}", "updated")
    return {"ok": True, "has_override": True}


AUTOMATION_TRIGGERS = {
    "low_disk_gb", "failed_updates", "pending_update_age_days",
    "reboot_pending_days", "service_stopped", "antivirus_missing",
}


def _automation_rule_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["target_ids"] = json.loads(row["target_ids"] or "[]")
    except (ValueError, TypeError):
        d["target_ids"] = []
    try:
        d["variables"] = json.loads(row["variables"] or "{}")
    except (ValueError, TypeError):
        d["variables"] = {}
    action = (row["action_type"] if "action_type" in row.keys() else "") or "script"
    if action == "script":
        s = conn.execute("SELECT name, shell FROM scripts WHERE id=?", (row["script_id"],)).fetchone()
        d["script_name"] = s["name"] if s else "(deleted script)"
        d["script_shell"] = (s["shell"] or "powershell") if s else "powershell"
    else:
        d["script_name"] = ""
        d["script_shell"] = ""
    # Live target count is intentionally calculated at read time so a dynamic
    # group always shows today's real match count, even before the rule runs.
    d["target_count"] = len(_automation_targets(conn, row))
    return d


def _automation_targets(conn: sqlite3.Connection, rule: sqlite3.Row) -> list[sqlite3.Row]:
    try:
        ids = json.loads(rule["target_ids"] or "[]")
    except (ValueError, TypeError):
        ids = []
    if rule["target_type"] == "orgs":
        vals = [int(x) for x in ids if str(x).isdigit()]
        if not vals:
            return []
        q = ",".join("?" for _ in vals)
        return conn.execute(f"SELECT * FROM agents WHERE org_id IN ({q})", vals).fetchall()
    if rule["target_type"] == "machines":
        vals = [str(x) for x in ids]
        if not vals:
            return []
        q = ",".join("?" for _ in vals)
        return conn.execute(f"SELECT * FROM agents WHERE id IN ({q})", vals).fetchall()
    if rule["target_type"] == "group":
        gid = int(ids[0]) if ids else 0
        row = conn.execute("SELECT filters FROM device_groups WHERE id=?", (gid,)).fetchone()
        if not row:
            return []
        try:
            gf = json.loads(row["filters"] or "{}")
        except (ValueError, TypeError):
            gf = {}
        mids = resolve_group_filters(conn, gf)
        if not mids:
            return []
        q = ",".join("?" for _ in mids)
        return conn.execute(f"SELECT * FROM agents WHERE id IN ({q})", mids).fetchall()
    return conn.execute("SELECT * FROM agents").fetchall()


def _automation_condition(conn: sqlite3.Connection, rule: sqlite3.Row, agent: sqlite3.Row, now: float):
    trigger = rule["trigger_type"]
    threshold = float(rule["threshold"] or 0)
    if trigger == "low_disk_gb":
        try:
            disks = json.loads(agent["disks"] or "[]")
        except (ValueError, TypeError):
            disks = []
        vals = [float(d.get("free_gb") or 0) for d in disks if isinstance(d, dict)]
        val = min(vals) if vals else 999999
        return val < threshold, f"{val:.1f} GB free"
    if trigger == "failed_updates":
        val = conn.execute(
            "SELECT COUNT(*) FROM updates WHERE agent_id=? AND status='failed'", (agent["id"],)
        ).fetchone()[0]
        return val >= threshold, f"{val} failed update(s)"
    if trigger == "pending_update_age_days":
        row = conn.execute(
            "SELECT MIN(detected_at) AS oldest FROM updates WHERE agent_id=? AND status IN ('pending','failed')",
            (agent["id"],),
        ).fetchone()
        val = (now - float(row["oldest"] or now)) / 86400 if row and row["oldest"] else 0
        return val >= threshold, f"{val:.1f} days"
    if trigger == "reboot_pending_days":
        val = (now - float(agent["reboot_since"] or now)) / 86400 if agent["reboot_since"] else 0
        return bool(agent["reboot_required"] and val >= threshold), f"{val:.1f} days"
    if trigger == "service_stopped":
        val = conn.execute(
            "SELECT COUNT(*) FROM service_monitors WHERE agent_id=? AND last_state IN ('stopped','restarted-failed')",
            (agent["id"],),
        ).fetchone()[0]
        return val >= max(1, threshold), f"{val} stopped service(s)"
    if trigger == "antivirus_missing":
        return agent["bdgz_protected"] != 1, "Bitdefender not confirmed"
    return False, "unsupported trigger"


def _queue_automation_script(conn: sqlite3.Connection, rule: sqlite3.Row,
                             agent: sqlite3.Row, observed: str, now: float) -> str | None:
    keys = rule.keys()
    action = (rule["action_type"] if "action_type" in keys else "") or "script"
    if action in ("reboot", "shutdown", "install_updates"):
        job_type = "install_updates" if action == "install_updates" else "reboot"
        if action == "shutdown":
            payload = json.dumps(build_power_job_payload(
                "shutdown", f"OpenPrimeRMM automation: {rule['name']}", "automation", now))
        elif action == "reboot":
            payload = json.dumps(build_power_job_payload(
                "reboot", f"OpenPrimeRMM automation: {rule['name']}", "automation", now,
                force_reboot=bool(rule["force_reboot"])))
        else:
            payload = json.dumps({"source": "automation"})
        job_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO jobs(id,agent_id,type,label,payload,created_at) VALUES(?,?,?,?,?,?)",
            (job_id, agent["id"], job_type, f"Automation: {rule['name']}", payload, now),
        )
        conn.execute(
            "INSERT INTO automation_runs(rule_id,agent_id,job_id,trigger_key,created_at) VALUES(?,?,?,?,?)",
            (rule["id"], agent["id"], job_id, rule["trigger_type"], now),
        )
        conn.execute("UPDATE automation_rules SET last_run_at=? WHERE id=?", (now, rule["id"]))
        return job_id
    script = conn.execute("SELECT * FROM scripts WHERE id=?", (rule["script_id"],)).fetchone()
    if not script:
        return None
    try:
        vals = json.loads(rule["variables"] or "{}")
    except (ValueError, TypeError):
        vals = {}
    vals = dict(vals) if isinstance(vals, dict) else {}
    vals.setdefault("OUTPOST_TRIGGER", rule["trigger_type"])
    vals.setdefault("OUTPOST_OBSERVED", observed)
    vals.setdefault("OUTPOST_HOSTNAME", agent["hostname"])
    env = resolve_variable_values(script_variables(script), vals, strict=False)
    env["OUTPOST_TRIGGER"] = rule["trigger_type"]
    env["OUTPOST_OBSERVED"] = observed[:500]
    env["OUTPOST_HOSTNAME"] = agent["hostname"]
    payload = json.dumps({
        "name": script["name"], "content": script["content"],
        "timeout_sec": script["timeout_sec"], "shell": script["shell"] or "powershell", "env": env,
    })
    job_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO jobs(id,agent_id,type,label,payload,created_at) VALUES(?,?,?,?,?,?)",
        (job_id, agent["id"], "run_script", f"Automation: {rule['name']}", payload, now),
    )
    conn.execute(
        "INSERT INTO automation_runs(rule_id,agent_id,job_id,trigger_key,created_at) VALUES(?,?,?,?,?)",
        (rule["id"], agent["id"], job_id, rule["trigger_type"], now),
    )
    conn.execute("UPDATE automation_rules SET last_run_at=? WHERE id=?", (now, rule["id"]))
    return job_id


def evaluate_automation_rules():
    now = time.time()
    wake_after_commit = set()
    with db() as conn:
        rules = conn.execute("SELECT * FROM automation_rules WHERE enabled=1").fetchall()
        for rule in rules:
            for agent in _automation_targets(conn, rule):
                # Remediation cannot run on a currently offline endpoint.
                if not agent["last_seen"] or now - float(agent["last_seen"]) > OFFLINE_AFTER_SECONDS:
                    continue
                active, observed = _automation_condition(conn, rule, agent, now)
                state = conn.execute(
                    "SELECT first_true_at FROM automation_rule_state WHERE rule_id=? AND agent_id=?",
                    (rule["id"], agent["id"]),
                ).fetchone()
                if not active:
                    if state:
                        conn.execute(
                            "DELETE FROM automation_rule_state WHERE rule_id=? AND agent_id=?",
                            (rule["id"], agent["id"]),
                        )
                    continue
                if state:
                    first_true = float(state["first_true_at"] or now)
                    conn.execute(
                        "UPDATE automation_rule_state SET last_true_at=? WHERE rule_id=? AND agent_id=?",
                        (now, rule["id"], agent["id"]),
                    )
                else:
                    first_true = now
                    conn.execute(
                        "INSERT INTO automation_rule_state(rule_id,agent_id,first_true_at,last_true_at) VALUES(?,?,?,?)",
                        (rule["id"], agent["id"], now, now),
                    )
                required_window = max(1, int(rule["window_minutes"] or 1)) * 60
                if now - first_true < required_window:
                    continue
                cooldown = max(5, int(rule["cooldown_minutes"] or 1440)) * 60
                recent = conn.execute(
                    "SELECT 1 FROM automation_runs WHERE rule_id=? AND agent_id=? AND created_at>?",
                    (rule["id"], agent["id"], now - cooldown),
                ).fetchone()
                if recent:
                    continue
                if conn.execute(
                    "SELECT 1 FROM jobs WHERE agent_id=? AND label=? AND status IN ('pending','running')",
                    (agent["id"], f"Automation: {rule['name']}"),
                ).fetchone():
                    continue
                if _queue_automation_script(conn, rule, agent, observed, now):
                    wake_after_commit.add(agent["id"])
    for agent_id in wake_after_commit:
        _wake_agent(agent_id)


@app.get("/api/automation-rules")
def api_list_automation_rules(request: Request):
    require_admin_role(request)
    with db() as conn:
        rows = conn.execute("SELECT * FROM automation_rules ORDER BY name COLLATE NOCASE").fetchall()
        return {"rules": [_automation_rule_dict(conn, r) for r in rows],
                "triggers": sorted(AUTOMATION_TRIGGERS)}


def _validate_automation_rule(body: dict) -> dict:
    name = str(body.get("name", "")).strip()[:128]
    trigger = str(body.get("trigger_type", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Rule name is required")
    if trigger not in AUTOMATION_TRIGGERS:
        raise HTTPException(status_code=400, detail="Unsupported trigger")
    target_type = str(body.get("target_type", "all"))
    if target_type not in ("all", "orgs", "machines", "group"):
        target_type = "all"
    ids = body.get("target_ids", []) if isinstance(body.get("target_ids", []), list) else []
    vals = body.get("variables", {}) if isinstance(body.get("variables", {}), dict) else {}
    action = str(body.get("action_type") or "script")
    if action not in ("script", "reboot", "shutdown", "install_updates"):
        action = "script"
    return {
        "name": name,
        "enabled": 1 if body.get("enabled", True) else 0,
        "trigger_type": trigger,
        "action_type": action,
        "force_reboot": validate_force_reboot(body, action),
        "threshold": max(0, float(body.get("threshold") or 0)),
        "window_minutes": max(1, min(1440, int(body.get("window_minutes") or 1))),
        "cooldown_minutes": max(5, min(43200, int(body.get("cooldown_minutes") or 1440))),
        "script_id": int(body.get("script_id") or 0),
        "target_type": target_type,
        "target_ids": json.dumps(ids[:1000]),
        "variables": json.dumps(vals),
    }


@app.post("/api/automation-rules")
async def api_create_automation_rule(request: Request):
    require_admin_role(request)
    v = _validate_automation_rule(await request.json())
    now = time.time()
    with db() as conn:
        if v["action_type"] == "script" and not conn.execute(
                "SELECT 1 FROM scripts WHERE id=?", (v["script_id"],)).fetchone():
            raise HTTPException(status_code=404, detail="Script not found")
        cur = conn.execute(
            """INSERT INTO automation_rules
               (name,enabled,trigger_type,threshold,window_minutes,cooldown_minutes,script_id,
                target_type,target_ids,variables,created_at,updated_at,action_type,force_reboot)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (v["name"],v["enabled"],v["trigger_type"],v["threshold"],v["window_minutes"],
             v["cooldown_minutes"],v["script_id"],v["target_type"],v["target_ids"],
             v["variables"],now,now,v["action_type"],v["force_reboot"]),
        )
    audit(request, "automation_create", str(cur.lastrowid), v["name"])
    return {"ok": True, "id": cur.lastrowid}


@app.put("/api/automation-rules/{rule_id}")
async def api_update_automation_rule(rule_id: int, request: Request):
    require_admin_role(request)
    v = _validate_automation_rule(await request.json())
    with db() as conn:
        if v["action_type"] == "script" and not conn.execute(
                "SELECT 1 FROM scripts WHERE id=?", (v["script_id"],)).fetchone():
            raise HTTPException(status_code=404, detail="Script not found")
        conn.execute(
            """UPDATE automation_rules SET name=?,enabled=?,trigger_type=?,threshold=?,window_minutes=?,
               cooldown_minutes=?,script_id=?,target_type=?,target_ids=?,variables=?,updated_at=?,action_type=?,force_reboot=? WHERE id=?""",
            (v["name"],v["enabled"],v["trigger_type"],v["threshold"],v["window_minutes"],
             v["cooldown_minutes"],v["script_id"],v["target_type"],v["target_ids"],
             v["variables"],time.time(),v["action_type"],v["force_reboot"],rule_id),
        )
    audit(request, "automation_update", str(rule_id), v["name"])
    return {"ok": True}


@app.post("/api/automation-rules/{rule_id}/toggle")
def api_toggle_automation_rule(rule_id: int, request: Request):
    require_admin_role(request)
    with db() as conn:
        row = conn.execute("SELECT enabled,name FROM automation_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        enabled = 0 if row["enabled"] else 1
        conn.execute("UPDATE automation_rules SET enabled=?,updated_at=? WHERE id=?",
                     (enabled, time.time(), rule_id))
    audit(request, "automation_toggle", str(rule_id), f"{'enabled' if enabled else 'disabled'}: {row['name']}")
    return {"ok": True, "enabled": bool(enabled)}


@app.delete("/api/automation-rules/{rule_id}")
def api_delete_automation_rule(rule_id: int, request: Request):
    require_admin_role(request)
    with db() as conn:
        conn.execute("DELETE FROM automation_rules WHERE id=?", (rule_id,))
    audit(request, "automation_delete", str(rule_id), "")
    return {"ok": True}


@app.post("/api/automation-rules/{rule_id}/run")
def api_run_automation_rule(rule_id: int, request: Request):
    require_admin_role(request)
    now = time.time()
    created = 0
    wake_after_commit = set()
    with db() as conn:
        rule = conn.execute("SELECT * FROM automation_rules WHERE id=?", (rule_id,)).fetchone()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        for agent in _automation_targets(conn, rule):
            if _queue_automation_script(conn, rule, agent, "manual test", now):
                created += 1
                wake_after_commit.add(agent["id"])
    for agent_id in wake_after_commit:
        _wake_agent(agent_id)
    audit(request, "automation_run", str(rule_id), f"{created} jobs")
    return {"ok": True, "jobs_created": created}


@app.post("/api/patching/retry-failed")
async def api_retry_failed_patches(request: Request):
    require_admin(request)
    body = await request.json()
    agent_ids = [str(x) for x in body.get("agent_ids", [])] if isinstance(body.get("agent_ids", []), list) else []
    update_id = str(body.get("update_id", "")).strip()
    now = time.time()
    with db() as conn:
        where = ["status='failed'"]
        params = []
        if agent_ids:
            where.append("agent_id IN (%s)" % ",".join("?" for _ in agent_ids))
            params.extend(agent_ids)
        if update_id:
            where.append("update_id=?")
            params.append(update_id)
        rows = conn.execute(
            f"SELECT agent_id,update_id FROM updates WHERE {' AND '.join(where)}", params
        ).fetchall()
        by_agent = {}
        for r in rows:
            by_agent.setdefault(r["agent_id"], []).append(r["update_id"])
        created = 0
        for agent_id, ids in by_agent.items():
            if conn.execute(
                "SELECT 1 FROM jobs WHERE agent_id=? AND type='install_updates' AND status IN ('pending','running')",
                (agent_id,),
            ).fetchone():
                continue
            q = ",".join("?" for _ in ids)
            conn.execute(
                f"UPDATE updates SET status='approved',status_changed_at=? WHERE agent_id=? AND update_id IN ({q})",
                (now, agent_id, *ids),
            )
            conn.execute(
                "INSERT INTO jobs(id,agent_id,type,label,payload,created_at) VALUES(?,?,?,?,?,?)",
                (str(uuid.uuid4()),agent_id,"install_updates",f"Retry {len(ids)} failed update(s)",
                 json.dumps({"update_ids": ids}),now),
            )
            _wake_agent(agent_id)
            created += 1
    audit(request, "patch_retry_failed", update_id or "all", f"{created} device(s)")
    return {"ok": True, "jobs_created": created, "updates": len(rows)}


_last_backup_slot = ""
_last_cleanup_date = ""


def run_scheduled_maintenance():
    global _last_backup_slot, _last_cleanup_date
    now_dt = datetime.datetime.now()
    today = now_dt.strftime("%Y-%m-%d")
    with db() as conn:
        cfg = get_system_settings(conn)
        slot_row = conn.execute("SELECT value FROM settings WHERE key='last_backup_slot'").fetchone()
        persisted_backup_slot = str(slot_row["value"] if slot_row else "")
    try:
        backup_hh, backup_mm = [int(x) for x in str(cfg.get("backup_time") or "02:00").split(":", 1)]
    except (ValueError, TypeError):
        backup_hh, backup_mm = 2, 0
    backup_days = {int(x) for x in (cfg.get("backup_days") or [])}
    backup_slot = f"{today}-{backup_hh:02d}{backup_mm:02d}"
    due_now = (now_dt.hour, now_dt.minute) >= (backup_hh, backup_mm)
    if (cfg.get("backup_enabled") and now_dt.weekday() in backup_days and due_now
            and _last_backup_slot != backup_slot and persisted_backup_slot != backup_slot):
        create_database_backup()
        prune_database_backups(int(cfg["backup_retention_days"]))
        with db() as conn:
            conn.execute(
                "INSERT INTO settings(key,value) VALUES('last_backup_slot',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (backup_slot,),
            )
        _last_backup_slot = backup_slot
    if cfg.get("cleanup_enabled") and now_dt.hour >= 3 and _last_cleanup_date != today:
        run_data_cleanup(cfg)
        _last_cleanup_date = today


def run_due_schedules():
    now = time.time()
    with db() as conn:
        due = conn.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run_at IS NOT NULL"
            " AND next_run_at<=?", (now,),
        ).fetchall()
        for s in due:
            fire_schedule(conn, s, now)
            if s["mode"] == "once":
                # Fired once — disable so it never runs again
                conn.execute(
                    "UPDATE schedules SET last_run_at=?, enabled=0, next_run_at=NULL WHERE id=?",
                    (now, s["id"]),
                )
            else:
                conn.execute(
                    "UPDATE schedules SET last_run_at=?, next_run_at=? WHERE id=?",
                    (now, compute_next_run(s["mode"], s["interval_minutes"], s["daily_time"], now, _sched_weekdays(s)),
                     s["id"]),
                )


def reap_stale_jobs():
    """Fail jobs stuck in 'running' long past any plausible completion time.
    A job goes 'running' the moment it's handed to an agent; if the agent dies
    mid-job, reboots, or the check-in response is lost, no result ever arrives —
    without this, the job would show 'running' forever."""
    now = time.time()
    with db() as conn:
        rows = conn.execute(
            "SELECT id, type, payload, started_at, output FROM jobs WHERE status='running'"
        ).fetchall()
        for j in rows:
            if not j["started_at"]:
                continue
            if j["type"] == "run_script":
                try:
                    tmo = int(json.loads(j["payload"]).get("timeout_sec") or 900)
                except (ValueError, TypeError):
                    tmo = 900
                deadline = j["started_at"] + tmo + 1800          # timeout + 30 min grace
            elif j["type"] == "install_updates":
                deadline = j["started_at"] + 5 * 3600            # big cumulative updates
            else:
                deadline = j["started_at"] + 1800
            if now > deadline:
                note = ("STALE: the agent picked this job up but never reported a result "
                        "(agent process killed, machine rebooted mid-job, or the check-in "
                        "response was lost). Marked failed by the server watchdog. "
                        "Use Retry to queue it again.")
                out = (j["output"] + "\n" if j["output"] else "") + note
                conn.execute(
                    "UPDATE jobs SET status='failed', output=?, finished_at=? WHERE id=?",
                    (out, now, j["id"]),
                )


_bdgz_last_sync = 0.0


_monitor_last = 0.0
_automation_last = 0.0
_maintenance_last = 0.0


async def scheduler_loop():
    while True:
        try:
            await asyncio.to_thread(run_due_schedules)
        except Exception:
            pass  # never let a bad schedule kill the loop
        try:
            await asyncio.to_thread(run_auto_approve)
        except Exception:
            pass
        try:
            await asyncio.to_thread(run_offline_alerts)
        except Exception:
            pass
        try:
            await asyncio.to_thread(reap_stale_jobs)
        except Exception:
            pass
        global _monitor_last, _automation_last, _maintenance_last
        now_tick = time.time()
        try:
            if now_tick - _monitor_last >= 60:
                _monitor_last = now_tick
                await asyncio.to_thread(evaluate_monitoring)
        except Exception as exc:
            print(f"[monitoring] evaluation failed: {exc}", flush=True)
        try:
            if now_tick - _automation_last >= 60:
                _automation_last = now_tick
                await asyncio.to_thread(evaluate_automation_rules)
        except Exception as exc:
            print(f"[automation] evaluation failed: {exc}", flush=True)
        try:
            if now_tick - _maintenance_last >= 300:
                _maintenance_last = now_tick
                await asyncio.to_thread(run_scheduled_maintenance)
        except Exception as exc:
            print(f"[maintenance] scheduled maintenance failed: {exc}", flush=True)
        global _bdgz_last_sync
        try:
            if time.time() - _bdgz_last_sync > 6 * 3600:
                _bdgz_last_sync = time.time()
                await asyncio.to_thread(_sync_bdgz_if_enabled)
        except Exception:
            pass
        try:
            await asyncio.to_thread(_maybe_send_daily_digest)
        except Exception:
            pass
        await asyncio.sleep(30)


def _sync_bdgz_if_enabled():
    """Keep both the config read and optional remote sync off the event loop."""
    with db() as conn:
        cfg = get_bdgz(conn)
    if cfg.get("enabled") and cfg.get("api_key"):
        bdgz_sync_devices()


_digest_last_date = ""


def _maybe_send_daily_digest():
    """Send the digest once per day at ~07:00 local server time, if enabled."""
    global _digest_last_date
    with db() as conn:
        acfg = get_alerts(conn)
    if not acfg.get("enabled") or not acfg.get("digest_daily") or not acfg.get("webhook_url"):
        return
    lt = time.localtime()
    today = time.strftime("%Y-%m-%d", lt)
    if lt.tm_hour >= 7 and _digest_last_date != today:
        _digest_last_date = today
        try:
            _send_digest()
        except Exception:
            pass


@app.on_event("startup")
async def start_scheduler():
    asyncio.create_task(scheduler_loop())


def _schedule_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["target_ids"] = json.loads(row["target_ids"] or "[]")
    except (ValueError, TypeError):
        d["target_ids"] = []
    try:
        d["variables"] = json.loads(row["variables"] or "{}")
    except (ValueError, KeyError, IndexError):
        d["variables"] = {}
    try:
        d["weekdays"] = json.loads(row["weekdays"] or "[]") if "weekdays" in row.keys() else []
    except (ValueError, TypeError):
        d["weekdays"] = []
    action = (row["action_type"] if "action_type" in row.keys() else "") or "script"
    if action == "script":
        script = conn.execute("SELECT name, shell FROM scripts WHERE id=?", (row["script_id"],)).fetchone()
        d["script_name"] = script["name"] if script else "(deleted script)"
        d["script_shell"] = (script["shell"] or "powershell") if script else "powershell"
    else:
        d["script_name"] = {
            "reboot": "Reboot machine",
            "shutdown": "Shut down machine",
            "install_updates": "Install Windows updates",
        }.get(action, action)
        d["script_shell"] = ""
    d["target_count"] = len(resolve_targets(conn, row["target_type"], d["target_ids"]))
    # Result of the most recent run batch
    if row["last_run_at"]:
        res = conn.execute(
            """SELECT status, COUNT(*) n FROM jobs
               WHERE schedule_id=? AND created_at>=? GROUP BY status""",
            (row["id"], row["last_run_at"] - 1),
        ).fetchall()
        counts = {r["status"]: r["n"] for r in res}
        d["last_result"] = {
            "done": counts.get("done", 0),
            "failed": counts.get("failed", 0),
            "waiting": counts.get("pending", 0) + counts.get("running", 0),
        }
    else:
        d["last_result"] = None
    return d


def _validate_schedule_body(body: dict) -> dict:
    name = str(body.get("name", "")).strip()[:128]
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    mode = body.get("mode", "interval")
    if mode not in ("interval", "daily", "once"):
        raise HTTPException(status_code=400, detail="Bad mode")
    target_type = body.get("target_type", "all")
    if target_type not in ("all", "orgs", "machines", "group"):
        raise HTTPException(status_code=400, detail="Bad target type")
    action = (str(body.get("action_type") or "script")
              if str(body.get("action_type") or "script") in
              ("script", "reboot", "shutdown", "install_updates") else "script")
    return {
        "name": name,
        "script_id": int(body.get("script_id") or 0),
        "mode": mode,
        "action_type": action,
        "force_reboot": validate_force_reboot(body, action),
        "weekdays": json.dumps(sorted({int(d) for d in (body.get("weekdays") or []) if str(d).isdigit() and 0 <= int(d) <= 6})),
        "interval_minutes": max(5, int(body.get("interval_minutes") or 60)),
        "daily_time": str(body.get("daily_time") or "03:00")[:5],
        "target_type": target_type,
        "target_ids": json.dumps(body.get("target_ids", [])),
        "variables": json.dumps(body.get("variables") or {}),
        "enabled": 1 if body.get("enabled", True) else 0,
    }


@app.get("/api/groups")
def list_groups(request: Request):
    """Dynamic device groups with a LIVE match count (evaluated right now)."""
    require_admin(request)
    out = []
    with db() as conn:
        for g in conn.execute("SELECT * FROM device_groups ORDER BY LOWER(name)"):
            try:
                filters = json.loads(g["filters"] or "{}")
            except (ValueError, TypeError):
                filters = {}
            out.append({"id": g["id"], "name": g["name"], "filters": filters,
                        "match_count": len(resolve_group_filters(conn, filters))})
    return {"groups": out}


@app.post("/api/groups")
async def create_group(request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name") or "").strip()[:120]
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    filters = sanitize_group_filters(body.get("filters") or body)
    with db() as conn:
        cur = conn.execute("INSERT INTO device_groups (name, filters, created_at) VALUES (?,?,?)",
                           (name, json.dumps(filters), time.time()))
        gid = cur.lastrowid
    audit(request, "group_create", name, json.dumps(filters))
    return {"ok": True, "id": gid}


@app.put("/api/groups/{group_id}")
async def update_group(group_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("name") or "").strip()[:120]
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    filters = sanitize_group_filters(body.get("filters") or body)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM device_groups WHERE id=?", (group_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown group")
        conn.execute("UPDATE device_groups SET name=?, filters=? WHERE id=?",
                     (name, json.dumps(filters), group_id))
    audit(request, "group_update", name, json.dumps(filters))
    return {"ok": True}


@app.delete("/api/groups/{group_id}")
def delete_group(group_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        used = conn.execute(
            "SELECT COUNT(*) c FROM schedules WHERE target_type='group' AND target_ids=?",
            (json.dumps([group_id]),)).fetchone()["c"]
        used += conn.execute(
            "SELECT COUNT(*) c FROM automation_rules WHERE target_type='group' AND target_ids=?",
            (json.dumps([group_id]),)).fetchone()["c"]
        if used:
            raise HTTPException(status_code=400,
                                detail=f"{used} schedule(s)/rule(s) still target this group")
        conn.execute("DELETE FROM device_groups WHERE id=?", (group_id,))
    audit(request, "group_delete", str(group_id), "")
    return {"ok": True}


@app.post("/api/groups/preview")
async def preview_group(request: Request):
    """Show which machines match a filter set RIGHT NOW — the 'see before you
    save' step that makes dynamic groups trustworthy."""
    require_admin(request)
    body = await request.json()
    filters = sanitize_group_filters(body.get("filters") or body)
    with db() as conn:
        ids = resolve_group_filters(conn, filters)
        rows = []
        if ids:
            qmarks = ",".join("?" for _ in ids[:500])
            rows = conn.execute(
                f"""SELECT a.hostname, a.os_version, a.device_class, a.reboot_required,
                           a.last_seen, o.name AS org_name
                    FROM agents a LEFT JOIN orgs o ON o.id=a.org_id
                    WHERE a.id IN ({qmarks}) ORDER BY LOWER(a.hostname)""", ids[:500]).fetchall()
        now = time.time()
        devices = [{"hostname": r["hostname"], "customer": r["org_name"] or "Unassigned",
                    "class": device_class_of(r), "reboot_required": bool(r["reboot_required"]),
                    "online": (now - float(r["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS}
                   for r in rows]
    return {"ok": True, "count": len(ids), "devices": devices, "filters": filters}


@app.get("/api/schedules")
def list_schedules(request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute("SELECT * FROM schedules ORDER BY name COLLATE NOCASE").fetchall()
        return {"schedules": [_schedule_dict(conn, r) for r in rows]}


@app.post("/api/schedules")
async def create_schedule(request: Request):
    require_admin(request)
    v = _validate_schedule_body(await request.json())
    if v["force_reboot"]:
        require_admin_role(request)
    with db() as conn:
        if v["action_type"] == "script" and not conn.execute(
                "SELECT 1 FROM scripts WHERE id=?", (v["script_id"],)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown script")
        cur = conn.execute(
            """INSERT INTO schedules (name, script_id, mode, interval_minutes, daily_time,
                 target_type, target_ids, variables, enabled, next_run_at, created_at,
                 action_type, weekdays, force_reboot)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (v["name"], v["script_id"], v["mode"], v["interval_minutes"], v["daily_time"],
             v["target_type"], v["target_ids"], v["variables"], v["enabled"],
             compute_next_run(v["mode"], v["interval_minutes"], v["daily_time"], None,
                              json.loads(v["weekdays"])), time.time(),
             v["action_type"], v["weekdays"], v["force_reboot"]),
        )
        new_id = cur.lastrowid
    return {"ok": True, "id": new_id}


@app.put("/api/schedules/{sched_id}")
async def update_schedule(sched_id: int, request: Request):
    require_admin(request)
    v = _validate_schedule_body(await request.json())
    if v["force_reboot"]:
        require_admin_role(request)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM schedules WHERE id=?", (sched_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown schedule")
        conn.execute(
            """UPDATE schedules SET name=?, script_id=?, mode=?, interval_minutes=?,
                 daily_time=?, target_type=?, target_ids=?, variables=?, enabled=?, next_run_at=?,
                 action_type=?, weekdays=?, force_reboot=?
               WHERE id=?""",
            (v["name"], v["script_id"], v["mode"], v["interval_minutes"], v["daily_time"],
             v["target_type"], v["target_ids"], v["variables"], v["enabled"],
             compute_next_run(v["mode"], v["interval_minutes"], v["daily_time"], None,
                              json.loads(v["weekdays"])),
             v["action_type"], v["weekdays"], v["force_reboot"], sched_id),
        )
    return {"ok": True}


@app.post("/api/schedules/{sched_id}/toggle")
def toggle_schedule(sched_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (sched_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown schedule")
        if row["action_type"] == "reboot" and row["force_reboot"]:
            require_admin_role(request)
        enabled = 0 if row["enabled"] else 1
        next_run = compute_next_run(row["mode"], row["interval_minutes"], row["daily_time"], None, _sched_weekdays(row)) \
            if enabled else row["next_run_at"]
        conn.execute("UPDATE schedules SET enabled=?, next_run_at=? WHERE id=?",
                     (enabled, next_run, sched_id))
    return {"ok": True, "enabled": bool(enabled)}


@app.post("/api/schedules/{sched_id}/run-now")
def run_schedule_now(sched_id: int, request: Request):
    require_admin(request)
    now = time.time()
    with db() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (sched_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown schedule")
        if row["action_type"] == "reboot" and row["force_reboot"]:
            require_admin_role(request)
        created = fire_schedule(conn, row, now)
        conn.execute("UPDATE schedules SET last_run_at=? WHERE id=?", (now, sched_id))
    return {"ok": True, "jobs_created": created}


@app.delete("/api/schedules/{sched_id}")
def delete_schedule(sched_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        conn.execute("DELETE FROM schedules WHERE id=?", (sched_id,))
        # Job history is kept — it's part of each machine's activity record
    return {"ok": True}


# Jobs -----------------------------------------------------------------------


@app.get("/api/jobs")
def list_jobs(request: Request, limit: int = 100, archived: int = 0):
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            """SELECT j.id, j.agent_id, j.type, j.label, j.status, j.exit_code,
                      j.schedule_id, j.created_at, j.finished_at, a.hostname
               FROM jobs j LEFT JOIN agents a ON a.id = j.agent_id
               WHERE COALESCE(j.archived, 0) = ?
               ORDER BY j.created_at DESC LIMIT ?""",
            (1 if archived else 0, min(limit, 500)),
        ).fetchall()
    return {"jobs": [dict(r) for r in rows]}


@app.post("/api/jobs/purge")
async def purge_archived_jobs(request: Request):
    """Permanently delete ARCHIVED jobs older than N days (30/60/90...)."""
    require_admin(request)
    body = await request.json()
    days = int(body.get("older_days") or 0)
    if days < 7:
        raise HTTPException(status_code=400, detail="older_days must be at least 7")
    cutoff = time.time() - days * 86400
    with db() as conn:
        cur = conn.execute(
            "DELETE FROM jobs WHERE archived=1"
            " AND COALESCE(finished_at, created_at) < ?", (cutoff,),
        )
    audit(request, "jobs_purge", f"{days}d", f"{cur.rowcount} deleted")
    return {"ok": True, "deleted": cur.rowcount}


@app.post("/api/jobs/archive")
async def archive_jobs(request: Request):
    """Bulk archive/unarchive jobs. Body: {ids: [...], archived: true|false}."""
    require_admin(request)
    body = await request.json()
    ids = [str(x) for x in body.get("ids", [])][:500]
    if not ids:
        raise HTTPException(status_code=400, detail="No jobs selected")
    flag = 1 if body.get("archived", True) else 0
    qmarks = ",".join("?" for _ in ids)
    with db() as conn:
        cur = conn.execute(
            f"UPDATE jobs SET archived=? WHERE id IN ({qmarks})", (flag, *ids),
        )
    return {"ok": True, "updated": cur.rowcount}


@app.get("/api/jobs/{job_id}")
def job_detail(job_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute(
            """SELECT j.*, a.hostname FROM jobs j
               LEFT JOIN agents a ON a.id = j.agent_id WHERE j.id=?""",
            (job_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Unknown job")
    d = dict(row)
    try:
        d["variables"] = json.loads(row["payload"] or "{}").get("env") or {}
    except ValueError:
        d["variables"] = {}
    return d


@app.post("/api/jobs/{job_id}/retry")
def retry_job(job_id: str, request: Request):
    """Re-queue a job that failed or is stuck 'running' — the agent will pick it
    up again on its next check-in."""
    require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown job")
        if row["status"] not in ("running", "failed"):
            raise HTTPException(status_code=400, detail="Only running or failed jobs can be retried")
        conn.execute(
            "UPDATE jobs SET status='pending', started_at=NULL, finished_at=NULL,"
            " output='', exit_code=NULL WHERE id=?", (job_id,),
        )
    return {"ok": True}


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# ===========================================================================
# ScreenConnect / ConnectWise Control integration ----------------------------


@app.get("/api/integrations/screenconnect")
def api_get_screenconnect(request: Request):
    require_admin(request)
    with db() as conn:
        cfg = get_screenconnect_settings(conn)
        matched = conn.execute(
            "SELECT COUNT(*) FROM agents WHERE COALESCE(screenconnect_session_id,'')<>''"
        ).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    return {**cfg, "matched_devices": matched, "total_devices": total}


@app.post("/api/integrations/screenconnect")
async def api_save_screenconnect(request: Request):
    require_admin_role(request)
    cfg = sanitize_screenconnect_settings(await request.json())
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('screenconnect',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(cfg),),
        )
    audit(request, "screenconnect_settings", "integration", f"enabled={cfg['enabled']}")
    return cfg


@app.post("/api/machines/{agent_id}/screenconnect")
async def api_set_machine_screenconnect(agent_id: str, request: Request):
    require_admin_role(request)
    body = await request.json()
    sid = str(body.get("session_id") or "").strip()
    if sid:
        try:
            sid = str(uuid.UUID(sid))
        except ValueError:
            raise HTTPException(status_code=400, detail="Session ID must be a valid ScreenConnect GUID")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute(
            "UPDATE agents SET screenconnect_session_id=?, screenconnect_service_name=? WHERE id=?",
            (sid, "manual" if sid else "", agent_id),
        )
    audit(request, "screenconnect_mapping", agent_id, "set" if sid else "cleared")
    return {"ok": True, "session_id": sid}


# Bitdefender GravityZone integration
# ===========================================================================
# GravityZone's API is JSON-RPC 2.0 over HTTPS with HTTP Basic auth where the
# username is the API key and the password is empty. The Event Push Service
# POSTs security events to a URL we register (our receiver below), carrying an
# Authorization header value we choose.

import base64 as _b64
import urllib.request as _urlreq
import urllib.error as _urlerr

BDGZ_DEFAULT_URL = "https://cloud.gravityzone.bitdefender.com/api"


def get_bdgz(conn) -> dict:
    row = conn.execute("SELECT value FROM settings WHERE key='bdgz'").fetchone()
    cfg = {}
    if row:
        try:
            cfg = json.loads(row["value"])
        except ValueError:
            cfg = {}
    cfg.setdefault("enabled", False)
    cfg.setdefault("access_url", BDGZ_DEFAULT_URL)
    cfg.setdefault("api_key", "")
    if not cfg.get("push_token"):
        cfg["push_token"] = secrets.token_urlsafe(24)
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('bdgz', ?)",
                     (json.dumps(cfg),))
    return cfg


def bdgz_call(cfg: dict, service: str, method: str, params: dict):
    """One JSON-RPC call to GravityZone. Raises HTTPException with a readable
    message on any failure."""
    if not cfg.get("api_key"):
        raise HTTPException(status_code=400, detail="GravityZone API key not configured (Settings → Integrations)")
    url = cfg.get("access_url", BDGZ_DEFAULT_URL).rstrip("/") + "/v1.0/jsonrpc/" + service
    payload = json.dumps({"jsonrpc": "2.0", "method": method,
                          "params": params or {}, "id": secrets.token_hex(8)}).encode()
    auth = _b64.b64encode((cfg["api_key"] + ":").encode()).decode()
    req = _urlreq.Request(url, data=payload, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Basic " + auth})
    try:
        with _urlreq.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except _urlerr.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode("utf-8", "replace")).get("error", {}).get("message", "")
        except Exception:
            pass
        if e.code == 401:
            detail = detail or "Authentication failed — check the API key and that the required APIs are enabled on it"
        raise HTTPException(status_code=502, detail=f"GravityZone HTTP {e.code}: {detail or e.reason}")
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=502, detail=f"GravityZone unreachable: {e}")
    if data.get("error"):
        raise HTTPException(status_code=502,
                            detail=f"GravityZone error: {data['error'].get('message', data['error'])}")
    return data.get("result")


@app.get("/api/integrations/bdgz")
def bdgz_config(request: Request):
    require_admin(request)
    with db() as conn:
        cfg = get_bdgz(conn)
        orgs = conn.execute(
            """SELECT o.id, o.name, o.bdgz_company_id, o.bdgz_company_name,
                      COUNT(a.id) AS machines,
                      SUM(CASE WHEN a.bdgz_protected=1 THEN 1 ELSE 0 END) AS protected
               FROM orgs o LEFT JOIN agents a ON a.org_id=o.id
               GROUP BY o.id ORDER BY o.name COLLATE NOCASE"""
        ).fetchall()
    return {"enabled": cfg["enabled"], "access_url": cfg["access_url"],
            "has_key": bool(cfg["api_key"]), "push_token": cfg["push_token"],
            "orgs": [dict(r) for r in orgs]}


@app.post("/api/integrations/bdgz")
async def bdgz_save(request: Request):
    require_admin(request)
    body = await request.json()
    with db() as conn:
        cfg = get_bdgz(conn)
        cfg["enabled"] = bool(body.get("enabled", cfg["enabled"]))
        cfg["access_url"] = (str(body.get("access_url") or cfg["access_url"]).strip()
                             or BDGZ_DEFAULT_URL)
        if body.get("api_key"):                     # blank = keep existing key
            cfg["api_key"] = str(body["api_key"]).strip()
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('bdgz', ?)",
                     (json.dumps(cfg),))
    return {"ok": True}


@app.post("/api/integrations/bdgz/test")
def bdgz_test(request: Request):
    require_admin(request)
    with db() as conn:
        cfg = get_bdgz(conn)
    res = bdgz_call(cfg, "companies", "getCompanyDetails", {})
    return {"ok": True, "company": (res or {}).get("name", "unknown"),
            "company_id": (res or {}).get("id", "")}


@app.get("/api/integrations/bdgz/companies")
def bdgz_companies(request: Request, query: str = ""):
    require_admin(request)
    with db() as conn:
        cfg = get_bdgz(conn)
    res = bdgz_call(cfg, "companies", "findCompaniesByName",
                    {"nameFilter": (query or "").strip() or "*"})
    items = res if isinstance(res, list) else (res or {}).get("items", []) or []
    return {"companies": [{"id": c.get("id"), "name": c.get("name")} for c in items][:50]}


@app.post("/api/orgs/{org_id}/bdgz-link")
async def bdgz_link_org(org_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    cid = str(body.get("company_id") or "").strip()
    cname = str(body.get("company_name") or "").strip()
    with db() as conn:
        if not conn.execute("SELECT 1 FROM orgs WHERE id=?", (org_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown customer")
        conn.execute("UPDATE orgs SET bdgz_company_id=?, bdgz_company_name=? WHERE id=?",
                     (cid, cname, org_id))
        if not cid:   # unlink clears device status for that customer
            conn.execute("UPDATE agents SET bdgz_protected=NULL WHERE org_id=?", (org_id,))
    return {"ok": True}


@app.post("/api/orgs/{org_id}/bdgz-create")
def bdgz_create_company(org_id: int, request: Request):
    """Push an RMM customer to GravityZone as a new company (the NinjaOne-style
    org mapping), then link it."""
    require_admin(request)
    with db() as conn:
        cfg = get_bdgz(conn)
        org = conn.execute("SELECT * FROM orgs WHERE id=?", (org_id,)).fetchone()
    if not org:
        raise HTTPException(status_code=404, detail="Unknown customer")
    if org["bdgz_company_id"]:
        raise HTTPException(status_code=400, detail="Customer is already linked to a GravityZone company")
    res = bdgz_call(cfg, "companies", "createCompany",
                    {"type": 1, "name": org["name"]})
    cid = res if isinstance(res, str) else (res or {}).get("id", "")
    if not cid:
        raise HTTPException(status_code=502, detail="GravityZone did not return a company id")
    with db() as conn:
        conn.execute("UPDATE orgs SET bdgz_company_id=?, bdgz_company_name=? WHERE id=?",
                     (cid, org["name"], org_id))
    return {"ok": True, "company_id": cid}


def bdgz_sync_devices() -> dict:
    """Match GravityZone endpoints to RMM machines per linked customer, by
    hostname (case-insensitive). Sets agents.bdgz_protected 1/0."""
    with db() as conn:
        cfg = get_bdgz(conn)
        orgs = conn.execute(
            "SELECT id, name, bdgz_company_id FROM orgs WHERE bdgz_company_id != ''"
        ).fetchall()
    matched = unmatched = 0
    for org in orgs:
        names = set()
        page = 1
        while page <= 20:
            res = bdgz_call(cfg, "network", "getEndpointsList",
                            {"parentId": org["bdgz_company_id"], "page": page, "perPage": 100})
            items = (res or {}).get("items", []) or []
            for it in items:
                nm = str(it.get("name") or it.get("fqdn") or "").split(".")[0].lower()
                if nm:
                    names.add(nm)
            if page >= int((res or {}).get("pagesCount") or 1):
                break
            page += 1
        with db() as conn:
            for a in conn.execute("SELECT id, hostname FROM agents WHERE org_id=?", (org["id"],)):
                ok = a["hostname"].split(".")[0].lower() in names
                conn.execute("UPDATE agents SET bdgz_protected=? WHERE id=?",
                             (1 if ok else 0, a["id"]))
                matched += 1 if ok else 0
                unmatched += 0 if ok else 1
    return {"ok": True, "orgs_synced": len(orgs), "protected": matched, "unprotected": unmatched}


@app.post("/api/integrations/bdgz/sync")
def bdgz_sync(request: Request):
    require_admin(request)
    return bdgz_sync_devices()


@app.post("/api/integrations/bdgz/setup-push")
def bdgz_setup_push(request: Request):
    """Tell GravityZone (via its push service API) to POST security events to
    this server's receiver, authenticated with our push token."""
    require_admin(request)
    with db() as conn:
        cfg = get_bdgz(conn)
    host = request.headers.get("host", "")
    if not host:
        raise HTTPException(status_code=400, detail="Cannot determine this server's public URL")
    receiver = f"https://{host}/api/integrations/bdgz/events"
    bdgz_call(cfg, "push", "setPushEventSettings", {
        "status": 1, "serviceType": "jsonRPC",
        "serviceSettings": {"url": receiver, "requireValidSslCertificate": True,
                            "authorization": cfg["push_token"]},
        "subscribeToEventTypes": {"av": True, "avc": True, "aph": True, "fw": True,
                                  "uc": True, "dp": True, "hd": True,
                                  "antiexploit": True, "network-sandboxing": True,
                                  "ransomware-mitigation": True},
    })
    return {"ok": True, "receiver": receiver}


def _bdgz_extract_events(body) -> list:
    """The push service formats vary (jsonRPC envelope, bare list, single
    event); normalize to a list of dicts."""
    if isinstance(body, list):
        return [e for e in body if isinstance(e, dict)]
    if not isinstance(body, dict):
        return []
    if isinstance(body.get("events"), list):
        return [e for e in body["events"] if isinstance(e, dict)]
    params = body.get("params")
    if isinstance(params, dict) and isinstance(params.get("events"), list):
        return [e for e in params["events"] if isinstance(e, dict)]
    if body.get("module") or body.get("computer_name") or body.get("computerName"):
        return [body]
    return []


@app.post("/api/integrations/bdgz/events")
async def bdgz_events_receiver(request: Request):
    """Event Push Service receiver. Authenticated by the Authorization header
    matching our push token (GravityZone sends whatever we registered)."""
    with db() as conn:
        cfg = get_bdgz(conn)
    supplied = request.headers.get("authorization", "")
    if not cfg.get("push_token") or cfg["push_token"] not in supplied:
        raise HTTPException(status_code=401, detail="Bad push token")
    body = await read_agent_json(request)
    events = _bdgz_extract_events(body)
    stored = 0
    alerts = []
    now = time.time()
    with db() as conn:
        for ev in events[:100]:
            name = str(ev.get("computer_name") or ev.get("computerName") or "")[:128]
            short = name.split(".")[0].lower()
            agent = conn.execute(
                "SELECT id, org_id, hostname FROM agents WHERE LOWER(hostname) LIKE ?",
                (short + "%",)).fetchone() if short else None
            threat = str(ev.get("malware_name") or ev.get("malwareName") or
                         ev.get("exploit_type") or ev.get("threatType") or
                         ev.get("detection_name") or "")[:256]
            module = str(ev.get("module") or "")[:32]
            row = (now, module, name,
                   str(ev.get("computer_ip") or ev.get("computerIp") or "")[:64],
                   threat,
                   str(ev.get("file_path") or ev.get("filePath") or ev.get("url") or "")[:512],
                   str(ev.get("final_status") or ev.get("actionTaken") or
                       ev.get("status") or "")[:128],
                   agent["id"] if agent else None,
                   agent["org_id"] if agent else None,
                   json.dumps(ev)[:8000])
            conn.execute(
                """INSERT INTO av_events (received_at, module, computer_name, computer_ip,
                     threat, file_path, action, agent_id, org_id, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""", row)
            stored += 1
            if module in ("av", "avc", "aph", "antiexploit", "ransomware-mitigation",
                          "network-sandboxing"):
                alerts.append((name or "unknown machine", threat or module))
        # keep the table bounded
        conn.execute("""DELETE FROM av_events WHERE id NOT IN
                        (SELECT id FROM av_events ORDER BY id DESC LIMIT 5000)""")
    for name, threat in alerts[:10]:
        try:
            with db() as conn:
                acfg = get_alerts(conn)
            if acfg.get("enabled") and acfg.get("webhook_url"):
                send_discord(acfg["webhook_url"], f"\U0001F9A0 Bitdefender detection on {name}",
                             f"**Threat:** {threat}\nSee the Security page for details.",
                             color=0xC43D3D)
        except Exception:
            pass
    return {"ok": True, "stored": stored}




BDGZ_INSTALL_SCRIPT = r"""# Deploys Bitdefender Endpoint Security Tools silently.
# The downloader's FILENAME encodes which company/package it installs, so it
# must keep its original name - which contains [square brackets]. PowerShell
# file cmdlets treat brackets as WILDCARDS, so this script only uses
# bracket-safe operations (WebClient, -LiteralPath, .NET IO).
$ErrorActionPreference = 'Stop'
$link = $env:bdgzInstallLink
if (-not $link -or $link -eq 'null') { Write-Output 'No install link provided.'; exit 1 }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
if (Get-Service -Name 'EPSecurityService' -ErrorAction SilentlyContinue) {
    Write-Output 'Bitdefender Endpoint Security Tools is already installed.'; exit 0
}
$name = ''
try {
    $name = [IO.Path]::GetFileName(([Uri]$link).AbsolutePath)
    # CRITICAL: AbsolutePath percent-encodes the [brackets] as %5B/%5D. The
    # downloader parses its OWN FILENAME for the package config, so the name
    # must be decoded back to real brackets or it installs nothing.
    $name = [Uri]::UnescapeDataString($name)
} catch {}
if (-not $name) { $name = 'setupdownloader.exe' }
Write-Output "Package file name: $name"
$dst = Join-Path $env:TEMP $name
Write-Output "Downloading $name ..."
try {
    (New-Object System.Net.WebClient).DownloadFile($link, $dst)
} catch {
    Write-Output "Download failed: $($_.Exception.Message)"
    Write-Output 'Check that this machine has direct internet access to download.bitdefender.com.'
    exit 1
}
if (-not (Test-Path -LiteralPath $dst)) { Write-Output 'Download reported success but the file is not on disk.'; exit 1 }
$len = (Get-Item -LiteralPath $dst).Length
Write-Output ("Downloaded {0:N0} bytes." -f $len)
$fs = [IO.File]::OpenRead($dst)
$hdr = New-Object byte[] 2
$null = $fs.Read($hdr, 0, 2)
$fs.Close()
if ([Text.Encoding]::ASCII.GetString($hdr) -ne 'MZ') {
    Write-Output 'Downloaded file is not a Windows executable - the install link may be expired or blocked by a proxy. Regenerate the package link and try again.'
    exit 1
}
Write-Output 'Launching silent install (typically 10-20 minutes)...'
Start-Process -FilePath $dst -ArgumentList '/bdparams','/silent' | Out-Null
$deadline = (Get-Date).AddMinutes(35)
while ((Get-Date) -lt $deadline) {
    if (Get-Service -Name 'EPSecurityService' -ErrorAction SilentlyContinue) {
        Write-Output 'Bitdefender Endpoint Security Tools installed and service present.'
        Write-Output 'The device will appear in GravityZone within a few minutes; the next device sync will mark it protected here.'
        exit 0
    }
    Start-Sleep -Seconds 30
}
Write-Output 'Installer launched but the Bitdefender service was not detected within 35 minutes.'
Write-Output 'Check C:\Windows\Temp and Programs and Features on the machine; a conflicting AV can block BEST setup.'
exit 1
"""


def _bdgz_windows_link(res) -> str:
    """getInstallationLinks responses vary by console version — accept a list
    or {items:[...]} and prefer the small Windows downloader over full kits."""
    items = res if isinstance(res, list) else (res or {}).get("items", []) or []
    if isinstance(res, dict) and not items and (res.get("installLinkWindows") or res.get("fullKitWindowsX64")):
        items = [res]
    for key in ("installLinkWindows", "installLinkWindowsDownloader",
                "fullKitWindowsX64", "fullKitWindowsX86"):
        for it in items:
            if isinstance(it, dict) and it.get(key):
                return str(it[key])
    return ""


@app.post("/api/machines/{agent_id}/deploy-bdgz")
def deploy_bdgz(agent_id: str, request: Request):
    """Queue a job that installs Bitdefender on this machine, using the install
    package of the GravityZone company its customer is linked to."""
    require_admin(request)
    with db() as conn:
        cfg = get_bdgz(conn)
        a = conn.execute(
            """SELECT a.id, a.hostname, a.org_id, o.name AS org_name,
                      o.bdgz_company_id FROM agents a
               LEFT JOIN orgs o ON o.id=a.org_id WHERE a.id=?""", (agent_id,)).fetchone()
    if not a:
        raise HTTPException(status_code=404, detail="Unknown machine")
    if not a["bdgz_company_id"]:
        raise HTTPException(status_code=400,
                            detail=f"Customer '{a['org_name'] or 'Unassigned'}' is not linked to a "
                                   "GravityZone company yet (Settings → Integrations)")
    res = bdgz_call(cfg, "packages", "getInstallationLinks",
                    {"companyId": a["bdgz_company_id"]})
    link = _bdgz_windows_link(res)
    if not link:
        raise HTTPException(status_code=502,
                            detail="GravityZone returned no Windows install link for this company "
                                   "(create an installation package for it in Control Center → Network → Packages)")
    payload = json.dumps({"name": "Install Bitdefender", "content": BDGZ_INSTALL_SCRIPT,
                          "timeout_sec": 2700, "env": {"bdgzInstallLink": link}})
    with db() as conn:
        conn.execute(
            """INSERT INTO jobs (id, agent_id, type, label, payload, status, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), a["id"], "run_script", "Install Bitdefender",
             payload, "pending", time.time()))
    return {"ok": True, "hostname": a["hostname"]}


@app.get("/api/security/events")
def security_events(request: Request, limit: int = 500, archived: int = 0):
    require_admin(request)
    flag = 1 if archived else 0
    with db() as conn:
        rows = conn.execute(
            """SELECT e.*, a.hostname AS agent_hostname, o.name AS org_name
               FROM av_events e
               LEFT JOIN agents a ON a.id = e.agent_id
               LEFT JOIN orgs o ON o.id = e.org_id
               WHERE COALESCE(e.archived, 0)=?
               ORDER BY e.id DESC LIMIT ?""",
            (flag, min(max(int(limit), 1), 500))).fetchall()
        active_count = conn.execute(
            "SELECT COUNT(*) FROM av_events WHERE COALESCE(archived,0)=0"
        ).fetchone()[0]
        archived_count = conn.execute(
            "SELECT COUNT(*) FROM av_events WHERE COALESCE(archived,0)=1"
        ).fetchone()[0]
    return {"events": [dict(r) for r in rows],
            "active_count": active_count, "archived_count": archived_count}


def _security_event_ids(body) -> list[int]:
    raw = body.get("ids", []) if isinstance(body, dict) else []
    if not isinstance(raw, list):
        raise HTTPException(status_code=400, detail="ids must be a list")
    ids = []
    for value in raw[:500]:
        try:
            n = int(value)
        except (TypeError, ValueError):
            continue
        if n > 0 and n not in ids:
            ids.append(n)
    if not ids:
        raise HTTPException(status_code=400, detail="Select at least one security event")
    return ids


@app.post("/api/security/events/archive")
async def security_events_archive(request: Request):
    user = require_admin_role(request)
    body = await request.json()
    ids = _security_event_ids(body)
    archived = bool(body.get("archived", True))
    qmarks = ",".join("?" for _ in ids)
    with db() as conn:
        if archived:
            cur = conn.execute(
                f"UPDATE av_events SET archived=1, archived_at=?, archived_by=? "
                f"WHERE id IN ({qmarks})",
                (time.time(), user.get("u", ""), *ids),
            )
        else:
            cur = conn.execute(
                f"UPDATE av_events SET archived=0, archived_at=NULL, archived_by='' "
                f"WHERE id IN ({qmarks})", ids,
            )
    audit(request, "security_events_archive" if archived else "security_events_restore",
          f"{cur.rowcount} events", ",".join(map(str, ids[:50])))
    return {"ok": True, "updated": cur.rowcount, "archived": archived}


@app.post("/api/security/events/delete")
async def security_events_delete(request: Request):
    require_admin_role(request)
    body = await request.json()
    ids = _security_event_ids(body)
    qmarks = ",".join("?" for _ in ids)
    with db() as conn:
        cur = conn.execute(f"DELETE FROM av_events WHERE id IN ({qmarks})", ids)
    audit(request, "security_events_delete", f"{cur.rowcount} events",
          ",".join(map(str, ids[:50])))
    return {"ok": True, "deleted": cur.rowcount}


# ===========================================================================
# AI providers — failed job analysis and operations digest
# ===========================================================================

AI_PROVIDERS = {
    "anthropic": {
        "label": "Anthropic",
        "base_url": "https://api.anthropic.com",
        "model": "claude-haiku-4-5",
    },
    "openai_compatible": {
        "label": "OpenAI-compatible",
        "base_url": "https://api.openai.com/v1",
        "model": "",
    },
    "gemini": {
        "label": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "model": "",
    },
}


class AiProviderError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _bounded_int(value, default: int, low: int, high: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _optional_float(value):
    if value is None or str(value).strip() == "":
        return None
    try:
        return max(0.0, min(2.0, float(value)))
    except (TypeError, ValueError):
        return None


def get_ai(conn) -> dict:
    """Return a normalized AI configuration.

    Older releases stored only ``api_key`` and ``model`` and always called
    Anthropic.  Preserve that configuration by migrating it in memory to the
    Anthropic provider until the administrator saves the new form.
    """
    row = conn.execute("SELECT value FROM settings WHERE key='ai'").fetchone()
    cfg = {}
    if row:
        try:
            cfg = json.loads(row["value"])
        except (ValueError, TypeError):
            cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}

    provider = str(cfg.get("provider") or "anthropic").strip().lower()
    if provider not in AI_PROVIDERS:
        provider = "anthropic"
    preset = AI_PROVIDERS[provider]

    cfg["provider"] = provider
    cfg["enabled"] = bool(cfg.get("enabled", bool(cfg.get("api_key"))))
    cfg["api_key"] = str(cfg.get("api_key") or "")
    cfg["model"] = str(cfg.get("model") or preset["model"]).strip()[:160]
    cfg["base_url"] = str(cfg.get("base_url") or preset["base_url"]).strip()[:500].rstrip("/")
    cfg["auth_mode"] = str(cfg.get("auth_mode") or "bearer").strip().lower()
    if cfg["auth_mode"] not in ("bearer", "api_key", "custom", "none"):
        cfg["auth_mode"] = "bearer"
    cfg["auth_header"] = str(cfg.get("auth_header") or "Authorization").strip()[:80]
    cfg["auth_prefix"] = str(cfg.get("auth_prefix") if cfg.get("auth_prefix") is not None else "Bearer ")[:80]
    cfg["token_parameter"] = str(cfg.get("token_parameter") or "auto").strip().lower()
    if cfg["token_parameter"] not in ("auto", "max_tokens", "max_completion_tokens"):
        cfg["token_parameter"] = "auto"
    cfg["send_model"] = bool(cfg.get("send_model", True))
    cfg["max_tokens"] = _bounded_int(cfg.get("max_tokens"), 4000, 64, 16000)
    cfg["timeout_seconds"] = _bounded_int(cfg.get("timeout_seconds"), 60, 5, 180)
    cfg["temperature"] = _optional_float(cfg.get("temperature"))
    cfg["auto_diagnostics"] = bool(cfg.get("auto_diagnostics", False))
    return cfg


def _ai_public(cfg: dict) -> dict:
    return {
        "enabled": bool(cfg.get("enabled")),
        "provider": cfg.get("provider", "anthropic"),
        "provider_label": AI_PROVIDERS.get(cfg.get("provider"), AI_PROVIDERS["anthropic"])["label"],
        "has_key": bool(cfg.get("api_key")),
        "model": cfg.get("model", ""),
        "base_url": cfg.get("base_url", ""),
        "auth_mode": cfg.get("auth_mode", "bearer"),
        "auth_header": cfg.get("auth_header", "Authorization"),
        "auth_prefix": cfg.get("auth_prefix", "Bearer "),
        "token_parameter": cfg.get("token_parameter", "auto"),
        "send_model": bool(cfg.get("send_model", True)),
        "max_tokens": cfg.get("max_tokens", 1000),
        "timeout_seconds": cfg.get("timeout_seconds", 60),
        "temperature": cfg.get("temperature"),
        "auto_diagnostics": bool(cfg.get("auto_diagnostics", False)),
        "configured": _ai_ready(cfg),
    }


def _validate_ai_url(value: str) -> str:
    value = str(value or "").strip().rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        parsed = None
    if not parsed or parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="AI API URL must begin with http:// or https://")
    return value[:500]


def _normalize_ai_form(body: dict, current: dict) -> dict:
    cfg = dict(current)
    provider = str(body.get("provider", cfg.get("provider", "anthropic"))).strip().lower()
    if provider not in AI_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported AI provider")
    provider_changed = provider != cfg.get("provider")
    cfg["provider"] = provider
    cfg["enabled"] = bool(body.get("enabled", cfg.get("enabled", False)))
    cfg["model"] = str(body.get("model", cfg.get("model", ""))).strip()[:160]
    cfg["base_url"] = _validate_ai_url(
        body.get("base_url") or AI_PROVIDERS[provider]["base_url"]
    )

    mode = str(body.get("auth_mode", cfg.get("auth_mode", "bearer"))).strip().lower()
    if mode not in ("bearer", "api_key", "custom", "none"):
        raise HTTPException(status_code=400, detail="Unsupported AI authentication mode")
    cfg["auth_mode"] = mode

    header = str(body.get("auth_header", cfg.get("auth_header", "Authorization"))).strip()
    if header and not re.fullmatch(r"[A-Za-z0-9-]{1,80}", header):
        raise HTTPException(status_code=400, detail="Custom authentication header contains invalid characters")
    cfg["auth_header"] = header or "Authorization"
    cfg["auth_prefix"] = str(body.get("auth_prefix", cfg.get("auth_prefix", "Bearer ")))[:80]

    token_parameter = str(body.get("token_parameter", cfg.get("token_parameter", "auto"))).strip().lower()
    if token_parameter not in ("auto", "max_tokens", "max_completion_tokens"):
        token_parameter = "auto"
    cfg["token_parameter"] = token_parameter
    cfg["send_model"] = bool(body.get("send_model", cfg.get("send_model", True)))
    cfg["max_tokens"] = _bounded_int(body.get("max_tokens", cfg.get("max_tokens")), 1000, 64, 16000)
    cfg["timeout_seconds"] = _bounded_int(body.get("timeout_seconds", cfg.get("timeout_seconds")), 60, 5, 180)
    cfg["temperature"] = _optional_float(body.get("temperature", cfg.get("temperature")))
    cfg["auto_diagnostics"] = bool(body.get("auto_diagnostics", cfg.get("auto_diagnostics", False)))

    new_key = str(body.get("api_key") or "").strip()
    if body.get("clear_key"):
        cfg["api_key"] = ""
    elif new_key:
        cfg["api_key"] = new_key
    elif provider_changed:
        # Prevent an Anthropic key, for example, from silently being sent to a
        # different endpoint after switching providers.
        cfg["api_key"] = ""

    model_required = provider != "openai_compatible" or cfg.get("send_model", True)
    if cfg["enabled"] and model_required and not cfg["model"]:
        raise HTTPException(status_code=400, detail="Enter the model name used by this AI provider")
    return cfg


def _ai_ready(cfg: dict) -> bool:
    if not cfg.get("enabled") or not cfg.get("base_url"):
        return False
    if (cfg.get("provider") != "openai_compatible" or cfg.get("send_model", True)) and not cfg.get("model"):
        return False
    if cfg.get("provider") == "openai_compatible" and cfg.get("auth_mode") == "none":
        return True
    return bool(cfg.get("api_key"))


def _endpoint_url(base_url: str, suffix: str, exact_ending: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.path.rstrip("/").endswith(exact_ending):
        return base_url
    path = parsed.path.rstrip("/") + suffix
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def _ai_error_message(raw: bytes, fallback: str = "Request failed") -> str:
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return fallback
    try:
        data = json.loads(text)
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            text = str(err.get("message") or err.get("detail") or err.get("type") or text)
        elif err:
            text = str(err)
        elif isinstance(data, dict):
            text = str(data.get("message") or data.get("detail") or text)
    except (ValueError, TypeError):
        pass
    return text[:700]


def _ai_http_json(url: str, payload: dict, headers: dict, timeout: int, label: str) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = _urlreq.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"OpenPrimeRMM/{PLATFORM_VERSION}",
        **headers,
    })
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except _urlerr.HTTPError as exc:
        raw = exc.read()
        raise AiProviderError(
            f"{label} API {exc.code}: {_ai_error_message(raw, str(exc.reason))}",
            status=exc.code,
        ) from exc
    except (_urlerr.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise AiProviderError(f"{label} API unreachable: {reason}") from exc
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, TypeError) as exc:
        raise AiProviderError(f"{label} returned a non-JSON response") from exc
    if not isinstance(data, dict):
        raise AiProviderError(f"{label} returned an unexpected response")
    return data


def _text_from_openai(data: dict) -> str:
    choices = data.get("choices") or []
    if choices:
        choice = choices[0] if isinstance(choices[0], dict) else {}
        message = choice.get("message") or {}
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str) and content.strip():
            return content.strip()
        if isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    parts.append(part["text"])
            if parts:
                return "".join(parts).strip()
        if isinstance(choice.get("text"), str) and choice["text"].strip():
            return choice["text"].strip()
    # Responses API convenience field (some gateways return it for chat calls).
    if isinstance(data.get("output_text"), str) and data["output_text"].strip():
        return data["output_text"].strip()
    # Responses API 'output' array (reasoning models): find the message item's text.
    for item in (data.get("output") or []):
        if isinstance(item, dict) and item.get("type") == "message":
            for part in (item.get("content") or []):
                if isinstance(part, dict) and isinstance(part.get("text"), str) and part["text"].strip():
                    return part["text"].strip()
    return ""


def _openai_empty_reason(data: dict) -> str:
    """When extraction is empty, explain why (helps with reasoning models)."""
    choices = data.get("choices") or []
    if choices and isinstance(choices[0], dict):
        fr = choices[0].get("finish_reason")
        if fr == "length":
            return ("the model used its whole token budget before returning an "
                    "answer — raise Max tokens in Settings → Integrations (reasoning "
                    "models like GPT-5.x need 3000+).")
        if fr == "content_filter":
            return "the response was blocked by the provider's content filter."
        if fr:
            return f"the model stopped early (finish_reason={fr})."
    usage = data.get("usage") or {}
    if usage.get("completion_tokens") and not usage.get("completion_tokens_details", {}):
        return "the model returned tokens but no readable text content."
    return ""


def _text_from_anthropic(data: dict) -> str:
    return "".join(
        block.get("text", "") for block in (data.get("content") or [])
        if isinstance(block, dict) and block.get("type") == "text"
    ).strip()


def _text_from_gemini(data: dict) -> str:
    candidates = data.get("candidates") or []
    if not candidates:
        feedback = data.get("promptFeedback") or {}
        reason = feedback.get("blockReason") if isinstance(feedback, dict) else ""
        if reason:
            raise AiProviderError(f"Google Gemini blocked the prompt: {reason}")
        return ""
    candidate = candidates[0] if isinstance(candidates[0], dict) else {}
    content = candidate.get("content") or {}
    parts = content.get("parts") if isinstance(content, dict) else []
    return "".join(
        part.get("text", "") for part in (parts or [])
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    ).strip()


def _ai_complete(cfg: dict, prompt: str, max_tokens: int | None = None) -> str:
    if not _ai_ready(cfg):
        raise AiProviderError("AI integration is disabled or incomplete")
    provider = cfg["provider"]
    label = AI_PROVIDERS[provider]["label"]
    limit = _bounded_int(max_tokens or cfg.get("max_tokens"), 1000, 32, 16000)
    timeout = _bounded_int(cfg.get("timeout_seconds"), 60, 5, 180)
    temperature = cfg.get("temperature")

    if provider == "anthropic":
        url = _endpoint_url(cfg["base_url"], "/v1/messages", "/v1/messages")
        payload = {
            "model": cfg["model"],
            "max_tokens": limit,
            "messages": [{"role": "user", "content": prompt}],
        }
        if temperature is not None:
            payload["temperature"] = temperature
        data = _ai_http_json(url, payload, {
            "x-api-key": cfg["api_key"],
            "anthropic-version": "2023-06-01",
        }, timeout, label)
        text = _text_from_anthropic(data)

    elif provider == "gemini":
        parsed = urllib.parse.urlsplit(cfg["base_url"])
        if ":generateContent" in parsed.path:
            url = cfg["base_url"]
        else:
            model = urllib.parse.quote(cfg["model"], safe="-._")
            path = parsed.path.rstrip("/") + f"/models/{model}:generateContent"
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))
        generation = {"maxOutputTokens": limit}
        if temperature is not None:
            generation["temperature"] = temperature
        data = _ai_http_json(url, {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": generation,
        }, {"x-goog-api-key": cfg["api_key"]}, timeout, label)
        text = _text_from_gemini(data)

    else:  # OpenAI-compatible Chat Completions
        url = _endpoint_url(cfg["base_url"], "/chat/completions", "/chat/completions")
        headers = {}
        mode = cfg.get("auth_mode", "bearer")
        key = cfg.get("api_key", "")
        if mode == "bearer":
            if not key:
                raise AiProviderError("An API key is required for Bearer authentication")
            headers["Authorization"] = f"{cfg.get('auth_prefix', 'Bearer ')}{key}"
        elif mode == "api_key":
            if not key:
                raise AiProviderError("An API key is required for api-key authentication")
            headers["api-key"] = key
        elif mode == "custom":
            if not key:
                raise AiProviderError("An API key is required for custom-header authentication")
            headers[cfg.get("auth_header") or "Authorization"] = f"{cfg.get('auth_prefix', '')}{key}"

        base_payload = {"messages": [{"role": "user", "content": prompt}]}
        if cfg.get("send_model", True):
            base_payload["model"] = cfg["model"]
        if temperature is not None:
            base_payload["temperature"] = temperature
        parameter = cfg.get("token_parameter", "auto")
        attempts = [parameter] if parameter != "auto" else ["max_tokens", "max_completion_tokens"]
        last_error = None
        data = None
        for index, token_name in enumerate(attempts):
            payload = dict(base_payload)
            payload[token_name] = limit
            try:
                data = _ai_http_json(url, payload, headers, timeout, label)
                break
            except AiProviderError as exc:
                last_error = exc
                message = str(exc).lower()
                retryable = exc.status in (400, 422) and (
                    "max_tokens" in message or "max_completion_tokens" in message
                    or "unsupported parameter" in message or "unknown field" in message
                )
                if index + 1 >= len(attempts) or not retryable:
                    raise
        if data is None:
            raise last_error or AiProviderError(f"{label} did not return a response")
        text = _text_from_openai(data)
        if not text:
            reason = _openai_empty_reason(data)
            if reason:
                raise AiProviderError(f"{label} returned no usable text: {reason}")

    if not text:
        raise AiProviderError(f"{label} returned an empty text response")
    return text


@app.get("/api/integrations/ai")
def ai_config(request: Request):
    require_admin(request)
    with db() as conn:
        cfg = get_ai(conn)
    return _ai_public(cfg)


@app.post("/api/integrations/ai")
async def ai_save(request: Request):
    require_admin(request)
    body = await request.json()
    with db() as conn:
        current = get_ai(conn)
        cfg = _normalize_ai_form(body if isinstance(body, dict) else {}, current)
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ai', ?)",
                     (json.dumps(cfg),))
    audit(request, "ai_settings_update", AI_PROVIDERS[cfg["provider"]]["label"], cfg["model"])
    return {"ok": True, **_ai_public(cfg)}


@app.post("/api/integrations/ai/test")
async def ai_test(request: Request):
    require_admin(request)
    body = await request.json()
    with db() as conn:
        current = get_ai(conn)
    cfg = _normalize_ai_form(body if isinstance(body, dict) else {}, current)
    cfg["enabled"] = True
    started = time.monotonic()
    try:
        text = _ai_complete(
            cfg,
            "Reply with exactly one short sentence confirming the OpenPrimeRMM AI connection works.",
            max_tokens=96,
        )
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {
        "ok": True,
        "provider": AI_PROVIDERS[cfg["provider"]]["label"],
        "model": cfg["model"] or "endpoint-defined deployment",
        "latency_ms": int((time.monotonic() - started) * 1000),
        "response": text[:500],
    }


@app.post("/api/jobs/{job_id}/analyze")
def analyze_job(job_id: str, request: Request):
    """Send a failed job's script and output to the selected AI provider."""
    require_admin(request)
    with db() as conn:
        cfg = get_ai(conn)
        job = conn.execute(
            """SELECT j.*, a.hostname, a.os_version FROM jobs j
               LEFT JOIN agents a ON a.id=j.agent_id WHERE j.id=?""",
            (job_id,)).fetchone()
    if not job:
        raise HTTPException(status_code=404, detail="Unknown job")
    if not _ai_ready(cfg):
        raise HTTPException(status_code=400,
                            detail="AI integration is disabled or incomplete (Settings → Integrations)")
    try:
        payload = json.loads(job["payload"] or "{}")
    except ValueError:
        payload = {}
    prompt = (
        "You are helping an MSP technician diagnose a failed remote job from an RMM.\n"
        f"Machine: {job['hostname']} ({job['os_version']})\n"
        f"Job type: {job['type']} | Label: {job['label']} | Exit code: {job['exit_code']}\n"
        f"Script language: {payload.get('shell') or 'powershell'}\n"
        f"Script variables: {json.dumps(payload.get('env') or {})}\n\n"
        f"--- {(payload.get('shell') or 'powershell').upper()} script (ran as SYSTEM) ---\n"
        f"{(payload.get('content') or '(not a script job)')[:6000]}\n\n"
        "--- Output ---\n"
        f"{(job['output'] or '(no output)')[:6000]}\n\n"
        "Explain in 2-4 short paragraphs: (1) what failed and why, "
        "(2) the most likely fix, (3) how to verify it worked. Be specific and practical."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 6000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {
        "ok": True,
        "analysis": text,
        "provider": AI_PROVIDERS[cfg["provider"]]["label"],
        "model": cfg["model"] or "endpoint-defined deployment",
    }


def _fleet_snapshot(conn) -> dict:
    """Compact, provider-safe fleet summary reused by the AI features.
    Only aggregate counts + a bounded list of problem devices — never the
    whole fleet, to keep prompts small and cheap."""
    now = time.time()
    rows = conn.execute(
        """SELECT a.id, a.hostname, a.os_version, a.last_seen, a.org_id,
                  a.reboot_required, a.smart_failures, a.ext_inventory,
                  o.name AS org_name
           FROM agents a LEFT JOIN orgs o ON o.id=a.org_id"""
    ).fetchall()
    incidents = conn.execute(
        """SELECT a.hostname, o.name AS org_name, i.incident_type, i.severity, i.message
           FROM monitor_incidents i
           LEFT JOIN agents a ON a.id=i.agent_id
           LEFT JOIN orgs o ON o.id=i.org_id
           WHERE i.status='open' ORDER BY i.severity, i.first_seen DESC LIMIT 60"""
    ).fetchall()
    total = len(rows)
    online = sum(1 for r in rows if (now - float(r["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS)
    reboots = sum(1 for r in rows if r["reboot_required"])
    smart = sum(1 for r in rows if (r["smart_failures"] or 0) > 0)
    open_inc = [{"host": r["hostname"], "customer": r["org_name"] or "Unassigned",
                 "type": r["incident_type"], "severity": r["severity"],
                 "detail": (r["message"] or "")[:120]} for r in incidents]
    return {
        "total_devices": total, "online": online, "offline": total - online,
        "reboots_pending": reboots, "smart_failures": smart,
        "open_incident_count": len(open_inc), "open_incidents": open_inc,
        "generated_at": time.strftime("%Y-%m-%d %H:%M"),
    }


def _backups_snapshot(conn) -> dict:
    """Fleet backup posture counts + the actual problem devices."""
    now = time.time()
    global_pol = get_policy(conn)
    org_pol: dict = {}
    rows = conn.execute(
        """SELECT a.id, a.hostname, a.org_id, a.ext_inventory, o.name AS org_name
           FROM agents a LEFT JOIN orgs o ON o.id=a.org_id"""
    ).fetchall()
    counts = {"ok": 0, "stale": 0, "failing": 0, "none": 0}
    problems = []
    for r in rows:
        if r["org_id"] not in org_pol:
            org_pol[r["org_id"]] = effective_policy(conn, r["org_id"]) if r["org_id"] else global_pol
        threshold = max(1, int(org_pol[r["org_id"]].get("backup_stale_days") or 3))
        try:
            ext = json.loads(r["ext_inventory"] or "{}")
        except (ValueError, TypeError):
            ext = {}
        products = ext.get("backup") if isinstance(ext.get("backup"), list) else []
        best, fail = None, None
        for p in products:
            if not isinstance(p, dict):
                continue
            ls, lf = str(p.get("last_success") or ""), str(p.get("last_failure") or "")
            if ls and (best is None or ls > best):
                best = ls
            if lf and (fail is None or lf > fail):
                fail = lf
        if not products:
            state = "none"
        elif fail and (not best or fail > best):
            state = "failing"
        elif best is None:
            state = "stale"
        else:
            try:
                age = (now - time.mktime(time.strptime(best, "%Y-%m-%d %H:%M"))) / 86400
                state = "stale" if age > threshold else "ok"
            except (ValueError, OverflowError):
                state = "stale"
        counts[state] = counts.get(state, 0) + 1
        if state in ("failing", "stale"):
            problems.append({"host": r["hostname"], "customer": r["org_name"] or "Unassigned",
                             "state": state, "last_success": best or "never"})
    return {"counts": counts, "problems": problems[:40]}


@app.post("/api/ai/fleet-briefing")
def ai_fleet_briefing(request: Request):
    """A prioritized, plain-English 'what needs attention across the fleet'
    briefing. Advisory; reads aggregate state only."""
    require_admin(request)
    with db() as conn:
        cfg = get_ai(conn)
        if not _ai_ready(cfg):
            raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
        fleet = _fleet_snapshot(conn)
        backups = _backups_snapshot(conn)
    prompt = (
        "You are the lead technician for an MSP, writing the morning fleet briefing for the team.\n"
        f"Fleet snapshot ({fleet['generated_at']}):\n{json.dumps(fleet)}\n\n"
        f"Backups: {json.dumps(backups)}\n\n"
        "Write a SHORT prioritized briefing: the 3-6 things that actually need action today, most "
        "urgent first, each as one line naming the device/customer and why it matters. Group trivial "
        "or report-only noise into a single dismissive line. No preamble, no headings, no restating the "
        "totals back. Under ~200 words. If nothing is urgent, say so plainly."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 6000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}")
    audit(request, "ai_fleet_briefing", "", f"{fleet['open_incident_count']} incidents")
    return {"ok": True, "briefing": text, "snapshot": {"fleet": fleet, "backups": backups},
            "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or ""}


@app.post("/api/ai/customer-report")
async def ai_customer_report(request: Request):
    """Plain-English monthly summary for one customer — QBR narration."""
    require_admin(request)
    body = await request.json()
    try:
        org_id = int(body.get("org_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="org_id required")
    now = time.time()
    with db() as conn:
        cfg = get_ai(conn)
        if not _ai_ready(cfg):
            raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
        org = conn.execute("SELECT id, name FROM orgs WHERE id=?", (org_id,)).fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="Unknown customer")
        devs = conn.execute(
            """SELECT a.id, a.hostname, a.os_version, a.last_seen, a.reboot_required,
                      a.smart_failures, a.ext_inventory, a.bdgz_protected
               FROM agents a WHERE a.org_id=?""", (org_id,)).fetchall()
        pol = effective_policy(conn, org_id)
        stale_days = max(1, int(pol.get("backup_stale_days") or 3))
        # resolved incidents in the last 30 days = work done for the customer
        resolved = conn.execute(
            """SELECT COUNT(*) c FROM monitor_incidents i
               JOIN agents a ON a.id=i.agent_id
               WHERE a.org_id=? AND i.status='resolved' AND i.resolved_at > ?""",
            (org_id, now - 30 * 86400)).fetchone()["c"]
        open_now = conn.execute(
            """SELECT COUNT(*) c FROM monitor_incidents i
               JOIN agents a ON a.id=i.agent_id
               WHERE a.org_id=? AND i.status='open'""", (org_id,)).fetchone()["c"]
    total = len(devs)
    online = sum(1 for d in devs if (now - float(d["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS)
    protected = sum(1 for d in devs if d["bdgz_protected"] == 1)
    smart = sum(1 for d in devs if (d["smart_failures"] or 0) > 0)
    backup_ok = 0
    for d in devs:
        try:
            ext = json.loads(d["ext_inventory"] or "{}")
            if any(isinstance(p, dict) and p.get("last_success") for p in (ext.get("backup") or [])):
                backup_ok += 1
        except (ValueError, TypeError):
            pass
    facts = {"customer": org["name"], "devices": total, "online_now": online,
             "endpoint_protection_ok": protected, "with_recent_backup": backup_ok,
             "drives_flagged": smart, "incidents_resolved_30d": resolved,
             "incidents_open_now": open_now, "period": "last 30 days"}
    prompt = (
        "You are an MSP account manager writing the monthly summary a NON-TECHNICAL business owner will "
        "read. Base it ONLY on these facts:\n" + json.dumps(facts) + "\n\n"
        "Write 2-3 short paragraphs, warm and plain-English, framing the numbers as the value we "
        "provided: coverage, protection, problems we caught and fixed. Mention specifics (e.g. a flagged "
        "drive we're watching) only if the numbers support it. No jargon, no bullet lists, no headings, "
        "no invented facts. End with one forward-looking sentence. Under ~220 words."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 6000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}")
    audit(request, "ai_customer_report", org["name"], f"{total} devices")
    return {"ok": True, "report": text, "facts": facts,
            "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or ""}


@app.post("/api/ai/fleet-query")
async def ai_fleet_query(request: Request):
    """Answer a natural-language question about the fleet from a compact,
    server-built data table. AI reads the data we hand it — it does not
    query the database itself."""
    require_admin(request)
    body = await request.json()
    question = str(body.get("question") or "").strip()
    if len(question) < 3:
        raise HTTPException(status_code=400, detail="Ask a question about the fleet.")
    now = time.time()
    with db() as conn:
        cfg = get_ai(conn)
        if not _ai_ready(cfg):
            raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
        rows = conn.execute(
            """SELECT a.id, a.hostname, a.os_version, a.last_seen, a.reboot_required,
                      a.smart_failures, a.bdgz_protected, a.ext_inventory,
                      o.name AS org_name,
                      (SELECT COUNT(*) FROM updates u
                       WHERE u.agent_id=a.id AND u.status IN ('pending','failed')) AS pending_cnt
               FROM agents a LEFT JOIN orgs o ON o.id=a.org_id
               ORDER BY o.name, a.hostname"""
        ).fetchall()
    table = []
    for r in rows:
        try:
            ext = json.loads(r["ext_inventory"] or "{}")
        except (ValueError, TypeError):
            ext = {}
        backup_ok = any(isinstance(p, dict) and p.get("last_success") for p in (ext.get("backup") or []))
        table.append({
            "host": r["hostname"], "customer": r["org_name"] or "Unassigned",
            "os": r["os_version"], "online": (now - float(r["last_seen"] or 0)) < OFFLINE_AFTER_SECONDS,
            "reboot_pending": bool(r["reboot_required"]),
            "smart_fail": (r["smart_failures"] or 0) > 0,
            "bitdefender": ("yes" if r["bdgz_protected"] == 1 else "no" if r["bdgz_protected"] == 0 else "unknown"),
            "pending_updates": r["pending_cnt"] or 0,
            "recent_backup": backup_ok,
        })
    prompt = (
        "You answer questions about an MSP's Windows fleet using ONLY the JSON table provided. "
        "Each row is one device. Do not invent devices or fields.\n\n"
        f"QUESTION: {question[:400]}\n\n"
        f"DEVICES ({len(table)}):\n{json.dumps(table)}\n\n"
        "Answer concisely. If the answer is a list of devices, give host + customer, one per line. "
        "If nothing matches, say so. If the question can't be answered from these fields, say which "
        "field is missing. No preamble. Under ~180 words."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 6000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}")
    audit(request, "ai_fleet_query", question[:80], f"{len(table)} devices")
    return {"ok": True, "answer": text, "device_count": len(table),
            "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or ""}


@app.post("/api/ai/patch-risk")
def ai_patch_risk(request: Request):
    """Summarize the actionable pending updates into approve-now vs hold,
    using stance + failure history as risk signals. Advisory."""
    require_admin(request)
    with db() as conn:
        cfg = get_ai(conn)
        if not _ai_ready(cfg):
            raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
        rows = conn.execute(
            """SELECT u.update_id, u.kb, u.title, u.severity, u.status,
                      u.category AS worker_class, u.browse_only, COUNT(*) AS device_hits,
                      SUM(CASE WHEN u.status='failed' THEN 1 ELSE 0 END) AS failures
               FROM updates u
               WHERE u.status IN ('pending','failed')
               GROUP BY COALESCE(NULLIF(u.kb,''), u.title)
               ORDER BY device_hits DESC LIMIT 80"""
        ).fetchall()
        global_pol = get_policy(conn)
    items = []
    for r in rows:
        stance = policy_category_stance(global_pol, {"category": r["worker_class"], "browse_only": r["browse_only"]})
        if stance == "report":
            continue  # report-only noise: not actionable, skip
        items.append({"kb": r["kb"] or "", "title": (r["title"] or "")[:90],
                      "severity": r["severity"] or "Unspecified", "stance": stance,
                      "devices": r["device_hits"], "failures": r["failures"] or 0})
    if not items:
        return {"ok": True, "summary": "No actionable pending updates right now — everything pending is report-only.",
                "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or ""}
    prompt = (
        "You are an MSP patch manager triaging this week's ACTIONABLE Windows updates (report-only driver "
        "noise already excluded). For each, decide approve-now vs hold-and-review.\n\n"
        f"UPDATES:\n{json.dumps(items)}\n\n"
        "Give: (1) one line saying how many are routine/safe to approve; (2) a short list of any you'd "
        "HOLD, each with a one-line reason (high device count + failures already seen, driver/firmware, "
        "or unusual). Security updates with no failures are normally safe. No preamble, no headings. "
        "Under ~180 words."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 6000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}")
    audit(request, "ai_patch_risk", "", f"{len(items)} actionable")
    return {"ok": True, "summary": text, "actionable_count": len(items),
            "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or ""}


@app.post("/api/ai/generate-script")
async def ai_generate_script(request: Request):
    """Draft a script from a plain-English task. Returns code only — the
    technician reviews and saves/runs it. AI never executes anything."""
    require_admin(request)
    body = await request.json()
    task = str(body.get("task") or "").strip()
    shell = str(body.get("shell") or "powershell").strip().lower()
    if shell not in ("powershell", "cmd", "bash"):
        shell = "powershell"
    if len(task) < 4:
        raise HTTPException(status_code=400, detail="Describe the task (a sentence or two).")
    with db() as conn:
        cfg = get_ai(conn)
    if not _ai_ready(cfg):
        raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
    shell_ctx = {
        "powershell": "Windows PowerShell 5.1, running as SYSTEM via Task Scheduler on Windows 10/11 and Server",
        "cmd": "Windows CMD/batch, running as SYSTEM",
        "bash": "bash on Windows (Git Bash/WSL) — assume it may be absent",
    }[shell]
    prompt = (
        "You are helping an MSP technician write a remote administration script for their RMM.\n"
        f"Target shell/runtime: {shell_ctx}.\n"
        "The script runs unattended as SYSTEM with no interactive user. It must not prompt, "
        "must be idempotent where reasonable, should log what it does, and should exit non-zero on failure.\n"
        "Avoid destructive actions unless explicitly requested; never include credentials.\n\n"
        f"TASK: {task[:2000]}\n\n"
        "Return ONLY the script code, no explanation and no markdown fences. Start with a short comment "
        "block stating what it does and any assumptions."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 6000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}")
    # Strip accidental markdown fences if the model added them anyway.
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines)
    audit(request, "ai_generate_script", shell, task[:120])
    return {"ok": True, "shell": shell, "script": cleaned,
            "provider": AI_PROVIDERS[cfg["provider"]]["label"],
            "model": cfg["model"] or "endpoint-defined deployment"}


@app.post("/api/ai/advise-incident")
async def ai_advise_incident(request: Request):
    """Advise on active incidents *or* recent seven-day storage history.

    The model may choose only from existing Script Library candidates supplied
    by OpenPrimeRMM. No AI-authored code is executed by this endpoint.
    """
    require_admin(request)
    body = await request.json()
    agent_id = str(body.get("agent_id") or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id required")
    with db() as conn:
        cfg = get_ai(conn)
        if not _ai_ready(cfg):
            raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
        health = _ai_health_context(conn, agent_id)
        if not health:
            raise HTTPException(status_code=404, detail="Unknown machine")
        a = health["agent"]
        incidents = health["incidents"]
        recent = health["recent_storage"]
        candidates = _ai_candidate_scripts(conn, health["incident_types"])
        latest_run = conn.execute(
            """SELECT ar.job_id, ar.script_id, ar.created_at, ar.assessed_at, ar.assessment,
                      j.status, j.exit_code, j.finished_at, s.name AS script_name
               FROM ai_remediation_runs ar
               LEFT JOIN jobs j ON j.id=ar.job_id
               LEFT JOIN scripts s ON s.id=ar.script_id
               WHERE ar.agent_id=? ORDER BY ar.created_at DESC LIMIT 1""",
            (agent_id,),
        ).fetchone()

    if not incidents and not recent:
        return {
            "ok": True,
            "advice": "No active health incidents or recent storage warnings are present on this device.",
            "recommendation": None,
            "latest_remediation": dict(latest_run) if latest_run else None,
            "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or "",
        }

    try:
        ext = json.loads(a["ext_inventory"] or "{}")
    except (ValueError, TypeError):
        ext = {}
    try:
        de = json.loads(a["disk_events"] or "{}")
        disk_error_count = de.get("count") if isinstance(de, dict) else None
    except (ValueError, TypeError):
        disk_error_count = None

    open_lines = "\n".join(
        f"- [{i['severity']}] {i['incident_type']}: {i['message']} "
        f"(observed {i['value_text']}, threshold {i['threshold_text']})"
        for i in incidents
    ) or "- none"
    recent_lines = "- none"
    if recent:
        recent_lines = (
            f"- recent_storage_warning: {recent.get('message') or 'Disk I/O error'}; "
            f"detected={recent.get('first_seen')}; resolved={recent.get('resolved_at')}; "
            f"details={recent.get('value_text') or ''}; no active disk-I/O incident in the current 24h window"
        )
    context = {
        "os": a["os_version"], "reboot_required": bool(a["reboot_required"]),
        "smart_failures": a["smart_failures"], "disk_error_events_last_24h": disk_error_count,
        "uptime_hours": ext.get("uptime_hours"), "domain": ext.get("domain"),
    }
    candidate_lines = []
    allowed_ids = set()
    for script in candidates:
        summary = _ai_script_summary(script)
        allowed_ids.add(int(script["id"]))
        candidate_lines.append(
            f"- ID {script['id']}: {script['name']} | class={summary['safety_class']} | "
            f"risk={summary['risk']} | changes_system={summary['changes_system']} | "
            f"reboot={summary['reboot_impact']} | {script['description'] or ''}"
        )
    candidates_text = "\n".join(candidate_lines) or "- none"

    prompt = (
        "You are an MSP senior technician advising a technician through OpenPrimeRMM RMM. "
        "The machine may have active incidents or a recently-resolved storage warning that still requires verification.\n\n"
        f"Machine: {a['hostname']} ({a['os_version']})\n"
        f"Context: {json.dumps(context)}\n\n"
        f"Open incidents:\n{open_lines}\n\nRecent health history:\n{recent_lines}\n\n"
        "OpenPrimeRMM already has these APPROVED Script Library choices. Prefer a diagnostic script before a repair. "
        "You may recommend ONLY one ID from this list; do not invent a new script or command when an existing diagnostic covers the first step.\n"
        f"{candidates_text}\n\n"
        "Respond with: (1) the likely cause in one or two sentences; (2) at most four numbered steps; "
        "(3) mention the exact approved script name you want run first when appropriate. Keep it under about 180 words. "
        "At the very end add exactly [[SCRIPT_ID:N]] using one candidate ID, or [[SCRIPT_ID:none]] if no listed script should run. "
        "Do not put the marker in a code block."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 5000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI request failed: {exc}")

    match = re.search(r"\[\[SCRIPT_ID:(\d+|none)\]\]", text, flags=re.I)
    chosen_id = None
    if match and match.group(1).lower() != "none":
        try:
            parsed_id = int(match.group(1))
            if parsed_id in allowed_ids:
                chosen_id = parsed_id
        except ValueError:
            pass
    clean_text = re.sub(r"\s*\[\[SCRIPT_ID:(?:\d+|none)\]\]\s*$", "", text, flags=re.I).strip()
    # Provider formatting mistakes or an overly-conservative "none" must not
    # leave a real health warning without a useful next step. The candidate
    # mapping is deliberately diagnostic-first, so the fallback only exposes
    # an existing technician-approved Script Library item.
    if chosen_id is None and candidates:
        chosen_id = int(candidates[0]["id"])
    chosen = next((x for x in candidates if int(x["id"]) == chosen_id), None)
    recommendation = _ai_script_summary(chosen) if chosen else None

    audit(request, "ai_advise_incident", a["hostname"],
          f"{len(incidents)} open; recent_storage={bool(recent)}; script={chosen_id or 'none'}")
    return {
        "ok": True, "advice": clean_text,
        "recommendation": recommendation,
        "latest_remediation": dict(latest_run) if latest_run else None,
        "provider": AI_PROVIDERS[cfg["provider"]]["label"],
        "model": cfg["model"] or "endpoint-defined deployment",
    }


@app.post("/api/ai/run-remediation-script")
async def ai_run_remediation_script(request: Request):
    """Queue an AI-recommended *existing* Script Library item after tech approval."""
    require_admin(request)
    body = await request.json()
    agent_id = str(body.get("agent_id") or "").strip()
    try:
        script_id = int(body.get("script_id") or 0)
    except (TypeError, ValueError):
        script_id = 0
    if not agent_id or not script_id:
        raise HTTPException(status_code=400, detail="agent_id and script_id are required")
    with db() as conn:
        health = _ai_health_context(conn, agent_id)
        if not health:
            raise HTTPException(status_code=404, detail="Unknown machine")
        agent = health["agent"]
        if not agent["last_seen"] or time.time() - float(agent["last_seen"]) > OFFLINE_AFTER_SECONDS:
            raise HTTPException(status_code=409, detail="The device is offline; remediation was not queued")
        candidates = _ai_candidate_scripts(conn, health["incident_types"])
        script = next((x for x in candidates if int(x["id"]) == script_id), None)
        if not script:
            raise HTTPException(status_code=400, detail="That script is not an approved recommendation for the device's current health state")
        safety = (script["safety_class"] or "unclassified")
        if safety == "high_impact":
            raise HTTPException(status_code=400, detail="High-impact scripts must be opened and deployed manually from the Script Library")
        if safety in ("safe_remediation", "disruptive") and not body.get("confirmed"):
            raise HTTPException(status_code=409, detail="Technician confirmation is required for this remediation script")
        recent = health["recent_storage"]
        source_key = "recent-storage" if recent and not health["incidents"] else ",".join(
            str(i["dedupe_key"]) for i in health["incidents"][:5]
        )
        source_context = {
            "incident_types": health["incident_types"],
            "open_incidents": [dict(i) for i in health["incidents"][:10]],
            "recent_storage": recent,
        }
        job_id = _queue_ai_remediation_job(
            conn, agent=agent, script=script, source_type="technician_ai", source_key=source_key,
            source_context=source_context, variables=body.get("variables"), strict_variables=True,
        )
    audit(request, "ai_run_remediation", agent["hostname"], f"{script['name']} / {safety}")
    return {"ok": True, "job_id": job_id, "script": _ai_script_summary(script)}


@app.get("/api/ai/remediation-status/{agent_id}")
def ai_remediation_status(agent_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute(
            """SELECT ar.*, j.status, j.exit_code, j.output, j.finished_at,
                      s.name AS script_name, s.safety_class, s.changes_system, s.reboot_impact
               FROM ai_remediation_runs ar
               LEFT JOIN jobs j ON j.id=ar.job_id
               LEFT JOIN scripts s ON s.id=ar.script_id
               WHERE ar.agent_id=? ORDER BY ar.created_at DESC LIMIT 1""",
            (agent_id,),
        ).fetchone()
    if not row:
        return {"run": None}
    d = dict(row)
    d["output"] = str(d.get("output") or "")[:12000]
    return {"run": d}


@app.post("/api/ai/remediation-jobs/{job_id}/assess")
def ai_assess_remediation_job(job_id: str, request: Request):
    """Analyze the result of a previously queued AI-assisted library script."""
    require_admin(request)
    with db() as conn:
        cfg = get_ai(conn)
        if not _ai_ready(cfg):
            raise HTTPException(status_code=400, detail="AI integration is disabled or incomplete (Settings → Integrations)")
        row = conn.execute(
            """SELECT ar.*, j.status, j.exit_code, j.output, j.finished_at,
                      a.hostname, a.os_version, s.name AS script_name, s.description AS script_description,
                      s.safety_class, s.changes_system, s.reboot_impact
               FROM ai_remediation_runs ar
               JOIN jobs j ON j.id=ar.job_id
               JOIN agents a ON a.id=ar.agent_id
               LEFT JOIN scripts s ON s.id=ar.script_id
               WHERE ar.job_id=?""",
            (job_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown AI remediation job")
        if row["status"] not in ("done", "failed", "cancelled"):
            raise HTTPException(status_code=409, detail="The diagnostic is still queued or running")
        if row["assessment"] and not request.query_params.get("refresh"):
            return {
                "ok": True, "assessment": row["assessment"], "cached": True,
                "provider": AI_PROVIDERS[cfg["provider"]]["label"], "model": cfg["model"] or "",
            }
        health = _ai_health_context(conn, row["agent_id"])
        current_types = health["incident_types"] if health else []
        recent = health["recent_storage"] if health else None

    try:
        source_context = json.loads(row["source_context"] or "{}")
    except (ValueError, TypeError):
        source_context = {}
    prompt = (
        "You are an MSP senior technician reviewing the result of a OpenPrimeRMM-approved diagnostic/remediation script. "
        "Do not claim a disk or other hardware problem is repaired merely because the script exits successfully.\n\n"
        f"Machine: {row['hostname']} ({row['os_version']})\n"
        f"Script: {row['script_name']} | safety={row['safety_class']} | exit={row['exit_code']} | job_status={row['status']}\n"
        f"Original health context: {json.dumps(source_context, default=str)[:6000]}\n"
        f"Current incident types: {json.dumps(current_types)}\n"
        f"Current recent storage warning: {json.dumps(recent, default=str)[:2000]}\n\n"
        f"Script output:\n{(row['output'] or '(no output)')[:9000]}\n\n"
        "Give a concise post-run assessment: what the result proves, what it does NOT prove, and the next technician action. "
        "Use at most four short paragraphs or bullets. If hardware health is warning/failing, clearly recommend hardware inspection/replacement."
    )
    try:
        text = _ai_complete(cfg, prompt, max_tokens=min(cfg["max_tokens"], 4000))
    except AiProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    with db() as conn:
        conn.execute(
            "UPDATE ai_remediation_runs SET assessment=?, assessed_at=? WHERE job_id=?",
            (text, time.time(), job_id),
        )
    audit(request, "ai_assess_remediation", row["hostname"], row["script_name"] or job_id)
    return {
        "ok": True, "assessment": text, "cached": False,
        "provider": AI_PROVIDERS[cfg["provider"]]["label"],
        "model": cfg["model"] or "endpoint-defined deployment",
    }


# ===========================================================================
# Security: two-factor auth, audit log, login alerts
# ===========================================================================

@app.post("/api/2fa/setup")
def twofa_setup(request: Request):
    """Generate a new TOTP secret for the current user and return the
    otpauth:// URI (the dashboard renders it as a QR code). Not enabled until
    confirmed with a valid code."""
    user = current_user(request)
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    with db() as conn:
        conn.execute("UPDATE users SET totp_secret=?, totp_enabled=0 WHERE id=?",
                     (secret, user["uid"]))
    label = f"OpenPrime-RMM:{user['u']}"
    uri = f"otpauth://totp/{label}?secret={secret}&issuer=OpenPrime-RMM"
    return {"secret": secret, "uri": uri}


@app.post("/api/2fa/enable")
async def twofa_enable(request: Request):
    user = current_user(request)
    body = await request.json()
    with db() as conn:
        row = conn.execute("SELECT totp_secret FROM users WHERE id=?", (user["uid"],)).fetchone()
        if not row or not row["totp_secret"]:
            raise HTTPException(status_code=400, detail="Start setup first")
        if not totp_verify(row["totp_secret"], str(body.get("code", ""))):
            raise HTTPException(status_code=400, detail="That code didn't match — check your authenticator app")
        conn.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["uid"],))
    audit(request, "2fa_enabled", user["u"])
    return {"ok": True}


@app.post("/api/2fa/disable")
async def twofa_disable(request: Request):
    user = current_user(request)
    body = await request.json()
    with db() as conn:
        row = conn.execute("SELECT pw_hash FROM users WHERE id=?", (user["uid"],)).fetchone()
        if not verify_password(str(body.get("password", "")), row["pw_hash"]):
            raise HTTPException(status_code=403, detail="Password required to disable 2FA")
        conn.execute("UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (user["uid"],))
    audit(request, "2fa_disabled", user["u"])
    return {"ok": True}


@app.get("/api/audit")
def audit_log(request: Request, limit: int = 200):
    require_admin_role(request)
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                            (min(limit, 1000),)).fetchall()
    return {"entries": [dict(r) for r in rows]}


# ===========================================================================
# Software inventory + winget third-party patching
# ===========================================================================

WINGET_APPROVED_CATALOG = [
    {"id": "7zip.7zip", "name": "7-Zip", "category": "Utilities"},
    {"id": "VideoLAN.VLC", "name": "VLC media player", "category": "Media"},
    {"id": "Microsoft.PowerToys", "name": "Microsoft PowerToys", "category": "Utilities"},
    {"id": "Microsoft.VisualStudioCode", "name": "Visual Studio Code", "category": "Development"},
    {"id": "Git.Git", "name": "Git for Windows", "category": "Development"},
    {"id": "PuTTY.PuTTY", "name": "PuTTY", "category": "Remote access"},
    {"id": "WinSCP.WinSCP", "name": "WinSCP", "category": "Remote access"},
]


WINGET_SEARCH_SCRIPT = r"""# Search the endpoint's configured Winget community source without installing.
$ErrorActionPreference = 'Stop'
$wg = (Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1).FullName
if (-not $wg) { $wg = 'winget' }
try {
    $query = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:wingetQueryB64))
    $raw = @(& $wg search --query $query --source winget --count 50 --accept-source-agreements --disable-interactivity 2>&1)
    $lines = @($raw | ForEach-Object { [string]$_ })
    $separator = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*-{2,}\s+-{2,}') { $separator = $i; break }
    }
    if ($separator -lt 0) { throw 'Winget returned no parseable package table.' }
    $runs = @([regex]::Matches($lines[$separator], '-{2,}'))
    if ($runs.Count -lt 2) { throw 'Winget package table did not contain an ID column.' }
    $starts = @($runs | ForEach-Object { $_.Index })
    $items = @()
    for ($i = $separator + 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if (-not $line.Trim() -or $line.Length -le $starts[1]) { continue }
        $name = $line.Substring(0, $starts[1]).Trim()
        $idEnd = if ($starts.Count -gt 2) { [Math]::Min($starts[2], $line.Length) } else { $line.Length }
        $id = $line.Substring($starts[1], $idEnd - $starts[1]).Trim()
        if (-not $name -or $id -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{1,199}$') { continue }
        $version = ''
        if ($starts.Count -gt 2 -and $line.Length -gt $starts[2]) {
            $versionEnd = if ($starts.Count -gt 3) { [Math]::Min($starts[3], $line.Length) } else { $line.Length }
            $version = $line.Substring($starts[2], $versionEnd - $starts[2]).Trim()
        }
        $items += @{ name = $name; id = $id; version = $version; source = 'winget' }
    }
    $json = ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    Write-Output "PNC_WINGET_SEARCH_JSON:$encoded"
} catch {
    Write-Error "Winget search failed: $($_.Exception.Message)"
    exit 2
}
"""


WINGET_INSTALL_SCRIPT = r"""# Install one exact package from the Winget community source.
$ErrorActionPreference = 'Stop'
$wg = (Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1).FullName
if (-not $wg) { $wg = 'winget' }
$packageId = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:wingetPackageIdB64))
if ($packageId -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{1,199}$') { throw 'Invalid Winget package ID.' }
Write-Output "Installing Winget package $packageId ..."
& $wg install --id $packageId --exact --source winget --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | Out-String | Write-Output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "Winget installation completed for $packageId."
"""


@app.get("/api/winget/catalog")
def winget_catalog(request: Request):
    require_admin(request)
    return {"packages": WINGET_APPROVED_CATALOG}


def _winget_package_id(value) -> str:
    package_id = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{1,199}", package_id):
        raise HTTPException(status_code=400, detail="Invalid Winget package ID")
    return package_id

@app.get("/api/software")
def software_search(request: Request, q: str = ""):
    """Fleet-wide installed-software search. Returns (machine, program, version)
    rows matching the query."""
    require_admin(request)
    q = (q or "").strip().lower()
    out = []
    with db() as conn:
        rows = conn.execute(
            "SELECT id, hostname, software FROM agents WHERE software != '[]'").fetchall()
    for r in rows:
        try:
            progs = json.loads(r["software"] or "[]")
        except ValueError:
            continue
        for p in progs:
            name = str(p.get("name", ""))
            if not q or q in name.lower():
                out.append({"agent_id": r["id"], "hostname": r["hostname"],
                            "name": name, "version": str(p.get("version", "")),
                            "publisher": str(p.get("publisher", ""))})
    out.sort(key=lambda x: (x["name"].lower(), x["hostname"].lower()))
    return {"software": out[:2000], "truncated": len(out) > 2000}


WINGET_UPGRADE_SCRIPT = r"""# Upgrade third-party apps via winget (runs as SYSTEM).
$ErrorActionPreference = 'Continue'
$wg = (Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1).FullName
if (-not $wg) { $wg = 'winget' }
$ids = $env:wingetIds
$names = @()
if ($env:wingetNamesB64 -and $env:wingetNamesB64 -ne 'null') {
    try {
        $namesJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:wingetNamesB64))
        $names = @($namesJson | ConvertFrom-Json)
    } catch {
        Write-Error "Selected application list could not be decoded: $($_.Exception.Message)"
        exit 2
    }
}
if ($names.Count -gt 0) {
    foreach ($name in $names) {
        $name = [string]$name; if (-not $name.Trim()) { continue }
        Write-Output "Upgrading selected application: $name ..."
        & $wg upgrade --name $name --exact --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | Out-String | Write-Output
    }
} elseif ($ids -and $ids -ne 'null') {
    foreach ($id in ($ids -split ',')) {
        $id = $id.Trim(); if (-not $id) { continue }
        Write-Output "Upgrading $id ..."
        & $wg upgrade --id $id --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | Out-String | Write-Output
    }
} else {
    Write-Output 'Upgrading ALL eligible apps...'
    & $wg upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 | Out-String | Write-Output
}
Write-Output 'winget upgrade complete.'
"""


@app.get("/api/machines/{agent_id}/software")
def machine_software(agent_id: str, request: Request):
    """Return a device's installed-software inventory for technician selection."""
    require_admin(request)
    with db() as conn:
        row = conn.execute(
            "SELECT hostname, software FROM agents WHERE id=?", (agent_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Unknown machine")
    try:
        raw = json.loads(row["software"] or "[]")
    except (ValueError, TypeError):
        raw = []
    apps = []
    seen = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        key = name.casefold()
        if not name or key in seen:
            continue
        seen.add(key)
        apps.append({
            "name": name[:300],
            "installed_version": str(item.get("version") or "")[:128],
            "publisher": str(item.get("publisher") or "")[:300],
        })
    apps.sort(key=lambda item: item["name"].casefold())
    return {"hostname": row["hostname"], "software": apps[:1000]}


@app.post("/api/machines/{agent_id}/winget-upgrade")
async def winget_upgrade(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json()
    ids = ",".join(str(x).strip() for x in (body.get("ids") or []) if str(x).strip())
    raw_names = body.get("names") or []
    if not isinstance(raw_names, list):
        raise HTTPException(status_code=400, detail="Application names must be a list")
    names = []
    seen_names = set()
    for value in raw_names:
        name = str(value).strip()
        key = name.casefold()
        if not name or key in seen_names:
            continue
        if len(name) > 300:
            raise HTTPException(status_code=400, detail="Application name is too long")
        seen_names.add(key)
        names.append(name)
    if len(names) > 100:
        raise HTTPException(status_code=400, detail="Select no more than 100 applications")
    names_b64 = base64.b64encode(json.dumps(names).encode("utf-8")).decode("ascii") if names else "null"
    with db() as conn:
        a = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        payload = json.dumps({"name": "winget upgrade", "content": WINGET_UPGRADE_SCRIPT,
                              "timeout_sec": 3600, "env": {
                                  "wingetIds": ids or "null", "wingetNamesB64": names_b64}})
        selection = f"selected {len(names)}" if names else (ids or "all")
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, status, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), agent_id, "run_script",
             f"winget upgrade ({selection})",
             payload, "pending", time.time()))
    audit(request, "winget_upgrade", a["hostname"], selection)
    return {"ok": True}


@app.post("/api/machines/{agent_id}/winget-search")
async def winget_search(agent_id: str, request: Request):
    """Queue a read-only search against the selected endpoint's Winget source."""
    require_admin(request)
    body = await request.json()
    query = str(body.get("query") or "").strip()
    if len(query) < 2:
        raise HTTPException(status_code=400, detail="Enter at least two characters")
    if len(query) > 100:
        raise HTTPException(status_code=400, detail="Winget search is limited to 100 characters")
    job_id = str(uuid.uuid4())
    encoded = base64.b64encode(query.encode("utf-8")).decode("ascii")
    payload = json.dumps({
        "name": "winget search", "content": WINGET_SEARCH_SCRIPT,
        "timeout_sec": 180, "env": {"wingetQueryB64": encoded},
    })
    with db() as conn:
        agent = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, status, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (job_id, agent_id, "run_script", f"winget search ({query[:48]})",
             payload, "pending", time.time()),
        )
    _nudge_agents[agent_id] = time.time() + 180
    _wake_agent(agent_id)
    audit(request, "winget_search", agent["hostname"], query)
    return {"ok": True, "job_id": job_id}


@app.post("/api/machines/{agent_id}/winget-install")
async def winget_install(agent_id: str, request: Request):
    """Queue one exact-ID install after the dashboard's explicit confirmation."""
    require_admin(request)
    body = await request.json()
    package_id = _winget_package_id(body.get("package_id"))
    source = str(body.get("source") or "live").strip().lower()
    if source not in ("approved", "live"):
        raise HTTPException(status_code=400, detail="Invalid Winget catalog source")
    if source == "approved" and package_id.casefold() not in {
        p["id"].casefold() for p in WINGET_APPROVED_CATALOG
    }:
        raise HTTPException(status_code=400, detail="Package is not in the approved catalog")
    job_id = str(uuid.uuid4())
    encoded = base64.b64encode(package_id.encode("utf-8")).decode("ascii")
    payload = json.dumps({
        "name": "winget install", "content": WINGET_INSTALL_SCRIPT,
        "timeout_sec": 3600, "env": {"wingetPackageIdB64": encoded},
    })
    with db() as conn:
        agent = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, status, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (job_id, agent_id, "run_script", f"winget install ({package_id})",
             payload, "pending", time.time()),
        )
    _nudge_agents[agent_id] = time.time() + 180
    _wake_agent(agent_id)
    audit(request, "winget_install", agent["hostname"], f"{source}: {package_id}")
    return {"ok": True, "job_id": job_id}


# ===========================================================================
# Service monitors
# ===========================================================================

@app.get("/api/machines/{agent_id}/monitors")
def list_monitors(agent_id: str, request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute("SELECT * FROM service_monitors WHERE agent_id=? ORDER BY service_name",
                            (agent_id,)).fetchall()
    return {"monitors": [dict(r) for r in rows]}


@app.post("/api/machines/{agent_id}/monitors")
async def add_monitor(agent_id: str, request: Request):
    require_admin(request)
    body = await request.json()
    name = str(body.get("service_name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail="Service name required")
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Unknown machine")
        conn.execute(
            "INSERT INTO service_monitors (agent_id, service_name, auto_restart, created_at)"
            " VALUES (?,?,?,?)",
            (agent_id, name, 1 if body.get("auto_restart", True) else 0, time.time()))
    audit(request, "monitor_add", agent_id, name)
    return {"ok": True}


@app.delete("/api/monitors/{monitor_id}")
def del_monitor(monitor_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        conn.execute("DELETE FROM service_monitors WHERE id=?", (monitor_id,))
    return {"ok": True}


# ===========================================================================
# AI daily digest
# ===========================================================================

def build_digest_facts() -> dict:
    now = time.time()
    with db() as conn:
        agents = conn.execute("SELECT * FROM agents").fetchall()
        offline = [a["hostname"] for a in agents if a["last_seen"] and now - a["last_seen"] > 24 * 3600]
        hw = []
        incidents = conn.execute(
            "SELECT computer_name, threat FROM av_events WHERE received_at > ? ORDER BY id DESC LIMIT 20",
            (now - 86400,)).fetchall()
        pend = conn.execute(
            """SELECT o.name AS org, COUNT(*) AS n FROM updates u
               JOIN agents a ON a.id=u.agent_id LEFT JOIN orgs o ON o.id=a.org_id
               WHERE u.status='pending' GROUP BY o.id ORDER BY n DESC""").fetchall()
        for a in agents:
            try:
                dh = json.loads(a["disk_health"] or "[]")
            except ValueError:
                dh = []
            bad = [d for d in dh if isinstance(d, dict)
                   and str(d.get("health", "")).lower() not in ("healthy", "")]
            if bad or (a["smart_failures"] or 0):
                hw.append(a["hostname"])
    return {
        "offline": offline,
        "hardware_warnings": hw,
        "incidents": [{"machine": r["computer_name"], "threat": r["threat"]} for r in incidents],
        "pending_updates_by_customer": [{"customer": r["org"] or "Unassigned", "count": r["n"]} for r in pend],
    }


@app.post("/api/digest/run")
def run_digest(request: Request):
    require_admin_role(request)
    return _send_digest(force=True)


def _send_digest(force: bool = False) -> dict:
    with db() as conn:
        acfg = get_alerts(conn)
        aicfg = get_ai(conn)
    if not acfg.get("webhook_url"):
        raise HTTPException(status_code=400, detail="Configure a Discord webhook first")
    facts = build_digest_facts()
    text = None
    if _ai_ready(aicfg):
        prompt = ("You are an MSP operations assistant. Write a concise morning digest "
                  "for technicians from this JSON of overnight fleet status. Lead with "
                  "anything urgent. 4-8 short lines, plain text, no preamble.\n\n"
                  + json.dumps(facts))
        try:
            text = _ai_complete(aicfg, prompt, max_tokens=min(aicfg["max_tokens"], 600))
        except AiProviderError:
            text = None
    if not text:   # fallback: plain summary without AI
        lines = []
        if facts["offline"]:
            lines.append(f"🔴 Offline >24h: {', '.join(facts['offline'][:10])}")
        if facts["hardware_warnings"]:
            lines.append(f"💽 Disk warnings: {', '.join(facts['hardware_warnings'][:10])}")
        if facts["incidents"]:
            lines.append(f"🦠 {len(facts['incidents'])} security detection(s) overnight")
        for pu in facts["pending_updates_by_customer"][:5]:
            lines.append(f"🔧 {pu['customer']}: {pu['count']} pending update(s)")
        text = "\n".join(lines) or "✅ All quiet — nothing needs attention."
    send_discord(acfg["webhook_url"], "📋 Morning fleet digest", text, color=0x5865F2)
    return {"ok": True, "digest": text}


# ===========================================================================
# Support requests (systray "Request support" form) + SMTP email
# ===========================================================================

import smtplib
from email.mime.text import MIMEText


def get_smtp(conn) -> dict:
    row = conn.execute("SELECT value FROM settings WHERE key='smtp'").fetchone()
    cfg = {}
    if row:
        try:
            cfg = json.loads(row["value"])
        except ValueError:
            cfg = {}
    for k, v in [("host", ""), ("port", 587), ("tls", True), ("username", ""),
                 ("password", ""), ("from_addr", ""), ("to_addr", "")]:
        cfg.setdefault(k, v)
    return cfg


def send_email_strict(cfg: dict, subject: str, body: str, to_addr: str = "",
                      attachment: tuple = None) -> tuple:
    """Send a plain-text email via the configured SMTP relay. Returns (ok, detail).
    attachment, if given, is (filename, mime_type, raw_bytes)."""
    to_addr = to_addr or cfg.get("to_addr", "")
    if not cfg.get("host") or not to_addr:
        return False, "SMTP host and destination address must be configured"
    from_addr = cfg.get("from_addr") or cfg.get("username") or "rmm@localhost"
    if attachment:
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders
        msg = MIMEMultipart()
        msg.attach(MIMEText(body, "plain", "utf-8"))
        fname, fmime, fbytes = attachment
        maintype, _, subtype = (fmime or "application/octet-stream").partition("/")
        part = MIMEBase(maintype or "application", subtype or "octet-stream")
        part.set_payload(fbytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment", filename=fname)
        msg.attach(part)
    else:
        msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(cfg["host"], int(cfg.get("port") or 587), timeout=20) as s:
            s.ehlo()
            if cfg.get("tls", True):
                s.starttls()
                s.ehlo()
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password", ""))
            s.sendmail(from_addr, [to_addr], msg.as_string())
        return True, f"sent to {to_addr}"
    except smtplib.SMTPAuthenticationError as e:
        return False, f"SMTP login rejected: {e.smtp_error.decode('utf-8','replace') if isinstance(e.smtp_error, bytes) else e.smtp_error}"
    except (smtplib.SMTPException, OSError) as e:
        return False, f"SMTP error: {e}"


def send_discord_file(webhook_url: str, content: str, filename: str,
                      file_bytes: bytes) -> bool:
    """Post a message with a file attachment (image) to Discord via multipart."""
    url = (webhook_url or "").strip()
    if not url.startswith("https://"):
        return False
    boundary = "----OpenPrimeBoundary" + secrets.token_hex(8)
    payload = json.dumps({"content": content[:1900], "username": "OpenPrime-RMM"})
    parts = []
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(b'Content-Disposition: form-data; name="payload_json"\r\n')
    parts.append(b"Content-Type: application/json\r\n\r\n")
    parts.append(payload.encode() + b"\r\n")
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'.encode())
    parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
    parts.append(file_bytes + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    data = b"".join(parts)
    try:
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                     "User-Agent": "OpenPrime-RMM RMM (webhook)"})
        urllib.request.urlopen(req, timeout=15)
        return True
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[support] discord file upload failed: {e}", flush=True)
        return False


@app.get("/api/integrations/smtp")
def smtp_config(request: Request):
    require_admin_role(request)
    with db() as conn:
        cfg = get_smtp(conn)
    return {"host": cfg["host"], "port": cfg["port"], "tls": cfg["tls"],
            "username": cfg["username"], "has_password": bool(cfg["password"]),
            "from_addr": cfg["from_addr"], "to_addr": cfg["to_addr"]}


@app.post("/api/integrations/smtp")
async def smtp_save(request: Request):
    require_admin_role(request)
    body = await request.json()
    with db() as conn:
        cfg = get_smtp(conn)
        cfg["host"] = str(body.get("host", cfg["host"])).strip()
        cfg["port"] = max(1, min(65535, int(body.get("port") or 587)))
        cfg["tls"] = bool(body.get("tls", True))
        cfg["username"] = str(body.get("username", cfg["username"])).strip()
        if body.get("password"):
            cfg["password"] = str(body["password"])
        cfg["from_addr"] = str(body.get("from_addr", cfg["from_addr"])).strip()
        cfg["to_addr"] = str(body.get("to_addr", cfg["to_addr"])).strip()
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('smtp', ?)",
                     (json.dumps(cfg),))
    return {"ok": True}


@app.post("/api/integrations/smtp/test")
def smtp_test(request: Request):
    require_admin_role(request)
    with db() as conn:
        cfg = get_smtp(conn)
    ok, detail = send_email_strict(
        cfg, "OpenPrime-RMM test email",
        "If you can read this, support-request emails are configured correctly.")
    if not ok:
        raise HTTPException(status_code=502, detail=detail)
    return {"ok": True, "detail": detail}


_support_rate: dict = {}   # agent_id -> [timestamps]


@app.post("/api/support-request")
async def support_request(request: Request):
    """Receives the tray form. Authenticated only by a valid agent_id (the tray
    runs in user sessions and must not hold the agent token) — rate-limited to
    prevent abuse."""
    body = await read_agent_json(request)
    agent_id = str(body.get("agent_id", ""))[:64]
    with db() as conn:
        a = conn.execute(
            """SELECT a.id, a.hostname, a.org_id, a.os_version, a.public_ip, a.local_ip,
                      o.name AS org_name, l.name AS loc_name
               FROM agents a LEFT JOIN orgs o ON o.id=a.org_id
               LEFT JOIN locations l ON l.id=a.location_id WHERE a.id=?""",
            (agent_id,)).fetchone()
    if not a:
        raise HTTPException(status_code=403, detail="Unknown device")
    now = time.time()
    times = [x for x in _support_rate.get(agent_id, []) if now - x < 3600]
    if len(times) >= 5:
        raise HTTPException(status_code=429, detail="Too many requests from this device — try later")
    times.append(now)
    _support_rate[agent_id] = times

    fields = {k: str(body.get(k, ""))[:300].strip()
              for k in ("first_name", "last_name", "email", "phone", "subject", "username")}
    text = str(body.get("body", ""))[:4000].strip()
    if not fields["subject"] and not text:
        raise HTTPException(status_code=400, detail="Empty request")

    # Optional attachment: base64 in "attach_data", with "attach_name"/"attach_mime".
    attach_bytes = None
    attach_name = ""
    attach_mime = ""
    raw_b64 = body.get("attach_data")
    if raw_b64:
        try:
            attach_bytes = base64.b64decode(str(raw_b64), validate=False)
        except Exception:
            attach_bytes = None
        if attach_bytes:
            if len(attach_bytes) > 10 * 1024 * 1024:      # 10 MB cap
                raise HTTPException(status_code=413, detail="Attachment too large (max 10 MB)")
            attach_name = (str(body.get("attach_name", "attachment"))[:120]
                           .replace("/", "_").replace("\\", "_").replace("..", "_"))
            attach_mime = str(body.get("attach_mime", ""))[:80] or "application/octet-stream"

    with db() as conn:
        cur = conn.execute(
            """INSERT INTO support_requests (ts, agent_id, hostname, org_id, first_name,
                 last_name, email, phone, subject, body, username, attach_name, attach_mime)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (now, agent_id, a["hostname"], a["org_id"], fields["first_name"],
             fields["last_name"], fields["email"], fields["phone"],
             fields["subject"], text, fields["username"], attach_name, attach_mime))
        req_id = cur.lastrowid
        conn.execute("""DELETE FROM support_requests WHERE id NOT IN
                        (SELECT id FROM support_requests ORDER BY id DESC LIMIT 5000)""")
        smtp_cfg = get_smtp(conn)
        acfg = get_alerts(conn)

    # Persist the attachment file on disk, keyed by request id
    if attach_bytes:
        try:
            adir = DATA_DIR / "support_attachments"
            adir.mkdir(parents=True, exist_ok=True)
            (adir / f"{req_id}_{attach_name}").write_bytes(attach_bytes)
        except Exception as e:
            print(f"[support] could not store attachment: {e}", flush=True)

    who = f"{fields['first_name']} {fields['last_name']}".strip() or fields["username"] or "someone"
    email_body = (
        f"New support request from {who}\n\n"
        f"First name: {fields['first_name']}\nLast name: {fields['last_name']}\n"
        f"Email: {fields['email']}\nPhone: {fields['phone']}\n"
        f"Subject: {fields['subject']}\n\nProblem description:\n{text}\n\n"
        f"--- Device ---\n"
        f"Device: {a['hostname']}\nSigned-in user: {fields['username']}\n"
        f"OS: {a['os_version']}\nPublic IP: {a['public_ip']}\nLocal IP: {a['local_ip']}\n"
        f"Customer: {a['org_name'] or 'Unassigned'}\nLocation: {a['loc_name'] or '-'}\n"
        f"Device ID: {a['id']}\n\nSent by {COMPANY_NAME} RMM tray."
    )
    if smtp_cfg.get("host") and smtp_cfg.get("to_addr"):
        try:
            att = (attach_name, attach_mime, attach_bytes) if attach_bytes else None
            ok, detail = send_email_strict(
                smtp_cfg, f"[Support] {fields['subject'] or 'New request'} — "
                          f"{who} @ {a['org_name'] or a['hostname']}", email_body,
                attachment=att)
            if not ok:
                print(f"[support] email failed: {detail}", flush=True)
        except Exception as e:
            print(f"[support] email crashed: {e}", flush=True)
    try:
        support_webhook = acfg.get("support_webhook_url") or acfg.get("webhook_url")
        if acfg.get("enabled") and support_webhook:
            msg = (f"📩 **Support request from {who}**\n"
                   f"**Subject:** {fields['subject']}\n**Device:** {a['hostname']}"
                   f" ({a['org_name'] or 'Unassigned'})\n**Contact:** {fields['email']}"
                   f" {fields['phone']}\n\n{text[:800]}")
            # If there's an image attachment, upload it with the message so it
            # shows inline in Discord; otherwise send the normal embed.
            if attach_bytes and attach_mime.startswith("image/"):
                if not send_discord_file(support_webhook, msg, attach_name, attach_bytes):
                    send_discord(support_webhook, f"📩 Support request from {who}",
                                 msg, color=0x5865F2)
            else:
                extra = f"\n\n📎 Attachment: {attach_name}" if attach_name else ""
                send_discord(support_webhook, f"📩 Support request from {who}",
                             f"**Subject:** {fields['subject']}\n**Device:** {a['hostname']}"
                             f" ({a['org_name'] or 'Unassigned'})\n**Contact:** {fields['email']}"
                             f" {fields['phone']}\n\n{text[:800]}{extra}", color=0x5865F2)
    except Exception:
        pass
    return {"ok": True}


@app.get("/api/support-requests/{req_id}/attachment")
def support_attachment(req_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT attach_name, attach_mime FROM support_requests WHERE id=?",
                           (req_id,)).fetchone()
    if not row or not row["attach_name"]:
        raise HTTPException(status_code=404, detail="No attachment")
    path = DATA_DIR / "support_attachments" / f"{req_id}_{row['attach_name']}"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Attachment file missing")
    return FileResponse(path, media_type=row["attach_mime"] or "application/octet-stream",
                        filename=row["attach_name"])


@app.get("/api/support-requests")
def list_support_requests(request: Request, limit: int = 100):
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            """SELECT s.*, o.name AS org_name FROM support_requests s
               LEFT JOIN orgs o ON o.id=s.org_id ORDER BY s.id DESC LIMIT ?""",
            (min(limit, 500),)).fetchall()
    return {"requests": [dict(r) for r in rows]}


@app.post("/api/support-requests/{req_id}/close")
def close_support_request(req_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        conn.execute("UPDATE support_requests SET status='closed' WHERE id=?", (req_id,))
    audit(request, "support_closed", str(req_id))
    return {"ok": True}


# ===========================================================================
# Wake-on-LAN (peer-relayed)
# ===========================================================================

def _online_cutoff() -> float:
    return time.time() - 11 * 60   # a machine seen in the last ~2 check-ins


@app.post("/api/machines/{agent_id}/wake")
def wake_machine(agent_id: str, request: Request):
    """Wake a sleeping machine by having an ONLINE agent at the same site
    broadcast the magic packet. Same site = same public IP (behind one NAT)
    and, when set, same customer/location."""
    require_admin(request)
    with db() as conn:
        target = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Unknown machine")
        try:
            macs = json.loads(target["macs"] or "[]")
        except ValueError:
            macs = []
        if not macs:
            raise HTTPException(status_code=400,
                                detail="No MAC address on record for this machine yet — it needs to "
                                       "check in at least once on the updated agent first.")
        cutoff = _online_cutoff()
        # Prefer a peer sharing public IP AND org; fall back to public IP only.
        peer = conn.execute(
            """SELECT * FROM agents
               WHERE id != ? AND last_seen > ? AND public_ip = ? AND public_ip != ''
                 AND (org_id IS ? OR ? IS NULL)
               ORDER BY last_seen DESC LIMIT 1""",
            (target["id"], cutoff, target["public_ip"], target["org_id"], target["org_id"])
        ).fetchone()
        if not peer:
            peer = conn.execute(
                """SELECT * FROM agents WHERE id != ? AND last_seen > ?
                     AND public_ip = ? AND public_ip != '' ORDER BY last_seen DESC LIMIT 1""",
                (target["id"], cutoff, target["public_ip"])).fetchone()
        if not peer:
            raise HTTPException(
                status_code=409,
                detail="No online machine found at the same site to send the wake signal. "
                       "Wake-on-LAN needs another agent powered on at that location.")
        payload = json.dumps({"macs": macs, "target_hostname": target["hostname"]})
        conn.execute(
            """INSERT INTO jobs (id, agent_id, type, label, payload, status, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), peer["id"], "wake",
             f"Wake {target['hostname']}", payload, "pending", time.time()))
    audit(request, "wake", target["hostname"], f"via {peer['hostname']}")
    return {"ok": True, "via": peer["hostname"], "queued": True}


# ===========================================================================
# Ad-hoc command runner (run a one-off command without saving a script)
# ===========================================================================

# Machines that should check in again quickly because a command is waiting.
# Populated when an ad-hoc command is queued; consulted (and cleared) on checkin.
_nudge_agents: dict = {}   # agent_id -> expiry timestamp

# --- Persistent long-poll ("live mode") ------------------------------------
# Each connected agent that is in live mode holds a /api/agent/poll request open.
# The handler waits on this per-agent asyncio.Event (NOT a DB connection, so one
# worker scales to the whole fleet). Queuing a job for an agent sets its event,
# waking the held request instantly; the agent then fetches and runs the job in
# ~1-2s. Events live only in memory - fine, because they're pure signals; the
# jobs themselves are durable in SQLite, so a server restart loses no work.
_live_events: dict = {}          # agent_id -> asyncio.Event
_live_event_loops: dict = {}     # agent_id -> loop that owns the Event
_live_connected: dict = {}       # agent_id -> last poll-connect timestamp (for UI)

def _register_live_event_loop(agent_id: str, loop: asyncio.AbstractEventLoop) -> None:
    _live_event_loops[agent_id] = loop

def _wake_agent(agent_id: str) -> None:
    """Signal the live poll on its owning event loop (including from workers)."""
    ev = _live_events.get(agent_id)
    loop = _live_event_loops.get(agent_id)
    if ev is not None and loop is not None:
        try:
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                current_loop = None
            if current_loop is not loop:
                loop.call_soon_threadsafe(ev.set)
                return
            ev.set()
        except RuntimeError:
            pass  # Closed loop: pending jobs remain durable for the next check-in.

def effective_live_mode(conn, agent_row) -> bool:
    """Resolve whether an agent should run in persistent long-poll mode.
    Precedence: per-machine override (live_mode 0/1) > per-org default > global
    off. NULL machine value means inherit."""
    try:
        mv = agent_row["live_mode"]
    except (KeyError, IndexError, TypeError):
        mv = None
    if mv is not None:
        return bool(mv)
    org_id = None
    try:
        org_id = agent_row["org_id"]
    except (KeyError, IndexError, TypeError):
        org_id = None
    if org_id:
        r = conn.execute("SELECT live_mode_default FROM orgs WHERE id=?", (org_id,)).fetchone()
        if r and r["live_mode_default"]:
            return True
    return False


@app.post("/api/machines/{agent_id}/run-command")
async def run_command(agent_id: str, request: Request):
    """Queue a one-off command in the chosen shell (powershell/cmd/bash) and
    nudge the machine to check in fast so output returns in seconds."""
    require_admin(request)
    body = await request.json()
    content = str(body.get("content", "")).strip()
    shell = str(body.get("shell", "powershell")).lower()
    if shell not in ("powershell", "cmd", "bash"):
        shell = "powershell"
    if not content:
        raise HTTPException(status_code=400, detail="Command is empty")
    if len(content) > 20000:
        raise HTTPException(status_code=400, detail="Command too long")
    with db() as conn:
        a = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not a:
            raise HTTPException(status_code=404, detail="Unknown machine")
        label = content.splitlines()[0][:60] if content else "command"
        payload = json.dumps({"name": f"[{shell}] {label}", "content": content,
                              "timeout_sec": int(body.get("timeout_sec") or 300),
                              "shell": shell})
        job_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO jobs (id, agent_id, type, label, payload, status, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (job_id, agent_id, "run_script", f"[{shell}] {label}", payload, "pending", time.time()))
    _nudge_agents[agent_id] = time.time() + 180     # ask for fast check-ins for 3 min
    _wake_agent(agent_id)                            # live-mode: fire instantly
    audit(request, "run_command", a["hostname"], f"{shell}: {label}")
    return {"ok": True, "job_id": job_id}
