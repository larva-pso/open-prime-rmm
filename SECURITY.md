# Security policy

OpenPrimeRMM can run administrative automation on managed Windows endpoints. Treat the server, database, backups, enrollment key, agent tokens, administrator sessions, and endpoint install folders as sensitive infrastructure.

OpenPrimeRMM is a community-source RMM project, not a magic security boundary. If an attacker already has local Administrator or SYSTEM on an endpoint, they can usually read, alter, or disable endpoint management software. OpenPrimeRMM's goal is to authenticate the control plane, reduce accidental exposure, make tampering harder, preserve auditability, and keep the endpoint recovery path alive.

## Built-in security controls

### Agent authentication

- Each enrolled endpoint receives a unique `AgentId` and randomly generated `AgentToken`.
- The shared enrollment key is used only for enrollment and repair enrollment. Existing agents authenticate with their own per-device token.
- Agent check-in, long-poll, and job-result APIs require `X-Agent-Id` and `X-Agent-Token` headers.
- The server stores only a SHA-256 hash of each agent token, not the raw token.
- Token verification uses constant-time comparison to avoid simple timing leaks.
- Invalid or missing agent credentials receive `401` responses and cannot retrieve queued jobs.

### Tenant-safe enrollment

- Reinstall/repair enrollment prefers a preserved `AgentId` when available.
- Hostname matching is scoped to the selected customer, not global across all tenants.
- Windows `MachineGuid` is used as a collision guard to prevent a copied or stale config from silently taking over a different Windows installation.
- Ambiguous duplicate hostnames or cross-customer identity conflicts are rejected instead of overwriting existing device records.
- The enrollment key can be rotated after onboarding waves without breaking already-enrolled agents.

### Endpoint local hardening

- Agent configuration is stored under `C:\ProgramData\OpenPrime\config.json`.
- The Windows installer locks the data directory ACL to SYSTEM and local Administrators so standard users cannot read the agent token.
- Program code is installed under `C:\Program Files\OpenPrime`.
- The scheduled task runs as SYSTEM intentionally because RMM work such as patching, software install, inventory, service recovery, and automation requires elevated privileges.
- The task launches Windows PowerShell by full system path and uses a generated command launcher instead of relying on user-writable paths.
- Temporary script/job staging is under the locked OpenPrime data directory, not under world-writable `%TEMP%` or `C:\Windows\Temp`.
- Script jobs have bounded execution time, output capture limits, and result reporting.
- Windows Update work is delegated to separate scheduled workers with hard timeouts so a hung Windows Update API call cannot strand the main check-in and recovery loop.

### Control-plane behavior

- Endpoints do not open an inbound listener for remote commands. Agents initiate outbound HTTPS requests to the server.
- Jobs are claimed only after the endpoint authenticates to the server.
- Pending jobs are marked running when claimed to reduce duplicate execution.
- Patch install jobs are rechecked at pickup time so newly denied updates are not handed to the endpoint by an older queued job.
- Job output is capped before upload to protect server storage and dashboard rendering.
- Operational API responses use no-store/no-cache headers to avoid stale security-sensitive state in browsers or proxies.

### Dashboard and administrator security

- Dashboard passwords are stored with PBKDF2-HMAC-SHA256 and per-password salts.
- Sessions and login challenges are HMAC-signed with the instance secret.
- Optional TOTP two-factor authentication is available for dashboard users.
- Login attempts are rate limited with an in-memory brake.
- Administrative actions are protected by role checks.
- The read-only Hermes/API integration is token-gated and intentionally excludes raw secrets, agent tokens, enrollment keys, dashboard sessions, and raw configs.

### Server install security

- The Linux installer creates a dedicated service user for the application.
- The installer generates unique per-instance secrets on first install instead of shipping shared default credentials.
- Instance secrets are written to `/etc/open-prime-rmm.env` with mode `600`.
- The systemd unit runs the app as the dedicated service user and includes basic hardening such as `NoNewPrivileges=true`, `ProtectSystem=full`, and a limited `ReadWritePaths` for application data.
- Optional Caddy configuration terminates public HTTPS and reverse-proxies to the local application listener.
- The installer preserves or rotates existing secrets explicitly on reinstall instead of silently replacing them.

## Recommended deployment controls

- Use HTTPS for all agent/server communication. Do not deploy production agents against plain HTTP.
- Put the dashboard behind VPN, a trusted IP allowlist, SSO/reverse-proxy access controls, or another administrative access boundary where practical.
- Enable TOTP 2FA for dashboard users.
- Use strong generated secrets and rotate the enrollment key after initial rollout.
- Store `/etc/open-prime-rmm.env` and `/opt/open-prime-rmm/server/data` backups securely.
- Do not publish logs, databases, environment files, agent configs, tokens, generated installers, or backup archives.
- Pilot endpoint-agent changes on a lab workstation and a lab server before broad deployment.
- Monitor job history, failed logins, offline alerts, and unexpected re-enrollment events.
- Treat server compromise as fleet compromise; isolate, rotate secrets, audit queued jobs, and redeploy agents if needed.

## Known limitations and hardening roadmap

OpenPrimeRMM currently uses a PowerShell scheduled-task agent for broad Windows compatibility and easy recovery. This is a practical control-plane design, but it is not the final hardened endpoint architecture.

Planned or recommended hardening work includes:

- signed scripts or signed native endpoint binaries
- MSI/native Windows service packaging with a guarded rollback path
- agent self-integrity checks for local script/config tampering
- stricter ACL validation during every agent run
- per-job signatures or server-issued job HMACs
- certificate pinning or stronger server identity validation options
- token rotation workflows for individual devices and fleets
- stronger tamper detection and alerting when install paths, scheduled tasks, or config ACLs change
- expanded audit trails for administrator actions and script execution
- optional network policy restrictions for dashboard and agent API paths

## Reporting vulnerabilities

Do not open a public issue for exploitable security bugs.

Report security issues privately to the project owner or maintainer. If no private contact is listed on the GitHub repository, open a minimal public issue asking for a private security contact without disclosing exploit details.

Please include:

- affected version or commit
- affected component
- impact
- reproduction steps
- suggested mitigation, if known
