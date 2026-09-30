# OpenPrimeRMM Endpoint Recovery Guide

## What we learned from the 1.15.0 incident

1. **A server rollback is not enough when an endpoint agent fails before check-in.** A broken agent cannot download its own rollback.
2. **Every endpoint release needs a pinned known-good recovery copy.** The recovery copy must be independent from the active `/downloads/agent.ps1` route.
3. **Device identity must be preserved during rollback.** Do not delete `C:\ProgramData\OpenPrime\config.json` during normal agent recovery.
4. **Use a fixed working folder.** Recovery tools use `C:\Windows\Temp\OpenPrimeRMM` instead of `%TEMP%`, because SYSTEM and interactive administrators have different TEMP paths.
5. **Task repair and agent-file repair are separate problems.** A task can report `Last Result: 0` while the installed agent file is still the wrong version.
6. **Endpoint-changing releases require a pilot.** Server/dashboard-only releases are lower risk; agent releases must be tested on a lab device and a small pilot before fleet rollout.
7. **Recovery must not depend on enrollment.** Re-enrollment can rotate identity tokens or create collisions. Recover the existing file and task first.

## Emergency workflow when many devices go offline after an agent release

1. Stop further rollout and deploy a server package that serves the last known-good agent.
2. Verify the server and public download route show the expected agent version.
3. On each affected endpoint, run **Stable Agent Recovery** from the Recovery Center.
4. Confirm the scheduled task runs as SYSTEM every minute.
5. Review `C:\ProgramData\OpenPrime\agent.log` for a recent successful check-in.
6. Collect diagnostics from any endpoint that remains offline.
7. Do not delete or re-enroll the device unless the local identity is actually missing or invalid.

## Tool selection

### Stable Agent Recovery
Use when the task runs but the endpoint remains offline after a bad agent release. It downloads the pinned stable agent, preserves `config.json`, repairs the launcher if needed, and starts the task.

### Scheduled Task Repair
Use when `OpenPrime RMM Agent` is missing, disabled, malformed, or cannot run. It does not download an agent and does not re-enroll the device.

### Diagnostics Collector
Use before deeper troubleshooting. It gathers task state, task XML, agent/tray versions and hashes, recent logs, connectivity results, event logs, and a redacted configuration. It intentionally excludes the agent token.

## Safety rules

- Run recovery tools as Administrator or SYSTEM.
- Use HTTPS.
- Do not share `config.json`; it contains the agent token.
- Do not delete `config.json` during rollback or task repair.
- Do not re-enroll merely because a device is offline.
- Keep Bitdefender exclusions narrow and verify quarantine before replacing files.
