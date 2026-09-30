# OpenPrimeRMM MSP Windows Workstation Script Pack

Pack version: `2026.08.02-v1`
Scripts: `28`

All scripts are added to the normal editable Script Library. Names are prefixed with `[MSP]` so the pack can be found quickly with Script Library search.

## Seeding behavior

- The pack is seeded once when OpenPrimeRMM 1.29.2 starts against an existing database.
- Existing scripts with the same name are never overwritten.
- The pack marker prevents duplicate scripts on later restarts.
- After the one-time seed, deleting a built-in script is respected; it is not recreated automatically.
- No agent or tray update is required.

## Script catalog

| Script | Risk | Timeout | Purpose |
|---|---|---:|---|
| [MSP] Workstation Health Summary | READ-ONLY | 180s | Read-only workstation snapshot: OS, uptime, CPU/RAM, disks, logged-on user, pending reboot, network, and key service state. |
| [MSP] Pending Reboot Check | READ-ONLY | 90s | Read-only check for Windows servicing, Windows Update, pending file rename, domain join, and computer rename reboot indicators. |
| [MSP] Network & DNS Diagnostics | READ-ONLY | 180s | Read-only network diagnostic: adapters, routes, DNS servers/cache, default gateway reachability, DNS resolution, and HTTPS connectivity. |
| [MSP] Test TCP Port | READ-ONLY | 120s | Tests DNS resolution and TCP connectivity to a technician-supplied host and port. |
| [MSP] Recent Critical Event Log Summary | READ-ONLY | 180s | Read-only summary of recent Critical/Error events from System and Application logs, grouped by provider and event ID. |
| [MSP] Automatic Services Not Running | READ-ONLY | 120s | Read-only audit of Automatic services that are currently stopped. Trigger-start and delayed-start behavior may make some findings normal. |
| [MSP] Top CPU & Memory Processes | READ-ONLY | 90s | Read-only snapshot of highest CPU-time and working-set processes, including PID and executable path where available. |
| [MSP] Disk & SMART Health | READ-ONLY | 180s | Read-only physical/logical disk health, storage reliability counters when available, and free-space summary. |
| [MSP] Local Administrators Audit | READ-ONLY | 120s | Read-only listing of members of the local Administrators group, including domain/AzureAD accounts when Windows resolves them. |
| [MSP] Security Posture Quick Audit | READ-ONLY | 180s | Read-only workstation security snapshot: Firewall, Defender registration/status, TPM, Secure Boot, BitLocker, SMBv1, UAC, and Remote Desktop state. |
| [MSP] BitLocker Status | READ-ONLY | 120s | Read-only BitLocker status for all volumes. Does not expose recovery passwords. |
| [MSP] Installed Software Inventory | READ-ONLY | 180s | Read-only installed application inventory from registry uninstall keys. Avoids Win32_Product and its repair side effects. |
| [MSP] Driver Problem Devices | READ-ONLY | 180s | Read-only list of Plug-and-Play devices reporting a non-zero ConfigManager error code, plus signed driver details where available. |
| [MSP] User Profile Disk Usage | READ-ONLY | 900s | Read-only size summary for local user profile folders. Useful for locating unusually large profiles before cleanup or migration. |
| [MSP] Windows Update History | READ-ONLY | 180s | Read-only installed hotfix/update history for the selected number of days. Does not initiate a Windows Update scan. |
| [MSP] Battery Health Summary | READ-ONLY | 180s | Read-only laptop battery status and Windows battery-report location. Desktop systems safely report that no battery was detected. |
| [MSP] OpenPrimeRMM Agent Health Check | READ-ONLY | 120s | Read-only OpenPrimeRMM endpoint self-check: agent/tray versions, enrollment presence without exposing tokens, scheduled task status, launcher, and recent log activity. |
| [MSP] ScreenConnect Health Check | READ-ONLY | 120s | Read-only discovery of ScreenConnect / ConnectWise Control services, process state, startup type, and installed service executable paths. |
| [MSP] Safe Temporary File Cleanup | SAFE / DRY-RUN DEFAULT | 1800s | Removes old files from Windows/user temp locations. Defaults to DRY RUN. Optional recycle-bin cleanup is disabled by default. |
| [MSP] Repair Windows Image (DISM + SFC) | MAINTENANCE | 7200s | Runs DISM RestoreHealth followed by SFC /scannow. Long-running repair; does not reboot automatically. |
| [MSP] Restart Print Spooler & Clear Queue | CAUTION | 300s | Stops Print Spooler, removes queued spool files, and starts the service. WARNING: deletes all currently queued print jobs. |
| [MSP] Repair Windows Time Sync | MAINTENANCE | 300s | Repairs Windows Time service and resyncs. Domain members use domain hierarchy; workgroup machines use time.windows.com. |
| [MSP] Refresh Group Policy | MAINTENANCE | 600s | Runs gpupdate /force for computer and user policy. Useful on domain-managed endpoints; harmlessly reports errors on workgroup PCs. |
| [MSP] Reset Windows Update Components | CAUTION | 1800s | Repairs a stuck Windows Update cache by stopping update services and rotating SoftwareDistribution/Catroot2. Does not change OpenPrimeRMM update-management policy and does not reboot. |
| [MSP] Reset Winsock & TCP-IP Stack | CAUTION | 300s | Resets Winsock and TCP/IP stack. WARNING: may disrupt networking and normally requires a reboot to fully apply; does not reboot automatically. |
| [MSP] Restart Service by Name | CAUTION | 300s | Restarts one Windows service by service name or display name and verifies the resulting state. |
| [MSP] Flush DNS Cache | MAINTENANCE | 120s | Flushes the Windows DNS resolver cache and restarts the DNS Client service only when Windows permits it. |
| [MSP] Component Store Cleanup | MAINTENANCE | 3600s | Runs DISM StartComponentCleanup to reduce superseded Windows component-store files. Does not use /ResetBase and preserves update uninstall capability. |

## Operational guidance

- **READ-ONLY** scripts are suitable for broad diagnostics and information gathering.
- **MAINTENANCE** scripts change Windows state but are designed not to reboot automatically.
- **CAUTION** scripts can interrupt a service, delete a print queue, reset update caches, or temporarily affect networking. Run them on selected endpoints first.
- `[MSP] Safe Temporary File Cleanup` defaults to **Dry run = true**. Review the result before setting Dry run to false.
- `[MSP] Reset Winsock & TCP-IP Stack` recommends a reboot but deliberately does not reboot the workstation.
- `[MSP] Reset Windows Update Components` rotates Windows Update cache directories but does not remove OpenPrimeRMM update-management registry policy.
- The OpenPrimeRMM agent-health script verifies that an enrollment token exists but never prints the token value.
