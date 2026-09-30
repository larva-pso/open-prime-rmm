# Security policy

OpenPrimeRMM can execute scripts as SYSTEM on managed Windows endpoints. Treat every server deployment, backup, enrollment key, agent token, and administrator session as sensitive infrastructure.

## Reporting vulnerabilities

Do not open a public issue for exploitable security bugs.

Report security issues privately to the project owner or maintainer. If no private contact is listed on the GitHub repository, open a minimal public issue asking for a private security contact without disclosing exploit details.

Please include:

- affected version or commit
- affected component
- impact
- reproduction steps
- suggested mitigation, if known

## Deployment guidance

- Use HTTPS for all agent/server communication.
- Restrict dashboard access by VPN or trusted IPs where practical.
- Use strong generated secrets and rotate the enrollment key after rollout.
- Back up `/opt/open-prime-rmm/server/data` and `/etc/open-prime-rmm.env` securely.
- Do not publish logs, databases, environment files, agent configs, tokens, or backup archives.
- Pilot endpoint-agent changes on lab devices before broad deployment.
