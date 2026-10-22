# 🐸 Frog SOC 5.2

[Polski](README.md) · **English**

A lightweight **Alpine Linux / OpenRC** cybersecurity lab dashboard: VPS
monitoring, an HTTP honeypot, connection history from the separate **Endlessh**
SSH tarpit, a shared event timeline, Discord alerts and a frog that earns XP.
Python standard library only; no pip, Node.js or Docker required.

Frog observes and alerts. It does not block IPs or replace a firewall or SIEM.

## New in 5.2

- **Login attempt statistics** (`/credential-stats`): attempt and distinct-IP
  counts, top 20 usernames, passwords and combinations, plus distinct IPs per
  combination. These protected statistics use retained submissions only.
- **Similar bot patterns** (`/campaigns`): matching username/password pairs
  across different IPs and similar HTTP path families. Default window: 24 hours,
  at least 2 IPs and 3 attempts. Path families cover WordPress, CGI/router,
  login panels and paths with numeric identifiers. Similarity is a heuristic,
  not proof of common attribution. Up to 20 groups and 20 IPs per group are shown.
- **Daily Discord report** (`/reports`): defaults to **20:00 in the server timezone**,
  covering the previous complete calendar day. It includes HTTP, Endlessh and
  failed-SSH counts, the longest session started that day, newly observed IPs
  within retained history, submission count and currently active alert count.
  Submitted usernames and passwords are never included. Requires `.discord-webhook`.
- **Submission deletion** (`/credentials`): delete selected records or the entire
  history as it existed when the form was opened, across all pages. Type `USUN`
  and select the appropriate button. Deletion requires authentication and a
  signed token valid for 30 minutes; GET never deletes data. Submissions captured
  after the form was opened remain untouched. Deletion cannot be undone.
  Reopen the form after a service restart.

New settings can be added to an existing `config.json`:

```json
{
  "daily_report": {"enabled": true, "hour": 20, "minute": 0},
  "campaigns": {"window_hours": 24, "min_ips": 2, "min_attempts": 3}
}
```

The report scheduler checks every minute. The last successfully reported day
is persisted in SQLite, so a restart does not resend it. Failed delivery is
retried; a timeout after Discord accepts a message can cause a duplicate.
After downtime, only the latest complete day is reported, without replaying
the entire backlog. `/reports` provides a preview and delivery status.
Statistics and pattern detection respect data retention; deleted submissions
also disappear from those summaries.

## New in 5.1: router honeypot form capture

The fake router login now records the username and password submitted as an
`application/x-www-form-urlencoded` form (`username`, `password`) to `/login`
or another recognized honeypot path. Actual Frog administrator authentication
is never collected by this feature.

- View submissions at **`/credentials`**, through the protected dashboard.
- Storage: `/opt/frog-soc/honeypot-credentials.sqlite3`, file mode `600`.
- Passwords are stored **in plaintext**. Expand “Pokaż hasło” to view a password.
  Collapsing the field only hides it visually; it does not encrypt the data.
- This database is separate and is **not included** in automatic telemetry
  backups or deployment backups.
- Default retention: **7 days / 10,000 submissions**, enforced on insertion
  and during maintenance.
- Maximum request body: 4 KiB / 16 fields; usernames are limited to 256
  characters and passwords to 512 characters.
- Submissions are not sent to Discord, HTTP event logs or the Endlessh CSV export.
- Set `capture_credentials: false` in `config.json` to stop collection.
  Existing records remain until retention removes them. Configure
  `retention.credentials_days` and `retention.credentials_rows` to change limits.

## Features introduced in 5.0

- A single `config.json` for ports, logs, trusted networks, alert thresholds,
  retention, refresh/import intervals and backups.
- Endlessh history filters for IP, dates, status and minimum duration;
  newest/longest sorting and CSV export using the same filters.
- Per-IP details: HTTP/SSH event and session counts, first/last session,
  total time and longest connection. IPv4-mapped IPv6 addresses are supported.
- A shared timeline of HTTP requests, Endlessh sessions and failed sshd/Dropbear logins.
- Returning-IP rankings and hourly HTTP/Endlessh activity charts.
- Stable alert identifiers and state persisted in SQLite. Changing a counter
  does not bypass the cooldown, and restarting does not reset notification times.
- Recovery notices, HTTP traffic surge detection and longest-session notices.
- Daily consistent SQLite backups and automatic data retention.
- Persistent frog XP: 10 per HTTP event and 5 per Endlessh session.
  Expiring history does not reduce the frog's level.
- Background refresh without full-page reloads; edited forms are preserved.
- Responsive layout and dashboard status for the importer, backups and maintenance.
- A fresh installer and an updater with backups and authenticated HTTP checks.

## Architecture and ports

**31888 and 41888 are examples from the author's VPS, not required port numbers.**
Choose ports available on your hosting account, and configure the services,
firewall and any NAT mappings accordingly.

| Service | Role | Example local port |
| --- | --- | --- |
| Frog SOC | HTTP honeypot and protected web dashboard | 31888/TCP |
| Endlessh | Separate SSH tarpit | 41888/TCP |
| Real SSH | VPS administration | A separate port chosen by you or the hosting provider |

Frog and Endlessh must use **different ports**. Allow the relevant two TCP ports
in your firewall and hosting panel. If your hosting uses NAT, configure:

```text
YOUR_PUBLIC_HTTP_PORT → VPS:FROG_PORT_FROM_CONFIG
YOUR_PUBLIC_SSH_TARPIT_PORT → VPS:ENDLESSH_PORT
```

Public and local ports may be identical or different. Application settings do
not create firewall rules or port mappings.

Frog runs an HTTP server. Endlessh runs separately and slowly sends an SSH
banner before authentication, tying up clients. It is not a login server and
does not collect SSH passwords. Keep your real administration SSH separate.

Without Endlessh, system monitoring and the HTTP honeypot still work.
SSH connection history requires a working Endlessh instance **with logging enabled**.

## Requirements

- Alpine Linux with OpenRC.
- Python 3 including `sqlite3` (tested with Python 3.12 and 3.14).
- `/proc` access for memory, process and TCP monitoring.
- Root/sudo for installation, reading protected logs and restarting services.
- Endlessh for the SSH tarpit and connection logs.
- Tailscale for private remote dashboard access, or an SSH tunnel to localhost.
- Logrotate and a running cron service for log rotation. The installer/updater
  installs logrotate.

Gatus is optional and is only observed. Discord notifications are optional.
Geolocation requires HTTPS access to `ipwho.is`; notifications need Discord access.
The installer does not authenticate Tailscale or change network rules.

## One configuration file

Example: [`deploy/config.example.json`](deploy/config.example.json).
On the server: **`/opt/frog-soc/config.json`**.

The updater creates this file if absent and preserves existing settings on
subsequent deployments. Partial configurations are supported: missing options
use defaults. Unknown keys, wrong types, invalid ports and invalid networks
are rejected.

Example partial configuration:

```json
{
  "capture_credentials": true,
  "listen_host": "0.0.0.0",
  "http_port": 31888,
  "endlessh_port": 41888,
  "endlessh_logs": ["/var/log/endlessh.log*"],
  "trusted_networks": ["100.64.0.0/10"],
  "alerts": {
    "cooldown_seconds": 900,
    "http_hour": 100,
    "ip_hour": 50,
    "endlessh_record_seconds": 300
  },
  "retention": {
    "http_days": 90,
    "endlessh_days": 90,
    "endlessh_rows": 100000,
    "credentials_days": 7,
    "credentials_rows": 10000
  }
}
```

Replace example ports with yours. Restart after changing configuration:

```sh
sudo rc-service frog-soc restart
```

`endlessh_port` is the port Frog monitors. For a pre-existing Endlessh service,
set the same port in its `-p` argument and restart that service separately.
The fresh installer's `frog-endlessh` service reads its port from `config.json`
at startup; restart it too when changing ports. Restarting Endlessh disconnects
current sessions.

The dashboard password and Discord webhook remain separate secrets:
`.soc-password` and `.discord-webhook`, with mode `600`. Never commit them.
`/settings` displays non-secret configuration and maintenance status.

## Fresh installation

Clone the repository on Alpine, copy the example configuration and edit your ports:

```sh
cp deploy/config.example.json /tmp/frog-config.json
vi /tmp/frog-config.json
sudo sh install.sh /tmp/frog-config.json
```

The installer:

1. Installs Python, Endlessh and logrotate from Alpine repositories.
2. Validates configuration and asks for a new dashboard password, at least 12 characters.
3. Creates the application, data files and `frog-soc` OpenRC service.
4. If Endlessh is not already running, creates `frog-endlessh`, with `-v`
   logging to `/var/log/endlessh.log` and its port read from `config.json`.
5. Enables services at boot and installs the log rotation recipe.

The Endlessh package must be available in your configured Alpine repositories,
usually community. The installer refuses to replace an existing Frog installation.
If Endlessh is already running, it preserves that service; match its port and
log path in Frog's configuration. The default required-service list includes
Tailscale; remove it from `required_services` if you only use an SSH tunnel.

The fresh installer has shell syntax validation. The live VPS uses the existing-installation
updater described below.

## Updating an existing installation

Requires `/opt/frog-soc/app.py`, `.soc-password` and the `frog-soc` service.

```sh
scp -r deploy USER@VPS:~/frog-update-v52
ssh USER@VPS
sudo sh ~/frog-update-v52/deploy.sh
```

For a nonstandard administration port, use `scp -P PORT` and `ssh -p PORT`,
or your SSH alias. Use a new destination directory if one already exists,
so `scp -r` does not add an extra nested `deploy/` directory.

The updater preserves the password and configuration, backs up the application
and telemetry SQLite database under `/opt/frog-soc/backups/v5-DATE-TIME/`,
replaces the application and restarts Frog. It checks authenticated views,
CSV, JavaScript and invalid-filter handling. On restart/HTTP failure it restores
the previous application and any pre-existing configuration. The database copy
remains for manual restoration; new tables are not removed automatically.
Endlessh is not restarted. The separate submission database is not backed up.

A standalone generated updater is also available:

```sh
sudo sh update-frog-soc-4.sh
```

The filename is retained for compatibility; it installs **5.2** using the same
backup and validation procedure as `deploy/deploy.sh`.

## Access and dashboard routes

The dashboard shares Frog's port with the HTTP honeypot. Administrative routes
require localhost or a source address in `trusted_networks`, followed by HTTP
Basic Auth: username **`frog`**, password from `.soc-password`.

```text
http://TAILSCALE_ADDRESS:YOUR_FROG_PORT/soc
http://TAILSCALE_ADDRESS:YOUR_FROG_PORT/ssh
```

An SSH tunnel can be used instead of Tailscale:

```sh
ssh -L 8080:127.0.0.1:YOUR_FROG_PORT USER@VPS
```

Then open `http://127.0.0.1:8080/soc`.

| Route | Contents |
| --- | --- |
| `/soc` | VPS/service monitoring and HTTP/Endlessh chart |
| `/ssh` | Filtered session history and returning-IP ranking |
| `/ssh.csv` | CSV using the history filters |
| `/ip?ip=ADDRESS` | Per-IP summary |
| `/activity` | Latest 200 HTTP/Endlessh/SSH events; optional `ip` filter |
| `/credential-stats` | Username, password and combination statistics |
| `/campaigns` | Similar attempt patterns across different IPs |
| `/reports` | Daily Discord report preview and status |
| `/credentials` | Usernames/passwords submitted to the fake router form |
| `/settings` | Configuration, importer, backup and maintenance status |
| `/stats` | Recent HTTP and buffer rankings; hourly count from SQLite |
| `/history` | 48-hour HTTP history |
| `/investigate` | Alerts, processes and SSH log samples |
| `/geo` | Approximate coordinates of public HTTP client IPs |
| `/frog` | Persistent XP, level and badges |
| `/soc/json` | Monitoring JSON |
| `/health` | Public `ok` response |

`/ssh` and `/ssh.csv` filters: `ip`, `from`, `to` (inclusive dates in YYYY-MM-DD),
`status` (`closed`/`pending`), `min_seconds`, `sort` (`newest`/`longest`).
Dates filter session start times and use the server timezone. Page number: `page`.

The application does not provide HTTPS. Use Tailscale or an SSH tunnel.
A localhost reverse proxy changes the source address seen by Frog, which does
not trust `X-Forwarded-For`. Do not expose the dashboard through such a proxy
without additional access control.

## Endlessh logging

Example arguments for an existing service:

```text
-p YOUR_ENDLESSH_PORT -d 10000 -m 256 -v
```

`-v` enables the ACCEPT/CLOSE logs needed for history. For stdout logging, set
these in your OpenRC service:

```sh
output_log="/var/log/endlessh.log"
error_log="/var/log/endlessh.log"
```

Alternatively use `-v -s` for syslog and configure the appropriate file in
`endlessh_logs`. Do not import both stdout and syslog for the same instance:
timestamp precision differences can produce duplicates. Logs must come from
the intended single Endlessh instance. The `port` field is the **client source
port**, not the listening port.

Frog persists read offsets in SQLite and imports every 5 seconds by default.
It supports IPv4/IPv6, uncompressed log rotation and detected truncation.
Files ending in `.gz`, `.xz` or `.bz2` are skipped. Missing CLOSE means an
open connection or incomplete logs; a separate active TCP count comes from
the kernel. Duration is read from CLOSE; when ACCEPT is absent, start time is
calculated from end time and duration. Earlier sessions cannot be recovered
without retained logs. Yearless syslog timestamps use the file modification date.

## Alerts, storage and maintenance

Default thresholds: RAM/disk 85%, HTTP 100/hour, individual IP 50/hour,
failed SSH logins 10/hour, HTTP surge at least 3× the previous hour and at
least 100/hour, new longest Endlessh session from 300 seconds.
`required_services` controls monitored required services; Gatus is optional.

Alerts run every 60 seconds. Cooldown is 15 minutes for a stable alert type/IP,
independent of changing counts. State survives restarts. Failed delivery does
not consume the cooldown. Recovery messages are controlled by `alerts.recovery`;
a session record is a one-time observation. Service checks detect processes/ports,
not full tunnel or application health. Authentication logs are sampled from
each file's last 256 KiB per alert cycle; high traffic or rapid rotation can
cause events to be missed.

| Data | Default retention |
| --- | --- |
| HTTP SQLite events | 90 days / 30,000 rows |
| Endlessh SQLite sessions | 90 days / 100,000 rows |
| sshd/Dropbear events | 30 days |
| Router form submissions, separate database | 7 days / 10,000 rows |
| Automatic telemetry backups | Every 24 hours; keep latest 7 files |

In-app maintenance runs hourly. Consistent telemetry backups use SQLite's
backup API and are stored in `/opt/frog-soc/backups/automatic/` with mode `600`.
Deployment backups are separate and are not automatically removed. Retention
deletes rows but does not guarantee immediate SQLite file shrinkage. Monitor
free space and periodically archive backups off the VPS.

The logrotate recipe keeps 5 uncompressed rotations with a 5 MiB threshold.
It requires cron and uses `copytruncate` to avoid restarting the tarpit; a small
window of log loss is possible while copying/truncating. Size is checked when
logrotate runs, not after every write.

XP is initialized from retained history during migration, then tracked
persistently. Previously deleted history cannot be recovered. Geolocation sends
public HTTP client IPs to `ipwho.is`, up to 12 attempts/hour. It is approximate
and does not prove a person's location. Disable it with `geo_enabled: false`.

## Development and tests

**`deploy/app.py` is the canonical application source.** Regenerate the standalone
updater after changing deployment sources:

```sh
python3 tools/build_update.py
python3 tools/build_update.py --check
sh -n install.sh
sh -n deploy/deploy.sh
sh -n update-frog-soc-4.sh
python3 -m unittest discover -s tests -v
```

33 tests cover log import/rotation, IPv6, filters/CSV, configuration validation,
persistent alerts/XP, SQLite backups, authenticated HTTP routes, submission
capture, access control, retention, statistics, pattern grouping, report scheduling
and confirmed deletion with CSRF tokens. HTTP tests require local TCP sockets.

Keep **both README languages updated together**, as required by `AGENTS.md`.
Never commit passwords, webhook URLs, SSH keys, databases or logs. `.gitignore`
excludes common data and secret files.

Upstream documentation: [Endlessh](https://github.com/skeeto/endlessh).
