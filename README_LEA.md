# ARGUS LEA Deployment Guide

Law-enforcement edition of the ARGUS OSINT platform. This document covers installation, legal workflow, and evidence procedures.

## Requirements

- Python 3.9+
- macOS, Windows, Ubuntu, or Kali Linux
- Optional: Tor (`socks5h://127.0.0.1:9050`) for CLI-managed OpSec routing
- Optional: `wmn-data.json` (WhatsMyName dataset) in project root for username footprint scans
- Optional: `rockyou.txt` for hash/PDF cracking
- **Extended OSINT:** vendored [user-scanner](https://github.com/kaifcodec/user-scanner) (MIT) under `api/vendor/user_scanner/` — 285+ additional email/username platform checks beyond holehe and WhatsMyName

## Quick Start

```bash
cd "/path/to/Law project"
python3 console.py
```

Skip the startup typewriter animation (scripts/CI): `ARGUS_NO_ANIMATION=1 python3 console.py` or `python3 console.py --no-animation`

First boot runs an **interactive setup wizard** that prompts for your investigator display name (no password). It creates:

- `data/profiles.json` — local investigator profiles (display name + role)
- `data/.secret_key` — Flask session signing key
- `data/.vault_key` — Fernet key for encrypted API vault

If `data/users.json` exists from an older ARGUS install, display names are migrated to profiles on first load (password hashes are dropped).

Non-interactive environments (CI, pipes) with no existing profiles exit with an error — run `python3 console.py` interactively once to complete setup.

## First-Time User Guide

This section walks new analysts through setup, daily workflow, and user management on both the **CLI** and **Web GUI**.

### Step 1: First boot and profile setup

1. Open a terminal and start ARGUS (see Quick Start above).
2. On the **first run only**, ARGUS detects that no investigator profiles exist and launches an interactive setup wizard. Enter your **display name** — the first profile is created as **admin**.
3. The wizard writes `data/profiles.json`, `data/.secret_key`, and `data/.vault_key` (see Quick Start for details).

**Non-interactive environments** cannot complete the wizard. Run `python3 console.py` interactively once on a workstation, or set `ARGUS_PROFILE` / `ARGUS_PROFILE_ID` for scripted use after profiles exist.

**Disable the CLI startup animation:** `ARGUS_NO_ANIMATION=1 python3 console.py` or `python3 console.py --no-animation`

### Step 2: Select profile (CLI)

After setup, every CLI session:

1. Displays the **LEA authorization notice** — type `yes` to acknowledge.
2. Prompts for **investigator profile** — pick an existing profile or create a new one (no passwords).
3. Asks **Active Investigation Case mode?** — choose **yes** to create/open a case and log actions to per-case audit files, or **no** (default) for ad-hoc mode where all tools work without a case.

Non-interactive CLI (no TTY): set `ARGUS_PROFILE=<display_name>` or `ARGUS_PROFILE_ID=<uuid>`, or defaults to the first profile if one exists.

Type `guide` for a condensed quick start, or `/help` for the full command reference. After your first profile selection, ARGUS prints a one-line hint pointing you to these commands.

### Step 2b: Select profile (GUI)

1. From the CLI, type `gui`, or browse to `http://127.0.0.1:PORT` (port shown in the CLI banner).
2. The **Select Investigator Profile** modal appears if no profile is active in the browser session — click an existing profile or add a new one.
3. Each new browser tab session shows an **Investigation Case Mode** modal — enable case mode (create/open a case) or continue without a case (ad-hoc mode).
4. On first visit, a **Welcome to ARGUS** modal may appear. Choose **Start Tour** or **Skip**. Press the **?** icon in the header anytime to replay the tour.

### Step 3: Case mode — ad-hoc vs investigation case

ARGUS supports two session modes (chosen at every session start; not persisted across restarts):

| Mode | CLI prompt | GUI choice | Tools | Audit | Export case |
|------|------------|------------|-------|-------|-------------|
| **Ad-hoc** | `Enable case mode?` → no (default) | Continue Without Case | All tools, no case required | `audit.log` only | Not available (`export case` shows a friendly message) |
| **Case mode** | `Enable case mode?` → yes | Enable Case Mode | All tools; `X-Case-Id` sent | `audit.log` + `data/audit/audit_<case_id>.jsonl` | `export case` / Export Report |

When creating a case, **authorization reference** (warrant/court order number) is required. In ad-hoc mode, no case or authorization reference is needed to run scans.

**CLI mid-session:** `case new` or `case open` can upgrade ad-hoc → case mode. `case off` disables case mode for the remainder of the session.

**CLI case commands:**
```
case new          # interactive create + activate (enables case mode if ad-hoc)
case list         # list all cases
case open CASE-…  # set active case
case close CASE-… # close case
case status       # show active case or ad-hoc status
case off          # disable case mode for this session
```

**GUI:** **Investigation Case** panel in the sidebar (dimmed in ad-hoc mode). **Select** re-opens the case setup flow.

### Step 4: Configure optional API keys

**CLI:**
```bash
keys list
keys set vt <your_virustotal_key>
keys set abuse <your_abuseipdb_key>
keys set truecaller <installation_id>
```

**GUI:** Header lock icon (Settings) → **API Keys** tab → **Save & Lock Vault**.

### Step 5: Run your first scan

**CLI** — command or menu number:
```
username johndoe
ip 8.8.8.8
```

**GUI** — pick a sidebar module, enter a target, click **Run**.

### Dual search — Google dorks + DuckDuckGo HTML

Username dorking and domain email harvest use **both** channels:

| Channel | Role |
|---------|------|
| **Google dork URLs** | Offline, ready-to-click search links (always generated) |
| **DuckDuckGo HTML** | Live scraped result links when Google CAPTCHAs or blocks manual searches |

- DDG endpoint: `https://html.duckduckgo.com/html/` (static HTML, no JS)
- Random **4–9 second jitter** between consecutive DDG queries (and between paginated DDG pages) to reduce blocks
- **Paginated DDG** (`search_ddg_html_paginated`) fetches up to 5 pages per query for deeper email/username harvest
- Browser-like headers + optional Tor via `tor on` (CLI) / shared `Config` proxy
- CLI: `dork <username>` · `emailsite <domain>` · GUI: **Username Dorking** (Advanced OSINT Recon) · **Domain Email Harvest** (Domain section)

### Deep Domain Crawler (`domaincrawl`)

Async BFS web crawler for a single domain — extracts emails, phone patterns, social links, page titles, and meta descriptions from internal pages (`/about`, `/contact`, `/team`, etc.).

- Module: `api/modules/domain_crawler.py`
- Endpoint: `POST /api/recon/domain-crawl` — `{"domain": "example.com", "max_depth": 2}`
- CLI: **`domaincrawl <domain> [max_depth]`** — menu **#20** (Passive Recon)
- GUI: **Deep Domain Crawler** card (Domain section)

### GitHub Intel (`githubintel`)

Extracts commit author emails and public repos from the unauthenticated GitHub API. Filters `noreply@github.com` addresses. Domain mode searches users/code with matching email domains.

- Module: `api/modules/github_intel.py`
- Endpoint: `POST /api/recon/github` — `{"username": "..."}` OR `{"domain": "company.com"}`
- CLI: **`githubintel <username|domain>`** — menu **#21** (Recon / OSINT)
- GUI: **GitHub Intel** card (Advanced OSINT Recon section)
- Rate limit: 60 unauthenticated requests/hour — returns graceful warnings on HTTP 403

### Extended email & username scans (user-scanner)

`email` and `username` commands (and their GUI cards) run **three layers** in parallel where installed:

| Layer | Email | Username |
|-------|-------|----------|
| Primary | holehe (120+ registration probes) | WhatsMyName (600+ sites) |
| Extended | user-scanner email modules (100+) | user-scanner username modules (185+) |
| Legacy supplementary | 5 hand-picked probes (`supplementary=1`) | — |

Extended results include **clickable profile URLs** and optional `extra` metadata (bio, followers, etc.). Scans use bounded concurrency (25 parallel, ~2–5 min). NSFW/adult modules and “loud” email probes (forgot-password notifications) are skipped by default for LEA-safe operation. Username sync probes route through ARGUS `Config` Tor/headers; async email modules use their built-in httpx clients.

**Not integrated:** user-scanner CLI/TUI, Hudson Rock (`/api/infostealer` remains separate), PyPI auto-updater, bulk file mode, proxy rotation file, nix flake, abandoned modules.

### Step 6: Export evidence

**Case mode only** — full case audit trail export requires an active investigation case.

**CLI:** `export last json` (works in any mode) · `export case html` (case mode only)

**GUI:** **Export Report** in the case panel (case mode) · **Export Evidence** on result cards.

### Managing profiles (admin only)

Roles: `investigator`, `supervisor`, `admin`. The first profile created is always **admin**.

**CLI:**
```bash
user add Analyst One investigator   # display name + role
user list
profile list                        # alias
```

**GUI:** Settings → **Profiles** tab (admins only).

Each analyst picks their profile at session start; audit logs and exports tag the **display name** as the `user` field.

### Replay the guided tour (GUI)

Press the **?** icon in the dashboard header. The tour covers sidebar navigation, the case panel, a sample tool card, export, settings/keys, and the help icon.

### Tor, GUI vs CLI

| Feature | CLI | GUI |
|---------|-----|-----|
| Profile | Pick/create at session start (`X-Profile-Id` header) | Session cookie via `/api/auth/profile/select` |
| Case management | `case` commands | Investigation Case panel |
| API keys | `keys` commands | Settings → API Keys |
| Tor | `tor on\|off\|status\|rotate` (auto-install Linux/macOS) | Read-only pill |
| Profile management | `user add\|list` | Settings → Profiles (admin) |
| Guided tour | `tour` command | Welcome modal + **?** icon |

## Authentication

ARGUS uses **local investigator profiles** — no passwords, no external auth server.

| Interface | Method |
|-----------|--------|
| Web GUI | Flask session cookie after `POST /api/auth/profile/select` |
| CLI | `X-Profile-Id` + `X-Profile-Name` headers after profile picker |

Storage: `data/profiles.json`

Roles: `investigator`, `supervisor`, `admin` (first profile = admin)

Session timeout: 8 hours (configurable in `data/auth_config.json`)

**Migration:** If `data/users.json` exists from a prior install, usernames are imported as profiles on first boot; password hashes are not retained.

## Legal Authorization

1. On first launch, acknowledge the LEA notice (stored in `data/.lea_ack`)
2. At each session start, choose **case mode** (optional) or **ad-hoc mode** (default)
3. When case mode is enabled, create/open a case with `authorization_ref` (warrant/court order number)
4. If `X-Case-Id` is sent on API requests, the case must be open and have a non-empty `authorization_ref`

## Case Workflow

### CLI
```
case new          # interactive create + activate
case list         # list all cases
case open CASE-…  # set active case
case close CASE-… # close case
case status       # show active case or ad-hoc status
case off          # disable case mode for remainder of session
```

Ad-hoc mode: banner shows `Case: disabled (ad-hoc mode)`. All recon tools work without a case header.

### GUI
At login, the **Investigation Case Mode** modal offers enable or ad-hoc. Use the **Investigation Case** panel when case mode is active.

## API Key Vault

Never store keys in source code.

```bash
keys list
keys set vt <your_virustotal_key>
keys set abuse <your_abuseipdb_key>
keys set truecaller <installation_id>
```

GUI: **Settings** (header lock icon) → API Keys tab (encrypted server vault at `data/vault.json`).

## Truecaller Deep Lookup (Optional)

Truecaller adds identity enrichment (name, email, spam score, location) on top of the offline `phonenumbers` trace. It is **optional** — the `phone` command works without it.

### 1. Obtain an installation ID (one-time, requires Node.js)

Use a spare phone number for Truecaller login (not your primary device):

```bash
npx truecallerjs login
npx truecallerjs installation_id
```

### 2. Store the token in the ARGUS vault

**CLI:**

```bash
keys set truecaller <installation_id>
```

**GUI:** **Settings** (lock icon) → **API Keys** → **Truecaller Installation ID** → **Save & Lock Vault**.

The token is stored in the encrypted server vault (`data/vault.json`) under `TRUECALLER_ID`. Node.js is only needed to obtain the token — not for routine lookups.

### 3. Run a deep phone trace

```bash
phone +919876543210
```

Offline carrier/region/timezone data is always returned. When the vault token is set, the response also includes a `truecaller` dossier block (name, alternate names, email, spam score, location).

## Evidence Export

```bash
export last [json|html]    # last operation (any mode)
export case [json|html]    # full case audit trail (case mode only)
```

GUI: **Export Evidence** on result cards · **Export Report** in case panel.

Exports include SHA-256 integrity hashes, timestamps, user, authorization reference, and ARGUS version.

## Tor Setup

Tor is managed via **CLI only** (the GUI shows a read-only status pill).

### Windows

**Tor OpSec is not supported on Windows CLI.** Use Kali Linux, Ubuntu, or another Linux distribution for Tor routing. The ARGUS GUI on Windows can still run all tools in ad-hoc mode without Tor.

### Linux / macOS — auto-install

When you run `tor on` and Tor is not listening on `127.0.0.1:9050`, ARGUS offers to install and configure it:

| OS | Method | Prompt |
|----|--------|--------|
| **Linux** (Debian/Ubuntu/Kali) | `sudo apt-get install tor` + torrc edits | `Install and configure Tor now? [y/N]` |
| **macOS** | Homebrew bootstrap if needed, then `brew install tor` | `Install Homebrew now? [y/N]` → `Install Tor via Homebrew now? [Y/n]` |
| **Other Linux** (dnf/pacman) | Manual — printed package-manager steps | — |

On **apt-based Linux**, ARGUS also:

1. Sets `ControlPort 9051` in `/etc/tor/torrc`
2. Sets `CookieAuthentication 0` (allows `AUTHENTICATE ""` for NEWNYM)
3. Restarts Tor (`systemctl restart tor`, fallback `/etc/init.d/tor restart`)
4. Waits up to 30s for SOCKS port 9050
5. Runs an IP leak check (direct vs proxied)

**sudo** may prompt for your password in the terminal during install.

On **macOS**, if Homebrew is not installed, ARGUS first offers to run the official installer from [brew.sh](https://brew.sh). macOS may prompt for your password; the install can take several minutes. After install, ARGUS prepends `/opt/homebrew/bin` (Apple Silicon) or `/usr/local/bin` (Intel) to `PATH` for the current session so `brew` works immediately.

Fedora/RHEL and Arch users see manual `dnf` / `pacman` instructions (no auto-install).

### CLI commands

```bash
tor on       # auto-install if needed, enable SOCKS5 routing, leak check
tor off      # disable proxy (clearnet)
tor status   # proxy + daemon status
tor rotate   # SIGNAL NEWNYM (new circuit)
```

### Verify routing

Compare your real IP vs Tor exit IP:

```bash
curl ifconfig.me
torify curl ifconfig.me    # should differ when Tor is active
```

Or use ARGUS leak check output after `tor on`.

### Circuit rotation (NEWNYM)

ARGUS sends this to the Tor control port (`127.0.0.1:9051`):

```bash
echo -e 'AUTHENTICATE ""\r\nsignal NEWNYM\r\nQUIT' | nc 127.0.0.1 9051
```

Equivalent: `tor rotate` in the ARGUS CLI.

### Docker (optional)

```bash
docker compose --profile tor up -d tor
```

Proxy URL used by ARGUS: `socks5h://127.0.0.1:9050` (`socks5h` resolves DNS through Tor).

## Docker Deployment

```bash
docker compose build
docker compose up -d
```

Data persists in Docker volumes `argus_data` and `argus_audit`. Bind only to `127.0.0.1:5000` for local LEA workstation use.

Debug mode: set `ARGUS_DEBUG=1` (never in production).

## Supervisor Dashboard

`GET /api/supervisor/overview` — admin/supervisor only.

Shows open case count, recent audit entries, online sessions.

## Chain of Custody

Audit logs:
- `audit.log` — legacy + human-readable lines
- `data/audit/audit_<case_id>.jsonl` — structured per-case JSON-lines

Each entry: timestamp, interface, user, case_id, authorization_ref, module, target, action, result_hash (SHA-256), IP.

## Agency Configuration Checklist

- [ ] Complete first-run setup (investigator profile) if not already done
- [ ] Configure VT / AbuseIPDB / Truecaller keys via vault
- [ ] Install and test Tor if required
- [ ] Place `wmn-data.json` for username footprint recon (WhatsMyName)
- [ ] Place `rockyou.txt` for cracking modules
- [ ] Document agency SOP for case creation and evidence export
- [ ] Restrict network binding to localhost or agency VPN

## Security Notes

- API rate limit: 60 requests/minute per IP
- CORS restricted to `http://127.0.0.1:*` and `http://localhost:*`
- All `/api/*` routes require an active investigator profile except health and profile/auth endpoints
- Do not commit `data/.vault_key`, `data/vault.json`, or `data/profiles.json` on shared machines without agency policy
