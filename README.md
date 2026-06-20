# ARGUS OSINT Console & Web Intelligence Suite
## Law Enforcement Agency (LEA) Operational Specifications & Forensic Integrity Manual

---

**Evidentiary PDF Shared Access Link (Google Drive):**  
🔗 [INSERT GOOGLE DRIVE PDF SHARE LINK HERE]  

**GitHub Source Code Audit Repository:**  
🔗 [https://github.com/X5464/argus-osint](https://github.com/X5464/argus-osint)  

---

## 1. Project Overview & Operational Mandate

### 1.1 What is ARGUS?
**ARGUS** is a local-first, forensic-grade Open Source Intelligence (OSINT) and digital intelligence collection platform. It is engineered for investigators, analysts, and law enforcement agencies (LEA) that require swift, compliant, and documented collection of digital evidence from public records, network interfaces, and third-party threat databases.

ARGUS enforces strict procedural controls to ensure that all queries are associated with an active case number and a verified legal authorization reference. The platform is operated via two interfaces that interact with the same local Flask API daemon:
*   **Tactical CLI Console**: A fast terminal-based shell built using the Python `cmd.Cmd` loop, featuring visual banners, startup animations, color-coded tabular outputs, and recursive wizard-driven navigation prompts.
*   **Tactical Web Dashboard**: A cyber-tactical dark-mode Single Page Application (SPA) frontend running on a local Flask server, facilitating mouse-driven visualization, onboarding tours, settings management, and report generation.

```
                  ┌─────────────────────────────────────────┐
                  │          Analyst User Workspace         │
                  └────────────────────┬────────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
     ┌─────────────────────┐                       ┌─────────────────────┐
     │  Tactical Terminal  │                       │  Cyber Web Console  │
     │  (console.py CLI)   │                       │ (localhost GUI SPA) │
     └──────────┬──────────┘                       └──────────┬──────────┘
                │                                             │
                └──────────────────────┬──────────────────────┘
                                       ▼
                       ┌──────────────────────────────┐
                       │  Flask Local Service (API)   │
                       └──────────────┬───────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          ▼                           ▼                           ▼
 ┌───────────────────┐       ┌───────────────────┐       ┌───────────────────┐
 │ OSINT & Forensics │       │   Identity Vault  │       │ Legally Enforced  │
 │  (18 Core Tools)  │       │ (Encrypted Keys)  │       │ Audit Logs (Case) │
 └───────────────────┘       └───────────────────┘       └───────────────────┘
```

### 1.2 Why ARGUS is the Best-in-Class OSINT Suite
Unlike generic tools that only perform single tasks (e.g., username search or domain mapping) and run as independent scripts, ARGUS stands out for several structural reasons:
1.  **Dual Interface Parity**: Execute complex passive recon or network sweeps via keyboard-first CLI commands or point-and-click GUI widgets. They run on the same backend, ensuring consistent result structures.
2.  **Enforced Legal Chain-of-Custody (Case Mode)**: Prevents rogue scans. Prior to initiating sensitive probes (like active port sweeps or target lookups), analysts must open a Case file and insert a valid **Authorization Reference** (e.g., warrant, court order, or formal case ID).
3.  **Local-First & Data Sovereignty**: All harvested data, search configurations, local dictionaries, and logs remain strictly within the analyst's machine. No investigative target parameters are leaked to cloud storage.
4.  **Automatic OpSec (Tor Integration)**: Out-of-the-box routing toggles let analysts proxy all outbound traffic through the Tor network, checking for DNS and IP leaks dynamically.
5.  **Self-Bootstrapping Environment**: The application automatically sets up a local virtual environment (`.venv`), upgrades its local package manager (`pip`), and verifies/installs all dependencies on launch. No complex developer configuration required.

---

## 2. System Architecture, Source Audits & Internals

ARGUS prioritizes architectural transparency to support judicial reviews and independent agency source code audits.

### 2.1 Core Source Code Directory (GitHub Reference)
Auditors can inspect key platform files on GitHub to verify they do not contain remote data exfiltration or backdoors:
*   [console.py](console.py): The primary CLI shell coordinator and bootstrapper.
*   [api/app.py](api/app.py): The local Flask server wrapper, rate-limiter, and middleware router.
*   [api/audit.py](api/audit.py): The logging controller for recording investigations.
*   [api/vault.py](api/vault.py): The encryption manager for API keys.
*   [api/cases.py](api/cases.py): Manages open and archived cases.
*   [api/evidence.py](api/evidence.py): Compiles gathered logs and exports evidence packages.

### 2.2 Bootstrapping Logic
When `console.py` is invoked, it runs a cross-platform bootstrap script that:
*   Detects if execution is inside a Python virtual environment.
*   If not, it automatically creates a `.venv` directory in the project root and restarts the process inside the virtual environment.
*   Upgrades `pip` quietly and validates 12 critical library imports. Any missing packages are downloaded and installed on-the-fly using the local `requirements.txt`.

### 2.3 Flask Web Endpoint Registry
The local backend is hosted by Flask (binding strictly to `127.0.0.1` to prevent unauthorized remote requests). The API routes are separated into specialized modular blueprints:
*   `/api/auth`: Handles investigator profile initialization, profile switching, and LEA acknowledgment.
*   `/api/cases`: Manages active case lifecycles, auditing reference codes, and status configurations.
*   `/api/vault`: Securely handles the setting, listing, and fetching of encrypted service API keys.
*   `/api/identity`: Coordinates geodata lookups, carrier traces, and WhatsMyName username footprinting.
*   `/api/webcheck`: Handles email checks via Holehe and DuckDuckGo domain email harvesting.
*   `/api/spiderweb`: Coordinates offline port scanners, subnet discoveries (`netscan`), and CT-Log subdomain sweeps.
*   `/api/recon`: Coordinates advanced probes (SMTP checks, async port sweeps, MAC vendor lookups).
*   `/api/evidence`: Compiles gathered artifacts into chain-of-custody export packages (JSON & HTML format).

### 2.4 Cryptographic Key Vault
ARGUS avoids plain-text configurations for sensitive credentials. The local vault (`api/vault.py`) generates a unique hardware-tied secret key using the standard Fernet symmetric encryption algorithm from the `cryptography` module.
*   Keys such as `VT_API_KEY`, `ABUSE_IPDB_KEY`, `GITHUB_TOKEN`, and `TRUECALLER_ID` are encrypted before being written to local DB files.
*   They are dynamically decrypted in-memory only when the corresponding API modules require validation.

### 2.5 Legal Auditing Middleware (`audit.py`)
Every API call to a sensitive endpoint is piped through a security middleware interceptor. It logs a structured JSON audit trail containing:
*   `interface`: GUI or CLI.
*   `user`: The investigator's display name.
*   `case_id`: The active case UUID.
*   `authorization_ref`: Legally binding reference.
*   `module` & `action`: The exact module name and HTTP method.
*   `target`: The target being investigated (IP, domain, handle) with sensitive values redacted.
*   `result_status`: Success or Failure.
*   `ip_address`: Local loopback origin validation.
*   `details`: Detailed metadata of the request.
The audit entries are continuously appended to `audit.log`.

---

## 3. Installation, Environment Setup & Prerequisites

Before launching ARGUS, verify that your host environment meets the necessary system requirements.

### 3.1 Software Prerequisites

#### A. Python 3.8 to 3.11
*   **macOS**: Install via Homebrew: `brew install python`
*   **Linux (Ubuntu/Debian)**: `sudo apt install python3 python3-pip python3-venv`
*   **Windows**: Download the installer from the official Python website. Ensure **"Add Python to PATH"** is checked during setup.

#### B. Node.js & npm (Required for Truecaller Integration)
*   **macOS**: `brew install node`
*   **Linux (Ubuntu/Debian)**:
    ```bash
    curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash -
    sudo apt install -y nodejs
    ```
*   **Windows**: Download and run the Node.js Windows Installer (`.msi`).

#### C. Tor Service (Required for OpSec Proxy Routing)
*   **macOS**: `brew install tor`
*   **Linux (Ubuntu/Debian)**: `sudo apt install tor`
*   **Windows**: Download the Windows Expert Bundle or run the Tor Browser in the background mapping to port 9050.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tor Service Active Check**
> *Capture a screenshot of your terminal/process list demonstrating the local Tor service running on the standard SOCKS5 port (127.0.0.1:9050).*
> Recommended Filename: `ss_prereq_tor_status.png`

---

### 3.2 Local Wordlist Placement (Forensics Dictionary)
For the Cryptographic Hash Recovery (`hashcrack`) and PDF Password Recovery (`pdfcrack`) tools to function, a wordlist must be configured.
1.  Download the standard `rockyou.txt` password dictionary.
2.  Save it directly into the project root directory alongside `console.py`.
3.  On launch, ARGUS checks the file presence and displays:
    `Dictionary: rockyou.txt ready (14,344,391 passwords, 133.44 MB)`

---

## 4. Launching & Shutting Down the Platform

ARGUS runs locally and is accessed using either the command line or a web browser.

### 4.1 Starting the Tactical CLI
Execute the following command in your terminal from the project directory:
```bash
python3 console.py
```
*   To disable typewriter loading animations for faster startup, append the `--no-animation` flag or set the environment variable:
    ```bash
    ARGUS_NO_ANIMATION=1 python3 console.py
    ```

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: CLI First Boot & Bootstrapping**
> *Capture the terminal view when executing 'python3 console.py' for the first time, showing the bootstrapping log files, virtual environment creation, and dependency verification.*
> Recommended Filename: `ss_cli_bootstrapping.png`

---

### 4.2 Starting the Web GUI Dashboard
There are three ways to launch the Web GUI:

#### Option A: Dedicated Server Mode (Direct Terminal)
Run the console using the `--gui` command line flag. This starts the Flask web service in background daemon mode:
```bash
python3 console.py --gui
```

#### Option B: Dynamic CLI Launch (From Active Terminal Session)
Type `gui` inside an active terminal shell session. The console will automatically detect a free local port (ranging from 5000 to 5010), launch the Flask web application in a background thread, and trigger your default web browser to open:
```
  argus › gui
  Opening dashboard at http://127.0.0.1:5001/
```

#### Option C: Accessing the Web Portal Manually
Once the server starts via either method above, open any modern web browser and navigate to:
```
http://127.0.0.1:5000
```
*(Note: If port 5000 is occupied, the console will bind to 5001, 5002, etc. Check the port displayed in the CLI on launch).*

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: CLI Launching Web GUI**
> *Capture the terminal showing the output of entering the 'gui' command, demonstrating the daemon server initialization and browser launch confirmation.*
> Recommended Filename: `ss_cli_gui_launch.png`

---

### 4.3 Safe Platform Shutdown
*   **CLI Console**: Type `exit`, `quit`, or press `Ctrl+D` (EOF). This safely shuts down background execution loops and exits the shell.
*   **GUI / Flask Daemon**: Press `Ctrl+C` in the terminal hosting the Flask app. This terminates background processes, sockets, and web routes.

---

## 5. Investigator Profiles & Case Audit Workflows

ARGUS is built to maintain legally defensible logs. When launched interactively, the console walks you through the profile and case setup wizard.

### 5.1 Investigator Profile Selection
1.  On startup, the system scans the local database for existing investigator profiles.
2.  If none exist, you are prompted to create your first profile by entering a display name.
3.  On subsequent boots, you can choose from the menu:
    *   **`1) Use existing profile`**: Select your user profile from a numbered list.
    *   **`2) Create new profile`**: Create a new profile with assigned roles (`investigator`, `supervisor`, `admin`).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Profile Selector CLI Menu**
> *Capture the CLI prompt asking to select an existing investigator profile or create a new profile.*
> Recommended Filename: `ss_cli_profile_selector.png`

---

### 5.2 Active Case Mode Enforcements
After selecting your profile, the system prompts:
`Enable case mode? [y/N] › `
*   **Selecting No (Ad-hoc mode)**: Allows you to run scans without case tracking. The evidence export system is locked, and audits are recorded as ad-hoc events.
*   **Selecting Yes (Case mode)**: Requires you to select an existing open case or create a new case. 

```
  Active Investigation Case mode?
  (yes) — log all actions to a case file; export evidence later
  (no)  — use all tools freely; no case file created

  Enable case mode? [y/N] › y
  
  1) Create new case
  2) Open existing case
  Choose [1/2]: 1
  
  Enter Case Name: Warrant-2026-F
  Enter Case Description: Email lookup search for target identity files.
  Enter Legal Authorization Reference (Warrant/Court Order ID): COURT-ORD-88712
```

The **Authorization Reference** is recorded along with all sensitive scans in `audit.log`.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Case Mode Enforced Prompts**
> *Capture the terminal prompts showing the successful setup of a new case, inputting the description, and setting the legal authorization reference.*
> Recommended Filename: `ss_cli_case_mode_setup.png`

---

## 6. Third-Party APIs & Key Vault Configuration

### 6.1 Setting Keys in CLI
Type `keys list` to see which APIs are configured. To encrypt and set a key, use the following syntax:
```bash
keys set <service> <api_key_value>
```
*   *Services*: `vt` (VirusTotal), `abuse` (AbuseIPDB), `truecaller` (Truecaller installation token), `github` (GitHub Personal Access Token).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Key Vault Configurations (CLI)**
> *Capture the console showing the execution of 'keys list', verifying which API keys are active or unconfigured.*
> Recommended Filename: `ss_cli_keys_list.png`

---

### 6.2 Setting Keys in Web GUI
1.  Open the Web GUI.
2.  Click the **Settings Cog Icon (⚙️)** in the top right header.
3.  Enter the keys in the input fields inside the Settings Modal and click **Save Settings**. The web application will encrypt the keys and save them to the local vault.

---

## 7. The 18 Numbered CLI Core Tools

The command-line interface features an interactive, wizard-driven structure. When you launch a tool by typing its number or command:
1.  **Usage Card**: The console displays the tool name, its description, CLI syntax, and examples.
2.  **API Status**: Checks the local vault and displays if required keys are configured.
3.  **Prompt & Execute**: Prompts you for input fields, runs the search through the Flask API, and displays a formatted box table of results.
4.  **Recursive Prompt Loop**: Displays a prompt: `Do you want to reuse the <tool_name> or see the menu? [y: reuse / n: menu] › `.
    *   Pressing **`y`** reruns the interactive input prompt immediately.
    *   Pressing **`n`** or **Enter** reprints the 18-tool menu card and returns you to the main shell prompt.

---

### Tool 1: IP & Network Scan (`ip`)
*   **Usage / Syntax**: `ip <ip_address>` (e.g. `ip 8.8.8.8`)
*   **What it does**: Gathers threat intelligence and geolocation coordinates for a target IP address.
*   **Input**: An IPv4 or IPv6 address.
*   **APIs**: `ipwho.is` (geo), `Shodan InternetDB` (passive ports), `VirusTotal` & `AbuseIPDB` (reputation scores).
*   **Vault Keys**: `VT_API_KEY` (Optional), `ABUSE_IPDB_KEY` (Optional).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 1 - IP & Network Scan Output**
> *Capture the result table output for 'ip 8.8.8.8' showing geolocation data, open ports, and the reuse prompt.*
> Recommended Filename: `ss_tool1_ip_output.png`

---

### Tool 2: Telecom & Carrier Trace (`phone`)
*   **Usage / Syntax**: `phone <+countrycode_number> [--offline]` (e.g. `phone +919876543210`)
*   **What it does**: Resolves carrier names, international format data, and queries the Truecaller database.
*   **Input**: Mobile phone number prefixed with country code (e.g., `+1` or `+91`).
*   **APIs**: `phonenumbers` local library, `Truecaller API`.
*   **Vault Keys**: `TRUECALLER_ID` (Optional).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 2 - Telecom & Carrier Trace Output**
> *Capture the result table output of a phone lookup, displaying name indicators, line types, and spam metrics.*
> Recommended Filename: `ss_tool2_phone_output.png`

---

### Tool 3: Username Footprint Scan (`username`)
*   **Usage / Syntax**: `username <handle>` (e.g. `username johnsmith`)
*   **What it does**: Asynchronously footprints usernames across 600+ web platforms.
*   **Input**: Profile handle to search.
*   **APIs**: Direct async checks matching `wmn-data.json`.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 3 - Username Footprint Scan Output**
> *Capture the async scan results of a username check, showing the list of platforms where the handle was detected.*
> Recommended Filename: `ss_tool3_username_output.png`

---

### Tool 4: Email Intelligence Suite (`email`)
*   **Usage / Syntax**: `email <email_address>` (e.g. `email target@gmail.com`)
*   **What it does**: Audits email platform registrations, breaches, and mail server status.
*   **Input**: Email address.
*   **APIs**: `Holehe` (registrations), `XposedOrNot` (breaches), `Hudson Rock` (compromised logs), `Google Profile API` (Gaia ID).
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 4 - Email Intelligence Suite Output**
> *Capture the multi-stage email report, showing Holehe site registrations and XposedOrNot leak counts.*
> Recommended Filename: `ss_tool4_email_output.png`

---

### Tool 5: Domain Email Harvest (`emailsite`)
*   **Usage / Syntax**: `emailsite <domain>` (e.g. `emailsite example.com`)
*   **What it does**: Scrapes search engines to identify public emails associated with a domain.
*   **Input**: Target domain.
*   **APIs**: DuckDuckGo search parser.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 5 - Domain Email Harvest Output**
> *Capture the scraped email list returned for a target domain name.*
> Recommended Filename: `ss_tool5_emailsite_output.png`

---

### Tool 6: Deep Domain Crawler (`domaincrawl`)
*   **Usage / Syntax**: `domaincrawl <domain> [max_depth]` (e.g. `domaincrawl example.com 2`)
*   **What it does**: Crawls a domain up to a set depth, extracting contact emails, numbers, and social links.
*   **Input**: Base domain name and link depth limit.
*   **APIs/Libraries**: Local BFS crawler using `httpx`.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 6 - Deep Domain Crawler Output**
> *Capture the crawling log displaying the discovered links, scraped emails, and social media handles.*
> Recommended Filename: `ss_tool6_domaincrawl_output.png`

---

### Tool 7: VirusTotal Reputation Scan (`virustotal`)
*   **Usage / Syntax**: `virustotal <ip_address>` (e.g. `virustotal 8.8.8.8`)
*   **What it does**: Dedicated query to check the VirusTotal reputation database for an IP address.
*   **Input**: Target IP address.
*   **APIs**: VirusTotal API.
*   **Vault Keys**: `VT_API_KEY` (Required).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 7 - VirusTotal Reputation Scan Output**
> *Capture the output table of the VirusTotal reputation scan, demonstrating clean vs malicious engine detection scores.*
> Recommended Filename: `ss_tool7_virustotal_output.png`

---

### Tool 8: AbuseIPDB Threat Reputation (`abuseipdb`)
*   **Usage / Syntax**: `abuseipdb <ip_address>` (e.g. `abuseipdb 8.8.8.8`)
*   **What it does**: Dedicated lookup query to check AbuseIPDB reports and threat confidence scores for an IP address.
*   **Input**: Target IP address.
*   **APIs**: AbuseIPDB API.
*   **Vault Keys**: `ABUSE_IPDB_KEY` (Required).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 8 - AbuseIPDB Threat Reputation Output**
> *Capture the results table containing the abuse confidence score percentage and the list of reports.*
> Recommended Filename: `ss_tool8_abuseipdb_output.png`

---

### Tool 9: Local CIDR Host Discovery (`netscan`)
*   **Usage / Syntax**: `netscan <cidr_block>` (e.g. `netscan 192.168.1.0/24`)
*   **What it does**: High-speed ping sweep across a CIDR subnet block to map active network hosts.
*   **Input**: Subnet CIDR block.
*   **APIs**: Local ping utility execution.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 9 - Local CIDR Host Discovery Output**
> *Capture the hosts table displaying IP addresses, status, and hostnames discovered during the ping sweep.*
> Recommended Filename: `ss_tool9_netscan_output.png`

---

### Tool 10: Subdomain CT-Log Enumerator (`subdomain`)
*   **Usage / Syntax**: `subdomain <base_domain>` (e.g. `subdomain google.com`)
*   **What it does**: Queries Certificate Transparency (CT) logs to find subdomains that have security certificates issued.
*   **Input**: Base domain.
*   **APIs**: `crt.sh`.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 10 - Subdomain CT-Log Enumerator Output**
> *Capture the subdomain list matching certificates resolved via crt.sh.*
> Recommended Filename: `ss_tool10_subdomain_output.png`

---

### Tool 11: MAC Vendor Lookup (`maclookup`)
*   **Usage / Syntax**: `maclookup <mac>` (e.g. `maclookup 00:1A:2B:3C:4D:5E`)
*   **What it does**: Resolves MAC addresses to their hardware manufacturer using the IEEE database.
*   **Input**: MAC address.
*   **APIs**: Local IEEE OUI parsing database (`oui.txt`).
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 11 - MAC Vendor Lookup Output**
> *Capture the MAC vendor search result, displaying the hardware vendor associated with a query.*
> Recommended Filename: `ss_tool11_maclookup_output.png`

---

### Tool 12: Username Dork Generator (`dork`)
*   **Usage / Syntax**: `dork <username>` (e.g. `dork johnsmith`)
*   **What it does**: Generates Google search engine operators (dorks) for a username handle.
*   **Input**: Profile handle.
*   **APIs**: Offline dork compilers, optional DDG status checks.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 12 - Username Dork Generator Output**
> *Capture the compiled list of search engine dork URLs designed for footprinting.*
> Recommended Filename: `ss_tool12_dork_output.png`

---

### Tool 13: GitHub Intel Extractor (`githubintel`)
*   **Usage / Syntax**: `githubintel <username|domain>` (e.g. `githubintel octocat`)
*   **What it does**: Queries the GitHub API for public repositories, extracting commit histories to parse usernames and associated developer email addresses.
*   **Input**: GitHub username or domain query.
*   **APIs**: GitHub REST API.
*   **Vault Keys**: `GITHUB_TOKEN` (Optional - improves API rate limits).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 13 - GitHub Intel Extractor Output**
> *Capture the developer extraction tables, showing repositories, commits, and emails.*
> Recommended Filename: `ss_tool13_githubintel_output.png`

---

### Tool 14: Cryptographic Hash Recovery (`hashcrack`)
*   **Usage / Syntax**: `hashcrack <hash> <type> [wordlist] [salt=..] [mode=prepend|append]` (e.g. `hashcrack 5f4dcc3b5aa765d61d8327deb882cf99 md5`)
*   **What it does**: Executes dictionary attacks using local wordlists to crack MD5, SHA-1, SHA-256, and SHA-512 hashes.
*   **Input**: Hash string, type (md5/sha256/etc), optional salt values, and salt configuration.
*   **APIs**: Local dictionary processor.
*   **Vault Keys**: None (Uses local `rockyou.txt`).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 14 - Cryptographic Hash Recovery Output**
> *Capture the active progress bar and successful password extraction message.*
> Recommended Filename: `ss_tool14_hashcrack_output.png`

---

### Tool 15: PDF Cryptography Lock (`pdfprotect`)
*   **Usage / Syntax**: `pdfprotect <pdf_file_path> <password> [owner_password]` (e.g. `pdfprotect doc.pdf secretPass`)
*   **What it does**: Secures local PDF documents with AES-256 password protection.
*   **Input**: PDF file location path, user password, and optional owner password.
*   **APIs/Libraries**: Local `PyPDF2` lock integration.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 15 - PDF Cryptography Lock Output**
> *Capture the CLI output showing file protection confirmation and path output.*
> Recommended Filename: `ss_tool15_pdfprotect_output.png`

---

### Tool 16: PDF Password Recovery (`pdfcrack`)
*   **Usage / Syntax**: `pdfcrack <locked_pdf_path> [wordlist]` (e.g. `pdfcrack locked_doc.pdf`)
*   **What it does**: Runs dictionary attacks to recover lost passwords for locked PDF files.
*   **Input**: Locked PDF path, path to a custom wordlist.
*   **APIs**: Local `PyPDF2` decryption loops.
*   **Vault Keys**: None.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 16 - PDF Password Recovery Output**
> *Capture the successful password recovery output matching dictionary lines.*
> Recommended Filename: `ss_tool16_pdfcrack_output.png`

---

### Tool 17: Tor OpSec Engine (`tor`)
*   **Usage / Syntax**: `tor [on|off|status|rotate]` (e.g. `tor status`)
*   **What it does**: Toggles and status checks outbound SOCKS proxy routing via the Tor network.
*   **Input**: Target action (on/off/status/rotate).
*   **APIs**: Local SOCKS proxy interface.
*   **Vault Keys**: None (Socks daemon running on port 9050).

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 17 - Tor OpSec Engine Output**
> *Capture the execution of 'tor status' demonstrating proxy routing validation and active IP lookup changes.*
> Recommended Filename: `ss_tool17_tor_output.png`

---

### Tool 18: Truecaller Re-Setup (`truecaller-setup`)
*   **Usage / Syntax**: `truecaller-setup`
*   **What it does**: Triggers OTP validation wizard to update Truecaller authorization tokens.
*   **Input**: Follow instructions to enter mobile number and SMS OTP code.
*   **Vault Keys**: Automatically updates `TRUECALLER_ID` inside the encrypted local vault.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Tool 18 - Truecaller Re-Setup Output**
> *Capture the OTP setup wizard terminal prompts during Truecaller authentication.*
> Recommended Filename: `ss_tool18_truecaller_setup_output.png`

---

## 8. Advanced CLI Commands Reference

ARGUS supports additional direct console actions and helper commands that do not map to the main numbered list.

### 8.1 Direct Scanners & Tools
*   `emailgoogle <email_address>`: Queries Google endpoints to resolve GAIA IDs, account profiles, and avatars.
*   `emailsmtp <email_address>`: Resolves DNS MX servers and runs SMTP handshakes to confirm mailbox availability.
*   `portscan-async <ip_or_cidr_block>`: Runs high-speed asynchronous port sweeps and records server response banners.
*   `deepuser <handle>`: Footprints username accounts across extensive directories using custom settings.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: Advanced CLI Scan Output**
> *Capture the execution output of an advanced command (e.g. 'emailsmtp target@domain.com') displaying detailed connection steps.*
> Recommended Filename: `ss_cli_advanced_scan.png`

---

### 8.2 Configuration & Admin Commands
*   `user add <name> <role>`: Registers a new investigator profile (Requires Admin role).
*   `user list`: Lists active investigator profiles.
*   `case <new|list|open|close|status|off>`: Case tracking configuration commands.
*   `keys <list|set>`: Key vault configuration commands.
*   `export <case|last> [json|html]`: Exports forensic records for investigations.
*   `gui`: Starts background threads and launches the Web GUI.
*   `tour`: Starts the command-line step-by-step tour wizard.
*   `guide`: Displays first-time quick start instructions.
*   `clear`: Clears the screen buffer and reprints the status card.
*   `exit` / `quit`: Exits the CLI environment.

---

## 9. Web GUI Dashboard Tab Specifications

The Web GUI Single Page Application provides visualization capabilities matching the CLI framework.

```
┌────────────────────────────────────────────────────────────────────────┐
│  [🐺] ARGUS LOGO      ACTIVE CASE: [Warrant-2026-F]    SETTINGS [⚙️]    │
├─────────────┬──────────────────────────────────────────────────────────┤
│             │                                                          │
│  Navigation │                     MAIN WORKSPACE                       │
│  ────────── │                                                          │
│  📊 Dashboard│  ┌────────────────────────────────────────────────────┐  │
│  📁 Cases    │  │ [IP Tab] Target IP: [ 8.8.8.8        ] [Run Scan]  │  │
│  🔑 Vault    │  ├────────────────────────────────────────────────────┤  │
│  🕵️ Intel    │  │               Interactive Output                   │  │
│  🛡️ Forensics│  │                                                    │  │
│  🗂️ Reports  │  │ • ISP: Google LLC                                  │  │
│             │  │ • Location: Mountain View, CA                      │  │
│             │  │ • Threat Level: Clean                              │  │
│             │  └────────────────────────────────────────────────────┘  │
└─────────────┴──────────────────────────────────────────────────────────┘
```

---

### 9.1 Dashboard Tab
Overview of the application status, displaying system health metrics, local wordlist configuration paths, and case information cards.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Dashboard Overview**
> *Capture the main Dashboard interface, displaying system metrics and the howling wolf header graphic.*
> Recommended Filename: `ss_gui_dashboard.png`

---

### 9.2 Cases Tab
Manage active investigation cases, configure authorization reference codes, review case details, and archive completed files.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Cases Controller**
> *Capture the Cases management interface, showing active cases list, open/close options, and the authorization fields.*
> Recommended Filename: `ss_gui_cases.png`

---

### 9.3 Vault Tab
Manage API keys for VirusTotal, AbuseIPDB, GitHub, and Truecaller. Clicking edit decrypts and reveals keys in-memory.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Vault Panel**
> *Capture the Vault interface, showing active keys and key updating forms.*
> Recommended Filename: `ss_gui_vault.png`

---

### 9.4 Intelligence Probes Tab
Interactive forms for IP scans, Carrier traces, Username searches, and Email audits. Results are formatted as visual cards.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Intelligence Probes**
> *Capture an intelligence search result inside the Web GUI (e.g. an email registration check showing status highlights).*
> Recommended Filename: `ss_gui_intel_probes.png`

---

### 9.5 Digital Forensics Suite Tab
Includes input forms for running hash cracks, PDF protection, and PDF decryption. Progress meters track active processes.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Digital Forensics Tools**
> *Capture the Forensics panel, showing active hash recovery forms or PDF protect inputs.*
> Recommended Filename: `ss_gui_forensics.png`

---

### 9.6 Onboarding Tour Overlay
The interactive guide overlay that highlights UI controls to walk users through the platform features.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Onboarding Tour**
> *Capture the Guided Tour overlay during an active onboarding run, demonstrating the tooltips highlighting interface components.*
> Recommended Filename: `ss_gui_onboarding_tour.png`

---

### 9.7 Evidence Timeline & Export Manager
Provides dynamic timelines logging all completed scans, with options to download HTML or JSON evidence packages.

---

> [!IMPORTANT]
> **SCREENSHOT PLACEHOLDER: GUI Evidence Timeline**
> *Capture the Evidence Timeline interface, displaying logged event timelines and the PDF/HTML download buttons.*
> Recommended Filename: `ss_gui_evidence_timeline.png`

---

## 10. Forensic Auditing Specifications & Compliance

The platform maintains an immutable audit record matching legal compliance frameworks.
*   **Audit File**: Saved as `audit.log` in the application directory.
*   **Verification Checksums**: Analysts should generate SHA-256 signatures for exported files to ensure record integrity.
    ```bash
    shasum -a 256 evidence_case_last.json > checksum.txt
    ```
*   **Forensic Report Structuring**: If submitting reports in judicial filings, the matching `audit.log` segment and signature values must be attached to the evidence package to prove non-repudiation and prevent data tampering.
