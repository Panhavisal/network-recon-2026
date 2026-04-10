# User Guide — Network Recon

A complete walkthrough of how to install, run, and understand this tool.
For the short pitch and feature list, see the [README](README.md).

---

## Table of contents

1. [Install](#install)
2. [First run](#first-run)
3. [Interactive menu — option by option](#interactive-menu--option-by-option)
4. [CLI mode — every flag explained](#cli-mode--every-flag-explained)
5. [Targets you can scan](#targets-you-can-scan)
6. [Parallel scanning](#parallel-scanning)
7. [Reports — Markdown, JSON, PDF](#reports--markdown-json-pdf)
8. [How it works under the hood](#how-it-works-under-the-hood)
9. [Troubleshooting](#troubleshooting)
10. [Legal & ethics](#legal--ethics)

---

## Install

### Requirements

- Python **3.10+**
- [`nmap`](https://nmap.org/download.html) on your `PATH`
- `sudo` / root (needed for SYN scan and OS detection)

### Get the code

```bash
git clone https://github.com/Panhavisal/network-recon-2026.git
cd network-recon-2026
```

### Python dependencies

You **don't need to install anything manually**. On first run the tool detects
missing packages and installs them automatically:

- `fpdf2` — required for PDF reports
- `psutil` — optional, for accurate RAM detection in parallel mode

If auto-install fails (restricted environment, no pip, etc.) install manually:

```bash
pip install fpdf2 psutil
# or, on PEP 668 systems (recent macOS / Debian):
pip install --break-system-packages fpdf2 psutil
```

### Install nmap

```bash
# macOS
brew install nmap

# Debian / Ubuntu
sudo apt install nmap

# Arch
sudo pacman -S nmap
```

---

## First run

```bash
sudo python3 nmap.py
```

You'll see:

```
[*] Checking dependencies...      # only on first run, then silent
[+] fpdf2 installed.

+==========================================================+
|             Network Recon (nmap wrapper)                 |
|                                                          |
|  WARNING: Only scan networks you are authorized to test  |
+==========================================================+

+---------------------------------------+
|           SCAN OPTIONS                |
+---------------------------------------+
|  1. Full Vulnerability Scan           |
|  2. Discover Live Hosts               |
|  3. Port Scan (all ports)             |
|  4. CVE / Vulnerability Scan          |
|  5. Quick Scan (top 100 ports)        |
|  6. Custom nmap Command               |
|  7. Show Discovered Hosts             |
|  8. Auto-Scan My WiFi Network         |
|  0. Exit & Generate Report            |
+---------------------------------------+
  [WiFi: 192.168.1.42 on en0 - network 192.168.1.0/24]

[?] Select option:
```

Press `8` for the fastest path: it auto-detects your WiFi network, sweeps it
for live hosts, and offers a follow-up scan.

When you're done, press `0` to exit and generate reports — or just hit
`Ctrl+C` at any time. Either way, the tool writes a report of everything it
found before exiting.

---

## Interactive menu — option by option

### 1. Full Vulnerability Scan

The deepest single-host scan. Runs `nmap -p- -sS -sV -O -T4 -v --script vuln,vulners,exploit`
which means:

- `-p-` — every TCP port (1-65535)
- `-sS` — TCP SYN scan (stealthy, requires root)
- `-sV` — service & version detection
- `-O` — OS fingerprinting
- `-T4` — aggressive timing
- `--script vuln,vulners,exploit` — run NSE scripts that look up known CVEs

Use this when you have **one host** you want fully audited. Takes minutes.
You'll be asked for an output filename so the raw nmap output gets a
recognizable name.

### 2. Discover Live Hosts

A ping sweep (`nmap -sn -T4`) over a CIDR range. No ports are scanned —
this just tells you **which IPs are alive** so you can scan them next.

After discovery, the tool shows a follow-up menu:

- `a` — Port Scan all discovered hosts
- `b` — CVE Scan all discovered hosts
- `c` — Full Scan (ports + CVE) all discovered hosts
- `q` — Quick Scan (top 100 ports) all discovered hosts
- `s` — Skip (go back to main menu)

Discovered hosts are remembered for the rest of the session, so options 3-5
let you pick them by number instead of typing IPs.

### 3. Port Scan (all ports)

`nmap -p- -sS -sV -T4` — every TCP port + service/version detection on the
target(s) you select. Doesn't run vuln scripts (much faster than option 1).

You can:

- Type a single IP, domain, or CIDR
- Pick a number from the discovered host pool
- Pick multiple numbers like `1,3,5`
- Type `a` to scan all discovered hosts

### 4. CVE / Vulnerability Scan

`nmap -sV -T4 --script vuln,vulners,exploit` — focuses on finding known CVEs
on already-known services. Faster than option 1 because it doesn't scan
every port from scratch (only the default ~1000), but still runs all the
vuln scripts.

### 5. Quick Scan (top 100 ports)

`nmap --top-ports 100 -sS -sV -T4` — covers the 100 most common ports.
Use this for **fast triage** — you'll catch SSH, HTTP, HTTPS, SMB, RDP,
DNS, etc. in seconds without waiting for a full sweep.

### 6. Custom nmap Command

If you know what you're doing, type any extra `nmap` flags you want and
the tool will run them with your target appended:

```
[?] Extra nmap flags (e.g. -sU --top-ports 100): -sU --top-ports 50
```

This runs `nmap -sU --top-ports 50 <your-target>`, captures the output,
and saves the raw text + parsed findings into the session log.

### 7. Show Discovered Hosts

Lists everything in the current session's host pool — IP, hostname, MAC,
vendor. Useful for sanity-checking before you batch-scan.

### 8. Auto-Scan My WiFi Network

The one-button experience: detects your WiFi interface and CIDR, asks
what kind of scan you want, runs it. Replaces the manual sequence
"check WiFi → discover → batch scan."

### 0. Exit & Generate Report

Cleanly exits and writes the final session reports to `scan_results/`.
Same thing happens on `Ctrl+C`.

---

## CLI mode — every flag explained

The same scans are scriptable from the command line. Useful for automation,
cron jobs, CI checks, or when you want a one-liner instead of clicking
through the menu.

```bash
sudo python3 nmap.py [--mode MODE] [--target TARGET] [--output PREFIX] [--auto] [--jobs N]
```

| Flag | Type | Description |
|---|---|---|
| `--mode`, `-m` | choice | One of `full`, `discover`, `quick`, `ports`, `vuln` |
| `--target`, `-t` | string | What to scan: IP, domain, hostname, or CIDR range |
| `--output`, `-o` | string | Filename prefix for the raw nmap output (default: `scan`) |
| `--auto` | flag | Only with `--mode discover`: after discovery, auto-runs port + CVE scans on every live host |
| `--jobs`, `-j` | int | Worker count for batch scans. Default: auto-detect from CPU/RAM. `1` forces serial. |

### Examples

```bash
# Quick triage of one host
sudo python3 nmap.py --mode quick --target 192.168.1.1

# Full vulnerability sweep on one host (saves output as server1_*.txt)
sudo python3 nmap.py --mode full --target 192.168.1.1 --output server1

# Discover an entire /24 then auto-scan every live host (parallel)
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto

# Same, but force 8 parallel workers
sudo python3 nmap.py --mode discover --target 10.0.0.0/24 --auto --jobs 8

# CVE scan on a public target you own
sudo python3 nmap.py --mode vuln --target example.com
```

---

## Targets you can scan

Every target prompt accepts any of these formats:

| Form | Example |
|---|---|
| Single local IP | `192.168.1.10` |
| Single public IP | `1.1.1.1`, `8.8.8.8` |
| Domain / hostname | `example.com`, `scanme.nmap.org` |
| Local CIDR range | `192.168.1.0/24` |
| Public CIDR range | `45.33.32.0/24` |
| Comma-separated list | `host1,host2,1.2.3.4` |
| Number from host pool | `3` (after running Discover) |

`nmap` resolves hostnames automatically, so domains work everywhere IPs do.

> **Important:** scanning public IPs / domains without authorization is
> illegal in most jurisdictions. See [Legal & ethics](#legal--ethics).

---

## Parallel scanning

When you scan multiple hosts at once (interactive batch, `--auto`, or
multi-target selection), the tool runs `nmap` invocations **in parallel**.
The worker count is auto-tuned to your hardware.

### How the auto-tuning works

- **CPU budget:** half your CPU count (`nmap -T4` already uses internal
  parallelism, so we don't want to oversubscribe).
- **RAM budget:** ~400 MB per concurrent scan. Detected via `psutil` if
  installed, otherwise a conservative 4 GB fallback is assumed.
- **Hard cap:** 8 workers maximum, no matter how big the box is.

The chosen value is printed before the batch starts:

```
[*] Parallel mode: 4 worker(s) (8 CPU, 12.3 GB free RAM)
[*] Output is buffered per host and printed when each scan finishes.
```

### Why output is buffered

If multiple `nmap` processes streamed to stdout simultaneously, the terminal
would garble all their output together. Instead, each worker captures its
host's output to a buffer and dumps it as **one contiguous, labeled block**
when its scan finishes — so the terminal stays readable.

### Override

```bash
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto --jobs 1   # serial
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto --jobs 8   # force 8
```

Inside the interactive menu there is no parallel toggle — the auto value
is always used. Use `--jobs 1` from the CLI if you need serial output for
some reason (debugging, demos, etc.).

---

## Reports — Markdown, JSON, PDF

When you exit (`0`, `Ctrl+C`, or end of CLI run), the tool writes **three
files** to `scan_results/`:

| File | Purpose |
|---|---|
| `report_<timestamp>.md` | Human-readable Markdown |
| `report_<timestamp>.json` | Structured data for piping into other tools |
| `report_<timestamp>.pdf` | Styled, **colored** PDF for sharing |

### Report structure

The reports are laid out like a professional security assessment document:

1. **Executive Summary** — Narrative overview of the risk posture, a severity
   breakdown table (CRITICAL/HIGH/MEDIUM/LOW/INFO counts), and the overall
   risk level.
2. **Scope & Methodology** — Which hosts were in scope, which nmap techniques
   were used, and how the severity ratings are defined.
3. **Host Risk Matrix** — Per-host summary table: risk tier, weighted score,
   number of open ports, CVE count, and finding count.
4. **Detailed Findings** — The core of the report. Grouped per host, each
   finding includes:
   - Severity badge (CRITICAL / HIGH / MEDIUM / LOW / INFO)
   - Endpoint (host:port)
   - Evidence (the exact line nmap returned)
   - Description (what the issue is and why it matters)
   - Recommendation (specific, actionable remediation steps)
5. **Remediation Roadmap** — Flat, numbered priority list of every finding
   across all hosts, grouped by severity so you can work top-to-bottom.
6. **Technical Appendix** — Raw data: CVE catalog matches, open-ports
   inventory, OS detections, per-scan log with commands and raw-output
   filenames.
7. **Disclaimer** — Authorization reminder and scope caveats.

### How findings are generated

Findings are produced by a rules-based analysis engine in
[core/recommendations.py](core/recommendations.py) that maps raw nmap data
to structured findings. The engine has three kinds of rules:

- **Service rules** — match on a specific port (e.g. `23/tcp` -> CRITICAL
  Telnet) and/or a banner substring (e.g. `"busybox "` -> HIGH legacy
  BusyBox). ~35 rules out of the box covering plaintext protocols (telnet,
  ftp, rsh, rlogin, rexec, tftp, pop3, imap), databases (redis, mongodb,
  elasticsearch, mysql, postgres, mssql, oracle, couchdb, memcached), file
  shares (smb, nfs, rsync), management interfaces (rdp, vnc, docker api,
  android adb), IoT/camera services (upnp, rtsp, dahua dvr), EoL web servers
  (apache 1.x/2.2, iis 6), and more.
- **OS rules** — flag end-of-life operating systems (Windows XP / 2000 /
  2003 / 7 / Server 2008 / 8 / Server 2012, Linux 2.4 / 2.6 kernels).
- **CVE density** — the number of CVEs reported by the `vulners` nmap script
  against the installed software versions drives a CRITICAL / HIGH / MEDIUM
  finding based on count thresholds (16+ / 6-15 / 1-5).
- **NSE confirmed vulns** — any `VULNERABLE` (confirmed) result from
  `--script vuln` becomes a CRITICAL finding; `LIKELY VULNERABLE` becomes
  HIGH. "NOT VULNERABLE" results are counted but not listed individually.

Each host gets a **risk tier** (the worst finding's severity) and a
**weighted score** (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5). Hosts with no
findings still appear in the scope table but are skipped from the detailed
findings section.

### Adding your own rules

Edit [core/recommendations.py](core/recommendations.py), append a dict to
`SERVICE_RULES` or `OS_RULES` following the schema of existing entries:

```python
{
    "id": "SVC-EXAMPLE",
    "port": "9999/tcp",            # exact port, optional
    "banner": "exampleapp/",        # banner substring, optional (case-insensitive)
    "severity": "HIGH",
    "title": "Example service exposed",
    "description": "Why this is a problem...",
    "recommendation": "How to fix it...",
}
```

At least one of `port` or `banner` must be present. If both are set, both
must match. Changes take effect on the next scan run — no build step.

### PDF colors

The PDF builder applies severity-based coloring throughout the document:

| Color | Meaning |
|---|---|
| **Dark blue** | Section headers (`##`) and sub-headers (`###`) |
| **Light blue fill** | Table header rows |
| **Dark red bold** | `CRITICAL`, `VULNERABLE`, `CVE-...` |
| **Orange bold** | `HIGH`, `FAILED` |
| **Yellow bold** | `MEDIUM`, `WARNING` |
| **Green bold** | `SUCCESS`, `LOW` |
| **Grey italic** | Footer / dim text |

So when you skim the PDF you can spot all the findings worth caring about
at a glance — anything red is what to fix first.

### JSON output

The JSON file contains the raw `session_log` (one entry per scan) plus the
discovered hosts list. Each scan entry has:

```json
{
  "time": "2026-04-10T13:58:01.639924",
  "description": "Full port scan with service detection on 192.168.1.1",
  "command": "nmap -p- -sS -sV -T4 -v 192.168.1.1 -oN scan_results/...",
  "return_code": 0,
  "output_file": "scan_results/ports_2026-04-10_13-57-15.txt",
  "findings": {
    "hosts_up": 1,
    "open_ports": ["..."],
    "cves": ["CVE-2021-42385", "..."],
    "services": ["..."],
    "os_detected": ["..."],
    "vulns": ["..."]
  }
}
```

Pipe this into anything: `jq`, a SIEM, a custom dashboard, etc.

### Raw nmap output

Every scan also writes its own raw `nmap` output to `scan_results/<mode>_<timestamp>.txt`,
linked from the report's "Raw output" line. So the parsed findings in the
report are always cross-referenced with the unmodified `nmap` log.

---

## How it works under the hood

If you want to read or modify the source, here's the layout:

```
.
├── nmap.py                  # Tiny entry point: runs `python -m core`
├── README.md                # Project pitch
├── USAGE.md                 # This file
├── LICENSE                  # MIT
└── core/
    ├── __main__.py          # Root check, dependency check, signal handling, dispatch
    ├── deps.py              # Auto-detect & install missing Python packages on startup
    ├── concurrency.py       # CPU/RAM-aware worker count for parallel scans
    ├── cli.py               # argparse, CLI mode wiring
    ├── menu.py              # Interactive menu loop and target prompts
    ├── scanner.py           # nmap subprocess wrapper, scan modes, parallel batch
    ├── network.py           # WiFi/local network auto-detection (macOS + Linux)
    ├── state.py             # Shared session_log + discovered_hosts (with locks in scanner.py)
    ├── report.py            # Markdown / JSON / colored-PDF report builders
    └── colors.py            # ANSI terminal color helpers
```

### Lifecycle of a scan

1. `nmap.py` is just `runpy.run_module("core")` → loads `core/__main__.py`.
2. `__main__.py` checks for root, calls `ensure_dependencies()` (auto-installs
   missing pip packages), installs a SIGINT handler that always generates a
   report on exit, then dispatches to either `cli_mode()` or `interactive_menu()`.
3. The selected scan mode calls `run_nmap()` in `scanner.py`, which:
   - Builds the `nmap` argv
   - Spawns it via `subprocess.Popen` with `stdout=PIPE`
   - Streams output line-by-line (or buffers it under `_print_lock` if running
     in a parallel worker thread)
   - Parses findings via `extract_findings()` (regex over the nmap text)
   - Appends a structured entry to `session_log` (under `_log_lock`)
4. When the user exits, `generate_reports()` reads `session_log` + `discovered_hosts`,
   builds the Markdown via `build_markdown()`, then converts that same Markdown
   to JSON and a colored PDF.

### Parallel scanning internals

`scan_batch()` in `scanner.py` is the entry point for multi-host scans:

1. `optimal_workers()` from `core/concurrency.py` picks a worker count based on
   `os.cpu_count()` and (if `psutil` is installed) available RAM.
2. If workers ≤ 1 → serial loop (preserves the original live-streaming
   behavior).
3. Otherwise → `ThreadPoolExecutor(max_workers=workers)`. Each future runs
   `_run_quiet(scan_fn, ip, tag)`, which sets a thread-local `_ctx.quiet = True`
   flag, calls the scan function, then resets.
4. `run_nmap()` checks `_ctx.quiet` on entry. If true, it suppresses live
   printing and instead buffers all output, then prints the entire block
   atomically under `_print_lock` when the scan finishes.
5. `session_log.append(...)` is wrapped in `_log_lock`, so concurrent workers
   never corrupt the shared list.

### How findings are extracted

`extract_findings()` in `scanner.py` parses every line of nmap output looking for:

- `Nmap scan report for <host>` → tracks the current host
- `Host is up` → increments host count
- Lines containing `/tcp` or `/udp` with `open` → open port + service
- `OS details:` / `Running:` → OS fingerprint
- `CVE-yyyy-nnnn` → CVE list (de-duplicated)
- `VULNERABLE` → vulnerability indicator

These structured findings are saved alongside the raw output in `session_log`,
so the report can show pretty tables without re-parsing nmap text later.

---

## Troubleshooting

### "This script requires root privileges"

Run with `sudo`. The SYN scan (`-sS`) and OS detection (`-O`) need raw socket
access.

### "nmap not found"

Install nmap (`brew install nmap` / `apt install nmap`) and make sure it's
on your `PATH` for the user running the script (root, if you're using `sudo`).

### "fpdf2 is required for PDF reports"

The auto-installer should handle this on first run. If it fails:

```bash
sudo python3 -m pip install --break-system-packages fpdf2
```

(Use the same `python3` your script runs with — usually whatever `sudo python3`
resolves to, not your user `python3`.)

### "PDF generation failed: ..."

Look at the full traceback printed under the error line. Common causes:

- Disk full
- `scan_results/` not writable
- A new Unicode character not in the `_UNICODE_FALLBACKS` table in `report.py`
  (just add it)

Markdown and JSON reports are still written before the PDF step, so you don't
lose data even if the PDF fails.

### Parallel scans output is interleaved / unreadable

That shouldn't happen — output is buffered per host and printed under a lock.
If you're hitting it, file an issue with your terminal/OS info.

### "Externally managed environment" pip error

Modern Python (PEP 668) refuses system-wide installs. The auto-installer in
`core/deps.py` retries with `--break-system-packages`. If you want to avoid
that, run inside a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fpdf2 psutil
sudo .venv/bin/python3 nmap.py
```

### Scans are slow

- Are you running serial? Try without `--jobs 1`.
- Is `-T4` aggressive enough? Use Custom Mode (option 6) and pass `-T5` (max).
- Are you scanning a CIDR over the public internet? That's slow regardless.

---

## Legal & ethics

**Only scan networks you own or have explicit written permission to test.**

Active port scanning is a probing activity that:

- Is illegal under computer-misuse laws in most jurisdictions if done without
  authorization (e.g. Computer Fraud and Abuse Act in the US, Computer Misuse
  Act in the UK, Article 615 ter in Italy, etc.)
- Can trigger your ISP's abuse desk
- Can trigger IDS / WAF alerts and get you banned from services
- Can be considered malicious activity by SOC teams

**Legitimate uses include:**

- Auditing your own LAN, home router, lab equipment
- Pentesting under a written engagement (with scope)
- CTF and security training environments
- `scanme.nmap.org` — explicitly opened by the nmap project for testing

**Don't:**

- Scan hosts or networks you don't own without permission
- Use this against employer infrastructure without going through your security
  team
- Run aggressive timing (`-T4`/`-T5`) against fragile production systems
  without warning the owners

The author of this tool is not responsible for misuse.
