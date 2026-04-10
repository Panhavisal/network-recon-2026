# Network Recon 2026

An interactive Python wrapper around `nmap` for fast network reconnaissance, vulnerability discovery, and clean PDF/Markdown/JSON reporting.

Built for security researchers, sysadmins, and CTF players who want a structured, repeatable way to enumerate hosts, ports, services, and CVEs without re-typing the same `nmap` flags every time.

> **Authorized use only.** Only scan networks and hosts you own or have explicit written permission to test.

---

## Features

- **Interactive menu** — pick a scan, pick a target, get results.
- **CLI mode** — fully scriptable for automation and pipelines.
- **Five scan modes:**
  - `discover` — ping sweep to find live hosts on a subnet.
  - `quick` — top 100 ports, fast triage.
  - `ports` — full TCP port scan with service/version detection.
  - `vuln` — CVE & vulnerability scripts (`vuln`, `vulners`, `exploit`).
  - `full` — all of the above in one shot, plus OS detection.
- **Host pool** — discovered hosts are remembered for the session, so you can scan them by number instead of typing IPs.
- **Batch mode** — run a scan against many hosts in one command.
- **Reports** — every session is exported as Markdown, JSON, and a styled PDF, with parsed findings (open ports, services, CVEs, OS detection).
- **Live colored output** — CVEs and `VULNERABLE` lines are highlighted as `nmap` streams.
- **Graceful Ctrl+C** — interrupting a scan still generates a report of what was found.

---

## Requirements

- Python **3.10+**
- [`nmap`](https://nmap.org/download.html) installed and on your `PATH`
- `sudo` / root (required for SYN scan and OS detection)
- Python packages:
  ```bash
  pip install fpdf2
  ```

---

## Installation

```bash
git clone https://github.com/Panhavisal/network-recon-2026.git
cd network-recon-2026
pip install fpdf2
```

Make sure `nmap` is installed:

```bash
# macOS
brew install nmap

# Debian / Ubuntu
sudo apt install nmap

# Arch
sudo pacman -S nmap
```

---

## Usage

### Interactive mode

```bash
sudo python3 nmap.py
```

You'll get a menu — pick a scan type, enter a target, watch it run.

### CLI mode

```bash
# Full vulnerability scan on a single host
sudo python3 nmap.py --mode full --target 192.168.1.1 --output server1

# Discover live hosts on a /24 and auto-run port + vuln scans on them
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto

# Quick top-100 port scan
sudo python3 nmap.py --mode quick --target 192.168.1.1

# Full port scan with service detection
sudo python3 nmap.py --mode ports --target 192.168.1.1

# CVE / vulnerability scan
sudo python3 nmap.py --mode vuln --target 192.168.1.1
```

### Flags

| Flag | Description |
|------|-------------|
| `--mode` | `discover`, `quick`, `ports`, `vuln`, or `full` |
| `--target`, `-t` | IP, hostname, or CIDR range |
| `--output`, `-o` | Output file prefix (default: `scan`) |
| `--auto` | After `discover`, auto-run port + vuln scans on every live host |
| `--jobs`, `-j` | Parallel workers for batch scans (default: auto from CPU/RAM, `1` = serial) |

---

## Performance — parallel scanning

When you scan multiple hosts in one go (interactive batch, `--auto`, or any
multi-target selection in the menu), scans run in parallel. The worker count
is auto-tuned to your machine:

- **CPU budget:** half the logical CPU count (nmap `-T4` already uses internal
  parallelism — running 1 nmap per core would oversubscribe).
- **RAM budget:** ~400 MB per concurrent scan.
- **Hard cap:** 8 workers, regardless of how big the box is.

Override with `--jobs N`:

```bash
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto            # auto
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto --jobs 4   # force 4
sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto --jobs 1   # serial
```

In parallel mode each host's `nmap` output is buffered and printed as one
contiguous block when that scan finishes, so the terminal stays readable.

For accurate RAM detection install `psutil` (optional — without it the tool
falls back to a conservative 4 GB assumption):

```bash
pip install psutil
```

---

## Output

Each session writes to a `results/` directory:

- `*.txt` — raw `nmap` output per scan
- `report_*.md` — readable Markdown summary
- `report_*.json` — structured findings (great for piping into other tools)
- `report_*.pdf` — styled PDF report with parsed findings, CVEs, services

---

## Project structure

```
.
├── nmap.py              # Entry point
└── core/
    ├── __main__.py      # Module entry, root check, signal handling
    ├── cli.py           # Argparse / CLI mode
    ├── menu.py          # Interactive menu
    ├── scanner.py       # nmap wrappers + finding extraction
    ├── network.py       # Local network detection
    ├── report.py        # Markdown / JSON / PDF report builders
    ├── state.py         # Session state (host pool, log)
    └── colors.py        # ANSI color helpers
```

---

## Forking & credit

You're welcome to fork this project, build on it, and adapt it for your own workflows.

**If you fork or reuse this code, please give credit** by linking back to the original repo:

> Based on [network-recon-2026](https://github.com/Panhavisal/network-recon-2026) by [@Panhavisal](https://github.com/Panhavisal).

A line in your README or a comment in the source is enough — it's appreciated and helps others find the original.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for **educational purposes and authorized security testing only**. The author is not responsible for any misuse or damage caused by this program. Scanning networks without permission is illegal in most jurisdictions. **You are responsible for your own actions.**
