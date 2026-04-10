"""Nmap scan functions — discovery, ports, vuln, full, quick."""

import os
import re
import subprocess
from datetime import datetime

from .state import (
    NMAP_BIN, RESULTS_DIR,
    session_log, discovered_hosts, get_discovered_ips, timestamp,
)
from .colors import red, yellow, green, cyan, bold, dim, progress


# ── Helpers ─────────────────────────────────────────────────────────────────

def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def output_path(name: str) -> str:
    return os.path.join(RESULTS_DIR, f"{name}_{timestamp()}.txt")


def extract_findings(output: str) -> dict:
    """Parse nmap output for key findings."""
    findings = {
        "hosts_up": 0,
        "hosts": [],
        "open_ports": [],
        "os_detected": [],
        "cves": [],
        "vulns": [],
        "services": [],
    }

    current_host = None

    for line in output.splitlines():
        stripped = line.strip()

        match = re.match(r"Nmap scan report for (.+)", stripped)
        if match:
            current_host = match.group(1)
            findings["hosts"].append(current_host)

        if "Host is up" in line:
            findings["hosts_up"] += 1

        # Open ports
        if "/tcp" in stripped or "/udp" in stripped:
            parts = stripped.split()
            if len(parts) >= 3 and parts[1] == "open":
                port_info = stripped
                if current_host:
                    port_info = f"{current_host} — {stripped}"
                findings["open_ports"].append(stripped)
                findings["services"].append(port_info)

        # OS detection
        if "OS details:" in stripped or "Running:" in stripped:
            findings["os_detected"].append(stripped)

        # CVEs
        if "CVE-" in stripped.upper():
            cves = re.findall(r"CVE-\d{4}-\d+", stripped, re.IGNORECASE)
            for cve in cves:
                if cve.upper() not in [c.upper() for c in findings["cves"]]:
                    findings["cves"].append(cve.upper())

        # Vulnerability findings
        if "VULNERABLE" in stripped.upper():
            findings["vulns"].append(stripped)

    return findings


def run_nmap(args: list[str], description: str, out_file: str | None = None) -> str | None:
    """Run nmap with the given arguments, stream output live, and optionally save to file."""
    cmd = [NMAP_BIN] + args
    if out_file:
        ensure_results_dir()
        cmd += ["-oN", out_file]

    print(f"\n{cyan('=' * 60)}")
    print(f"{bold('[*]')} {description}")
    print(f"{dim('[*] Command:')} {' '.join(cmd)}")
    print(f"{cyan('=' * 60)}\n")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        output_lines = []
        for line in process.stdout:
            # Color CVEs and VULNERABLE in output
            display = line
            if "CVE-" in line:
                display = red(line.rstrip()) + "\n"
            elif "VULNERABLE" in line.upper():
                display = red(line.rstrip()) + "\n"
            elif "open" in line and ("/tcp" in line or "/udp" in line):
                display = yellow(line.rstrip()) + "\n"
            print(display, end="")
            output_lines.append(line)
        process.wait()
        full_output = "".join(output_lines)

        entry = {
            "time": datetime.now().isoformat(),
            "description": description,
            "command": " ".join(cmd),
            "return_code": process.returncode,
            "output_file": out_file,
            "findings": extract_findings(full_output),
        }
        session_log.append(entry)

        if process.returncode == 0:
            if out_file:
                print(f"\n{green('[+]')} Results saved to: {out_file}")
        else:
            print(f"\n{red('[!]')} nmap exited with code {process.returncode}")

        return full_output

    except FileNotFoundError:
        print(f"{red('[!]')} nmap not found. Make sure it is installed and in PATH.")
        return None
    except KeyboardInterrupt:
        print(f"\n{yellow('[!]')} Scan interrupted by user.")
        process.terminate()
        session_log.append({
            "time": datetime.now().isoformat(),
            "description": description,
            "command": " ".join(cmd),
            "return_code": -1,
            "output_file": out_file,
            "findings": {"status": "interrupted"},
        })
        return None


# ── Scan Modes ──────────────────────────────────────────────────────────────

def scan_full(target: str, output_name: str):
    """Full vulnerability scan with OS detection, service versions, and vuln scripts."""
    out = output_path(output_name)
    run_nmap(
        [
            "-p-", "-sS", "-sV", "-O", "-T4", "-v",
            "--script", "vuln,vulners,exploit",
            "--script-args", "vulners.showall=true",
            target,
        ],
        f"Full vulnerability scan on {target}",
        out,
    )


def scan_discover(target: str):
    """Ping sweep to find all live hosts. Only saves hosts that are UP."""
    out = output_path("discovery")
    output = run_nmap(
        ["-sn", "-T4", "-v", target],
        f"Host discovery (ping sweep) on {target}",
        out,
    )
    if not output:
        return

    lines = output.splitlines()
    new_hosts = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        match = re.match(r"Nmap scan report for (.+)", stripped)
        if match:
            host_str = match.group(1)

            # Extract hostname and IP
            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", host_str)
            if ip_match:
                ip = ip_match.group(1)
                hostname = host_str.split("(")[0].strip()
            else:
                ip = host_str.strip()
                hostname = ""

            # Look ahead for "Host is up", MAC address
            is_up = False
            mac = ""
            vendor = ""
            for j in range(i + 1, min(i + 5, len(lines))):
                next_line = lines[j].strip()
                if next_line.startswith("Nmap scan report for"):
                    break
                if "Host is up" in next_line:
                    is_up = True
                mac_match = re.match(
                    r"MAC Address:\s+([0-9A-Fa-f:]+)\s*\(?(.*?)\)?$", next_line
                )
                if mac_match:
                    mac = mac_match.group(1)
                    vendor = mac_match.group(2).strip().rstrip(")")

            if is_up:
                existing_ips = get_discovered_ips()
                if ip not in existing_ips:
                    host_entry = {
                        "ip": ip,
                        "hostname": hostname,
                        "mac": mac,
                        "vendor": vendor,
                    }
                    discovered_hosts.append(host_entry)
                    new_hosts.append(host_entry)

        i += 1

    if new_hosts:
        print(f"\n{green('[+]')} {bold(str(len(new_hosts)))} live host(s) saved to target pool:")
        _print_host_table(new_hosts)
        print(f"\n[*] Total hosts in pool: {bold(str(len(discovered_hosts)))}")
    else:
        print(f"\n{yellow('[*]')} No new live hosts found.")


def scan_ports(target: str):
    """Find all open ports on a target with service versions."""
    out = output_path("ports")
    run_nmap(
        ["-p-", "-sS", "-sV", "-T4", "-v", target],
        f"Full port scan with service detection on {target}",
        out,
    )


def scan_quick(target: str):
    """Quick scan — top 100 ports only. Much faster than full port scan."""
    out = output_path("quick")
    run_nmap(
        ["--top-ports", "100", "-sS", "-sV", "-T4", "-v", target],
        f"Quick scan (top 100 ports) on {target}",
        out,
    )


def scan_vuln(target: str):
    """Scan for CVEs and vulnerabilities on a target."""
    out = output_path("vuln")
    run_nmap(
        [
            "-sV", "-T4", "-v",
            "--script", "vuln,vulners,exploit",
            "--script-args", "vulners.showall=true",
            target,
        ],
        f"Vulnerability/CVE scan on {target}",
        out,
    )


# ── Batch scanning with progress ───────────────────────────────────────────

def scan_batch(ips: list[str], scan_fn, action_name: str = "Scanning"):
    """Run a scan function on multiple IPs with progress tracking."""
    total = len(ips)
    for i, ip in enumerate(ips, 1):
        print(f"\n{progress(i, total, ip, action_name)}")
        scan_fn(ip)
    print(f"\n{green('[+]')} Batch complete: {total} host(s) scanned.")


# ── Display helpers ─────────────────────────────────────────────────────────

def _print_host_table(hosts: list[dict]):
    """Print a formatted table of hosts with colors."""
    print(f"    {bold('#'):<14} {bold('IP'):<27} {bold('Hostname'):<39} {bold('MAC/Vendor')}")
    print(f"    {'-'*5} {'-'*18} {'-'*30} {'-'*25}")
    for idx, h in enumerate(hosts, 1):
        hostname_col = h.get("hostname") or dim("-")
        vendor_col = h.get("vendor") or h.get("mac") or dim("-")
        print(f"    {idx:<5} {h['ip']:<18} {hostname_col:<30} {vendor_col}")
