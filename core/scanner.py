"""Nmap scan functions — discovery, ports, vuln, full, quick."""

import os
import re
import subprocess
import threading
import time
from datetime import datetime

from .state import (
    NMAP_BIN, RESULTS_DIR,
    session_log, discovered_hosts, get_discovered_ips, timestamp,
)
from .colors import red, yellow, green, cyan, bold, dim, progress


# Locks for thread-safe parallel scanning
_log_lock = threading.Lock()    # guards session_log + discovered_hosts mutations
_print_lock = threading.Lock()  # serializes per-host output blocks in parallel mode

# Per-thread context: when set, run_nmap buffers output instead of streaming live
_ctx = threading.local()


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


def _colorize(line: str) -> str:
    """Apply severity coloring to a single nmap output line."""
    if "CVE-" in line:
        return red(line.rstrip()) + "\n"
    if "VULNERABLE" in line.upper():
        return red(line.rstrip()) + "\n"
    if "open" in line and ("/tcp" in line or "/udp" in line):
        return yellow(line.rstrip()) + "\n"
    return line


def run_nmap(args: list[str], description: str, out_file: str | None = None) -> str | None:
    """Run nmap with the given arguments, stream output live, and optionally save to file.

    When called from a worker thread that has set ``_ctx.quiet = True`` (via
    ``_run_quiet``), output is buffered and printed atomically as one block when
    the scan finishes — keeps the terminal readable in parallel mode.
    """
    quiet = getattr(_ctx, "quiet", False)
    tag = getattr(_ctx, "tag", "")

    cmd = [NMAP_BIN] + args
    if out_file:
        ensure_results_dir()
        cmd += ["-oN", out_file]

    header_label = f"[{tag}] " if tag else ""

    if not quiet:
        print(f"\n{cyan('=' * 60)}")
        print(f"{bold('[*]')} {header_label}{description}")
        print(f"{dim('[*] Command:')} {' '.join(cmd)}")
        print(f"{cyan('=' * 60)}\n")

    started = time.monotonic()
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
            output_lines.append(line)
            if not quiet:
                print(_colorize(line), end="")
        process.wait()
        elapsed = time.monotonic() - started
        full_output = "".join(output_lines)

        entry = {
            "time": datetime.now().isoformat(),
            "description": description,
            "command": " ".join(cmd),
            "return_code": process.returncode,
            "output_file": out_file,
            "findings": extract_findings(full_output),
        }
        with _log_lock:
            session_log.append(entry)

        if quiet:
            # Print the whole block atomically so parallel workers don't garble each other.
            with _print_lock:
                print(f"\n{cyan('=' * 60)}")
                print(f"{bold('[*]')} {header_label}{description} {dim(f'({elapsed:.1f}s)')}")
                print(f"{dim('[*] Command:')} {' '.join(cmd)}")
                print(f"{cyan('=' * 60)}")
                for line in output_lines:
                    print(_colorize(line), end="")
                if process.returncode == 0:
                    if out_file:
                        print(f"{green('[+]')} {header_label}Results saved to: {out_file}")
                else:
                    print(f"{red('[!]')} {header_label}nmap exited with code {process.returncode}")
        else:
            if process.returncode == 0:
                if out_file:
                    print(f"\n{green('[+]')} Results saved to: {out_file}")
            else:
                print(f"\n{red('[!]')} nmap exited with code {process.returncode}")

        return full_output

    except FileNotFoundError:
        with _print_lock:
            print(f"{red('[!]')} nmap not found. Make sure it is installed and in PATH.")
        return None
    except KeyboardInterrupt:
        with _print_lock:
            print(f"\n{yellow('[!]')} Scan interrupted by user.")
        try:
            process.terminate()
        except Exception:
            pass
        with _log_lock:
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
                with _log_lock:
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

def _run_quiet(scan_fn, ip: str, tag: str):
    """Worker entry point: mark thread as quiet, run scan, restore."""
    _ctx.quiet = True
    _ctx.tag = tag
    try:
        scan_fn(ip)
    finally:
        _ctx.quiet = False
        _ctx.tag = ""


def scan_batch(ips: list[str], scan_fn, action_name: str = "Scanning", jobs: int | None = None):
    """Run a scan function on multiple IPs.

    With multiple workers, scans run in parallel and each host's output is
    buffered then printed atomically when its scan finishes. With one worker
    (or one host), behavior is identical to the old serial path.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from .concurrency import optimal_workers, describe_workers

    total = len(ips)
    if total == 0:
        return

    workers = optimal_workers(total, user_override=jobs)

    if workers <= 1:
        for i, ip in enumerate(ips, 1):
            print(f"\n{progress(i, total, ip, action_name)}")
            scan_fn(ip)
    else:
        print(f"\n{cyan('[*]')} Parallel mode: {describe_workers(workers)}")
        print(f"{dim('[*] Output is buffered per host and printed when each scan finishes.')}")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(_run_quiet, scan_fn, ip, f"{idx}/{total} {ip}"): ip
                for idx, ip in enumerate(ips, 1)
            }
            done = 0
            for fut in as_completed(futures):
                done += 1
                try:
                    fut.result()
                except Exception as e:
                    ip = futures[fut]
                    with _print_lock:
                        print(f"{red('[!]')} Scan failed for {ip}: {e}")
                with _print_lock:
                    print(f"{cyan('[*]')} Progress: {done}/{total} host(s) finished.")

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
