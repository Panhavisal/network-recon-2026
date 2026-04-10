"""Shared state across all modules."""

from datetime import datetime

# Discovered hosts: [{"ip": "...", "hostname": "...", "mac": "...", "vendor": "..."}]
discovered_hosts: list[dict] = []

# Scan session log
session_log: list[dict] = []

# Config
NMAP_BIN = "nmap"
RESULTS_DIR = "scan_results"


def get_discovered_ips() -> list[str]:
    return [h["ip"] for h in discovered_hosts]


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
