"""CLI argument parsing for non-interactive mode."""

import argparse

from .state import discovered_hosts, get_discovered_ips
from .scanner import scan_full, scan_discover, scan_ports, scan_quick, scan_vuln, scan_batch
from .report import generate_reports


def cli_mode() -> bool:
    """Parse CLI args and run scan. Returns False if no args (-> interactive mode)."""
    parser = argparse.ArgumentParser(
        description="Network Recon — nmap wrapper with PDF reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 nmap.py --mode full --target 192.168.1.1 --output server1
  sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto
  sudo python3 nmap.py --mode quick --target 192.168.1.1
  sudo python3 nmap.py --mode ports --target 192.168.1.1
  sudo python3 nmap.py --mode vuln --target 192.168.1.1
        """,
    )
    parser.add_argument("--mode", choices=["full", "discover", "ports", "quick", "vuln"],
                        help="Scan mode")
    parser.add_argument("--target", "-t", help="Target IP, hostname, or CIDR range")
    parser.add_argument("--output", "-o", default="scan", help="Output file name prefix (default: scan)")
    parser.add_argument("--auto", action="store_true",
                        help="After discovery, auto-run port + vuln scan on all live hosts")
    parser.add_argument("--jobs", "-j", type=int, default=None,
                        help="Parallel scan workers for batch scans (default: auto-detect from CPU/RAM, 1 = serial)")

    args = parser.parse_args()

    # No arguments -> interactive mode
    if args.mode is None and args.target is None:
        return False

    if not args.target:
        parser.error("--target is required in CLI mode")

    if args.mode == "full":
        scan_full(args.target, args.output)
    elif args.mode == "discover":
        scan_discover(args.target)
        if args.auto and discovered_hosts:
            ips = get_discovered_ips()
            print(f"\n[*] --auto: Running port + CVE scan on {len(ips)} live host(s)...\n")
            scan_batch(ips, scan_ports, "Port scanning", jobs=args.jobs)
            scan_batch(ips, scan_vuln, "CVE scanning", jobs=args.jobs)
    elif args.mode == "quick":
        scan_quick(args.target)
    elif args.mode == "ports":
        scan_ports(args.target)
    elif args.mode == "vuln":
        scan_vuln(args.target)

    generate_reports()
    return True
