"""Interactive menu for the scanner."""

import signal

from .state import discovered_hosts, get_discovered_ips
from .scanner import (
    scan_full, scan_discover, scan_ports, scan_quick, scan_vuln,
    scan_batch, run_nmap, output_path, _print_host_table,
)
from .network import get_wifi_network
from .report import generate_reports
from .colors import bold, cyan, green, yellow, red, dim


def _pick_target(prompt: str) -> str | None:
    """Let user type an IP or pick from discovered hosts."""
    if discovered_hosts:
        print(f"\n[*] Discovered hosts ({len(discovered_hosts)}):")
        _print_host_table(discovered_hosts)
        print(f"    Or type an IP/CIDR manually.")
        answer = input(f"[?] {prompt} (number or IP): ").strip()
        if answer.isdigit():
            idx = int(answer)
            if 1 <= idx <= len(discovered_hosts):
                return discovered_hosts[idx - 1]["ip"]
            print(red("[!] Invalid selection."))
            return None
        return answer if answer else None
    else:
        answer = input(f"[?] {prompt}: ").strip()
        return answer if answer else None


def _pick_targets(prompt: str) -> list[str]:
    """Let user select one, multiple, or all discovered hosts."""
    if discovered_hosts:
        print(f"\n[*] Discovered hosts ({len(discovered_hosts)}):")
        _print_host_table(discovered_hosts)
        print(f"    a. All hosts")
        print(f"    Or type an IP manually.")
        answer = input(f"[?] {prompt} (numbers like 1,3,5 / 'a' for all / IP): ").strip()

        if not answer:
            print(red("[!] Target is required."))
            return []

        if answer.lower() == "a":
            ips = get_discovered_ips()
            print(green(f"[*] Selected all {len(ips)} host(s)."))
            return ips

        # Comma-separated numbers
        if all(part.strip().isdigit() for part in answer.split(",")):
            selected = []
            for part in answer.split(","):
                idx = int(part.strip())
                if 1 <= idx <= len(discovered_hosts):
                    selected.append(discovered_hosts[idx - 1]["ip"])
                else:
                    print(yellow(f"[!] Skipping invalid index: {idx}"))
            if selected:
                print(green(f"[*] Selected {len(selected)} host(s): {', '.join(selected)}"))
                return selected
            print(red("[!] No valid hosts selected."))
            return []

        # Single number
        if answer.isdigit():
            idx = int(answer)
            if 1 <= idx <= len(discovered_hosts):
                return [discovered_hosts[idx - 1]["ip"]]
            print(red("[!] Invalid selection."))
            return []

        return [answer]
    else:
        answer = input(f"[?] Target IP: ").strip()
        if not answer:
            print(red("[!] Target is required."))
            return []
        return [answer]


def _show_hosts():
    if not discovered_hosts:
        print(yellow("\n[*] No hosts discovered yet. Run option 2 first."))
        return
    print(f"\n{green('[+]')} Discovered hosts ({len(discovered_hosts)}):")
    _print_host_table(discovered_hosts)


def _follow_up_menu():
    """After discovery, ask user what to do next."""
    if not discovered_hosts:
        return

    print(f"\n+------------------------------------------+")
    print(f"|  {bold('Hosts found! What do you want to do?')}    |")
    print(f"+------------------------------------------+")
    print(f"|  a. Port Scan all discovered hosts       |")
    print(f"|  b. CVE Scan all discovered hosts        |")
    print(f"|  c. Full Scan (ports + CVE) all hosts    |")
    print(f"|  q. Quick Scan (top 100 ports) all hosts |")
    print(f"|  s. Skip — go back to main menu          |")
    print(f"+------------------------------------------+")

    follow = input("\n[?] Select: ").strip().lower()
    ips = get_discovered_ips()

    if follow == "a":
        scan_batch(ips, scan_ports, "Port scanning")
    elif follow == "b":
        scan_batch(ips, scan_vuln, "CVE scanning")
    elif follow == "c":
        print(f"\n[*] Running port + CVE scan on {len(ips)} host(s)...\n")
        for i, ip in enumerate(ips, 1):
            from .colors import progress
            print(f"\n{progress(i, len(ips), ip, 'Full scanning')}")
            scan_ports(ip)
            scan_vuln(ip)
    elif follow == "q":
        scan_batch(ips, scan_quick, "Quick scanning")
    else:
        print(dim("[*] Skipped. You can scan them later from the main menu."))


def interactive_menu():
    """Main interactive loop with graceful Ctrl+C handling."""

    # Handle Ctrl+C gracefully at any point
    def _handle_sigint(sig, frame):
        print(f"\n\n{yellow('[!]')} Interrupted. Generating report before exit...\n")
        generate_reports()
        print(f"\n{dim('[*] Goodbye.')}\n")
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _handle_sigint)

    print(f"""
{cyan('+')}{'=' * 58}{cyan('+')}
|{bold('             Network Recon (nmap wrapper)')              }|
|                                                          |
|  {yellow('WARNING: Only scan networks you are authorized to test')} |
{cyan('+')}{'=' * 58}{cyan('+')}
    """)

    while True:
        print(f"\n+---------------------------------------+")
        print(f"|           {bold('SCAN OPTIONS')}                |")
        print(f"+---------------------------------------+")
        print(f"|  1. Full Vulnerability Scan           |")
        print(f"|  2. Discover Live Hosts               |")
        print(f"|  3. Port Scan (all ports)             |")
        print(f"|  4. CVE / Vulnerability Scan          |")
        print(f"|  5. Quick Scan (top 100 ports)        |")
        print(f"|  6. Custom nmap Command               |")
        print(f"|  7. Show Discovered Hosts             |")
        print(f"|  8. Auto-Scan My WiFi Network         |")
        print(f"|  0. Exit & Generate Report            |")
        print(f"+---------------------------------------+")

        wifi = get_wifi_network()
        if wifi:
            wifi_text = f"[WiFi: {wifi['ip']} on {wifi['interface']} — network {wifi['cidr']}]"
            print(f"  {dim(wifi_text)}")
        if discovered_hosts:
            host_text = f"[{len(discovered_hosts)} live host(s) in target pool]"
            print(f"  {green(host_text)}")

        try:
            choice = input(f"\n[?] Select option: ").strip()
        except EOFError:
            choice = "0"

        if choice == "1":
            target = _pick_target("Target (IP/range/CIDR)")
            if not target:
                continue
            name = input("[?] Output name (e.g. server1): ").strip() or "full_scan"
            scan_full(target, name)

        elif choice == "2":
            wifi = get_wifi_network()
            if wifi:
                print(f"[*] WiFi detected: {bold(wifi['cidr'])}")
                use_wifi = input(f"[?] Use {wifi['cidr']}? (Y/n): ").strip().lower()
                if use_wifi in ("", "y", "yes"):
                    target = wifi["cidr"]
                else:
                    target = input("[?] Network range (e.g. 192.168.1.0/24): ").strip()
            else:
                target = input("[?] Network range (e.g. 192.168.1.0/24): ").strip()
            if not target:
                print(red("[!] Target is required."))
                continue
            scan_discover(target)
            _follow_up_menu()

        elif choice == "3":
            targets = _pick_targets("Select target(s) for port scan")
            if targets:
                scan_batch(targets, scan_ports, "Port scanning")

        elif choice == "4":
            targets = _pick_targets("Select target(s) for CVE scan")
            if targets:
                scan_batch(targets, scan_vuln, "CVE scanning")

        elif choice == "5":
            targets = _pick_targets("Select target(s) for quick scan")
            if targets:
                scan_batch(targets, scan_quick, "Quick scanning")

        elif choice == "6":
            target = _pick_target("Target")
            if not target:
                continue
            extra = input("[?] Extra nmap flags (e.g. -sU --top-ports 100): ").strip()
            args = extra.split() + [target] if extra else [target]
            out = output_path("custom")
            run_nmap(args, f"Custom scan on {target}", out)

        elif choice == "7":
            _show_hosts()

        elif choice == "8":
            _wifi_auto_scan()

        elif choice == "0":
            generate_reports()
            print(f"\n{dim('[*] Goodbye.')}\n")
            break

        else:
            print(red("[!] Invalid option."))


def _wifi_auto_scan():
    """Auto-detect WiFi network and offer scan options."""
    wifi = get_wifi_network()
    if not wifi:
        print(red("[!] Could not detect WiFi network. Are you connected?"))
        return

    print(f"\n{green('[+]')} Detected WiFi network:")
    print(f"    Interface: {bold(wifi['interface'])}")
    print(f"    Your IP:   {bold(wifi['ip'])}")
    print(f"    Network:   {bold(wifi['cidr'])}")

    print(f"\n+------------------------------------------+")
    print(f"|  {bold('What do you want to scan?')}               |")
    print(f"+------------------------------------------+")
    print(f"|  a. Discover all live hosts              |")
    print(f"|  b. Discover + Port Scan all hosts       |")
    print(f"|  c. Discover + CVE Scan all hosts        |")
    print(f"|  d. Discover + Full (ports + CVE) all    |")
    print(f"|  q. Discover + Quick Scan (top 100)      |")
    print(f"|  s. Skip                                 |")
    print(f"+------------------------------------------+")

    auto_choice = input("\n[?] Select: ").strip().lower()

    if auto_choice == "s":
        print(dim("[*] Skipped."))
        return

    scan_discover(wifi["cidr"])
    ips = get_discovered_ips()

    if not ips:
        return

    if auto_choice == "a":
        pass  # Discovery already done
    elif auto_choice == "b":
        scan_batch(ips, scan_ports, "Port scanning")
    elif auto_choice == "c":
        scan_batch(ips, scan_vuln, "CVE scanning")
    elif auto_choice == "d":
        for i, ip in enumerate(ips, 1):
            from .colors import progress
            print(f"\n{progress(i, len(ips), ip, 'Full scanning')}")
            scan_ports(ip)
            scan_vuln(ip)
    elif auto_choice == "q":
        scan_batch(ips, scan_quick, "Quick scanning")
