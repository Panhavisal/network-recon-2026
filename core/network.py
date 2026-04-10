"""WiFi detection and network utilities."""

import platform
import re
import subprocess


def get_wifi_network() -> dict | None:
    """Detect the current WiFi interface IP and subnet (works on macOS and Linux)."""
    system = platform.system()

    try:
        if system == "Darwin":
            return _detect_macos()
        else:
            return _detect_linux()
    except Exception:
        return None


def _detect_macos() -> dict | None:
    iface_result = subprocess.run(
        ["networksetup", "-listallhardwareports"],
        capture_output=True, text=True,
    )
    wifi_iface = None
    lines = iface_result.stdout.splitlines()
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line:
            for j in range(i + 1, min(i + 3, len(lines))):
                if lines[j].strip().startswith("Device:"):
                    wifi_iface = lines[j].split(":")[1].strip()
                    break
            break
    if not wifi_iface:
        wifi_iface = "en0"

    ifconfig = subprocess.run(
        ["ifconfig", wifi_iface], capture_output=True, text=True,
    )
    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ifconfig.stdout)
    mask_match = re.search(r"netmask (0x[0-9a-f]+)", ifconfig.stdout)

    if not ip_match:
        return None

    ip = ip_match.group(1)
    if mask_match:
        hex_mask = mask_match.group(1)
        mask_int = int(hex_mask, 16)
        cidr = bin(mask_int).count("1")
    else:
        mask_int = 0xFFFFFF00
        cidr = 24

    ip_parts = [int(p) for p in ip.split(".")]
    mask_parts = [(mask_int >> (8 * (3 - i))) & 0xFF for i in range(4)]
    net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
    network = ".".join(str(p) for p in net_parts)

    return {
        "interface": wifi_iface,
        "ip": ip,
        "cidr": f"{network}/{cidr}",
        "subnet": f"/{cidr}",
    }


def _detect_linux() -> dict | None:
    ip_result = subprocess.run(
        ["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True,
    )
    for line in ip_result.stdout.splitlines():
        if "lo" in line.split()[1]:
            continue
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if match:
            ip = match.group(1)
            cidr = int(match.group(2))
            iface = line.split()[1]
            ip_parts = [int(p) for p in ip.split(".")]
            mask_int = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
            mask_parts = [(mask_int >> (8 * (3 - i))) & 0xFF for i in range(4)]
            net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            network = ".".join(str(p) for p in net_parts)
            return {
                "interface": iface,
                "ip": ip,
                "cidr": f"{network}/{cidr}",
                "subnet": f"/{cidr}",
            }
    return None
