"""Entry point: sudo python3 -m core"""

import os
import sys
import signal

from .deps import ensure_dependencies
from .report import generate_reports


def check_root():
    if os.geteuid() != 0:
        print("\n[!] This script requires root privileges for SYN scan and OS detection.")
        print("    Run with: sudo python3 -m core\n")
        sys.exit(1)


def main():
    check_root()
    ensure_dependencies()

    # Global Ctrl+C handler for CLI mode
    def _sigint_handler(sig, frame):
        print("\n\n[!] Interrupted. Generating report before exit...\n")
        generate_reports()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint_handler)

    from .cli import cli_mode
    if not cli_mode():
        from .menu import interactive_menu
        interactive_menu()


main()
