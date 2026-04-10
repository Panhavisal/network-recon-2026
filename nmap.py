#!/usr/bin/env python3
"""
Network Recon — Interactive nmap wrapper with PDF reporting.

Usage:
    Interactive menu:   sudo python3 nmap.py
    CLI mode:           sudo python3 nmap.py --mode full --target 192.168.1.1 --output server1
                        sudo python3 nmap.py --mode discover --target 192.168.1.0/24 --auto
                        sudo python3 nmap.py --mode quick --target 192.168.1.1
                        sudo python3 nmap.py --mode ports --target 192.168.1.1
                        sudo python3 nmap.py --mode vuln --target 192.168.1.1

Requires: sudo (for SYN scan and OS detection)
Dependencies: pip install fpdf2
"""

import runpy
runpy.run_module("core", run_name="__main__")
