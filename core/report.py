"""Report generation — Markdown, PDF, and JSON."""

import json
import os
import re
from datetime import datetime

from .state import session_log, discovered_hosts, RESULTS_DIR, timestamp


# ── Markdown ────────────────────────────────────────────────────────────────

def build_markdown() -> str:
    """Build a Markdown report from session_log."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = []

    md.append("# Network Recon — Session Report")
    md.append("")
    md.append(f"**Generated:** {now}")
    md.append(f"**Total Scans:** {len(session_log)}")
    md.append("")
    md.append("---")
    md.append("")

    # Aggregate stats
    total_hosts = 0
    all_ports = []
    all_cves = []
    all_vulns = []
    all_os = []
    all_services = []

    for entry in session_log:
        f = entry.get("findings", {})
        total_hosts += f.get("hosts_up", 0)
        all_ports.extend(f.get("open_ports", []))
        all_cves.extend(f.get("cves", []))
        all_vulns.extend(f.get("vulns", []))
        all_os.extend(f.get("os_detected", []))
        all_services.extend(f.get("services", []))

    # Executive summary
    md.append("## Executive Summary")
    md.append("")
    md.append("| Metric | Count |")
    md.append("|--------|-------|")
    md.append(f"| Scans Performed | {len(session_log)} |")
    md.append(f"| Hosts Discovered | {total_hosts} |")
    md.append(f"| Open Ports Found | {len(all_ports)} |")
    md.append(f"| CVEs Identified | {len(set(all_cves))} |")
    md.append(f"| Vulnerabilities | {len(all_vulns)} |")
    md.append("")

    risk = "CRITICAL" if all_cves else ("MEDIUM" if all_ports else "LOW")
    md.append(f"**Overall Risk Level:** {risk}")
    md.append("")
    md.append("---")
    md.append("")

    # Discovered hosts table
    if discovered_hosts:
        md.append("## Discovered Hosts")
        md.append("")
        md.append("| # | IP | Hostname | MAC/Vendor |")
        md.append("|---|-----|----------|------------|")
        for idx, h in enumerate(discovered_hosts, 1):
            hostname = h.get("hostname") or "-"
            vendor = h.get("vendor") or h.get("mac") or "-"
            md.append(f"| {idx} | {h['ip']} | {hostname} | {vendor} |")
        md.append("")
        md.append("---")
        md.append("")

    # CVE summary
    if all_cves:
        md.append("## CVEs Found")
        md.append("")
        unique_cves = sorted(set(all_cves))
        md.append("| # | CVE ID |")
        md.append("|---|--------|")
        for idx, cve in enumerate(unique_cves, 1):
            md.append(f"| {idx} | {cve} |")
        md.append("")
        md.append("---")
        md.append("")

    # OS detection
    if all_os:
        md.append("## Operating Systems Detected")
        md.append("")
        for o in sorted(set(all_os)):
            md.append(f"- {o}")
        md.append("")
        md.append("---")
        md.append("")

    # Open ports & services
    if all_ports:
        md.append("## Open Ports & Services")
        md.append("")
        md.append("| Port | State | Service/Version |")
        md.append("|------|-------|-----------------|")
        for p in sorted(set(all_ports)):
            parts = p.split(None, 2)
            if len(parts) >= 3:
                md.append(f"| {parts[0]} | {parts[1]} | {parts[2]} |")
            else:
                md.append(f"| {p} | | |")
        md.append("")
        md.append("---")
        md.append("")

    # Individual scan details
    md.append("## Scan Details")
    md.append("")

    for i, entry in enumerate(session_log, 1):
        status = "Success" if entry["return_code"] == 0 else "Failed / Interrupted"
        md.append(f"### Scan #{i}: {entry['description']}")
        md.append("")
        md.append(f"- **Time:** {entry['time']}")
        md.append(f"- **Status:** {status}")
        md.append("- **Command:**")
        md.append("  ```")
        md.append(f"  {entry['command']}")
        md.append("  ```")

        if entry.get("output_file"):
            md.append(f"- **Raw output:** `{entry['output_file']}`")

        f = entry.get("findings", {})

        if f.get("hosts"):
            hosts = f["hosts"]
            if len(hosts) > 12:
                shown = ", ".join(hosts[:12]) + f", ... (+{len(hosts) - 12} more, {len(hosts)} total)"
            else:
                shown = ", ".join(hosts)
            md.append(f"- **Hosts scanned:** {shown}")
        if f.get("hosts_up"):
            md.append(f"- **Hosts up:** {f['hosts_up']}")
        if f.get("open_ports"):
            md.append(f"- **Open ports:** {len(f['open_ports'])}")
        if f.get("cves"):
            cves = f["cves"]
            if len(cves) > 15:
                shown = ", ".join(cves[:15]) + f", ... (+{len(cves) - 15} more, {len(cves)} total)"
            else:
                shown = ", ".join(cves)
            md.append(f"- **CVEs:** {shown}")
        if f.get("vulns"):
            md.append("- **Vulnerabilities:**")
            for v in f["vulns"]:
                md.append(f"  - {v}")

        md.append("")

    md.append("---")
    md.append("")
    md.append("*Report generated by Network Recon*")

    return "\n".join(md)


# ── JSON ────────────────────────────────────────────────────────────────────

def build_json() -> str:
    """Build a JSON report from session_log."""
    data = {
        "generated": datetime.now().isoformat(),
        "total_scans": len(session_log),
        "discovered_hosts": discovered_hosts,
        "scans": session_log,
    }
    return json.dumps(data, indent=2)


# ── PDF ─────────────────────────────────────────────────────────────────────

# Color scheme (R, G, B). Used throughout generate_pdf.
_COLOR_TITLE        = (15, 50, 95)      # deep navy for cover title
_COLOR_HEADER       = (24, 78, 119)     # dark blue for ## headers
_COLOR_SUBHEADER    = (60, 110, 150)    # medium blue for ### headers
_COLOR_DEFAULT      = (40, 40, 40)      # near-black body text
_COLOR_DIM          = (110, 110, 110)   # captions / footers
_COLOR_RULE         = (180, 195, 215)   # horizontal rule line
_COLOR_TABLE_HEAD   = (220, 232, 244)   # light blue table header fill
_COLOR_TABLE_BORDER = (170, 180, 200)
_COLOR_CODE_BG      = (244, 246, 250)
_COLOR_CRITICAL     = (190, 30, 30)     # CRITICAL / VULNERABLE / CVE-
_COLOR_HIGH         = (205, 95, 25)
_COLOR_MEDIUM       = (190, 150, 30)
_COLOR_LOW          = (50, 130, 65)     # success / LOW
_COLOR_INFO         = _COLOR_SUBHEADER

# Substring -> color rules for inline severity highlighting
_SEVERITY_RULES = [
    ("CRITICAL",   _COLOR_CRITICAL),
    ("VULNERABLE", _COLOR_CRITICAL),
    ("CVE-",       _COLOR_CRITICAL),
    ("HIGH",       _COLOR_HIGH),
    ("FAILED",     _COLOR_HIGH),
    ("MEDIUM",     _COLOR_MEDIUM),
    ("WARNING",    _COLOR_MEDIUM),
    ("SUCCESS",    _COLOR_LOW),
    ("LOW",        _COLOR_LOW),
]


def _severity_color(text: str):
    """Return the (r,g,b) for the first severity keyword found, or None."""
    upper = text.upper()
    for keyword, color in _SEVERITY_RULES:
        if keyword in upper:
            return color
    return None


def generate_pdf(md_content: str, pdf_path: str):
    """Convert the report content into a styled PDF with color highlighting."""
    try:
        from fpdf import FPDF
    except ImportError as e:
        raise ImportError(
            "fpdf2 is required for PDF reports. Install with: pip install fpdf2"
        ) from e

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Cover / title ──
    pdf.set_text_color(*_COLOR_TITLE)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 14, "Network Recon", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_text_color(*_COLOR_SUBHEADER)
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, "Session Report", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_text_color(*_COLOR_DIM)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(
        0, 6,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        new_x="LMARGIN", new_y="NEXT", align="C",
    )
    pdf.ln(3)

    # Decorative rule under title
    pdf.set_draw_color(*_COLOR_HEADER)
    pdf.set_line_width(0.6)
    y = pdf.get_y()
    pdf.line(pdf.l_margin + 30, y, pdf.w - pdf.r_margin - 30, y)
    pdf.set_line_width(0.2)
    pdf.ln(6)

    # Reset to body defaults
    pdf.set_text_color(*_COLOR_DEFAULT)
    pdf.set_font("Helvetica", "", 10)

    in_code_block = False
    in_table = False

    # Defensive cap so legacy reports with thousands of hosts joined onto one
    # line (or any future bug emitting a multi-kB line) can't crash multi_cell.
    MAX_LINE_CHARS = 800

    for raw_line in md_content.splitlines():
        if len(raw_line) > MAX_LINE_CHARS:
            line = raw_line[:MAX_LINE_CHARS] + f" ... [+{len(raw_line) - MAX_LINE_CHARS} chars truncated]"
        else:
            line = raw_line

        if line.startswith("# Network Recon"):
            continue

        # Horizontal rule
        if line.strip() == "---":
            pdf.ln(2)
            pdf.set_draw_color(*_COLOR_RULE)
            y = pdf.get_y()
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.ln(4)
            in_table = False
            continue

        # Code block toggle
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            if in_code_block:
                pdf.set_font("Courier", "", 8)
            else:
                pdf.set_font("Helvetica", "", 10)
            continue

        # Code block content
        if in_code_block:
            pdf.set_fill_color(*_COLOR_CODE_BG)
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Courier", "", 8)
            safe = _safe(line)
            pdf.cell(0, 5, f"  {safe}", new_x="LMARGIN", new_y="NEXT", fill=True)
            continue

        # ## Headers — colored, bold, with a thin underline
        if line.startswith("## "):
            pdf.ln(4)
            pdf.set_text_color(*_COLOR_HEADER)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, _safe(line[3:]), new_x="LMARGIN", new_y="NEXT")
            # Underline accent
            pdf.set_draw_color(*_COLOR_HEADER)
            pdf.set_line_width(0.4)
            y = pdf.get_y()
            pdf.line(pdf.l_margin, y, pdf.l_margin + 60, y)
            pdf.set_line_width(0.2)
            pdf.ln(3)
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)
            in_table = False
            continue

        # ### Sub-headers — colored, bold
        if line.startswith("### "):
            pdf.ln(3)
            pdf.set_text_color(*_COLOR_SUBHEADER)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 7, _safe(line[4:]), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)
            in_table = False
            continue

        # Table separator (skip)
        if line.strip().startswith("|--") or line.strip().startswith("|-"):
            continue

        # Table rows — colored header row, severity-colored cells
        if line.strip().startswith("|") and line.strip().endswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            col_count = len(cells)
            usable = pdf.w - pdf.l_margin - pdf.r_margin
            col_w = usable / col_count

            pdf.set_draw_color(*_COLOR_TABLE_BORDER)

            if not in_table:
                in_table = True
                pdf.set_fill_color(*_COLOR_TABLE_HEAD)
                pdf.set_text_color(*_COLOR_HEADER)
                pdf.set_font("Helvetica", "B", 9)
                for cell in cells:
                    pdf.cell(col_w, 7, _safe(cell), border=1, align="C", fill=True)
                pdf.ln()
                pdf.set_text_color(*_COLOR_DEFAULT)
                pdf.set_font("Helvetica", "", 9)
            else:
                for cell in cells:
                    sev = _severity_color(cell)
                    if sev:
                        pdf.set_text_color(*sev)
                        pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(col_w, 6, _safe(cell), border=1)
                    if sev:
                        pdf.set_text_color(*_COLOR_DEFAULT)
                        pdf.set_font("Helvetica", "", 9)
                pdf.ln()
            pdf.set_draw_color(*_COLOR_RULE)
            continue

        if in_table and not line.strip().startswith("|"):
            in_table = False

        # Bullet points — apply severity color if the bullet text contains a keyword
        if line.startswith("- "):
            text = re.sub(r"\*\*(.+?)\*\*", r"\1", line[2:])
            sev = _severity_color(text)
            pdf.set_text_color(*(sev or _COLOR_DEFAULT))
            pdf.set_font("Helvetica", "B" if sev else "", 10)
            pdf.multi_cell(0, 6, "- " + _safe(text), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)
            continue

        if line.startswith("  - "):
            text = line[4:]
            sev = _severity_color(text)
            pdf.set_text_color(*(sev or _COLOR_DEFAULT))
            pdf.set_font("Helvetica", "B" if sev else "", 9)
            pdf.multi_cell(0, 5, "    - " + _safe(text), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)
            continue

        # Bold lines (label: value) — color the value if it carries a severity
        bold_match = re.match(r"\*\*(.+?)\*\*\s*(.*)", line)
        if bold_match:
            label = _safe(bold_match.group(1))
            value = _safe(bold_match.group(2))
            sev = _severity_color(value)
            pdf.set_text_color(*_COLOR_HEADER)
            pdf.set_font("Helvetica", "B", 10)
            label_w = pdf.get_string_width(label) + 2
            pdf.cell(label_w, 6, label)
            pdf.set_text_color(*(sev or _COLOR_DEFAULT))
            pdf.set_font("Helvetica", "B" if sev else "", 10)
            pdf.cell(0, 6, value, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)
            continue

        # Italic / footer
        if line.startswith("*") and line.endswith("*"):
            pdf.ln(4)
            pdf.set_text_color(*_COLOR_DIM)
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, _safe(line.strip("*")), new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)
            continue

        # Regular text — apply severity coloring if applicable
        if line.strip():
            text = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
            text = re.sub(r"`(.+?)`", r"\1", text)
            sev = _severity_color(text)
            pdf.set_text_color(*(sev or _COLOR_DEFAULT))
            pdf.set_font("Helvetica", "B" if sev else "", 10)
            pdf.multi_cell(0, 6, _safe(text), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*_COLOR_DEFAULT)
            pdf.set_font("Helvetica", "", 10)

    pdf.output(pdf_path)


# Common Unicode chars used in our markdown that latin-1 can't encode.
# Translate to readable ASCII equivalents instead of letting them turn into "?".
_UNICODE_FALLBACKS = {
    "\u2022": "*",   # bullet
    "\u2014": "-",   # em dash
    "\u2013": "-",   # en dash
    "\u2192": "->",  # rightwards arrow
    "\u2190": "<-",  # leftwards arrow
    "\u2713": "v",   # check mark
    "\u2717": "x",   # cross mark
    "\u2705": "[OK]",
    "\u274C": "[X]",
    "\u26A0": "!",   # warning
    "\u2026": "...", # ellipsis
    "\u201C": '"', "\u201D": '"',  # smart quotes
    "\u2018": "'", "\u2019": "'",
    # Box drawing chars used in menu banners / tables
    "\u2550": "=", "\u2551": "|",
    "\u2500": "-", "\u2502": "|",
    "\u250C": "+", "\u2510": "+",
    "\u2514": "+", "\u2518": "+",
    "\u251C": "+", "\u2524": "+",
    "\u252C": "+", "\u2534": "+", "\u253C": "+",
}


def _safe(text: str) -> str:
    """Make text safe for latin-1 PDF encoding.

    First substitute common Unicode chars (bullets, em dashes, box drawing)
    with ASCII equivalents so they render as expected, then fall back to
    'replace' for anything else (becomes '?').
    """
    for unicode_char, ascii_char in _UNICODE_FALLBACKS.items():
        if unicode_char in text:
            text = text.replace(unicode_char, ascii_char)
    return text.encode("latin-1", "replace").decode("latin-1")


# ── Generate all reports ────────────────────────────────────────────────────

def generate_reports():
    """Generate .md, .pdf, and .json session reports."""
    if not session_log:
        print("\n[*] No scans were performed this session.")
        return

    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = timestamp()

    # Markdown
    md_content = build_markdown()
    md_path = os.path.join(RESULTS_DIR, f"report_{ts}.md")
    with open(md_path, "w") as fh:
        fh.write(md_content)
    print(f"\n[+] Markdown report: {md_path}")

    # JSON
    json_content = build_json()
    json_path = os.path.join(RESULTS_DIR, f"report_{ts}.json")
    with open(json_path, "w") as fh:
        fh.write(json_content)
    print(f"[+] JSON report:     {json_path}")

    # PDF
    pdf_path = os.path.join(RESULTS_DIR, f"report_{ts}.pdf")
    try:
        generate_pdf(md_content, pdf_path)
        print(f"[+] PDF report:      {pdf_path}")
    except Exception as e:
        import traceback
        print(f"[!] PDF generation failed: {type(e).__name__}: {e}")
        print("[!] Full traceback:")
        traceback.print_exc()
        print("[!] Markdown and JSON reports were still generated above.")

    # Terminal summary
    print(f"\n{'=' * 60}")
    print(md_content)
    print(f"{'=' * 60}")
