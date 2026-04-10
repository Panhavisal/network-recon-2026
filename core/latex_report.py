"""LaTeX-based PDF report backend.

Produces a publication-quality security assessment PDF by rendering the
structured analysis into a LaTeX ``article`` template and invoking
``pdflatex``. Falls back to the fpdf2 backend in ``report.py`` when
``pdflatex`` is not installed.

Design notes:
- The LaTeX source is built directly from ``session_log`` and the
  ``analyze_session`` output, NOT from the Markdown file. This means the
  LaTeX template has full control over every section and can use features
  the Markdown renderer cannot (colored boxes, booktabs, longtable,
  hyperref, etc.).
- We use only ``pdflatex``-compatible packages, no XeLaTeX/fontspec. This
  means the default Computer Modern font family — which actually looks
  very appropriate for an audit document.
- All user-provided strings are passed through ``_esc()`` to escape the
  LaTeX special characters ``# $ % & _ { } ~ ^ \\``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime

from .state import session_log, discovered_hosts
from .recommendations import analyze_session, SEVERITY_ORDER


# ── Package detection ──────────────────────────────────────────────────────


def find_latex_engine() -> str | None:
    """Return the name of the first available LaTeX engine, or None.

    We prefer tectonic when present because it auto-downloads the required
    packages on first run. Falls back to standard pdflatex.
    """
    for candidate in ("tectonic", "pdflatex"):
        if shutil.which(candidate):
            return candidate
    return None


def pdflatex_available() -> bool:
    """Return True if any supported LaTeX engine is installed."""
    return find_latex_engine() is not None


def install_hint() -> str:
    """Install instructions shown when no LaTeX engine is found."""
    return (
        "No LaTeX engine found. For a publication-quality PDF report,\n"
        "    install one of:\n"
        "\n"
        "    # Option A: tectonic (recommended - auto-downloads packages)\n"
        "      brew install tectonic\n"
        "      # or on Linux:  cargo install tectonic\n"
        "\n"
        "    # Option B: pdflatex via BasicTeX (macOS)\n"
        "      brew install --cask basictex\n"
        "      sudo tlmgr update --self\n"
        "      sudo tlmgr install tcolorbox booktabs fancyhdr titlesec enumitem\n"
        "\n"
        "    # Option C: pdflatex via TeX Live (Linux)\n"
        "      sudo apt install texlive-latex-recommended texlive-latex-extra texlive-fonts-recommended"
    )


# ── Escaping ───────────────────────────────────────────────────────────────


_LATEX_ESCAPE_TABLE = {
    "\\": r"\textbackslash{}",
    "&":  r"\&",
    "%":  r"\%",
    "$":  r"\$",
    "#":  r"\#",
    "_":  r"\_",
    "{":  r"\{",
    "}":  r"\}",
    "~":  r"\textasciitilde{}",
    "^":  r"\textasciicircum{}",
    "<":  r"\textless{}",
    ">":  r"\textgreater{}",
    "|":  r"\textbar{}",
}


def _esc(text) -> str:
    """Escape LaTeX metacharacters in a user-supplied string."""
    if text is None:
        return ""
    s = str(text)
    # Backslash first so we don't double-escape our own replacements
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch in _LATEX_ESCAPE_TABLE:
            out.append(_LATEX_ESCAPE_TABLE[ch])
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _esc_url(url: str) -> str:
    """Escape URLs for \\href{} — # and % must be protected differently."""
    return url.replace("#", r"\#").replace("%", r"\%").replace("&", r"\&")


# ── Template sections ──────────────────────────────────────────────────────


_PREAMBLE = r"""
\documentclass[11pt,a4paper]{article}

% ── Geometry & basic layout ──────────────────────────────────────────────
\usepackage[a4paper,margin=2.2cm,headheight=14pt]{geometry}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage{microtype}
\usepackage{setspace}
\setstretch{1.12}

% ── Colors ────────────────────────────────────────────────────────────────
\usepackage{xcolor}
\definecolor{ReportNavy}{RGB}{15,50,95}
\definecolor{ReportBlue}{RGB}{24,78,119}
\definecolor{ReportLightBlue}{RGB}{220,232,244}
\definecolor{ReportGrey}{RGB}{110,110,110}
\definecolor{SevCritical}{RGB}{190,30,30}
\definecolor{SevHigh}{RGB}{205,95,25}
\definecolor{SevMedium}{RGB}{190,150,30}
\definecolor{SevLow}{RGB}{50,130,65}
\definecolor{SevInfo}{RGB}{110,110,110}

% ── Hyperlinks ───────────────────────────────────────────────────────────
\usepackage[hidelinks,colorlinks=true,linkcolor=ReportBlue,urlcolor=ReportBlue,
            citecolor=ReportBlue]{hyperref}

% ── Tables ───────────────────────────────────────────────────────────────
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{tabularx}
\usepackage{ltablex}
\keepXColumns
\renewcommand{\arraystretch}{1.2}

% ── Section styling ──────────────────────────────────────────────────────
\usepackage{titlesec}
\titleformat{\section}{\normalfont\Large\bfseries\color{ReportNavy}}{\thesection}{0.6em}{}
\titleformat{\subsection}{\normalfont\large\bfseries\color{ReportBlue}}{\thesubsection}{0.5em}{}
\titleformat{\subsubsection}{\normalfont\normalsize\bfseries\color{ReportBlue}}{\thesubsubsection}{0.4em}{}
\titlespacing*{\section}{0pt}{1.4em}{0.6em}
\titlespacing*{\subsection}{0pt}{1.0em}{0.4em}
\titlespacing*{\subsubsection}{0pt}{0.8em}{0.3em}

% ── Headers / footers ────────────────────────────────────────────────────
\usepackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\color{ReportGrey} Network Security Assessment}
\fancyhead[R]{\small\color{ReportGrey} CONFIDENTIAL}
\fancyfoot[C]{\small\color{ReportGrey} Page \thepage\ of \pageref{LastPage}}
\renewcommand{\headrulewidth}{0.3pt}
\renewcommand{\footrulewidth}{0.0pt}

\usepackage{lastpage}
\usepackage{enumitem}
\setlist[itemize]{leftmargin=1.2em,topsep=2pt,itemsep=2pt,parsep=0pt}
\setlist[enumerate]{leftmargin=1.4em,topsep=2pt,itemsep=2pt,parsep=0pt}

% ── Severity badges & finding boxes ──────────────────────────────────────
\usepackage[most]{tcolorbox}

\newcommand{\sevbadge}[2]{%
  \tcbox[on line, colback=#1, coltext=white, boxrule=0pt, arc=1pt,
         left=3pt, right=3pt, top=1pt, bottom=1pt,
         nobeforeafter]{\small\bfseries #2}%
}
\newcommand{\sevcritical}{\sevbadge{SevCritical}{CRITICAL}}
\newcommand{\sevhigh}{\sevbadge{SevHigh}{HIGH}}
\newcommand{\sevmedium}{\sevbadge{SevMedium}{MEDIUM}}
\newcommand{\sevlow}{\sevbadge{SevLow}{LOW}}
\newcommand{\sevinfo}{\sevbadge{SevInfo}{INFO}}

% Colored finding box. Arg 1 = severity color, arg 2 = severity word,
% arg 3 = title, arg 4 = body contents
\newtcolorbox{findingbox}[4]{
  colback=#1!5!white,
  colframe=#1,
  arc=1.5pt,
  boxrule=0.8pt,
  left=8pt, right=8pt, top=6pt, bottom=6pt,
  fonttitle=\bfseries,
  title={\textcolor{white}{\sevbadge{#1}{#2}\ \ #3}}
}

% ── Code blocks ──────────────────────────────────────────────────────────
\usepackage{listings}
\lstset{
  basicstyle=\ttfamily\footnotesize,
  backgroundcolor=\color{ReportLightBlue!40},
  frame=single,
  rulecolor=\color{ReportLightBlue},
  breaklines=true,
  columns=flexible,
  xleftmargin=6pt,
  xrightmargin=6pt,
  aboveskip=4pt,
  belowskip=4pt,
}

\begin{document}
"""


_COVER_TEMPLATE = r"""
\begin{titlepage}
  \centering
  \vspace*{4cm}
  {\color{ReportNavy}\Huge\bfseries Network Security\\[0.3em]Assessment Report\par}
  \vspace{1.2cm}
  {\color{ReportBlue}\Large An automated reconnaissance \& vulnerability assessment\par}
  \vspace{2.5cm}
  \begin{tabular}{rl}
    \textbf{Report generated:} & %(date)s \\
    \textbf{Tool:}              & Network Recon (nmap wrapper) \\
    \textbf{Scans performed:}   & %(scan_count)d \\
    \textbf{Hosts in scope:}    & %(host_count)d \\
    \textbf{Overall risk:}      & \sev%(tier_cmd)s \\
  \end{tabular}
  \vfill
  {\color{ReportGrey}\small
    This document contains sensitive information. Handle as CONFIDENTIAL.\\
    Distribute only to personnel with a legitimate need to know.\par}
\end{titlepage}
"""


_DOCUMENT_END = r"""
\end{document}
"""


_SEVERITY_TO_CMD = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "info",
}

_SEVERITY_TO_COLOR = {
    "CRITICAL": "SevCritical",
    "HIGH":     "SevHigh",
    "MEDIUM":   "SevMedium",
    "LOW":      "SevLow",
    "INFO":     "SevInfo",
}


def _sev_cmd(severity: str) -> str:
    return "\\sev" + _SEVERITY_TO_CMD.get(severity.upper(), "info")


# ── Body builders ──────────────────────────────────────────────────────────


def _risk_narrative(tier: str, total: int, counts: dict) -> str:
    """Same executive narrative as the Markdown report, LaTeX-safe."""
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    med = counts.get("MEDIUM", 0)
    if tier == "CRITICAL":
        return (
            f"The overall risk posture is \\sevcritical. This assessment surfaced "
            f"{total} finding(s) across the in-scope hosts, including {crit} critical "
            f"and {high} high-severity issue(s). Immediate remediation of the critical "
            f"findings is required; the affected hosts should be considered actively "
            f"at risk until the issues listed below are resolved."
        )
    if tier == "HIGH":
        return (
            f"The overall risk posture is \\sevhigh. {high} high-severity and {med} "
            f"medium-severity finding(s) were identified. These should be addressed "
            f"as part of the next scheduled maintenance window; some findings may be "
            f"exploitable by unauthenticated attackers."
        )
    if tier == "MEDIUM":
        return (
            f"The overall risk posture is \\sevmedium. The assessment identified "
            f"{med} medium-severity finding(s) and no confirmed critical or high "
            f"issues. Address the findings below in the course of routine patching "
            f"and configuration hardening."
        )
    if tier == "LOW":
        return (
            "The overall risk posture is \\sevlow. No critical, high, or medium-"
            "severity findings were identified. The observations below are "
            "informational and represent general hardening opportunities."
        )
    return (
        "The scan completed successfully but no actionable findings were generated "
        "by the rules engine. This typically means no open ports, services, or CVEs "
        "matched the assessment ruleset."
    )


def _build_executive_summary(analysis: dict) -> str:
    counts = analysis["severity_counts"]
    lines = [
        r"\section{Executive Summary}",
        "",
        _risk_narrative(analysis["overall_tier"], analysis["total_findings"], counts),
        "",
        r"\subsection{Findings by Severity}",
        "",
        r"\begin{center}",
        r"\begin{tabular}{lr}",
        r"\toprule",
        r"\textbf{Severity} & \textbf{Count} \\",
        r"\midrule",
    ]
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count or sev in ("CRITICAL", "HIGH", "MEDIUM"):
            lines.append(f"{_sev_cmd(sev)} & {count} \\\\")
    lines += [
        r"\midrule",
        f"\\textbf{{TOTAL}} & \\textbf{{{analysis['total_findings']}}} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{center}",
        "",
    ]
    return "\n".join(lines)


def _build_scope_section() -> str:
    lines = [
        r"\section{Scope \& Methodology}",
        "",
        r"\subsection{Scope}",
        "",
    ]
    if discovered_hosts:
        lines.append(f"{len(discovered_hosts)} host(s) were identified as live and "
                     "in-scope for detailed analysis.")
        lines.append("")
        lines.append(r"\begin{longtable}{clll}")
        lines.append(r"\toprule")
        lines.append(r"\textbf{\#} & \textbf{IP} & \textbf{Hostname} & \textbf{Vendor / MAC} \\")
        lines.append(r"\midrule")
        lines.append(r"\endhead")
        for idx, h in enumerate(discovered_hosts, 1):
            hostname = _esc(h.get("hostname") or "-")
            vendor = _esc(h.get("vendor") or h.get("mac") or "-")
            ip = _esc(h.get("ip", "-"))
            lines.append(f"{idx} & \\texttt{{{ip}}} & {hostname} & {vendor} \\\\")
        lines.append(r"\bottomrule")
        lines.append(r"\end{longtable}")
        lines.append("")
    else:
        targets = sorted({e.get("target") for e in session_log if e.get("target")})
        if targets:
            lines.append("The following targets were specified for assessment:")
            lines.append(r"\begin{itemize}")
            for t in targets:
                lines.append(f"  \\item \\texttt{{{_esc(t)}}}")
            lines.append(r"\end{itemize}")

    lines += [
        r"\subsection{Methodology}",
        "",
        r"The assessment used \texttt{nmap}-based active reconnaissance with the "
        r"following techniques, depending on which scan modes were invoked during "
        r"the session:",
        r"\begin{itemize}",
        r"  \item \textbf{Host discovery} (\texttt{-sn}) --- ICMP/ARP ping sweep to identify live hosts.",
        r"  \item \textbf{Port enumeration} (\texttt{-p-}, \texttt{-sS}) --- full TCP SYN port scan.",
        r"  \item \textbf{Service \& version detection} (\texttt{-sV}) --- banner-based service identification.",
        r"  \item \textbf{OS fingerprinting} (\texttt{-O}) --- TCP/IP stack-based OS identification.",
        r"  \item \textbf{Vulnerability enumeration} (\texttt{-{}-script vuln,vulners,exploit}) --- Nmap Scripting Engine checks for known CVEs and misconfigurations.",
        r"\end{itemize}",
        "",
        r"Findings were then processed by a rules-based analysis engine which "
        r"correlates open ports, service banners, detected OS, CVE matches, and "
        r"NSE vuln-check results against a curated list of known-risky services, "
        r"end-of-life software, and default misconfigurations. Each finding is "
        r"assigned a severity rating along with a human-written description and "
        r"recommended remediation.",
        "",
        r"\subsection{Severity Rating Criteria}",
        "",
        r"\begin{tabularx}{\linewidth}{l X}",
        r"\toprule",
        r"\textbf{Rating} & \textbf{Definition} \\",
        r"\midrule",
        r"\sevcritical & Confirmed vulnerability, unauthenticated remote code execution, plaintext credentials on a reachable service, or default-credential database exposed to untrusted networks. Immediate action required. \\",
        r"\sevhigh & Serious exposure requiring prompt remediation: end-of-life software with known CVEs, exposed management interfaces, weak authentication protocols. \\",
        r"\sevmedium & Meaningful hardening issue: information leakage, deprecated protocols, weak configurations that enable secondary attacks. \\",
        r"\sevlow & Informational exposure: expected services that still warrant review for least-privilege configuration. \\",
        r"\sevinfo & Observation with no direct security impact. \\",
        r"\bottomrule",
        r"\end{tabularx}",
        "",
    ]
    return "\n".join(lines)


def _build_risk_matrix(analysis: dict) -> str:
    hosts = analysis["hosts"]
    if not hosts:
        return ""
    lines = [
        r"\section{Host Risk Matrix}",
        "",
        r"\begin{longtable}{l l c r r r r}",
        r"\toprule",
        r"\textbf{Host} & \textbf{Label} & \textbf{Risk} & \textbf{Score} & \textbf{Open} & \textbf{CVEs} & \textbf{Findings} \\",
        r"\midrule",
        r"\endhead",
    ]
    for h in hosts:
        label = _esc(h["hostname"] or h["vendor"] or "-")
        ip = _esc(h["host"])
        tier_cmd = _sev_cmd(h["tier"])
        lines.append(
            f"\\texttt{{{ip}}} & {label} & {tier_cmd} & {h['score']} & "
            f"{h['open_port_count']} & {h['cve_count']} & {len(h['findings'])} \\\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{longtable}",
        "",
        r"\textit{\small Host risk tiers are derived from the worst-severity finding "
        r"on each host. Scores are a weighted sum of all findings "
        r"(CRITICAL=10, HIGH=5, MEDIUM=2, LOW=0.5).}",
        "",
    ]
    return "\n".join(lines)


def _cve_hyperlink(cve: str) -> str:
    """Turn CVE-YYYY-NNNNN into a hyperlink to NVD."""
    return f"\\href{{https://nvd.nist.gov/vuln/detail/{cve}}}{{\\texttt{{{cve}}}}}"


def _build_detailed_findings(analysis: dict) -> str:
    hosts = analysis["hosts"]
    if not any(h["findings"] for h in hosts):
        return ""
    lines = [
        r"\section{Detailed Findings}",
        "",
        r"Findings are grouped by host, ordered by severity. Each finding includes "
        r"a description of the issue, the evidence observed, and a specific "
        r"remediation recommendation.",
        "",
    ]
    for h in hosts:
        if not h["findings"]:
            continue
        label_parts = [_esc(h["host"])]
        if h["hostname"]:
            label_parts.append(_esc(h["hostname"]))
        if h["vendor"]:
            label_parts.append(_esc(h["vendor"]))
        header_label = " --- ".join(label_parts)

        lines.append(f"\\subsection{{{header_label}}}")
        lines.append("")
        lines.append(r"\begin{itemize}")
        lines.append(f"  \\item \\textbf{{Risk Tier:}} {_sev_cmd(h['tier'])}")
        lines.append(f"  \\item \\textbf{{Weighted Score:}} {h['score']}")
        lines.append(f"  \\item \\textbf{{Open Ports:}} {h['open_port_count']}")
        lines.append(f"  \\item \\textbf{{CVE Catalog Matches:}} {h['cve_count']}")
        lines.append(r"\end{itemize}")
        lines.append("")

        for idx, finding in enumerate(h["findings"], 1):
            sev = finding["severity"].upper()
            color = _SEVERITY_TO_COLOR.get(sev, "SevInfo")
            title = _esc(finding["title"])
            # Colored finding box with severity badge in the title
            lines.append(
                f"\\begin{{findingbox}}{{{color}}}{{{sev}}}"
                f"{{Finding {idx}: {title}}}"
            )
            lines.append("")
            lines.append(r"\begin{itemize}")
            lines.append(f"  \\item \\textbf{{Endpoint:}} \\texttt{{{_esc(finding['endpoint'])}}}")
            lines.append(f"  \\item \\textbf{{Evidence:}} {_esc(finding['evidence'])}")
            lines.append(r"\end{itemize}")
            lines.append("")
            lines.append(r"\textbf{Description:}")
            lines.append("")
            lines.append(_esc(finding["description"]))
            lines.append("")
            lines.append(r"\textbf{Recommendation:}")
            lines.append("")
            lines.append(_esc(finding["recommendation"]))
            lines.append(r"\end{findingbox}")
            lines.append("")
    return "\n".join(lines)


def _build_roadmap(analysis: dict) -> str:
    if not analysis["total_findings"]:
        return ""
    lines = [
        r"\section{Remediation Roadmap}",
        "",
        r"The following priority list consolidates every finding across all hosts, "
        r"ordered by severity. Items should be addressed top-to-bottom.",
        "",
    ]
    flat = []
    for h in analysis["hosts"]:
        flat.extend(h["findings"])
    flat.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["title"]))

    priority = 1
    current_sev = None
    for finding in flat:
        if finding["severity"] != current_sev:
            if current_sev is not None:
                lines.append(r"\end{enumerate}")
                lines.append("")
            current_sev = finding["severity"]
            lines.append(f"\\subsection*{{{_sev_cmd(current_sev)}\\ priority}}")
            lines.append(r"\begin{enumerate}")
            lines.append(f"\\setcounter{{enumi}}{{{priority - 1}}}")
        lines.append(
            f"  \\item \\textbf{{{_esc(finding['title'])}}} --- "
            f"\\texttt{{{_esc(finding['endpoint'])}}}\\\\ "
            f"{_esc(finding['recommendation'])}"
        )
        priority += 1
    if current_sev is not None:
        lines.append(r"\end{enumerate}")
        lines.append("")
    return "\n".join(lines)


def _build_appendix(analysis: dict) -> str:
    lines = [
        r"\section{Technical Appendix}",
        "",
        r"This appendix contains the raw technical data collected during the assessment.",
        "",
    ]

    # 6.1 CVEs
    all_cves = sorted({cve for entry in session_log
                       for cve in entry.get("findings", {}).get("cves", []) or []})
    if all_cves:
        lines += [
            r"\subsection{CVE Catalog Matches}",
            "",
            r"The following CVE identifiers were reported by the nmap \texttt{vulners} "
            r"script based on service-banner matching. Each entry links to the NVD "
            r"entry. These represent \textit{potential} issues and should be confirmed "
            r"against vendor advisories.",
            "",
            r"\begin{itemize}",
        ]
        for cve in all_cves:
            lines.append(f"  \\item {_cve_hyperlink(cve)}")
        lines.append(r"\end{itemize}")
        lines.append("")

    # 6.2 Open ports
    all_ports = []
    for entry in session_log:
        all_ports.extend(entry.get("findings", {}).get("open_ports", []) or [])
    unique_ports = sorted(set(all_ports))
    if unique_ports:
        lines += [
            r"\subsection{Open Ports \& Services Inventory}",
            "",
            r"\begin{longtable}{l l X}",
        ]
        # Use tabularx-style longtable for wrapping service column
        lines = lines[:-1]  # drop the longtable line, we need ltablex syntax
        lines += [
            r"\begin{tabularx}{\linewidth}{l l X}",
            r"\toprule",
            r"\textbf{Port} & \textbf{State} & \textbf{Service / Version} \\",
            r"\midrule",
        ]
        for p in unique_ports:
            parts = p.split(None, 2)
            if len(parts) >= 3:
                lines.append(f"\\texttt{{{_esc(parts[0])}}} & {_esc(parts[1])} & {_esc(parts[2])} \\\\")
            else:
                lines.append(f"\\texttt{{{_esc(p)}}} & & \\\\")
        lines += [
            r"\bottomrule",
            r"\end{tabularx}",
            "",
        ]

    # 6.3 OS
    all_os = sorted({os_line for entry in session_log
                     for os_line in entry.get("findings", {}).get("os_detected", []) or []})
    if all_os:
        lines += [
            r"\subsection{Operating Systems Detected}",
            "",
            r"\begin{itemize}",
        ]
        for os_line in all_os:
            lines.append(f"  \\item {_esc(os_line)}")
        lines += [
            r"\end{itemize}",
            "",
        ]

    # 6.4 Scan log
    lines += [
        r"\subsection{Scan Log}",
        "",
        r"Chronological log of the individual nmap invocations performed during this session.",
        "",
    ]
    for i, entry in enumerate(session_log, 1):
        status = "Success" if entry.get("return_code") == 0 else "Failed / Interrupted"
        desc = _esc(entry.get("description", "(no description)"))
        lines.append(f"\\subsubsection*{{Scan {i}: {desc}}}")
        lines.append(r"\begin{itemize}")
        lines.append(f"  \\item \\textbf{{Time:}} {_esc(entry.get('time', '-'))}")
        lines.append(f"  \\item \\textbf{{Status:}} {status}")
        lines.append(f"  \\item \\textbf{{Target:}} \\texttt{{{_esc(entry.get('target', '-'))}}}")
        out_file = entry.get("output_file")
        if out_file:
            lines.append(f"  \\item \\textbf{{Raw output:}} \\texttt{{{_esc(out_file)}}}")
        lines.append(r"\end{itemize}")
        lines.append(r"\textbf{Command:}")
        cmd = entry.get("command", "")
        # lstlisting to avoid escaping nightmares
        lines.append(r"\begin{lstlisting}")
        lines.append(cmd)
        lines.append(r"\end{lstlisting}")

        f = entry.get("findings", {})
        if isinstance(f, dict):
            bullets = []
            if f.get("hosts_up"):
                bullets.append(f"Hosts up: {f['hosts_up']}")
            if f.get("open_ports"):
                bullets.append(f"Open ports: {len(f['open_ports'])}")
            if f.get("cves"):
                bullets.append(f"CVE catalog matches: {len(f['cves'])}")
            scan_passed = f.get("vulns_passed", 0)
            scan_failed = f.get("vulns_failed") or []
            scan_likely = f.get("vulns_likely") or []
            if scan_failed or scan_likely:
                bullets.append(f"NSE confirmed: {len(scan_failed)}, likely: {len(scan_likely)}, passed: {scan_passed}")
            elif scan_passed:
                bullets.append(f"NSE vulnerability checks: {scan_passed} ran, all passed")
            if bullets:
                lines.append(r"\begin{itemize}")
                for b in bullets:
                    lines.append(f"  \\item {_esc(b)}")
                lines.append(r"\end{itemize}")
        lines.append("")
    return "\n".join(lines)


def _build_disclaimer() -> str:
    return (
        r"\section{Disclaimer}" "\n\n"
        r"This assessment was generated by an automated tool and reflects the state "
        r"of the target(s) at the time of scanning. It is not a substitute for a "
        r"manual penetration test or a full code/configuration audit. Findings based "
        r"on service-banner version matching (CVE catalog) may produce false positives "
        r"if the vendor has backported security fixes without changing the advertised "
        r"version string." "\n\n"
        r"\textbf{Authorization:} Active network scanning of systems you do not own "
        r"or have explicit written permission to test is illegal in most jurisdictions. "
        r"This report should only be distributed to parties with a legitimate need to know."
        "\n\n"
    )


# ── Orchestration ──────────────────────────────────────────────────────────


def build_latex() -> str:
    """Build the full LaTeX source for the current session."""
    analysis = analyze_session()
    cover = _COVER_TEMPLATE % {
        "date": _esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "scan_count": len(session_log),
        "host_count": len(discovered_hosts),
        "tier_cmd": _SEVERITY_TO_CMD.get(analysis["overall_tier"], "info"),
    }

    doc_body = "\n".join([
        cover,
        r"\tableofcontents",
        r"\clearpage",
        _build_executive_summary(analysis),
        _build_scope_section(),
        _build_risk_matrix(analysis),
        _build_detailed_findings(analysis),
        _build_roadmap(analysis),
        _build_appendix(analysis),
        _build_disclaimer(),
    ])

    return _PREAMBLE + doc_body + _DOCUMENT_END


def compile_latex(tex_path: str, pdf_path: str) -> tuple[bool, str]:
    """Compile a LaTeX source file to PDF using whichever engine is available.

    Tries tectonic first (single pass, auto-downloads packages), then
    pdflatex (two passes for TOC + LastPage). Returns (success, message).
    On failure, ``message`` contains the last 100 lines of the engine log.
    """
    engine = find_latex_engine()
    if engine is None:
        return False, "No LaTeX engine found in PATH"

    work_dir = os.path.dirname(os.path.abspath(tex_path))
    basename = os.path.splitext(os.path.basename(tex_path))[0]

    if engine == "tectonic":
        # Single-pass, auto-downloads missing packages
        try:
            proc = subprocess.run(
                ["tectonic", "--keep-logs", "--outdir", work_dir, tex_path],
                capture_output=True, text=True, timeout=300,
            )
        except subprocess.TimeoutExpired:
            return False, "tectonic timed out after 300s"

        if proc.returncode != 0:
            return False, (
                f"tectonic failed with code {proc.returncode}\n"
                f"--- stderr ---\n{proc.stderr[-3000:]}"
            )
    else:
        # pdflatex: two passes so \tableofcontents + \pageref{LastPage} resolve
        for _ in range(2):
            try:
                proc = subprocess.run(
                    ["pdflatex", "-interaction=nonstopmode", "-halt-on-error",
                     "-output-directory", work_dir, tex_path],
                    capture_output=True, text=True, timeout=120,
                )
            except subprocess.TimeoutExpired:
                return False, "pdflatex timed out after 120s"

            if proc.returncode != 0:
                log_path = os.path.join(work_dir, f"{basename}.log")
                tail = ""
                if os.path.isfile(log_path):
                    with open(log_path, "r", errors="replace") as fh:
                        all_lines = fh.readlines()
                        tail = "".join(all_lines[-100:])
                return False, (
                    f"pdflatex failed with code {proc.returncode}\n"
                    f"--- last 100 lines of log ---\n{tail}"
                )

    built_pdf = os.path.join(work_dir, f"{basename}.pdf")
    if not os.path.isfile(built_pdf):
        return False, f"{engine} reported success but no PDF was produced"

    if os.path.abspath(built_pdf) != os.path.abspath(pdf_path):
        os.replace(built_pdf, pdf_path)

    # Clean up auxiliary files
    for ext in (".aux", ".log", ".toc", ".out"):
        aux = os.path.join(work_dir, f"{basename}{ext}")
        if os.path.isfile(aux):
            try:
                os.remove(aux)
            except OSError:
                pass

    return True, "ok"


def generate_latex_pdf(tex_path: str, pdf_path: str) -> tuple[bool, str]:
    """Build LaTeX source, write it to tex_path, compile to pdf_path.

    Returns (success, message).
    """
    tex_source = build_latex()
    with open(tex_path, "w") as fh:
        fh.write(tex_source)
    return compile_latex(tex_path, pdf_path)
