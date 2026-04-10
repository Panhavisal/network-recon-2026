"""Rule-based security analysis of scan findings.

Maps raw nmap findings (open ports, service banners, CVEs, OS fingerprints,
confirmed vuln-check results) to severity-tiered findings with human-written
descriptions and remediation recommendations. Used by report.py to produce
professional security assessment output.

Adding a rule:
    Append a dict to SERVICE_RULES / OS_RULES. See the existing entries for
    the schema. Each rule needs an id, severity, title, description, and
    recommendation. Match on port, banner_substr, or both.
"""

import re

from .state import session_log, discovered_hosts


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.0}


# ── Rule tables ─────────────────────────────────────────────────────────────
#
# SERVICE_RULES match on an open-port line (e.g. "80/tcp open http BusyBox 1.19.4").
# Each rule may specify:
#   - "port":          exact port string ("23/tcp"), OR
#   - "banner":        case-insensitive substring of the port line, OR
#   - both (port AND banner must match)
#
# Every rule has an id (for dedup), severity, title, description, and recommendation.

SERVICE_RULES = [
    # ── Plaintext authentication protocols ──
    {
        "id": "SVC-TELNET",
        "port": "23/tcp",
        "severity": "CRITICAL",
        "title": "Telnet service exposed (plaintext credentials)",
        "description": (
            "Telnet transmits usernames, passwords, and all session data in cleartext. "
            "Any attacker with network access between the client and server can passively "
            "capture credentials, session tokens, and command history using a standard packet sniffer."
        ),
        "recommendation": (
            "Disable Telnet immediately. Migrate to SSH (port 22) with key-based authentication. "
            "If Telnet is required by legacy hardware, isolate it to a dedicated management VLAN "
            "behind strict ACLs and schedule its decommissioning."
        ),
    },
    {
        "id": "SVC-FTP",
        "port": "21/tcp",
        "severity": "HIGH",
        "title": "FTP service exposed (plaintext credentials)",
        "description": (
            "FTP transmits authentication credentials and file contents in cleartext. "
            "Anonymous access is commonly enabled in default installations."
        ),
        "recommendation": (
            "Replace with SFTP (SSH-based) or FTPS (TLS-based). If FTP must remain, disable "
            "anonymous login, enforce strong credentials, and restrict source IPs at the firewall."
        ),
    },
    {
        "id": "SVC-TFTP",
        "port": "69/udp",
        "severity": "HIGH",
        "title": "TFTP service exposed (unauthenticated file transfer)",
        "description": (
            "TFTP provides no authentication and transfers files in cleartext. It is frequently "
            "used to disclose or modify network device configurations, firmware images, and boot files."
        ),
        "recommendation": (
            "Disable TFTP unless strictly required for PXE/device provisioning. If needed, restrict "
            "to a provisioning VLAN with firewall rules limiting access to known MAC addresses."
        ),
    },
    {
        "id": "SVC-POP3",
        "port": "110/tcp",
        "severity": "HIGH",
        "title": "POP3 service exposed (plaintext email retrieval)",
        "description": (
            "POP3 on port 110 transmits mailbox credentials and message contents in cleartext."
        ),
        "recommendation": (
            "Disable POP3 and use POP3S (port 995) with TLS, or migrate users to IMAPS/webmail. "
            "If plaintext POP3 must remain temporarily, require STARTTLS and firewall it."
        ),
    },
    {
        "id": "SVC-IMAP",
        "port": "143/tcp",
        "severity": "HIGH",
        "title": "IMAP service exposed (plaintext email access)",
        "description": (
            "IMAP on port 143 transmits credentials and message data in cleartext unless STARTTLS "
            "is enforced at the server level."
        ),
        "recommendation": (
            "Disable IMAP and use IMAPS (port 993) with TLS. Enforce STARTTLS if IMAP must be kept."
        ),
    },
    {
        "id": "SVC-SMTP-OPEN",
        "port": "25/tcp",
        "severity": "LOW",
        "title": "SMTP service exposed",
        "description": (
            "SMTP is expected on mail servers but is also frequently targeted for open-relay abuse, "
            "user enumeration (VRFY/EXPN), and credential harvesting if STARTTLS is not enforced."
        ),
        "recommendation": (
            "Verify the server does not act as an open relay. Enforce STARTTLS. Disable VRFY/EXPN. "
            "Require SMTP AUTH for submission on port 587 rather than port 25."
        ),
    },

    # ── Remote access protocols ──
    {
        "id": "SVC-RSHELL",
        "port": "514/tcp",
        "severity": "CRITICAL",
        "title": "rsh (remote shell) service exposed",
        "description": (
            "rsh uses .rhosts / hosts.equiv trust files with no cryptography. Any attacker who can "
            "spoof a source IP or manipulate trust files gains remote code execution."
        ),
        "recommendation": (
            "Disable rshd immediately. Remove the rsh-server package. Use SSH exclusively for remote access."
        ),
    },
    {
        "id": "SVC-RLOGIN",
        "port": "513/tcp",
        "severity": "CRITICAL",
        "title": "rlogin service exposed",
        "description": (
            "rlogin transmits credentials in cleartext and trusts .rhosts files. It has been "
            "obsolete for over two decades."
        ),
        "recommendation": (
            "Disable rlogind immediately. Remove the rsh-server / rlogin-server package. Use SSH."
        ),
    },
    {
        "id": "SVC-REXEC",
        "port": "512/tcp",
        "severity": "CRITICAL",
        "title": "rexec service exposed",
        "description": (
            "rexec passes credentials in cleartext and has been obsolete since the 1990s."
        ),
        "recommendation": (
            "Disable rexecd. Remove the rsh-server package. Use SSH instead."
        ),
    },
    {
        "id": "SVC-RDP",
        "port": "3389/tcp",
        "severity": "HIGH",
        "title": "Remote Desktop (RDP) exposed",
        "description": (
            "RDP exposed to untrusted networks is a primary vector for credential brute-forcing, "
            "BlueKeep-class vulnerabilities, and ransomware initial access."
        ),
        "recommendation": (
            "Front RDP with a VPN or bastion host. Require Network Level Authentication (NLA). "
            "Enforce multi-factor authentication. Rate-limit login attempts and alert on failures. "
            "Never expose RDP directly to the internet."
        ),
    },
    {
        "id": "SVC-VNC",
        "port": "5900/tcp",
        "severity": "HIGH",
        "title": "VNC service exposed",
        "description": (
            "VNC historically ships with weak authentication schemes and many deployments have no "
            "password at all. Credentials and framebuffer data are often transmitted unencrypted."
        ),
        "recommendation": (
            "Disable VNC unless strictly required. If required, tunnel over SSH, require a strong "
            "password, and never expose the raw VNC port to untrusted networks."
        ),
    },

    # ── File sharing ──
    {
        "id": "SVC-SMB",
        "port": "445/tcp",
        "severity": "HIGH",
        "title": "SMB / CIFS service exposed",
        "description": (
            "SMB has a long history of severe, wormable vulnerabilities (EternalBlue MS17-010, "
            "SMBGhost CVE-2020-0796, etc.). It should never be reachable from untrusted networks."
        ),
        "recommendation": (
            "Block SMB (139, 445) at the perimeter firewall. Disable SMBv1 everywhere. Patch to the "
            "latest vendor supported version. Segment file-sharing traffic to trusted VLANs only. "
            "Enable SMB signing."
        ),
    },
    {
        "id": "SVC-NETBIOS",
        "port": "139/tcp",
        "severity": "MEDIUM",
        "title": "NetBIOS session service exposed",
        "description": (
            "NetBIOS on port 139 is legacy SMB transport that leaks hostnames, domain names, and "
            "shares to anyone who can reach it."
        ),
        "recommendation": (
            "Disable NetBIOS over TCP/IP and rely on direct SMB (port 445) within trusted segments only. "
            "Block port 139 at the perimeter."
        ),
    },
    {
        "id": "SVC-NFS",
        "port": "2049/tcp",
        "severity": "HIGH",
        "title": "NFS service exposed",
        "description": (
            "NFS shares frequently export filesystems without authentication. Exposure outside trusted "
            "networks allows remote file read/write and potential privilege escalation via setuid binaries."
        ),
        "recommendation": (
            "Restrict NFS to trusted management networks. Use NFSv4 with Kerberos authentication. "
            "Explicitly scope /etc/exports to specific hosts and mount with no_root_squash disabled."
        ),
    },
    {
        "id": "SVC-RSYNC",
        "port": "873/tcp",
        "severity": "MEDIUM",
        "title": "rsync daemon exposed",
        "description": (
            "rsync running as a daemon (not over SSH) is frequently configured without authentication, "
            "allowing unauthenticated listing and copying of exposed modules."
        ),
        "recommendation": (
            "Tunnel rsync over SSH instead of running the daemon directly. If the daemon is required, "
            "configure auth_users and secrets file, and firewall the service."
        ),
    },

    # ── Databases (unauth-by-default) ──
    {
        "id": "SVC-REDIS",
        "port": "6379/tcp",
        "severity": "CRITICAL",
        "title": "Redis server exposed",
        "description": (
            "Redis ships with no authentication by default. A reachable Redis instance allows "
            "unauthenticated data read/write and often remote code execution via CONFIG SET / SLAVEOF / "
            "module load primitives."
        ),
        "recommendation": (
            "Bind Redis to 127.0.0.1 only, or require a strong password via requirepass. Enable protected-mode. "
            "Disable CONFIG command in production. Firewall port 6379 from all untrusted networks."
        ),
    },
    {
        "id": "SVC-MONGODB",
        "port": "27017/tcp",
        "severity": "CRITICAL",
        "title": "MongoDB server exposed",
        "description": (
            "Historically MongoDB installs with no authentication. Numerous large-scale ransomware "
            "campaigns (Meow, etc.) have wiped exposed instances en masse."
        ),
        "recommendation": (
            "Enable authentication (security.authorization: enabled). Bind to specific interfaces only. "
            "Use SCRAM-SHA-256 credentials. Firewall port 27017. Enable TLS for all client connections."
        ),
    },
    {
        "id": "SVC-ELASTICSEARCH",
        "port": "9200/tcp",
        "severity": "CRITICAL",
        "title": "Elasticsearch exposed",
        "description": (
            "Elasticsearch historically shipped without authentication. Exposed clusters leak indexed "
            "data (PII, logs, credentials) and are a common target for ransomware."
        ),
        "recommendation": (
            "Enable the built-in security features (xpack.security.enabled: true). Configure users/roles. "
            "Enforce TLS. Bind to specific interfaces. Firewall ports 9200 and 9300."
        ),
    },
    {
        "id": "SVC-COUCHDB",
        "port": "5984/tcp",
        "severity": "CRITICAL",
        "title": "CouchDB exposed",
        "description": (
            "CouchDB before 3.x shipped in 'admin party' mode (no authentication). CVE-2017-12635/12636 "
            "allowed remote code execution in exposed instances."
        ),
        "recommendation": (
            "Upgrade to CouchDB 3.x+. Configure an admin account. Bind to specific interfaces. "
            "Firewall port 5984."
        ),
    },
    {
        "id": "SVC-MEMCACHED",
        "port": "11211/tcp",
        "severity": "HIGH",
        "title": "Memcached exposed",
        "description": (
            "Memcached has no authentication. Exposed instances leak cached data (often session tokens) "
            "and have been weaponized for massive UDP amplification DDoS attacks."
        ),
        "recommendation": (
            "Bind Memcached to 127.0.0.1 only. Disable UDP listener (-U 0). Firewall port 11211. "
            "If remote access is required, use SASL authentication."
        ),
    },
    {
        "id": "SVC-MYSQL",
        "port": "3306/tcp",
        "severity": "HIGH",
        "title": "MySQL / MariaDB exposed",
        "description": (
            "Database services should never be reachable from untrusted networks. Exposure invites "
            "credential brute-forcing, SQL injection persistence, and data exfiltration."
        ),
        "recommendation": (
            "Bind MySQL to specific internal interfaces. Firewall port 3306 from the public internet. "
            "Require TLS for remote connections. Disable the anonymous account and test database. "
            "Enforce strong passwords and per-application database users."
        ),
    },
    {
        "id": "SVC-POSTGRES",
        "port": "5432/tcp",
        "severity": "HIGH",
        "title": "PostgreSQL exposed",
        "description": (
            "PostgreSQL should not be reachable from untrusted networks. Exposed instances are "
            "targeted for brute-forcing and data theft."
        ),
        "recommendation": (
            "Bind PostgreSQL to internal interfaces only. Configure pg_hba.conf to deny remote access "
            "except from explicit trusted hosts. Require TLS. Firewall port 5432 at the perimeter."
        ),
    },
    {
        "id": "SVC-MSSQL",
        "port": "1433/tcp",
        "severity": "HIGH",
        "title": "Microsoft SQL Server exposed",
        "description": (
            "MSSQL on the public internet is a frequent target for brute-forcing and xp_cmdshell-based "
            "remote code execution."
        ),
        "recommendation": (
            "Restrict MSSQL to internal networks. Disable xp_cmdshell. Require Windows Authentication "
            "where possible. Enforce TLS. Firewall ports 1433 and 1434."
        ),
    },
    {
        "id": "SVC-ORACLE",
        "port": "1521/tcp",
        "severity": "HIGH",
        "title": "Oracle Database listener exposed",
        "description": (
            "The Oracle TNS listener has a long history of default-credential attacks and listener-level "
            "command execution vulnerabilities."
        ),
        "recommendation": (
            "Restrict the listener to trusted networks. Set a listener password. Disable remote listener "
            "registration. Patch to the current Oracle Critical Patch Update."
        ),
    },

    # ── Management interfaces ──
    {
        "id": "SVC-DOCKER",
        "port": "2375/tcp",
        "severity": "CRITICAL",
        "title": "Docker API exposed without TLS",
        "description": (
            "Port 2375 is the unencrypted Docker remote API. An attacker with access can create privileged "
            "containers, mount the host filesystem, and achieve root-level RCE on the host."
        ),
        "recommendation": (
            "Immediately disable the TCP Docker socket, or switch to TLS-authenticated API on port 2376. "
            "Firewall port 2375 at the host level. Review existing containers for compromise."
        ),
    },
    {
        "id": "SVC-DOCKER-TLS",
        "port": "2376/tcp",
        "severity": "HIGH",
        "title": "Docker API exposed (TLS)",
        "description": (
            "Port 2376 is the TLS-authenticated Docker API. Even with TLS, exposure to untrusted networks "
            "expands the attack surface significantly."
        ),
        "recommendation": (
            "Verify strong client certificate authentication is enforced. Restrict access to known admin "
            "networks via firewall. Prefer SSH + 'docker context' for remote management."
        ),
    },
    {
        "id": "SVC-ADB",
        "port": "5555/tcp",
        "severity": "CRITICAL",
        "title": "Android Debug Bridge (ADB) exposed",
        "description": (
            "ADB on port 5555 provides root-equivalent control of an Android device with no authentication "
            "when 'ADB over network' is enabled. Exposed ADB is routinely worm-infected for cryptomining."
        ),
        "recommendation": (
            "Disable 'ADB over network' on the device immediately. If required for development, "
            "firewall port 5555 to a single trusted host."
        ),
    },

    # ── IoT / camera / router-specific ──
    {
        "id": "SVC-UPNP",
        "port": "1900/tcp",
        "severity": "MEDIUM",
        "title": "UPnP service exposed",
        "description": (
            "UPnP allows devices to automatically open NAT holes. Exposed UPnP is a common vector for "
            "unauthorized port-forward creation, reflection DDoS, and LAN device enumeration."
        ),
        "recommendation": (
            "Disable UPnP on internet-facing routers. If needed internally, firewall UPnP from the WAN side. "
            "Audit existing NAT mappings for unexpected entries."
        ),
    },
    {
        "id": "SVC-DAHUA-DVR",
        "port": "37777/tcp",
        "severity": "CRITICAL",
        "title": "Dahua DVR/NVR control port exposed",
        "description": (
            "Port 37777 is the proprietary Dahua/DVR protocol port. Dahua devices have a long history of "
            "default credentials (admin/admin), authentication bypass CVEs (CVE-2021-33044), and botnet "
            "conscription (Mirai variants)."
        ),
        "recommendation": (
            "Never expose port 37777 to the internet. Place DVR/NVR behind a VPN. Change default credentials. "
            "Update firmware to the latest vendor release. Audit device admin accounts."
        ),
    },
    {
        "id": "SVC-RTSP",
        "port": "554/tcp",
        "severity": "MEDIUM",
        "title": "RTSP camera stream exposed",
        "description": (
            "RTSP on port 554 streams camera video. Many cameras ship with no authentication or use weak "
            "default credentials, allowing unauthorized video access."
        ),
        "recommendation": (
            "Require RTSP authentication with strong credentials. Firewall port 554 from untrusted networks. "
            "Prefer ONVIF with digest authentication or TLS-protected RTSP-over-HTTPS."
        ),
    },

    # ── DNS / discovery ──
    {
        "id": "SVC-DNS",
        "port": "53/tcp",
        "severity": "LOW",
        "title": "DNS service exposed",
        "description": (
            "DNS on the public internet is expected for authoritative servers but should not be reachable "
            "on recursive resolvers. Open recursive resolvers are abused for amplification DDoS attacks."
        ),
        "recommendation": (
            "If this is an authoritative server, ignore. If it is recursive, disable recursion for external "
            "queries, restrict to trusted source networks, and enable response rate limiting (RRL)."
        ),
    },
    {
        "id": "SVC-SNMP",
        "port": "161/udp",
        "severity": "HIGH",
        "title": "SNMP service exposed",
        "description": (
            "SNMPv1/v2c use plaintext 'community strings' as authentication. Default strings "
            "('public', 'private') are frequently left in place and allow full device read/write."
        ),
        "recommendation": (
            "Upgrade to SNMPv3 with encryption and authentication. Change community strings from defaults. "
            "Set community strings to read-only where possible. Firewall SNMP to monitoring hosts only."
        ),
    },
    {
        "id": "SVC-LDAP",
        "port": "389/tcp",
        "severity": "MEDIUM",
        "title": "LDAP service exposed (cleartext)",
        "description": (
            "LDAP on port 389 transmits directory queries and, often, authentication credentials in cleartext. "
            "It frequently allows anonymous bind and enumeration of user accounts."
        ),
        "recommendation": (
            "Disable anonymous bind. Require LDAPS (port 636) with TLS. Firewall LDAP to authorized clients."
        ),
    },
    {
        "id": "SVC-MSRPC",
        "port": "135/tcp",
        "severity": "MEDIUM",
        "title": "Microsoft RPC endpoint mapper exposed",
        "description": (
            "Port 135 leaks information about running Windows services via the RPC endpoint mapper and "
            "has historically been exploited (Blaster worm, DCOM RCE CVEs)."
        ),
        "recommendation": (
            "Block port 135 at the perimeter firewall. Restrict RPC to internal trusted networks only."
        ),
    },

    # ── Banner-based EoL / known-old software ──
    {
        "id": "BANNER-BUSYBOX-OLD",
        "banner": "busybox ",
        "severity": "HIGH",
        "title": "Legacy BusyBox version detected",
        "description": (
            "BusyBox versions before 1.30 contain multiple known CVEs. BusyBox is common on embedded "
            "IoT devices (routers, cameras, DVRs) and is rarely updated by vendors."
        ),
        "recommendation": (
            "Update the device firmware to the latest vendor release. If the vendor has stopped issuing "
            "updates, plan replacement. Do not expose embedded management interfaces to untrusted networks."
        ),
    },
    {
        "id": "BANNER-DROPBEAR-OLD",
        "banner": "dropbear sshd 201",
        "severity": "MEDIUM",
        "title": "Outdated Dropbear SSH detected",
        "description": (
            "Dropbear SSH builds from 2019 and earlier are missing multiple security fixes. Common on "
            "embedded devices where OpenSSH is too large."
        ),
        "recommendation": (
            "Update device firmware. If the device admin panel is on the WAN, firewall it. "
            "Use key-based authentication only."
        ),
    },
    {
        "id": "BANNER-MINIUPNPD",
        "banner": "miniupnp",
        "severity": "HIGH",
        "title": "MiniUPnP daemon detected",
        "description": (
            "MiniUPnPd on a router allows automatic WAN port-forward creation. Multiple CVEs "
            "(CVE-2017-8798, CVE-2013-0229) have allowed authenticated and unauthenticated attacks."
        ),
        "recommendation": (
            "Disable UPnP on the router if not actively needed (most home networks do not need it). "
            "Update router firmware. Audit NAT port-forward mappings."
        ),
    },
    {
        "id": "BANNER-APACHE-1X",
        "banner": "apache/1.",
        "severity": "CRITICAL",
        "title": "End-of-life Apache 1.x HTTP Server",
        "description": (
            "Apache 1.x has been end-of-life since 2010. It has numerous unpatched RCE, DoS, and "
            "information disclosure CVEs."
        ),
        "recommendation": (
            "Upgrade to Apache 2.4.x (current) or replace with nginx. Do not run Apache 1.x in any "
            "production or internet-facing context."
        ),
    },
    {
        "id": "BANNER-APACHE-2022",
        "banner": "apache/2.2",
        "severity": "HIGH",
        "title": "End-of-life Apache 2.2 HTTP Server",
        "description": (
            "Apache 2.2 has been end-of-life since 2017. Multiple unpatched CVEs exist, including "
            "CVE-2017-9788 and others."
        ),
        "recommendation": (
            "Upgrade to Apache 2.4 (current supported line). Test the config migration on a staging "
            "server first."
        ),
    },
    {
        "id": "BANNER-IIS-OLD",
        "banner": "microsoft-iis/6.",
        "severity": "CRITICAL",
        "title": "End-of-life Microsoft IIS 6.0",
        "description": (
            "IIS 6.0 ships with Windows Server 2003, which has been end-of-life since 2015. It has "
            "unpatched RCE vulnerabilities (CVE-2017-7269 WebDAV)."
        ),
        "recommendation": (
            "Replace the underlying Windows Server 2003 host immediately. Migrate workloads to a "
            "currently supported Windows Server version (2019/2022)."
        ),
    },
    {
        "id": "BANNER-NOMINUM-VANTIO",
        "banner": "nominum vantio",
        "severity": "HIGH",
        "title": "End-of-life Nominum Vantio DNS",
        "description": (
            "Nominum Vantio was discontinued after the Akamai acquisition. Remaining deployments "
            "no longer receive security updates."
        ),
        "recommendation": (
            "Migrate to a currently supported DNS server such as BIND 9, Knot DNS, PowerDNS, or "
            "Unbound. Restrict recursion to trusted networks."
        ),
    },
]


# ── OS rules ────────────────────────────────────────────────────────────────

OS_RULES = [
    {
        "id": "OS-WINXP",
        "match": ("windows xp", "windows 2000", "windows 2003", "windows server 2003"),
        "severity": "CRITICAL",
        "title": "End-of-life Windows XP/2000/2003 detected",
        "description": (
            "These Windows versions have been end-of-life for over a decade and receive no security "
            "updates. They contain numerous unpatched remote code execution vulnerabilities (MS08-067, "
            "MS17-010 EternalBlue, etc.)."
        ),
        "recommendation": (
            "Replace the host immediately. Migrate workloads to Windows Server 2019 or 2022. If the "
            "host cannot be replaced, air-gap it from all other networks."
        ),
    },
    {
        "id": "OS-WIN7-2008",
        "match": ("windows 7", "windows server 2008"),
        "severity": "CRITICAL",
        "title": "End-of-life Windows 7 / Server 2008",
        "description": (
            "Windows 7 and Server 2008/2008 R2 reached end-of-life in January 2020. Extended Security "
            "Updates (ESU) ended January 2023 for most tiers. Unpatched BlueKeep (CVE-2019-0708) and "
            "subsequent RCEs affect these systems."
        ),
        "recommendation": (
            "Replace with Windows 10/11 or Server 2019/2022. If replacement is not immediately possible, "
            "purchase ESU where eligible and isolate the host from untrusted networks."
        ),
    },
    {
        "id": "OS-WIN8-2012",
        "match": ("windows 8", "windows server 2012"),
        "severity": "HIGH",
        "title": "End-of-life Windows 8 / Server 2012",
        "description": (
            "Windows 8/8.1 and Windows Server 2012/2012 R2 reached end-of-life in October 2023. "
            "No further security updates are available outside ESU."
        ),
        "recommendation": (
            "Migrate to a currently supported Windows version. Apply ESU if eligible and replacement is delayed."
        ),
    },
    {
        "id": "OS-LINUX-24",
        "match": ("linux 2.4",),
        "severity": "HIGH",
        "title": "End-of-life Linux 2.4 kernel",
        "description": (
            "Linux kernel 2.4.x has been end-of-life since 2011 and contains numerous privilege-escalation "
            "and remote vulnerabilities."
        ),
        "recommendation": (
            "Upgrade to a supported distribution running a 5.x/6.x kernel. If the hardware cannot run a "
            "modern kernel, replace the device."
        ),
    },
    {
        "id": "OS-LINUX-26",
        "match": ("linux 2.6",),
        "severity": "MEDIUM",
        "title": "End-of-life Linux 2.6 kernel",
        "description": (
            "Linux kernel 2.6.x is end-of-life. While some embedded vendors backport fixes, the kernel "
            "line contains many unpatched CVEs in mainline."
        ),
        "recommendation": (
            "Upgrade to a supported kernel (5.x or later). On embedded devices, update firmware or plan "
            "replacement."
        ),
    },
]


# ── Analysis ────────────────────────────────────────────────────────────────

def _port_of(port_line: str) -> str | None:
    """Extract 'NN/tcp' or 'NN/udp' from a port line."""
    m = re.match(r"^\s*(\d+/(?:tcp|udp))", port_line)
    return m.group(1) if m else None


def _finding_from_rule(rule: dict, host: str, port_line: str) -> dict:
    port = _port_of(port_line) or ""
    return {
        "id": rule["id"],
        "severity": rule["severity"],
        "title": rule["title"],
        "host": host,
        "endpoint": f"{host}:{port}" if port else host,
        "evidence": port_line.strip(),
        "description": rule["description"],
        "recommendation": rule["recommendation"],
    }


def _apply_service_rules(host: str, port_line: str) -> list[dict]:
    """Run every SERVICE_RULES entry against one port line, return matched findings."""
    results = []
    port = _port_of(port_line)
    lower = port_line.lower()
    for rule in SERVICE_RULES:
        port_ok = ("port" not in rule) or (rule["port"] == port)
        banner_ok = ("banner" not in rule) or (rule["banner"].lower() in lower)
        if "port" not in rule and "banner" not in rule:
            continue
        if port_ok and banner_ok:
            results.append(_finding_from_rule(rule, host, port_line))
    return results


def _apply_os_rules(host: str, os_lines: list[str]) -> list[dict]:
    results = []
    for os_line in os_lines:
        lower = os_line.lower()
        for rule in OS_RULES:
            if any(keyword in lower for keyword in rule["match"]):
                results.append({
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "host": host,
                    "endpoint": host,
                    "evidence": os_line.strip(),
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                })
                break  # one OS finding per line
    return results


def _cve_density_finding(host: str, cve_count: int) -> dict | None:
    if cve_count == 0:
        return None
    if cve_count >= 16:
        severity, tier_label = "CRITICAL", "critical"
    elif cve_count >= 6:
        severity, tier_label = "HIGH", "high"
    else:
        severity, tier_label = "MEDIUM", "moderate"
    return {
        "id": "CVE-DENSITY",
        "severity": severity,
        "title": f"{cve_count} CVEs associated with installed software",
        "host": host,
        "endpoint": host,
        "evidence": f"{cve_count} unique CVE IDs identified via service-banner matching",
        "description": (
            f"The version strings of services running on this host are associated with {cve_count} "
            f"published CVEs in the vulners.com database. This is a {tier_label} backlog of known issues. "
            f"Note that this list is based on version-string matching only — some CVEs may already be "
            f"backported and patched by the vendor, and exploitation often requires specific conditions."
        ),
        "recommendation": (
            "Prioritize patching the underlying software to its latest vendor-supported version. "
            "For embedded devices (routers, cameras, DVRs), update firmware — if the vendor no longer "
            "issues updates, plan replacement. Re-scan after patching to confirm the CVE count drops."
        ),
    }


def _confirmed_vuln_finding(host: str, vuln: dict) -> dict:
    return {
        "id": f"NSE-{vuln['script']}",
        "severity": "CRITICAL",
        "title": f"Confirmed: {vuln['description']}",
        "host": host,
        "endpoint": vuln.get("endpoint", host),
        "evidence": f"NSE script {vuln['script']} returned VULNERABLE",
        "description": (
            f"The nmap NSE script '{vuln['script']}' actively tested for this vulnerability and "
            f"confirmed the host is exploitable. Unlike CVE catalog matches (which are based on version "
            f"strings alone), this is a positive test result."
        ),
        "recommendation": (
            "Treat this as an immediate-remediation finding. Apply the vendor patch or mitigation "
            "referenced by the script name, then re-scan to confirm the issue is closed. If the host "
            "is internet-facing, consider taking it offline until remediated."
        ),
    }


def _likely_vuln_finding(host: str, vuln: dict) -> dict:
    return {
        "id": f"NSE-LIKELY-{vuln['script']}",
        "severity": "HIGH",
        "title": f"Likely vulnerable: {vuln['description']}",
        "host": host,
        "endpoint": vuln.get("endpoint", host),
        "evidence": f"NSE script {vuln['script']} returned LIKELY VULNERABLE",
        "description": (
            f"The nmap NSE script '{vuln['script']}' returned an inconclusive 'likely vulnerable' result. "
            f"This typically means the target matched some but not all of the script's positive indicators."
        ),
        "recommendation": (
            "Investigate manually to confirm. Check the target's software version against the advisory "
            "referenced by the script. Apply vendor patches and re-scan."
        ),
    }


def _score_to_tier(findings: list[dict]) -> tuple[str, float]:
    """Return (tier, score) where tier is CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    score = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    if any(f["severity"] == "CRITICAL" for f in findings):
        tier = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings):
        tier = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        tier = "MEDIUM"
    elif findings:
        tier = "LOW"
    else:
        tier = "INFO"
    return tier, round(score, 1)


def _is_single_host_target(target: str | None) -> bool:
    """Return True if the target string is a single IP/hostname, not a CIDR range."""
    if not target:
        return False
    if "/" in target:          # CIDR
        return False
    if "-" in target.split(".")[-1]:  # 192.168.1.1-100
        return False
    return True


def analyze_session() -> dict:
    """Run the rules engine over session_log and return a structured analysis."""
    # Group scan findings by target host
    host_data: dict[str, dict] = {}

    def _ensure(host: str) -> dict:
        if host not in host_data:
            host_data[host] = {
                "open_ports": [],
                "os_detected": set(),
                "cves": set(),
                "vulns_failed": [],
                "vulns_likely": [],
            }
        return host_data[host]

    # Pre-populate entries for every host in the discovered pool so single-host
    # scans can later enrich them, and so hosts with zero findings still appear.
    for h in discovered_hosts:
        _ensure(h["ip"])

    for entry in session_log:
        f = entry.get("findings", {})
        if not isinstance(f, dict):
            continue
        target = entry.get("target")

        if _is_single_host_target(target):
            hd = _ensure(target)
            hd["open_ports"].extend(f.get("open_ports", []))
            hd["os_detected"].update(f.get("os_detected", []))
            hd["cves"].update(f.get("cves", []))
            hd["vulns_failed"].extend(f.get("vulns_failed", []))
            hd["vulns_likely"].extend(f.get("vulns_likely", []))
        else:
            # Multi-target scan (CIDR, comma list, etc.): parse services list
            # for "host — port_line" pairs where we do know the host.
            for svc in f.get("services", []):
                if " — " in svc:
                    h, port_info = svc.split(" — ", 1)
                    hd = _ensure(h.strip())
                    hd["open_ports"].append(port_info)

    # Run rules per host
    per_host: list[dict] = []
    for host, data in host_data.items():
        findings: list[dict] = []

        # Dedupe rule matches by (rule_id + endpoint) so the same rule doesn't
        # fire twice if a port is reported by two scans.
        seen = set()

        for port_line in data["open_ports"]:
            for finding in _apply_service_rules(host, port_line):
                key = (finding["id"], finding["endpoint"])
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)

        for finding in _apply_os_rules(host, list(data["os_detected"])):
            key = (finding["id"], finding["endpoint"])
            if key not in seen:
                seen.add(key)
                findings.append(finding)

        for vuln in data["vulns_failed"]:
            findings.append(_confirmed_vuln_finding(host, vuln))

        for vuln in data["vulns_likely"]:
            findings.append(_likely_vuln_finding(host, vuln))

        cve_finding = _cve_density_finding(host, len(data["cves"]))
        if cve_finding:
            findings.append(cve_finding)

        findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["title"]))

        tier, score = _score_to_tier(findings)

        # Enrich with discovered_hosts metadata
        discovered_entry = next((h for h in discovered_hosts if h.get("ip") == host), None)
        hostname = discovered_entry.get("hostname", "") if discovered_entry else ""
        vendor = discovered_entry.get("vendor", "") if discovered_entry else ""
        mac = discovered_entry.get("mac", "") if discovered_entry else ""

        per_host.append({
            "host": host,
            "hostname": hostname,
            "vendor": vendor,
            "mac": mac,
            "tier": tier,
            "score": score,
            "open_port_count": len(set(_port_of(p) for p in data["open_ports"] if _port_of(p))),
            "cve_count": len(data["cves"]),
            "findings": findings,
        })

    # Sort hosts by tier severity (critical first), then by score
    per_host.sort(key=lambda h: (SEVERITY_ORDER.index(h["tier"]), -h["score"]))

    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for h in per_host:
        for f in h["findings"]:
            severity_counts[f["severity"]] += 1

    # Overall session risk = worst host tier
    if per_host:
        overall_tier = per_host[0]["tier"]
    else:
        overall_tier = "INFO"

    return {
        "hosts": per_host,
        "severity_counts": severity_counts,
        "total_findings": sum(severity_counts.values()),
        "overall_tier": overall_tier,
    }
