"""Terminal color utilities for severity-based output."""


class C:
    """ANSI color codes."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def red(text: str) -> str:
    return f"{C.RED}{text}{C.RESET}"


def yellow(text: str) -> str:
    return f"{C.YELLOW}{text}{C.RESET}"


def green(text: str) -> str:
    return f"{C.GREEN}{text}{C.RESET}"


def cyan(text: str) -> str:
    return f"{C.CYAN}{text}{C.RESET}"


def bold(text: str) -> str:
    return f"{C.BOLD}{text}{C.RESET}"


def dim(text: str) -> str:
    return f"{C.DIM}{text}{C.RESET}"


def severity(text: str, level: str) -> str:
    """Color text by severity level."""
    level = level.upper()
    if level in ("CRITICAL", "HIGH"):
        return red(text)
    if level in ("MEDIUM", "WARNING"):
        return yellow(text)
    if level in ("LOW", "INFO", "OK"):
        return green(text)
    return text


def risk_badge(level: str) -> str:
    """Return a colored risk badge."""
    level = level.upper()
    if level == "CRITICAL":
        return f"{C.RED}{C.BOLD}[CRITICAL]{C.RESET}"
    if level == "HIGH":
        return f"{C.RED}[HIGH]{C.RESET}"
    if level == "MEDIUM":
        return f"{C.YELLOW}[MEDIUM]{C.RESET}"
    if level == "LOW":
        return f"{C.GREEN}[LOW]{C.RESET}"
    return f"[{level}]"


def progress(current: int, total: int, target: str, action: str = "Scanning") -> str:
    """Return a progress line like [3/12] Scanning 192.168.4.95..."""
    return f"{C.CYAN}[{current}/{total}]{C.RESET} {action} {C.BOLD}{target}{C.RESET}..."
