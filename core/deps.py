"""Auto-detect and install missing Python dependencies on startup.

The user shouldn't have to remember `pip install fpdf2` before scanning,
especially when running under sudo (which uses a different Python). This
module checks for required + optional packages on startup and installs
the missing ones using whatever pip strategy works (plain, then
--break-system-packages for PEP 668 environments).
"""

import importlib
import subprocess
import sys


# (import_name, pip_package, required, description)
_DEPENDENCIES = [
    ("fpdf",   "fpdf2",  True,  "PDF report generation"),
    ("psutil", "psutil", False, "accurate RAM detection for parallel scanning"),
]


def _is_installed(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except ImportError:
        return False


def _pip_install(package: str) -> bool:
    """Try a few pip invocations to handle PEP 668 / externally-managed envs."""
    base = [sys.executable, "-m", "pip", "install",
            "--quiet", "--disable-pip-version-check"]
    attempts = [
        base + [package],
        base + ["--break-system-packages", package],
    ]
    for cmd in attempts:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    return False


def ensure_dependencies() -> None:
    """Check required + optional deps and auto-install whatever is missing."""
    missing = [
        (mod, pkg, required, desc)
        for mod, pkg, required, desc in _DEPENDENCIES
        if not _is_installed(mod)
    ]
    if not missing:
        return

    print("\n[*] Checking dependencies...")
    print(f"[*] Python: {sys.executable}")

    for mod, pkg, required, desc in missing:
        tag = "required" if required else "optional"
        print(f"[*] Installing {pkg} ({tag}) — {desc}")
        if _pip_install(pkg):
            importlib.invalidate_caches()
            if _is_installed(mod):
                print(f"[+] {pkg} installed.")
            else:
                # Installed but not importable in this process — rare, but warn.
                _handle_failure(pkg, required, "installed but cannot be imported")
        else:
            _handle_failure(pkg, required, "pip install failed")

    print()


def _handle_failure(package: str, required: bool, reason: str) -> None:
    if required:
        print(f"[!] {package}: {reason}.")
        print(f"[!] Install manually with one of:")
        print(f"      {sys.executable} -m pip install {package}")
        print(f"      {sys.executable} -m pip install --break-system-packages {package}")
        sys.exit(1)
    else:
        print(f"[!] {package}: {reason} (optional — continuing without it).")
