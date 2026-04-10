"""Hardware-aware worker count for parallel scans."""

import os


# Per-scan resource estimates (rough but conservative)
_RAM_PER_SCAN_GB = 0.4    # Each nmap process ~250-400 MB resident
_HARD_CAP = 8              # Never spin up more than this, even on huge servers


def _available_ram_gb() -> float:
    """Return available RAM in GB. Falls back to 4.0 if psutil is missing."""
    try:
        import psutil
        return psutil.virtual_memory().available / (1024 ** 3)
    except ImportError:
        return 4.0


def _cpu_count() -> int:
    return os.cpu_count() or 2


def optimal_workers(num_tasks: int, user_override: int | None = None) -> int:
    """
    Decide how many parallel scan workers to spin up.

    nmap -T4 already uses some internal parallelism (~1-2 cores per process),
    so we budget half the CPU count and ~400 MB RAM per worker. Hard cap of 8
    prevents pathological oversubscription.
    """
    if num_tasks <= 0:
        return 0

    if user_override is not None and user_override > 0:
        return min(user_override, num_tasks)

    cpu_budget = max(1, _cpu_count() // 2)
    ram_budget = max(1, int(_available_ram_gb() / _RAM_PER_SCAN_GB))
    return min(num_tasks, cpu_budget, ram_budget, _HARD_CAP)


def describe_workers(workers: int) -> str:
    """Human-readable summary of the chosen worker count and host resources."""
    cpu = _cpu_count()
    ram = _available_ram_gb()
    return f"{workers} worker(s) ({cpu} CPU, {ram:.1f} GB free RAM)"
