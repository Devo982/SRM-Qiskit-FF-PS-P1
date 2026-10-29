"""Environment metadata and best-effort cgroup resource-limit verification."""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[1]


def load_config(platform_id: str) -> dict[str, Any]:
    if platform_id not in {"A", "B"}:
        raise ValueError("platform_id must be 'A' or 'B'")
    path = ROOT / "platforms" / f"platform_{platform_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None


def _self_cgroup_dirs() -> list[Path]:
    """Return candidate cgroup directories for this process, closest first.

    In a container or a systemd user scope the effective limits live in the
    process's own cgroup, not the global filesystem root. We parse
    /proc/self/cgroup and walk upward so a tighter limit on any ancestor is
    still discovered.
    """
    dirs: list[Path] = []
    raw = _read_text("/proc/self/cgroup")
    if raw:
        for line in raw.splitlines():
            parts = line.split(":", 2)
            if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
                relative = parts[2].lstrip("/")
                if relative:
                    current = Path("/sys/fs/cgroup") / relative
                    while current != Path("/sys/fs/cgroup").parent:
                        dirs.append(current)
                        if current == Path("/sys/fs/cgroup"):
                            break
                        current = current.parent
                break
    if Path("/sys/fs/cgroup") not in dirs:
        dirs.append(Path("/sys/fs/cgroup"))
    return dirs


def _effective_dirs() -> list[str]:
    return [str(path) for path in _self_cgroup_dirs()]


def cgroup_limits() -> dict[str, Any]:
    """Read the tightest cgroup v2/v1 CPU and memory limits applying here."""
    cpu_quota = None
    memory_limit_bytes = None
    cpu_source = None
    memory_source = None

    for directory in _effective_dirs():
        cpu_max = _read_text(f"{directory}/cpu.max")
        if not cpu_max or cpu_max == "max":
            continue
        parts = cpu_max.split()
        if len(parts) != 2 or parts[0] == "max":
            continue
        try:
            quota, period = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if quota > 0 and period > 0:
            candidate = quota / period
            if cpu_quota is None or candidate < cpu_quota:
                cpu_quota = candidate
                cpu_source = f"cgroup_v2:{directory}/cpu.max"

    if cpu_quota is None:
        quota_text = _read_text("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        period_text = _read_text("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        try:
            quota, period = int(quota_text or "-1"), int(period_text or "0")
            if quota > 0 and period > 0:
                cpu_quota = quota / period
                cpu_source = "cgroup_v1:cpu.cfs_quota_us/cpu.cfs_period_us"
        except ValueError:
            pass

    for directory in _effective_dirs():
        memory_max = _read_text(f"{directory}/memory.max")
        if not memory_max or memory_max == "max":
            continue
        try:
            limit = int(memory_max)
        except ValueError:
            continue
        if limit > 0 and (memory_limit_bytes is None or limit < memory_limit_bytes):
            memory_limit_bytes = limit
            memory_source = f"cgroup_v2:{directory}/memory.max"

    if memory_limit_bytes is None:
        for path in (
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "/sys/fs/cgroup/memory.limit_in_bytes",
        ):
            value = _read_text(path)
            try:
                limit = int(value or "0")
                # Ignore v1's huge sentinel values, which mean effectively unlimited.
                if 0 < limit < (1 << 60):
                    memory_limit_bytes = limit
                    memory_source = f"cgroup_v1:{path}"
                    break
            except ValueError:
                continue

    return {
        "cpu_quota_cores": cpu_quota,
        "cpu_quota_source": cpu_source,
        "memory_limit_bytes": memory_limit_bytes,
        "memory_limit_source": memory_source,
        "cgroup_dirs_checked": _effective_dirs(),
    }


def environment_metadata(platform_id: str) -> dict[str, Any]:
    config = load_config(platform_id)
    limits = cgroup_limits()
    try:
        import cryptography

        cryptography_version = cryptography.__version__
    except Exception:
        cryptography_version = "unavailable"
    try:
        import logging

        logging.getLogger("oqs.oqs").disabled = True
        import oqs  # type: ignore[import-not-found]

        oqs_python_version = getattr(oqs, "oqs_python_version", lambda: "unknown")()
        liboqs_version = getattr(oqs, "oqs_version", lambda: "unknown")()
    except Exception:
        oqs_python_version = "unavailable"
        liboqs_version = "unavailable"

    cpu_quota = limits["cpu_quota_cores"]
    memory_limit = limits["memory_limit_bytes"]
    if platform_id == "B":
        cpu_verified = cpu_quota is not None and cpu_quota <= float(config["required_cpu_quota_cores"])
        memory_verified = (
            memory_limit is not None
            and memory_limit <= int(config["required_memory_mib"]) * 1024 * 1024
        )
        verified = bool(cpu_verified and memory_verified)
    else:
        cpu_verified = cpu_quota is not None
        memory_verified = memory_limit is not None
        verified = True  # A is baseline by definition; still report actual observed caps.

    return {
        "platform_id": platform_id,
        "platform_config": config,
        "platform_verified": verified,
        "cpu_limit_detected": cpu_verified,
        "memory_limit_detected": memory_verified,
        "os": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "python_version": sys.version.replace("\n", " "),
        "logical_cpu_count": psutil.cpu_count(logical=True),
        "physical_cpu_count": psutil.cpu_count(logical=False),
        "total_memory_bytes": psutil.virtual_memory().total,
        "cpu_quota_cores": cpu_quota,
        "cpu_quota_source": limits["cpu_quota_source"],
        "memory_limit_bytes": memory_limit,
        "memory_limit_source": limits["memory_limit_source"],
        "cgroup_dirs_checked": limits.get("cgroup_dirs_checked"),
        "cryptography_version": cryptography_version,
        "liboqs_python_version": oqs_python_version,
        "liboqs_version": liboqs_version,
        "environment_variables": {
            "CI": os.environ.get("CI"),
            "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"),
        },
    }
