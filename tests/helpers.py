"""Shared paths and subprocess helpers for the UefiSecureVault-Suite tests."""
from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKSPACE = REPO / "workspace"
LOGS = WORKSPACE / "logs"
PROFILES = REPO / "profiles"
SCRIPTS = REPO / "scripts"

# mkfs.vfat lives in /usr/sbin on Debian.
os.environ["PATH"] = "/usr/local/bin:/usr/sbin:/sbin:" + os.environ.get("PATH", "")


def run(cmd, **kwargs):
    kwargs.setdefault("cwd", REPO)
    kwargs.setdefault("text", True)
    if isinstance(cmd, (list, tuple)) and cmd:
        first = str(cmd[0])
        if first.endswith(".sh") and Path(first).is_file():
            cmd = ["bash", *cmd]
    return subprocess.run(cmd, **kwargs)


def run_ok(cmd, **kwargs):
    result = run(cmd, **kwargs)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {cmd}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def have_cmd(*names: str) -> bool:
    from shutil import which

    return all(which(n) for n in names)


def wait_for_path(path: Path, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise TimeoutError(f"path not created: {path}")


def connect_qmp(path: Path, timeout: float = 40.0):
    """Retry QMP connect+handshake until timeout. First successful client wins."""
    from qmp_client import QMP

    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        if path.exists():
            try:
                return QMP(str(path), timeout=5.0)
            except Exception as exc:  # noqa: BLE001
                last = exc
        time.sleep(0.2)
    raise TimeoutError(f"QMP not ready at {path}: {last}")
