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


def make_fat_image(path: Path, files: dict, size_mb: int = 8) -> Path:
    """Create a VFAT image and copy host files into it with mtools.

    `files` maps a DOS path (for example "EFI/BOOT/BOOTX64.EFI" or "startup.nsh")
    to a host Path or to bytes.
    """
    import subprocess as sp

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(size_mb * 1024 * 1024))
    sp.run(["mkfs.vfat", "-n", "USVFAT", str(path)], check=True, capture_output=True)
    created_dirs = {""}
    tmp_payloads = []
    try:
        for dos, src in files.items():
            dos = dos.replace("\\", "/").lstrip("/")
            parent = "/".join(dos.split("/")[:-1])
            # Create each parent directory once.
            accum = []
            if parent:
                for part in parent.split("/"):
                    accum.append(part)
                    rel = "/".join(accum)
                    if rel not in created_dirs:
                        sp.run(["mmd", "-i", str(path), f"::{rel}"], check=True, capture_output=True)
                        created_dirs.add(rel)
            if isinstance(src, (bytes, bytearray)):
                tmp = path.parent / f".fatpayload_{len(tmp_payloads)}"
                tmp.write_bytes(src)
                tmp_payloads.append(tmp)
                host = tmp
            else:
                host = Path(src)
            sp.run(
                ["mcopy", "-i", str(path), "-D", "o", str(host), f"::{dos}"],
                check=True,
                capture_output=True,
            )
    finally:
        for tmp in tmp_payloads:
            tmp.unlink(missing_ok=True)
    return path


def parse_auth2(path: Path) -> dict:
    """Parse an EFI_VARIABLE_AUTHENTICATION_2 packet."""
    import struct

    data = Path(path).read_bytes()
    if len(data) <= 16 + 24:
        raise ValueError(f"auth file too small: {len(data)}")
    dw_length, revision, cert_type = struct.unpack_from("<IHH", data, 16)
    return {
        "raw": data,
        "efi_time": data[:16],
        "dw_length": dw_length,
        "revision": revision,
        "cert_type": cert_type,
        "cert_guid": data[24:40],
        "pkcs7": data[40 : 16 + dw_length],
        "esl": data[16 + dw_length :],
    }


def wait_for_serial_marker(log: Path, marker: str, timeout: float, proc=None) -> str:
    """Poll a serial log until marker appears or timeout. Returns the text so far."""
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        if log.exists():
            text = log.read_text(errors="replace")
            if marker in text:
                return text
        if proc is not None and proc.poll() is not None:
            if log.exists():
                text = log.read_text(errors="replace")
            return text
        time.sleep(0.4)
    if log.exists():
        text = log.read_text(errors="replace")
    raise TimeoutError(f"serial marker {marker!r} not seen in {timeout}s; have:\n{text[-4000:]}")
