"""Idempotent ISO extract/patch/rebuild and WinPE injection."""
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest

from helpers import REPO, WORKSPACE, have_cmd, run, run_ok

ISO_DIR = REPO / "tmp_iso_extract"
STATE_DIR = REPO / "tmp_iso_state"
WIM_MOUNT = REPO / "tmp_wim_mount"


def _cleanup_iso_state():
    for path in (ISO_DIR, STATE_DIR, WIM_MOUNT):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def iso_workspace(tmp_path):
    if not have_cmd("xorriso"):
        pytest.skip("xorriso not installed")
    _cleanup_iso_state()
    vanilla = tmp_path / "vanilla.iso"
    signed = tmp_path / "signed.efi"
    signed.write_bytes(b"MZ-SIGNED-EFI-FIXTURE" + b"\x00" * 64)
    payload = tmp_path / "iso_tree"
    (payload / "efi" / "boot").mkdir(parents=True)
    (payload / "efi" / "microsoft" / "boot").mkdir(parents=True)
    (payload / "sources").mkdir(parents=True)
    (payload / "efi" / "boot" / "bootx64.efi").write_bytes(b"MZ-ORIGINAL-BOOTX64")
    (payload / "efi" / "microsoft" / "boot" / "cdboot.efi").write_bytes(b"MZ-ORIGINAL-CDBOOT")
    # Real two-image WIM when wimlib is available; otherwise a placeholder file.
    boot_wim = payload / "sources" / "boot.wim"
    if have_cmd("wimlib-imagex"):
        img1 = tmp_path / "wim1"
        img2 = tmp_path / "wim2"
        (img1 / "Windows" / "System32").mkdir(parents=True)
        (img2 / "Windows" / "System32").mkdir(parents=True)
        (img1 / "Windows" / "System32" / "setup.exe").write_text("setup-index1")
        (img2 / "Windows" / "System32" / "setup.exe").write_text("setup-index2")
        run_ok(["wimlib-imagex", "capture", str(img1), str(boot_wim), "Windows PE 1"], capture_output=True)
        run_ok(["wimlib-imagex", "append", str(img2), str(boot_wim), "Windows PE 2"], capture_output=True)
    else:
        boot_wim.write_bytes(b"WIM\x00placeholder")
    # Build a vanilla ISO (no El Torito required for extract tests).
    run_ok(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-R",
            "-J",
            "-V",
            "USVFAKE",
            "-o",
            str(vanilla),
            str(payload),
        ],
        capture_output=True,
    )
    yield {"iso": vanilla, "signed": signed, "has_wim": have_cmd("wimlib-imagex")}
    _cleanup_iso_state()


def test_11_all_and_idempotent_patch(iso_workspace, tmp_path):
    out_iso = tmp_path / "windows_patched.iso"
    cmd = [
        str(REPO / "11_extract_and_patch_iso.sh"),
        "--iso",
        str(iso_workspace["iso"]),
        "--signed-efi",
        str(iso_workspace["signed"]),
        "--output",
        str(out_iso),
        "--all",
    ]
    first = run_ok(cmd, capture_output=True)
    assert out_iso.exists() and out_iso.stat().st_size > 0, first.stdout
    assert (ISO_DIR / ".stamp_extract").is_file()
    assert (ISO_DIR / ".stamp_patch_iso").is_file()
    assert (ISO_DIR / "autounattend.xml").is_file()
    assert (ISO_DIR / "efi" / "boot" / "bootx64.efi").read_bytes() == iso_workspace["signed"].read_bytes()
    assert (STATE_DIR / "boot.wim.orig").is_file()

    second = run_ok(cmd, capture_output=True)
    combined = (second.stdout or "") + (second.stderr or "")
    assert "skipped" in combined.lower(), combined
    # Second rebuild may rewrite the output ISO; tree and orig wim stay.
    assert (STATE_DIR / "boot.wim.orig").is_file()


def test_11_extract_refuses_over_winpe_stamp(iso_workspace, tmp_path):
    # Produce a tree first.
    out_iso = tmp_path / "windows_patched.iso"
    run_ok(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(iso_workspace["iso"]),
            "--signed-efi",
            str(iso_workspace["signed"]),
            "--output",
            str(out_iso),
            "--extract",
            "--patch",
        ],
        capture_output=True,
    )
    (ISO_DIR / ".stamp_winpe").write_text("fake-winpe-stamp\n")
    refused = run(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(iso_workspace["iso"]),
            "--signed-efi",
            str(iso_workspace["signed"]),
            "--output",
            str(out_iso),
            "--extract",
        ],
        capture_output=True,
    )
    assert refused.returncode != 0
    text = (refused.stdout or "") + (refused.stderr or "")
    assert "stamp_winpe" in text or "--force" in text


def test_13_inject_idempotent(iso_workspace, tmp_path):
    if not iso_workspace["has_wim"]:
        pytest.skip("wimlib-imagex not installed")
    out_iso = tmp_path / "windows_patched.iso"
    run_ok(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(iso_workspace["iso"]),
            "--signed-efi",
            str(iso_workspace["signed"]),
            "--output",
            str(out_iso),
            "--extract",
            "--patch",
        ],
        capture_output=True,
    )
    WORKSPACE.mkdir(exist_ok=True)
    (WORKSPACE / "VerifyRuntimeBoundaries.exe").write_bytes(b"MZ-VRB")
    (WORKSPACE / "AuditMeasuredBootLog.exe").write_bytes(b"MZ-AMB")
    (WORKSPACE / "SignatureParserApp.efi").write_bytes(b"MZ-SPA")
    (WORKSPACE / "SecureManagerApp.efi").write_bytes(b"MZ-SMA")

    first = run_ok([str(REPO / "13_patch_winpe_image.sh")], capture_output=True)
    assert (ISO_DIR / ".stamp_winpe").is_file(), first.stdout
    second = run_ok([str(REPO / "13_patch_winpe_image.sh")], capture_output=True)
    text = (second.stdout or "") + (second.stderr or "")
    assert "skipped" in text.lower() or "no-op" in text.lower() or "matches" in text.lower(), text

    # Mount index 2 read-only and confirm injection.
    mount = tmp_path / "peek"
    mount.mkdir()
    run_ok(
        ["wimlib-imagex", "mount", str(ISO_DIR / "sources" / "boot.wim"), "2", str(mount)],
        capture_output=True,
    )
    try:
        sys32 = mount / "Windows" / "System32"
        assert (sys32 / "VerifyRuntimeBoundaries.exe").is_file()
        assert (sys32 / "winpeshl.ini").is_file()
        assert (ISO_DIR / "SignatureParserApp.efi").is_file()
        assert (ISO_DIR / "SecureManagerApp.efi").is_file()
    finally:
        run(["wimlib-imagex", "unmount", str(mount)], capture_output=True)
