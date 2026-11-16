"""Dry-run QEMU command shape, OVMF pair selection, and mismatch abort."""
from __future__ import annotations

import os
import shutil

import pytest

from helpers import LOGS, PROFILES, REPO, WORKSPACE, have_cmd, run, run_ok


def qemu_ready() -> bool:
    return have_cmd("qemu-system-x86_64") and any(
        (p / "OVMF_CODE_4M.secboot.fd").is_file() or (p / "OVMF_CODE_4M.fd").is_file() or (p / "OVMF_CODE.fd").is_file()
        for p in (
            __import__("pathlib").Path("/usr/share/OVMF"),
            __import__("pathlib").Path("/usr/share/edk2/ovmf"),
            __import__("pathlib").Path("/usr/share/qemu"),
        )
    )


pytestmark = pytest.mark.skipif(not qemu_ready(), reason="qemu-system-x86_64 or OVMF images missing")


def run_02(*flags, check=True):
    cmd = [str(REPO / "02_run_qemu.sh"), "--dry-run", *flags]
    fn = run_ok if check else run
    return fn(cmd, capture_output=True)


def combined(result) -> str:
    return (result.stdout or "") + (result.stderr or "")


def test_02_default_dry_run_includes_tpm_smm_ovmf():
    result = run_02("--reset-vars")
    text = combined(result)
    assert "OVMF_CODE" in text
    assert "smm=on" in text
    assert "tpm-crb" in text or "tpm-tis" in text
    assert "swtpm" in text
    assert "--dry-run: not launching" in text
    assert "q35" in text
    # Default TPM is on; firmware staged under workspace/ovmf
    assert (WORKSPACE / "ovmf" / "CODE.fd").is_file()
    assert (WORKSPACE / "ovmf" / "VARS.fd").is_file()
    assert (WORKSPACE / "ovmf" / "stamp").is_file()


def test_02_flag_combo_shape(tmp_path):
    serial = tmp_path / "serial.log"
    qmp = tmp_path / "qmp.sock"
    mon = tmp_path / "hmp.sock"
    debug = tmp_path / "ovmf_debug.log"
    result = run_02(
        "--reset-vars",
        "--smm",
        "--tpm",
        "--iommu",
        "--vbs",
        "on",
        "--fw-protections",
        "--fw-cfg",
        "name=opt/org.tianocore/test,string=yes",
        "--smbios-profile",
        str(PROFILES / "smbios_lab.conf"),
        "--debugcon",
        str(debug),
        "--nographic",
        "--serial-log",
        str(serial),
        "--qmp",
        str(qmp),
        "--monitor",
        str(mon),
        "--gdb-port",
        "19999",
        "--sev",
        "--tdx",
    )
    text = combined(result)
    assert "-machine" in text and "q35" in text and "smm=on" in text
    assert "kernel-irqchip=split" in text or "skipped" in text  # skipped if no KVM
    assert "intel-iommu" in text or "iommu" in text.lower()
    assert "PcdSetNxForStack" in text
    assert "EnableLegacyLoader" in text
    assert "opt/org.tianocore/test" in text and "string=yes" in text
    assert "type=0" in text and "USV" in text and "BIOS" in text
    assert "isa-debugcon.iobase=0x402" in text
    assert "display none" in text or "-display none" in text
    assert "tcp::19999" in text
    assert "-S" in text or " -S" in text
    # SEV/TDX must not invent machine properties; they are skipped here.
    assert "sev-guest" not in text
    assert "tdx-guest" not in text
    assert "skipped" in text.lower()
    # Feature table present
    assert "feature" in text and "state" in text


def test_02_no_tpm_no_smm_shape():
    result = run_02("--reset-vars", "--no-tpm", "--no-smm")
    text = combined(result)
    assert "tpm-crb" not in text and "tpm-tis" not in text
    assert "smm=on" not in text
    assert "cfi.pflash01" not in text


def test_02_empty_keys_uses_non_ms_vars():
    result = run_02("--empty-keys", "--reset-vars")
    text = combined(result)
    # Prefer VARS_4M.fd (empty) over VARS_4M.ms.fd
    assert "OVMF_VARS_4M.ms.fd" not in text or "OVMF_VARS_4M.fd" in text
    # The firmware line should mention the empty template when present on Debian.
    if "OVMF_VARS_4M.fd" in text:
        assert "VARS_4M.ms.fd" not in text.split("firmware")[1].split("\n")[0] if "firmware" in text else True


def test_02_switching_empty_keys_requires_reset_vars():
    run_02("--reset-vars")  # MS vars template
    result = run_02("--empty-keys", check=False)
    text = combined(result)
    assert result.returncode != 0, text
    assert "VARS template changed" in text or "empty-keys" in text


def test_02_code_mismatch_aborts_without_reset():
    # Stage a pair first.
    run_02("--reset-vars")
    stamp = WORKSPACE / "ovmf" / "stamp"
    original = stamp.read_text()
    lines = []
    for line in original.splitlines():
        if line.startswith("CODE_SHA256="):
            lines.append("CODE_SHA256=" + "ab" * 32)
        else:
            lines.append(line)
    stamp.write_text("\n".join(lines) + "\n")
    result = run_02(check=False)
    text = combined(result)
    assert result.returncode != 0, text
    assert "CODE source changed" in text or "Refusing to mix" in text
    # Restore the stamp and confirm --reset-vars is accepted
    stamp.write_text(original)
    reset = run_02("--reset-vars")
    assert reset.returncode == 0
    assert (WORKSPACE / "ovmf" / "VARS.fd").is_file()


def test_12_dry_run_without_iso(tmp_path):
    result = run(
        [
            str(REPO / "12_run_patched_iso_qemu.sh"),
            str(tmp_path / "missing.iso"),
            "--dry-run",
            "--reset-vars",
            "--no-nested",
            "--nographic",
        ],
        capture_output=True,
    )
    text = combined(result)
    assert result.returncode == 0, text
    assert "missing.iso" in text
    assert "windows_virtual_disk.qcow2" in text or "would create" in text
    # --no-nested should not force HV flags
    # (auto/off: enlightenments off)
    assert "hv-passthrough" not in text
    assert "hv-relaxed" not in text
