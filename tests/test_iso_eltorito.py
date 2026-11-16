"""Windows-style El Torito catalog and a live OVMF boot of a rebuilt fixture ISO."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from helpers import (
    REPO,
    WORKSPACE,
    have_cmd,
    make_fat_image,
    run,
    run_ok,
    wait_for_serial_marker,
)

ISO_DIR = REPO / "tmp_iso_extract"
STATE_DIR = REPO / "tmp_iso_state"
WIM_MOUNT = REPO / "tmp_wim_mount"
SHELL_EFI = Path("/usr/share/efi-shell-x64/shellx64.efi")


def _cleanup_iso_state():
    for path in (ISO_DIR, STATE_DIR, WIM_MOUNT):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


def _el_torito_report(iso: Path) -> str:
    result = run_ok(["xorriso", "-indev", str(iso), "-report_el_torito", "plain"], capture_output=True)
    return (result.stdout or "") + (result.stderr or "")


def _build_tree(tmp_path: Path, *, with_efisys: bool, with_startup: bool = False) -> Path:
    payload = tmp_path / "iso_tree"
    (payload / "efi" / "boot").mkdir(parents=True)
    (payload / "efi" / "microsoft" / "boot").mkdir(parents=True)
    (payload / "boot").mkdir(parents=True)
    (payload / "sources").mkdir(parents=True)
    (payload / "efi" / "boot" / "bootx64.efi").write_bytes(b"MZ-ORIGINAL-BOOTX64" + b"\x00" * 64)
    (payload / "efi" / "microsoft" / "boot" / "cdboot.efi").write_bytes(b"MZ-ORIGINAL-CDBOOT" + b"\x00" * 64)
    (payload / "sources" / "boot.wim").write_bytes(b"WIM\x00placeholder")
    (payload / "boot" / "etfsboot.com").write_bytes(b"ETFSBOOT" + b"\x00" * (4096 - 8))
    if with_efisys:
        (payload / "efi" / "microsoft" / "boot" / "efisys.bin").write_bytes(
            b"EFISYS-PROMPT" + b"\x00" * (64 * 1024 - 13)
        )
        (payload / "efi" / "microsoft" / "boot" / "efisys_noprompt.bin").write_bytes(
            b"EFISYS-NOPROMPT" + b"\x00" * (64 * 1024 - 15)
        )
    if with_startup:
        (payload / "startup.nsh").write_text("echo USV_ISO_BOOT_OK\nreset -s\n")
    return payload


def _vanilla_iso(tmp_path: Path, tree: Path) -> Path:
    vanilla = tmp_path / "vanilla.iso"
    run_ok(
        ["xorriso", "-as", "mkisofs", "-R", "-J", "-V", "USVFAKE", "-o", str(vanilla), str(tree)],
        capture_output=True,
    )
    return vanilla


@pytest.fixture
def patched_iso_with_catalog(tmp_path):
    if not have_cmd("xorriso"):
        pytest.skip("xorriso not installed")
    _cleanup_iso_state()
    tree = _build_tree(tmp_path, with_efisys=True)
    vanilla = _vanilla_iso(tmp_path, tree)
    signed = tmp_path / "signed.efi"
    signed.write_bytes(b"MZ-SIGNED-EFI-FIXTURE" + b"\x00" * 64)
    out_iso = tmp_path / "windows_patched.iso"
    run_ok(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(vanilla),
            "--signed-efi",
            str(signed),
            "--output",
            str(out_iso),
            "--all",
            "--force",
        ],
        capture_output=True,
    )
    yield out_iso
    _cleanup_iso_state()


def test_el_torito_catalog_has_bios_and_uefi(patched_iso_with_catalog):
    report = _el_torito_report(patched_iso_with_catalog)
    assert "El Torito images" in report or "El Torito boot img" in report, report
    assert "/boot/etfsboot.com" in report, report
    assert "/efi/microsoft/boot/efisys_noprompt.bin" in report, report
    # One BIOS entry and one UEFI entry, both no-emulation.
    assert "BIOS" in report and "UEFI" in report, report
    # xorriso -report_el_torito plain prints a table; accept either the
    # "El Torito boot img" wording or a platform-row form.
    bios_lines = [ln for ln in report.splitlines() if "BIOS" in ln]
    uefi_lines = [ln for ln in report.splitlines() if "UEFI" in ln]
    assert bios_lines, report
    assert uefi_lines, report
    assert any("none" in ln or "no-emul" in ln.lower() or "NoEmul" in ln for ln in bios_lines + report.splitlines())
    # BIOS load size 8 sectors for etfsboot.com.
    assert any((" 8 " in ln or ln.endswith(" 8") or "LdSiz" in report) for ln in bios_lines), report


def test_el_torito_prefers_noprompt_and_prompt_flag(tmp_path):
    if not have_cmd("xorriso"):
        pytest.skip("xorriso not installed")
    _cleanup_iso_state()
    tree = _build_tree(tmp_path, with_efisys=True)
    vanilla = _vanilla_iso(tmp_path, tree)
    signed = tmp_path / "signed.efi"
    signed.write_bytes(b"MZ-SIGNED-EFI" + b"\x00" * 32)
    out_iso = tmp_path / "prompt.iso"
    run_ok(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(vanilla),
            "--signed-efi",
            str(signed),
            "--output",
            str(out_iso),
            "--all",
            "--force",
            "--efi-eltorito",
            "prompt",
        ],
        capture_output=True,
    )
    report = _el_torito_report(out_iso)
    assert "/efi/microsoft/boot/efisys.bin" in report, report
    assert "efisys_noprompt.bin" not in report
    _cleanup_iso_state()


def test_el_torito_generates_esp_when_efisys_missing(tmp_path):
    if not have_cmd("xorriso", "mcopy", "mkfs.vfat"):
        pytest.skip("xorriso/mtools/dosfstools not installed")
    _cleanup_iso_state()
    tree = _build_tree(tmp_path, with_efisys=False)
    vanilla = _vanilla_iso(tmp_path, tree)
    signed = tmp_path / "signed.efi"
    signed.write_bytes(b"MZ-SIGNED-EFI" + b"\x00" * 32)
    out_iso = tmp_path / "generated.iso"
    run_ok(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(vanilla),
            "--signed-efi",
            str(signed),
            "--output",
            str(out_iso),
            "--all",
            "--force",
        ],
        capture_output=True,
    )
    report = _el_torito_report(out_iso)
    assert "/efi/microsoft/boot/efisys_lab.bin" in report, report
    assert "/boot/etfsboot.com" in report, report
    _cleanup_iso_state()


def test_ovmf_boots_rebuilt_iso_efi_entry(tmp_path):
    """Boot the rebuilt fixture under OVMF far enough to see a serial marker."""
    if not have_cmd("xorriso", "qemu-system-x86_64", "mcopy", "mkfs.vfat"):
        pytest.skip("qemu/xorriso/mtools not installed")
    secboot = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
    vars_empty = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
    if not secboot.is_file() or not vars_empty.is_file():
        pytest.skip("OVMF 4M secboot/empty VARS not installed")
    if not SHELL_EFI.is_file():
        pytest.skip("efi-shell-x64 (shellx64.efi) not installed")

    _cleanup_iso_state()
    tree = _build_tree(tmp_path, with_efisys=False)
    # Real FAT ESP used as the EFI El Torito image: Shell + startup.nsh.
    nsh = tmp_path / "startup.nsh"
    nsh.write_text("@echo -off\necho USV_ISO_BOOT_OK\nreset -s\n")
    esp = tmp_path / "efisys_noprompt.bin"
    make_fat_image(
        esp,
        {
            "EFI/BOOT/BOOTX64.EFI": SHELL_EFI,
            "startup.nsh": nsh,
        },
        size_mb=4,
    )
    shutil.copy(esp, tree / "efi" / "microsoft" / "boot" / "efisys_noprompt.bin")
    vanilla = _vanilla_iso(tmp_path, tree)
    # The signed replacement is also the Shell so --patch injects it into the ESP.
    out_iso = tmp_path / "windows_patched.iso"
    run_ok(
        [
            str(REPO / "11_extract_and_patch_iso.sh"),
            "--iso",
            str(vanilla),
            "--signed-efi",
            str(SHELL_EFI),
            "--output",
            str(out_iso),
            "--all",
            "--force",
            "--efi-eltorito",
            "noprompt",
        ],
        capture_output=True,
    )
    report = _el_torito_report(out_iso)
    assert "/efi/microsoft/boot/efisys_noprompt.bin" in report, report

    serial = tmp_path / "serial.log"
    debugcon = tmp_path / "debugcon.log"
    qmp = tmp_path / "qmp.sock"
    disk = tmp_path / "empty.qcow2"
    stdout_log = tmp_path / "qemu.out"
    stderr_log = tmp_path / "qemu.err"
    cmd = [
        str(REPO / "12_run_patched_iso_qemu.sh"),
        str(out_iso),
        "--disk",
        str(disk),
        "--memory",
        "512",
        "--smp",
        "1",
        "--empty-keys",
        "--reset-vars",
        "--no-tpm",
        "--no-nested",
        "--nographic",
        "--serial-log",
        str(serial),
        "--debugcon",
        str(debugcon),
        "--qmp",
        str(qmp),
        "--boot",
        "order=d",
    ]
    with stdout_log.open("w") as out, stderr_log.open("w") as err:
        proc = subprocess.Popen(cmd, cwd=str(REPO), stdout=out, stderr=err, start_new_session=True)
    try:
        text = wait_for_serial_marker(serial, "USV_ISO_BOOT_OK", timeout=120, proc=proc)
        assert "USV_ISO_BOOT_OK" in text
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                except Exception:
                    pass
        _cleanup_iso_state()


def _capture_synthetic_wim(dest: Path, payload_bytes: int, *, src: Path) -> Path:
    """Build a real (but synthetic) WIM with wimlib. Not a Windows install.wim."""
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    payload = src / "payload.bin"
    # A real file of the requested size so the split path has something to cut.
    with payload.open("wb") as fh:
        fh.write(b"USVWIM")
        remaining = max(0, payload_bytes - 6)
        chunk = b"\x00" * (1024 * 1024)
        while remaining:
            n = min(remaining, len(chunk))
            fh.write(chunk[:n])
            remaining -= n
    (src / "readme.txt").write_text(
        "Synthetic install.wim for UefiSecureVault-Suite split/UDF tests.\n"
        "This is not a Windows installation WIM and is well under 4 GiB.\n"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    run_ok(
        ["wimlib-imagex", "capture", str(src), str(dest), "synthetic", "--compress=none"],
        capture_output=True,
    )
    return dest


def _iso_ls(iso: Path, path: str = "/") -> str:
    result = run(["xorriso", "-indev", str(iso), "-ls", path], capture_output=True)
    return ((result.stdout or "") + (result.stderr or "")).lower()


def _iso_source_names(iso: Path) -> set[str]:
    names: set[str] = set()
    for raw in _iso_ls(iso, "/sources").replace("'", " ").split():
        name = Path(raw.split(";")[0]).name.lower()
        if name.startswith("install"):
            names.add(name)
    return names


def _iso_has_udf(iso: Path) -> bool:
    # UDF volume-recognition sequences live near the start of the image
    # (BEA01 / NSRxx / TEA01). isoinfo -d often omits them.
    data = iso.read_bytes()[: 128 * 2048]
    return b"NSR02" in data or b"NSR03" in data or b"BEA01" in data


def _udf_encoder_name() -> str | None:
    for cmd in ("genisoimage", "mkisofs"):
        if have_cmd(cmd):
            result = run([cmd, "-help"], capture_output=True)
            blob = ((result.stdout or "") + (result.stderr or "")).lower()
            if "-udf" in blob:
                return cmd
    if have_cmd("xorriso"):
        result = run(["xorriso", "-as", "mkisofs", "-help"], capture_output=True)
        blob = ((result.stdout or "") + (result.stderr or "")).lower()
        if "-udf" in blob:
            return "xorriso"
    return None


def test_split_install_wim_lowered_threshold(tmp_path):
    """Exercise 11's split path with a synthetic WIM and a lowered threshold.

    This is not a real >4 GiB Windows install.wim. The 4 GiB ISO 9660 ceiling is
    scaled down via --iso9660-max-file so the auto-split / --split-wim logic
    runs in a few seconds. --split-wim is forced so the split path is used even
    when a UDF-capable genisoimage is installed.
    """
    if not have_cmd("xorriso"):
        pytest.skip("xorriso not installed")
    if not have_cmd("wimlib-imagex"):
        pytest.skip("wimlib-imagex not installed")
    _cleanup_iso_state()
    try:
        tree = _build_tree(tmp_path, with_efisys=True)
        wim = tree / "sources" / "install.wim"
        _capture_synthetic_wim(wim, 2 * 1024 * 1024 + 512 * 1024, src=tmp_path / 'wim_src')
        wim_size = wim.stat().st_size
        threshold = 1024 * 1024  # 1 MiB, well under the synthetic WIM
        assert wim_size > threshold, (wim_size, threshold)
        vanilla = _vanilla_iso(tmp_path, tree)
        signed = tmp_path / "signed.efi"
        signed.write_bytes(b"MZ-SIGNED-EFI-FIXTURE" + b"\x00" * 64)
        out_iso = tmp_path / "windows_patched.iso"
        result = run_ok(
            [
                str(REPO / "11_extract_and_patch_iso.sh"),
                "--iso",
                str(vanilla),
                "--signed-efi",
                str(signed),
                "--output",
                str(out_iso),
                "--all",
                "--force",
                "--split-wim",
                "--iso9660-max-file",
                str(threshold),
            ],
            capture_output=True,
        )
        log = (result.stdout or "") + (result.stderr or "")
        assert "splitting" in log.lower() or "split part size" in log.lower(), log
        sources = ISO_DIR / "sources"
        assert not (sources / "install.wim").exists(), list(sources.iterdir())
        swms = sorted(sources.glob("install*.swm"))
        assert swms, f"no install*.swm after split\n{log}\n{list(sources.iterdir())}"
        names = _iso_source_names(out_iso)
        assert "install.swm" in names, names
        assert "install.wim" not in names, names
        print(
            f"NOTE synthetic split: wim_size={wim_size} threshold={threshold} "
            f"parts={[p.name + '=' + str(p.stat().st_size) for p in swms]}"
        )
    finally:
        _cleanup_iso_state()


def test_udf_install_wim_lowered_threshold(tmp_path):
    """Exercise 11's UDF path with a synthetic WIM and a lowered threshold.

    This is not a real >4 GiB Windows install.wim. When xorriso has no -udf
    but genisoimage/mkisofs does, 11 rebuilds with that encoder so the large
    (for the test threshold) WIM stays as install.wim on a UDF volume.
    """
    if not have_cmd("xorriso"):
        pytest.skip("xorriso not installed")
    encoder = _udf_encoder_name()
    if not encoder:
        pytest.skip("no UDF-capable xorriso/genisoimage/mkisofs is installed")
    if not have_cmd("wimlib-imagex"):
        pytest.skip("wimlib-imagex not installed")
    _cleanup_iso_state()
    try:
        tree = _build_tree(tmp_path, with_efisys=True)
        wim = tree / "sources" / "install.wim"
        _capture_synthetic_wim(wim, 2 * 1024 * 1024 + 512 * 1024, src=tmp_path / 'wim_src')
        wim_size = wim.stat().st_size
        threshold = 1024 * 1024
        assert wim_size > threshold, (wim_size, threshold)
        vanilla = _vanilla_iso(tmp_path, tree)
        signed = tmp_path / "signed.efi"
        signed.write_bytes(b"MZ-SIGNED-EFI-FIXTURE" + b"\x00" * 64)
        out_iso = tmp_path / "windows_patched.iso"
        result = run_ok(
            [
                str(REPO / "11_extract_and_patch_iso.sh"),
                "--iso",
                str(vanilla),
                "--signed-efi",
                str(signed),
                "--output",
                str(out_iso),
                "--all",
                "--force",
                "--iso9660-max-file",
                str(threshold),
            ],
            capture_output=True,
        )
        log = (result.stdout or "") + (result.stderr or "")
        assert "-udf" in log.lower() or "udf" in log.lower(), log
        sources = ISO_DIR / "sources"
        assert (sources / "install.wim").is_file(), list(sources.iterdir())
        assert not list(sources.glob("install*.swm")), list(sources.iterdir())
        names = _iso_source_names(out_iso)
        assert "install.wim" in names, names
        assert "install.swm" not in names, names
        assert _iso_has_udf(out_iso), "rebuilt ISO has no UDF volume-recognition sequence"
        print(
            f"NOTE synthetic UDF: encoder={encoder} wim_size={wim_size} "
            f"threshold={threshold} iso_size={out_iso.stat().st_size}"
        )
    finally:
        _cleanup_iso_state()

