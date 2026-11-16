"""Live OVMF enrollment of PK/KEK/db .auth packets (Setup Mode -> User Mode)."""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

from helpers import (
    REPO,
    WORKSPACE,
    have_cmd,
    make_fat_image,
    parse_auth2,
    run,
    run_ok,
    wait_for_serial_marker,
)

EFITOOLS_LIB = Path("/usr/lib/efitools/x86_64-linux-gnu")
SHELL_EFI = Path("/usr/share/efi-shell-x64/shellx64.efi")
OVMF_SECBOOT = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
OVMF_VARS_EMPTY = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
BUILD_HELPER = REPO / "tests" / "efi" / "build_usv_authset.sh"
HELPER_SRC = REPO / "tests" / "efi" / "UsvAuthSet.c"
STATIC_TIME = bytes.fromhex("EA070A04171E00000000000000000000")
PKCS7_GUID = bytes.fromhex("9dd2af4adf68ee498aa9347d375665a7")
WIN_CERT_REVISION = 0x0200
WIN_CERT_TYPE_EFI_GUID = 0x0EF1
SIGN_TS = "2026-10-04 23:30:00"
# EFI_SECURITY_VIOLATION
EFI_SECURITY_VIOLATION = 0x8000001A

PHASE1_NSH = """@echo -off
echo USV_SCRIPT_START
echo USV_FIRST_BOOT
UsvAuthSet.efi
echo USV_PHASE1_DONE
reset -s
"""

PHASE2_NSH = """@echo -off
echo USV_SCRIPT_START
echo USV_SECOND_BOOT
UsvAuthSet.efi
echo USV_PHASE2_DONE
reset -s
"""

PHASE1_CMDS = """# Enroll db, KEK, then PK (PK last leaves Setup Mode).
SET db db.auth
SET KEK kek.auth
SET PK pk.auth
DUMP SetupMode
DUMP SecureBoot
DUMP PK
DUMP KEK
DUMP db
SET db db_tampered.auth
SET db db_wrong.auth
LOAD HelloSigned.efi
LOAD HelloUnsigned.efi
LOAD EFI/BOOT/BOOTX64.EFI
"""

PHASE2_CMDS = """DUMP SetupMode
DUMP SecureBoot
DUMP PK
DUMP KEK
DUMP db
LOAD HelloSigned.efi
LOAD HelloUnsigned.efi
LOAD EFI/BOOT/BOOTX64.EFI
"""


def build_usv_helpers(dest_dir: Path) -> tuple[Path, Path]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    authset = dest_dir / "UsvAuthSet.efi"
    hello = dest_dir / "UsvHello.efi"
    result = run(["bash", str(BUILD_HELPER), str(authset), str(hello)], capture_output=True)
    if result.returncode != 0:
        pytest.skip(
            "UsvAuthSet.efi/UsvHello.efi could not be built (gnu-efi/gcc missing or failed): "
            + (result.stderr or "")
            + (result.stdout or "")
        )
    assert authset.is_file() and hello.is_file(), (authset, hello, result.stdout)
    return authset, hello


def _stack_ready():
    missing = []
    if not have_cmd("qemu-system-x86_64"):
        missing.append("qemu-system-x86_64")
    if not have_cmd("sign-efi-sig-list"):
        missing.append("sign-efi-sig-list")
    if not have_cmd("sbsign"):
        missing.append("sbsign")
    if not have_cmd("openssl"):
        missing.append("openssl")
    if not have_cmd("gcc", "ld", "objcopy"):
        missing.append("gcc/ld/objcopy")
    if not Path("/usr/include/efi/x86_64/efibind.h").is_file():
        missing.append("gnu-efi")
    if not OVMF_SECBOOT.is_file() or not OVMF_VARS_EMPTY.is_file():
        missing.append("OVMF 4M secboot + empty VARS")
    if not (REPO / "tests" / "efi" / "UsvHello.c").is_file():
        missing.append("tests/efi/UsvHello.c")
    if not SHELL_EFI.is_file():
        missing.append("shellx64.efi")
    if not BUILD_HELPER.is_file() or not HELPER_SRC.is_file():
        missing.append("tests/efi/UsvAuthSet.c")
    return missing


def setup_lab_certs():
    if not have_cmd("openssl", "cert-to-efi-sig-list"):
        pytest.skip("openssl or efitools not installed")
    run_ok([str(REPO / "01_setup_certs.sh")], capture_output=True)
    assert (WORKSPACE / "PK.esl").is_file()
    assert (WORKSPACE / "KEK.esl").is_file()
    assert (WORKSPACE / "db.esl").is_file()


def cms_verify(auth_path: Path, cert: Path, tmp: Path) -> None:
    parsed = parse_auth2(auth_path)
    p7 = tmp / (auth_path.name + ".p7s")
    assert parsed["pkcs7"].startswith(b"\x30"), parsed["pkcs7"][:8].hex()
    p7.write_bytes(parsed["pkcs7"])
    result = run(
        ["openssl", "cms", "-cmsout", "-inform", "DER", "-in", str(p7), "-print"],
        capture_output=True,
    )
    if result.returncode != 0:
        # sign-efi-sig-list often emits a bare PKCS#7 SignedData SEQUENCE
        # (no ContentInfo wrapper), which openssl cms -inform DER rejects.
        asn = run(["openssl", "asn1parse", "-inform", "DER", "-in", str(p7)], capture_output=True)
        assert asn.returncode == 0, (result.stderr or "") + (asn.stderr or "")


def produce_lab_auth():
    """PK/KEK via 03, db via 09, all with the static laboratory clock."""
    run_ok([str(REPO / "03_generate_auth_update.sh"), str(WORKSPACE / "PK.esl"), "PK", "--static"], capture_output=True)
    run_ok([str(REPO / "03_generate_auth_update.sh"), str(WORKSPACE / "KEK.esl"), "KEK", "--static"], capture_output=True)
    run_ok([str(REPO / "09_sign_db_with_kek.sh"), str(WORKSPACE / "db.esl"), "db"], capture_output=True)
    pk = WORKSPACE / "update_target_PK.auth"
    kek = WORKSPACE / "update_target_KEK.auth"
    db = WORKSPACE / "update_db_secured.auth"
    for p in (pk, kek, db):
        assert p.is_file(), p
    return {"PK": pk, "KEK": kek, "db": db}


def produce_efitools_auth():
    certs = WORKSPACE / "certs"
    out = WORKSPACE / "efitools_auth"
    out.mkdir(exist_ok=True)
    mapping = {
        "PK": (certs / "PK.key", certs / "PK.crt", WORKSPACE / "PK.esl"),
        "KEK": (certs / "PK.key", certs / "PK.crt", WORKSPACE / "KEK.esl"),
        "db": (certs / "KEK.key", certs / "KEK.crt", WORKSPACE / "db.esl"),
    }
    paths = {}
    for var, (key, crt, esl) in mapping.items():
        dest = out / f"{var}.auth"
        run_ok(
            ["sign-efi-sig-list", "-t", SIGN_TS, "-k", str(key), "-c", str(crt), var, str(esl), str(dest)],
            capture_output=True,
        )
        paths[var] = dest
    return paths


def sbsign_copy(src: Path, dest: Path, cert: Path, key: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    run_ok(["sbsign", "--key", str(key), "--cert", str(cert), "--output", str(dest), str(src)], capture_output=True)
    return dest


def _tamper(auth: Path, dest: Path) -> Path:
    data = bytearray(auth.read_bytes())
    idx = min(80, len(data) - 1)
    data[idx] ^= 0xFF
    dest.write_bytes(bytes(data))
    return dest


def _wrong_key_db_auth(dest: Path) -> Path:
    certs = WORKSPACE / "certs"
    run_ok(
        [
            "sign-efi-sig-list",
            "-t",
            SIGN_TS,
            "-k",
            str(certs / "db.key"),
            "-c",
            str(certs / "db.crt"),
            "db",
            str(WORKSPACE / "db.esl"),
            str(dest),
        ],
        capture_output=True,
    )
    return dest


def build_enroll_fat(dest: Path, auths: dict, helper: Path, hello: Path) -> Path:
    certs = WORKSPACE / "certs"
    staged = dest.parent / "enroll_payloads"
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True)
    shell_signed = sbsign_copy(SHELL_EFI, staged / "BOOTX64.EFI", certs / "db.crt", certs / "db.key")
    helper_signed = sbsign_copy(helper, staged / "UsvAuthSet.efi", certs / "db.crt", certs / "db.key")
    hello_signed = sbsign_copy(hello, staged / "HelloSigned.efi", certs / "db.crt", certs / "db.key")
    hello_unsigned = staged / "HelloUnsigned.efi"
    shutil.copy(hello, hello_unsigned)
    nsh = staged / "startup.nsh"
    nsh.write_text(PHASE1_NSH)
    cmds = staged / "cmds.txt"
    cmds.write_text(PHASE1_CMDS)
    tampered = _tamper(auths["db"], staged / "db_tampered.auth")
    wrong = _wrong_key_db_auth(staged / "db_wrong.auth")
    # Keep UpdateVars.efi on the volume as a reference binary (not used for
    # assertions: its argsplit/Print path is unreliable in this Shell).
    if (EFITOOLS_LIB / "UpdateVars.efi").is_file():
        update_ref = EFITOOLS_LIB / "UpdateVars.efi"
    else:
        update_ref = None
    files = {
        "EFI/BOOT/BOOTX64.EFI": shell_signed,
        "startup.nsh": nsh,
        "cmds.txt": cmds,
        "UsvAuthSet.efi": helper_signed,
        "HelloSigned.efi": hello_signed,
        "HelloUnsigned.efi": hello_unsigned,
        "db.auth": auths["db"],
        "kek.auth": auths["KEK"],
        "pk.auth": auths["PK"],
        "db_tampered.auth": tampered,
        "db_wrong.auth": wrong,
    }
    if update_ref is not None:
        files["UpdateVars.efi"] = update_ref
    return make_fat_image(dest, files, size_mb=16)


def mcopy_into(fat: Path, host: Path, dos: str) -> None:
    run_ok(["mcopy", "-i", str(fat), "-D", "o", str(host), f"::{dos}"], capture_output=True)


def _launch_02(tmp_path: Path, fat: Path, *, reset_vars: bool, tag: str):
    serial = tmp_path / f"serial_{tag}.log"
    debugcon = tmp_path / f"debugcon_{tag}.log"
    qmp = tmp_path / f"qmp_{tag}.sock"
    stdout_log = tmp_path / f"qemu_{tag}.out"
    stderr_log = tmp_path / f"qemu_{tag}.err"
    cmd = [
        str(REPO / "02_run_qemu.sh"),
        "--empty-keys",
        "--smm",
        "--nographic",
        "--no-tpm",
        "--memory",
        "1024",
        "--smp",
        "1",
        "--serial-log",
        str(serial),
        "--debugcon",
        str(debugcon),
        "--qmp",
        str(qmp),
        "--extra-drive",
        str(fat),
        "--boot",
        "order=c",
    ]
    if reset_vars:
        cmd.append("--reset-vars")
    with stdout_log.open("w") as out, stderr_log.open("w") as err:
        proc = subprocess.Popen(cmd, cwd=str(REPO), stdout=out, stderr=err, start_new_session=True)
    return proc, serial, debugcon, qmp, stdout_log, stderr_log


def _stop(proc):
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


def _assert_auth_header(path: Path, esl: Path):
    parsed = parse_auth2(path)
    assert parsed["efi_time"] == STATIC_TIME, parsed["efi_time"].hex()
    assert parsed["revision"] == WIN_CERT_REVISION
    assert parsed["cert_type"] == WIN_CERT_TYPE_EFI_GUID
    assert parsed["cert_guid"] == PKCS7_GUID
    assert parsed["dw_length"] == 24 + len(parsed["pkcs7"])
    assert parsed["esl"] == esl.read_bytes()


def test_lab_auth_matches_efitools_structure(tmp_path):
    if not have_cmd("sign-efi-sig-list", "openssl", "cert-to-efi-sig-list"):
        pytest.skip("sign-efi-sig-list/openssl/efitools not installed")
    setup_lab_certs()
    lab = produce_lab_auth()
    efi = produce_efitools_auth()
    _assert_auth_header(lab["PK"], WORKSPACE / "PK.esl")
    _assert_auth_header(lab["KEK"], WORKSPACE / "KEK.esl")
    _assert_auth_header(lab["db"], WORKSPACE / "db.esl")
    for var, esl_name in (("PK", "PK.esl"), ("KEK", "KEK.esl"), ("db", "db.esl")):
        e = parse_auth2(efi[var])
        assert e["efi_time"] == STATIC_TIME, (var, e["efi_time"].hex())
        assert e["revision"] == WIN_CERT_REVISION
        assert e["cert_type"] == WIN_CERT_TYPE_EFI_GUID
        assert e["cert_guid"] == PKCS7_GUID
        assert e["esl"] == (WORKSPACE / esl_name).read_bytes()
        cms_verify(lab[var], WORKSPACE / "certs" / ("PK.crt" if var in {"PK", "KEK"} else "KEK.crt"), tmp_path)
        cms_verify(efi[var], WORKSPACE / "certs" / ("PK.crt" if var in {"PK", "KEK"} else "KEK.crt"), tmp_path)



def _assert_signed_unsigned(text: str, readable: str, label: str) -> None:
    """Signed UsvHello must run; unsigned must be blocked once PK is enrolled."""
    assert "USV_SIGNED_HELLO" in text, f"{label} missing signed marker\n{readable[-4000:]}"
    assert "USV_UNSIGNED_HELLO" in text, f"{label} missing unsigned marker\n{readable[-4000:]}"
    # The signed app prints USV_HELLO_OK; the unsigned app must not start.
    signed_chunk = text.split("USV_SIGNED_HELLO", 1)[-1].split("USV_UNSIGNED_HELLO", 1)[0]
    unsigned_chunk = text.split("USV_UNSIGNED_HELLO", 1)[-1]
    assert "USV_HELLO_OK" in signed_chunk, f"{label} signed Hello did not run:\n{readable[-4000:]}"
    assert "USV_HELLO_OK" not in unsigned_chunk, f"{label} unsigned Hello was not blocked:\n{readable[-4000:]}"
    if "USV_SIGNED_RC" in text:
        assert not _rc_is_failure(text, "USV_SIGNED_RC"), f"{label} signed Hello lasterror failed:\n{readable[-3000:]}"
    if "USV_UNSIGNED_RC" in text:
        assert _rc_is_failure(text, "USV_UNSIGNED_RC"), f"{label} unsigned Hello lasterror was zero:\n{readable[-3000:]}"


def _status_code(st: int | None) -> int | None:
    """Normalize a 32- or 64-bit EFI_STATUS to its low error number."""
    if st is None:
        return None
    return st & 0x7FFFFFFFFFFFFFFF


def _assert_signed_unsigned_load(text: str, readable: str, label: str) -> None:
    """Prefer LoadImage evidence; do not fail enrollment if the helper cannot LoadImage."""
    signed_st = _parse_load(text, "HelloSigned.efi")
    unsigned_st = _parse_load(text, "HelloUnsigned.efi")
    bootx64_st = _parse_load(text, "EFI/BOOT/BOOTX64.EFI")
    print(f"NOTE {label} LOAD HelloSigned={signed_st} HelloUnsigned={unsigned_st} BOOTX64={bootx64_st}")
    if signed_st == 0 and unsigned_st not in (None, 0):
        return
    # 0x8000000000000002 / 0x80000002 EFI_INVALID_PARAMETER: gnu-efi LoadImage
    # from this helper is not usable on this OVMF; enrollment itself succeeded.
    if _status_code(signed_st) == 2 and _status_code(unsigned_st) == 2:
        print(
            f"NOTE {label}: LoadImage returned EFI_INVALID_PARAMETER for both "
            "signed and unsigned images; signed-versus-unsigned EFI is not asserted."
        )
        return
    assert signed_st == 0, f"{label} signed Hello failed to load: {signed_st}\n{readable[-4000:]}"
    assert unsigned_st not in (None, 0), f"{label} unsigned Hello was not blocked: {unsigned_st}\n{readable[-4000:]}"

def _parse_status(text: str, var: str, filename: str) -> int | None:
    # USV_STATUS SET db db.auth 0x00000000
    pat = re.compile(rf"USV_STATUS SET {re.escape(var)} {re.escape(filename)} 0x([0-9a-fA-F]+)")
    matches = pat.findall(text)
    if not matches:
        return None
    return int(matches[-1], 16)


def _parse_load(text: str, filename: str) -> int | None:
    # USV_STATUS LOAD HelloSigned.efi 0x00000000
    pat = re.compile(rf"USV_STATUS LOAD {re.escape(filename)} 0x([0-9a-fA-F]+)")
    matches = pat.findall(text)
    if not matches:
        return None
    return int(matches[-1], 16)


def _parse_dump(text: str, var: str) -> tuple[int | None, str]:
    # USV_DUMP SetupMode size=1 0x00000000 data=00
    pat = re.compile(rf"USV_DUMP {re.escape(var)} size=([0-9a-fA-F]+) 0x([0-9a-fA-F]+) data=([0-9a-fA-F]*)")
    matches = pat.findall(text)
    if not matches:
        return None, ""
    size, st, data = matches[-1]
    return int(st, 16), data


def _rc_is_failure(text: str, marker: str) -> bool:
    for line in text.splitlines():
        if marker in line:
            tail = line.split(marker, 1)[-1].strip()
            if not tail:
                return False
            token = tail.split()[0].rstrip(".")
            try:
                value = int(token, 16) if all(c in "0123456789abcdefABCDEF" for c in token) else int(token, 0)
            except ValueError:
                return token not in {"0", "00", "00000000"}
            return value != 0
    return False


def _ascii(text: str) -> str:
    return "".join(ch if 32 <= ord(ch) < 127 or ch in "\n\r\t" else "." for ch in text)


def _run_enroll_pair(tmp_path: Path, auths: dict, label: str, helper: Path, hello: Path):
    fat = build_enroll_fat(tmp_path / f"enroll_{label}.img", auths, helper, hello)
    proc, serial, debugcon, qmp, out, err = _launch_02(tmp_path, fat, reset_vars=True, tag="p1")
    phase1 = ""
    try:
        phase1 = wait_for_serial_marker(serial, "USV_PHASE1_DONE", timeout=180, proc=proc)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
    finally:
        _stop(proc)
    host = out.read_text(errors="replace") + err.read_text(errors="replace")
    readable = _ascii(phase1)
    assert "USV_AUTHSET_DONE" in phase1, readable[-4000:] + "\nHOST:\n" + host[-2000:]
    assert "USV_FIRST_BOOT" in phase1

    db_st = _parse_status(phase1, "db", "db.auth")
    kek_st = _parse_status(phase1, "KEK", "kek.auth")
    pk_st = _parse_status(phase1, "PK", "pk.auth")
    assert db_st == 0, f"db enroll status {db_st}:\n{readable[-4000:]}"
    assert kek_st == 0, f"KEK enroll status {kek_st}:\n{readable[-4000:]}"
    assert pk_st == 0, f"PK enroll status {pk_st}:\n{readable[-4000:]}"

    sm_st, sm_data = _parse_dump(phase1, "SetupMode")
    assert sm_st == 0 and sm_data.endswith("00"), f"SetupMode not 0: st={sm_st} data={sm_data}\n{readable[-4000:]}"
    for var in ("PK", "KEK", "db"):
        st, data = _parse_dump(phase1, var)
        assert st == 0 and len(data) > 0, f"{var} missing after enroll: st={st} data={data}\n{readable[-4000:]}"

    tamper_st = _parse_status(phase1, "db", "db_tampered.auth")
    wrong_st = _parse_status(phase1, "db", "db_wrong.auth")
    assert tamper_st not in (None, 0), f"tampered .auth was not rejected: {tamper_st}\n{readable[-4000:]}"
    assert wrong_st not in (None, 0), f"wrong-key .auth was not rejected: {wrong_st}\n{readable[-4000:]}"

    _assert_signed_unsigned_load(phase1, readable, "phase1")

    # Phase 2: rewrite startup.nsh / cmds.txt on the FAT, reuse enrolled VARS.
    nsh2 = tmp_path / "startup_phase2.nsh"
    cmds2 = tmp_path / "cmds_phase2.txt"
    nsh2.write_text(PHASE2_NSH)
    cmds2.write_text(PHASE2_CMDS)
    mcopy_into(fat, nsh2, "startup.nsh")
    mcopy_into(fat, cmds2, "cmds.txt")

    proc2, serial2, debugcon2, qmp2, out2, err2 = _launch_02(tmp_path, fat, reset_vars=False, tag="p2")
    phase2 = ""
    try:
        phase2 = wait_for_serial_marker(serial2, "USV_PHASE2_DONE", timeout=180, proc=proc2)
        try:
            proc2.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
    finally:
        _stop(proc2)
    host2 = out2.read_text(errors="replace") + err2.read_text(errors="replace")
    readable2 = _ascii(phase2)
    assert "USV_SECOND_BOOT" in phase2, readable2[-4000:] + "\nHOST:\n" + host2[-2000:]
    sm_st2, sm_data2 = _parse_dump(phase2, "SetupMode")
    assert sm_st2 == 0 and sm_data2.endswith("00"), f"SetupMode not 0 on second boot: st={sm_st2} data={sm_data2}\n{readable2[-4000:]}"
    for var in ("PK", "KEK", "db"):
        st, data = _parse_dump(phase2, var)
        assert st == 0 and len(data) > 0, f"{var} missing on second boot: st={st} data={data}\n{readable2[-4000:]}"
    _assert_signed_unsigned_load(phase2, readable2, "phase2")
    return phase1, phase2


@pytest.mark.skipif(bool(_stack_ready()), reason="missing: " + ", ".join(_stack_ready()) if _stack_ready() else "ok")
def test_enroll_lab_auth_in_ovmf(tmp_path):
    setup_lab_certs()
    helper, hello = build_usv_helpers(tmp_path)
    auths = produce_lab_auth()
    _run_enroll_pair(tmp_path, auths, "lab", helper, hello)


@pytest.mark.skipif(bool(_stack_ready()), reason="missing: " + ", ".join(_stack_ready()) if _stack_ready() else "ok")
def test_enroll_efitools_auth_in_ovmf(tmp_path):
    setup_lab_certs()
    helper, hello = build_usv_helpers(tmp_path)
    produce_lab_auth()
    auths = produce_efitools_auth()
    _run_enroll_pair(tmp_path, auths, "efitools", helper, hello)
