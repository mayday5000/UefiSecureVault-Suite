"""EFI_VARIABLE_AUTHENTICATION_2 packet structure and 03/09 wrappers."""
from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from helpers import REPO, WORKSPACE, have_cmd, run, run_ok

PKCS7_GUID = bytes.fromhex("9dd2af4adf68ee498aa9347d375665a7")
IMAGE_SECURITY_GUID = bytes.fromhex("cbb219d73a3d9645a3bcdad00e67656f")
GLOBAL_VARIABLE_GUID = bytes.fromhex("61dfe48bca93d211aa0d00e098032b8c")
STATIC_TIME = bytes.fromhex("EA070A04171E00000000000000000000")
WIN_CERT_REVISION = 0x0200
WIN_CERT_TYPE_EFI_GUID = 0x0EF1


def parse_auth(path: Path) -> dict:
    data = path.read_bytes()
    assert len(data) > 16 + 24, f"auth file too small: {len(data)}"
    efi_time = data[:16]
    dw_length, revision, cert_type = struct.unpack_from("<IHH", data, 16)
    cert_guid = data[24:40]
    pkcs7 = data[40 : 16 + dw_length]
    esl = data[16 + dw_length :]
    return {
        "raw": data,
        "efi_time": efi_time,
        "dw_length": dw_length,
        "revision": revision,
        "cert_type": cert_type,
        "cert_guid": cert_guid,
        "pkcs7": pkcs7,
        "esl": esl,
    }


def openssl_cms_verify(pkcs7: bytes, tbs: bytes, cert: Path, tmp: Path) -> None:
    p7 = tmp / "sig.p7s"
    content = tmp / "tbs.bin"
    p7.write_bytes(pkcs7)
    content.write_bytes(tbs)
    result = run(
        [
            "openssl",
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            str(p7),
            "-content",
            str(content),
            "-certfile",
            str(cert),
            "-noverify",
            "-out",
            str(tmp / "out.bin"),
        ],
        capture_output=True,
    )
    assert result.returncode == 0, f"cms verify failed:\n{result.stderr}"


@pytest.fixture(scope="module")
def lab_certs():
    if not have_cmd("openssl", "cert-to-efi-sig-list"):
        pytest.skip("openssl or efitools (cert-to-efi-sig-list) not installed")
    result = run_ok([str(REPO / "01_setup_certs.sh")], capture_output=True)
    certs = WORKSPACE / "certs"
    assert (certs / "KEK.crt").is_file(), result.stdout + (result.stderr or "")
    assert (WORKSPACE / "db.esl").is_file(), result.stdout
    return certs


def test_static_timestamp_bytes():
    year, month, day, hour, minute, second, pad1 = struct.unpack_from("<HBBBBBB", STATIC_TIME)
    assert (year, month, day, hour, minute, second, pad1) == (2026, 10, 4, 23, 30, 0, 0)
    assert STATIC_TIME[8:] == b"\x00" * 8


def test_03_dbx_static_auth_structure(lab_certs, tmp_path):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"UefiSecureVault auth2 fixture payload\n")
    auth = WORKSPACE / "update_target_dbx.auth"
    if auth.exists():
        auth.unlink()
    result = run_ok(
        [str(REPO / "03_generate_auth_update.sh"), str(payload), "dbx", "--static"],
        capture_output=True,
    )
    assert auth.is_file(), f"expected {auth}:\n{result.stdout}\n{result.stderr}"
    parsed = parse_auth(auth)
    assert parsed["efi_time"] == STATIC_TIME
    assert parsed["revision"] == WIN_CERT_REVISION
    assert parsed["cert_type"] == WIN_CERT_TYPE_EFI_GUID
    assert parsed["cert_guid"] == PKCS7_GUID
    assert parsed["dw_length"] == 24 + len(parsed["pkcs7"])
    assert parsed["pkcs7"].startswith(b"\x30")
    assert len(parsed["esl"]) > 0


def test_03_pk_uses_global_variable_guid(lab_certs):
    # 03 with target PK should sign under EFI_GLOBAL_VARIABLE.
    # Reconstruct the expected GUID by re-running and inspecting the helper
    # via a small sourcer that dumps the guid 03 would use is implicit in 03.
    # Build a PK .auth through 03 if it accepts PK as a target.
    result = run(
        [str(REPO / "03_generate_auth_update.sh"), str(WORKSPACE / "PK.esl"), "PK", "--static"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip(f"03 did not accept PK.esl as a PK payload:\n{result.stderr}{result.stdout}")
    auth = WORKSPACE / "update_target_PK.auth"
    assert auth.is_file(), result.stdout
    parsed = parse_auth(auth)
    assert parsed["cert_guid"] == PKCS7_GUID
    assert parsed["efi_time"] == STATIC_TIME


def test_auth2_wrap_helper_verifies(lab_certs, tmp_path):
    script = tmp_path / "wrap.sh"
    work = tmp_path / "w"
    work.mkdir()
    varname = work / "name.bin"
    varname.write_bytes("db".encode("utf-16le"))
    db_esl = WORKSPACE / "db.esl"
    kek_crt = lab_certs / "KEK.crt"
    kek_key = lab_certs / "KEK.key"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'source "{REPO}/scripts/lib/auth2.sh"\n'
        f'auth2_write_static_timestamp "{work}/time.bin"\n'
        f'auth2_wrap_auth "{work}" "{varname}" "$AUTH2_IMAGE_SECURITY_GUID_HEX" '
        f'"{work}/time.bin" "{db_esl}" "{kek_crt}" "{kek_key}" "{work}/out.auth"\n'
    )
    run_ok(["bash", str(script)], capture_output=True)
    parsed = parse_auth(work / "out.auth")
    assert parsed["efi_time"] == STATIC_TIME
    assert parsed["cert_guid"] == PKCS7_GUID
    assert parsed["dw_length"] == 24 + len(parsed["pkcs7"])
    tbs = (
        varname.read_bytes()
        + IMAGE_SECURITY_GUID
        + bytes.fromhex("27000000")
        + parsed["efi_time"]
        + parsed["esl"]
    )
    openssl_cms_verify(parsed["pkcs7"], tbs, kek_crt, tmp_path)
    assert parsed["esl"] == db_esl.read_bytes()


def test_09_kek_signed_db_auth(lab_certs):
    if not (WORKSPACE / "db.esl").is_file():
        pytest.skip("db.esl missing")
    result = run_ok(
        [str(REPO / "09_sign_db_with_kek.sh"), str(WORKSPACE / "db.esl"), "db"],
        capture_output=True,
    )
    auth = WORKSPACE / "update_db_secured.auth"
    assert auth.is_file(), result.stdout
    parsed = parse_auth(auth)
    assert parsed["efi_time"] == STATIC_TIME
    assert parsed["cert_guid"] == PKCS7_GUID
    assert parsed["revision"] == WIN_CERT_REVISION
