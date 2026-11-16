"""bash -n and shellcheck on the scripts this suite owns."""
from __future__ import annotations

import shutil

import pytest

from helpers import REPO, run

SCRIPTS = [
    "02_run_qemu.sh",
    "03_generate_auth_update.sh",
    "09_sign_db_with_kek.sh",
    "11_extract_and_patch_iso.sh",
    "12_run_patched_iso_qemu.sh",
    "13_patch_winpe_image.sh",
    "14_compile_win32_diagnostics.sh",
    "build_uefi.sh",
    "scripts/qemu_common.sh",
    "scripts/lib/auth2.sh",
    "tests/run_tests.sh",
]


@pytest.mark.parametrize("rel", SCRIPTS)
def test_bash_n(rel):
    path = REPO / rel
    assert path.is_file(), rel
    result = run(["bash", "-n", str(path)], capture_output=True)
    assert result.returncode == 0, f"bash -n {rel} failed:\n{result.stderr}"


@pytest.mark.parametrize("rel", SCRIPTS)
def test_shellcheck(rel):
    if shutil.which("shellcheck") is None:
        pytest.skip("shellcheck not installed")
    path = REPO / rel
    result = run(
        ["shellcheck", "-x", str(path)],
        capture_output=True,
    )
    assert result.returncode == 0, f"shellcheck -x {rel} failed:\n{result.stdout}{result.stderr}"
