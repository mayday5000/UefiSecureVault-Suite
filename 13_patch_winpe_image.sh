#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 13_patch_winpe_image.sh
# Mounts boot.wim index 2, injects Win32 diagnostics and winpeshl.ini, stages EFI apps on the ISO tree.
# Restores sources/boot.wim from tmp_iso_state/boot.wim.orig before a redo so injections never stack.
# Writes tmp_iso_extract/.stamp_winpe on success and skips when that stamp still matches the inputs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PATCHED_ISO_DIR="tmp_iso_extract"
if [ "${1:-}" == "-h" ] || [ "${1:-}" == "--help" ]; then
    echo "Usage: $0 [unpacked_iso_directory]"
    echo "Default directory: tmp_iso_extract"
    echo "  Produce the tree with: ./11_extract_and_patch_iso.sh --extract --patch"
    echo "  After this script:     ./11_extract_and_patch_iso.sh --rebuild"
    echo "Injects:"
    echo "  workspace/VerifyRuntimeBoundaries.exe"
    echo "  workspace/AuditMeasuredBootLog.exe   (if present)"
    echo "  winpeshl.ini"
    echo "  workspace/SignatureParserApp.efi and SecureManagerApp.efi onto the ISO root"
    echo "Restores sources/boot.wim from tmp_iso_state/boot.wim.orig before a redo."
    echo "Skips when .stamp_winpe still matches the injected inputs."
    exit 0
fi
if [ $# -gt 0 ]; then
    PATCHED_ISO_DIR="${1%/}"
fi

BOOT_WIM_PATH="${PATCHED_ISO_DIR}/sources/boot.wim"
STAMP_WINPE="${PATCHED_ISO_DIR}/.stamp_winpe"
STATE_DIR="$(dirname "$PATCHED_ISO_DIR")/tmp_iso_state"
if [ "$(dirname "$PATCHED_ISO_DIR")" = "." ]; then
    STATE_DIR="tmp_iso_state"
fi
BOOT_WIM_ORIG="${STATE_DIR}/boot.wim.orig"
MOUNT_DIR="tmp_wim_mount"
MOUNTED=0

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

input_hash_line() {
    local label="$1"
    local path="$2"
    if [ -f "$path" ]; then
        printf '%s=%s\n' "$label" "$(file_sha256 "$path")"
    else
        printf '%s=missing\n' "$label"
    fi
}

ComputeWinpeHash() {
    {
        input_hash_line VerifyRuntimeBoundaries.exe workspace/VerifyRuntimeBoundaries.exe
        input_hash_line AuditMeasuredBootLog.exe workspace/AuditMeasuredBootLog.exe
        input_hash_line winpeshl.ini winpeshl.ini
        input_hash_line SignatureParserApp.efi workspace/SignatureParserApp.efi
        input_hash_line SecureManagerApp.efi workspace/SecureManagerApp.efi
    } | sha256sum | awk '{print $1}'
}

WinpeStampBody() {
    local composite="$1"
    echo "sha256=${composite}"
    input_hash_line VerifyRuntimeBoundaries.exe workspace/VerifyRuntimeBoundaries.exe
    input_hash_line AuditMeasuredBootLog.exe workspace/AuditMeasuredBootLog.exe
    input_hash_line winpeshl.ini winpeshl.ini
    input_hash_line SignatureParserApp.efi workspace/SignatureParserApp.efi
    input_hash_line SecureManagerApp.efi workspace/SecureManagerApp.efi
}

WimMount() {
    local wim="$1"
    local dest="$2"
    if command -v wimmountrw >/dev/null 2>&1; then
        wimmountrw "$wim" 2 "$dest"
    elif command -v wimlib-imagex >/dev/null 2>&1; then
        wimlib-imagex mountrw "$wim" 2 "$dest"
    else
        echo "[-] Error: wimmountrw / wimlib-imagex not found. Install wimtools (wimlib) and retry."
        exit 1
    fi
}

WimUnmountCommit() {
    local dest="$1"
    if command -v wimunmount >/dev/null 2>&1; then
        wimunmount --commit "$dest"
    elif command -v wimlib-imagex >/dev/null 2>&1; then
        wimlib-imagex unmount "$dest" --commit
    else
        echo "[-] Error: no wim unmount tool found."
        exit 1
    fi
}

WimUnmountDiscard() {
    local dest="$1"
    if command -v wimunmount >/dev/null 2>&1; then
        wimunmount "$dest" >/dev/null 2>&1 || true
    elif command -v wimlib-imagex >/dev/null 2>&1; then
        wimlib-imagex unmount "$dest" >/dev/null 2>&1 || true
    fi
}

cleanup() {
    if [ "$MOUNTED" -eq 1 ]; then
        echo "[*] Cleaning up: discarding WinPE mount at $MOUNT_DIR"
        WimUnmountDiscard "$MOUNT_DIR"
        MOUNTED=0
    fi
    if [ -d "$MOUNT_DIR" ]; then
        rmdir "$MOUNT_DIR" 2>/dev/null || rm -rf "$MOUNT_DIR"
    fi
}
trap cleanup EXIT

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: WinPE Image Extraction & Injection Engine     "
echo "========================================================================="

if [ ! -d "$PATCHED_ISO_DIR" ]; then
    echo "[-] Error: Unpacked ISO directory missing ($PATCHED_ISO_DIR)."
    echo "    Run ./11_extract_and_patch_iso.sh --extract --patch first."
    exit 1
fi
if [ ! -f "$BOOT_WIM_PATH" ]; then
    echo "[-] Error: $BOOT_WIM_PATH not found. Run ./11_extract_and_patch_iso.sh --extract --patch first."
    exit 1
fi
if [ ! -f workspace/VerifyRuntimeBoundaries.exe ]; then
    echo "[-] Error: Compiled Win32 boundary verification executable missing."
    echo "    Run ./14_compile_win32_diagnostics.sh first."
    exit 1
fi
if [ ! -f winpeshl.ini ]; then
    echo "[-] Error: winpeshl.ini is not in the repository root."
    exit 1
fi

WINPE_HASH="$(ComputeWinpeHash)"
if [ -f "$STAMP_WINPE" ] && grep -q "^sha256=${WINPE_HASH}$" "$STAMP_WINPE"; then
    echo "[*] WinPE injection skipped: $STAMP_WINPE matches the current inputs."
    echo "[*] Rebuild the ISO with: ./11_extract_and_patch_iso.sh --rebuild"
    trap - EXIT
    exit 0
fi

if [ ! -f "$BOOT_WIM_ORIG" ]; then
    echo "[-] Error: pristine boot.wim original missing ($BOOT_WIM_ORIG)."
    echo "    Re-run ./11_extract_and_patch_iso.sh --extract --force to recapture it."
    exit 1
fi

echo "[*] Restoring sources/boot.wim from $BOOT_WIM_ORIG so injections do not stack..."
cp -f "$BOOT_WIM_ORIG" "$BOOT_WIM_PATH"

mkdir -p "$MOUNT_DIR"
echo "[*] STEP 1: Mounting boot.wim index 2 (Windows Setup WinPE)..."
WimMount "$BOOT_WIM_PATH" "$MOUNT_DIR"
MOUNTED=1

echo "[*] STEP 2: Injecting Win32 low-level diagnostics into WinPE system path..."
mkdir -p "${MOUNT_DIR}/Windows/System32"
cp workspace/VerifyRuntimeBoundaries.exe "${MOUNT_DIR}/Windows/System32/"
if [ -f workspace/AuditMeasuredBootLog.exe ]; then
    cp workspace/AuditMeasuredBootLog.exe "${MOUNT_DIR}/Windows/System32/"
fi
echo "[*] Injecting custom winpeshl.ini shell interception hook configuration..."
cp winpeshl.ini "${MOUNT_DIR}/Windows/System32/"

echo "[*] STEP 3: Staging UEFI utilities onto the media storage root..."
if [ -f workspace/SignatureParserApp.efi ]; then
    cp workspace/SignatureParserApp.efi "${PATCHED_ISO_DIR}/"
else
    echo "[-] SignatureParserApp.efi not staged yet."
fi
if [ -f workspace/SecureManagerApp.efi ]; then
    cp workspace/SecureManagerApp.efi "${PATCHED_ISO_DIR}/"
else
    echo "[-] SecureManagerApp.efi not staged yet."
fi

echo "[*] STEP 4: Unmounting and committing modified boot.wim..."
WimUnmountCommit "$MOUNT_DIR"
MOUNTED=0
rmdir "$MOUNT_DIR" 2>/dev/null || rm -rf "$MOUNT_DIR"

WinpeStampBody "$WINPE_HASH" > "$STAMP_WINPE"

echo -e "\n[++] SUCCESS: WinPE matrix successfully patched."
echo "[*] Stamp written: $STAMP_WINPE"
echo "[*] Rebuild the ISO from this tree with: ./11_extract_and_patch_iso.sh --rebuild"
