#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 13_patch_winpe_image.sh
# Mounts boot.wim index 2, injects Win32 diagnostics and winpeshl.ini, stages EFI apps on the ISO tree.
set -euo pipefail

PATCHED_ISO_DIR="${1:-tmp_iso_extract}"
BOOT_WIM_PATH="${PATCHED_ISO_DIR}/sources/boot.wim"

if [ "${1:-}" == "-h" ] || [ "${1:-}" == "--help" ]; then
    echo "Usage: $0 [unpacked_iso_directory]"
    echo "Default directory: tmp_iso_extract  (produce it with 11_extract_and_patch_iso.sh --keep-tree)"
    echo "Injects:"
    echo "  workspace/VerifyRuntimeBoundaries.exe"
    echo "  workspace/AuditMeasuredBootLog.exe   (if present)"
    echo "  winpeshl.ini"
    echo "  workspace/SignatureParserApp.efi and SecureManagerApp.efi onto the ISO root"
    exit 0
fi

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: WinPE Image Extraction & Injection Engine     "
echo "========================================================================="

if [ ! -d "$PATCHED_ISO_DIR" ]; then
    echo "[-] Error: Unpacked ISO directory missing. Run ./11_extract_and_patch_iso.sh --keep-tree first."
    exit 1
fi
if [ ! -f workspace/VerifyRuntimeBoundaries.exe ]; then
    echo "[-] Error: Compiled Win32 boundary verification executable missing."
    echo "    Run ./14_compile_win32_diagnostics.sh first."
    exit 1
fi

mkdir -p tmp_wim_mount
echo "[*] STEP 1: Mounting boot.wim index 2 (Windows Setup WinPE)..."
wimmountrw "$BOOT_WIM_PATH" 2 tmp_wim_mount

echo "[*] STEP 2: Injecting Win32 low-level diagnostics into WinPE system path..."
cp workspace/VerifyRuntimeBoundaries.exe tmp_wim_mount/Windows/System32/
if [ -f workspace/AuditMeasuredBootLog.exe ]; then
    cp workspace/AuditMeasuredBootLog.exe tmp_wim_mount/Windows/System32/
fi
echo "[*] Injecting custom winpeshl.ini shell interception hook configuration..."
cp winpeshl.ini tmp_wim_mount/Windows/System32/

echo "[*] STEP 3: Staging UEFI utilities onto the media storage root..."
cp workspace/SignatureParserApp.efi "$PATCHED_ISO_DIR/" || echo "[-] SignatureParserApp.efi not staged yet."
cp workspace/SecureManagerApp.efi "$PATCHED_ISO_DIR/" || echo "[-] SecureManagerApp.efi not staged yet."

echo "[*] STEP 4: Unmounting and committing modified boot.wim..."
wimunmount --commit tmp_wim_mount
rmdir tmp_wim_mount || true

echo -e "\n[++] SUCCESS: WinPE matrix successfully patched."
echo "[*] Re-run 11_extract_and_patch_iso.sh only if you still need a fresh ISO from this tree,"
echo "    or rebuild with xorriso against $PATCHED_ISO_DIR if you edited it in place."
