#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 11_extract_and_patch_iso.sh
# Merges 11_extract_and_patch_iso.sh and 11_extract_and_patch_iso_2.sh.
# Replaces media bootloaders, drops autounattend.xml, rebuilds a UEFI-bootable ISO.
set -euo pipefail

VANILLA_ISO="windows11_vanilla.iso"
PATCHED_ISO="workspace/windows_patched.iso"
SIGNED_EFI="workspace/winboot_signed.efi"
KEEP_TREE=0

PrintHelp() {
    echo "Usage: $0 [--iso PATH] [--signed-efi PATH] [--output PATH] [--keep-tree]"
    echo "  --iso PATH         Vanilla ISO. Default windows11_vanilla.iso"
    echo "                     (also accepts windows10_vanilla.iso or windows_vanilla.iso)."
    echo "  --signed-efi PATH  Replacement bootloader. Default workspace/winboot_signed.efi"
    echo "  --output PATH      Patched ISO. Default workspace/windows_patched.iso"
    echo "  --keep-tree        Leave tmp_iso_extract/ in place for 13_patch_winpe_image.sh."
    echo "Volume label: VAULT_LAB"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --iso) VANILLA_ISO="${2:?}"; shift ;;
        --signed-efi) SIGNED_EFI="${2:?}"; shift ;;
        --output) PATCHED_ISO="${2:?}"; shift ;;
        --keep-tree) KEEP_TREE=1 ;;
        -h|--help) PrintHelp; exit 0 ;;
        *) echo "[-] Unknown argument: $1"; PrintHelp; exit 1 ;;
    esac
    shift
done

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: Unified ISO Compilation & Patching Engine     "
echo "========================================================================="

for cmd in xorriso wimlib-imagex; do
    if ! command -v "$cmd" &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y xorriso wimtools
        break
    fi
done

if [ ! -f "$VANILLA_ISO" ]; then
    echo "[-] Error: Vanilla target missing ($VANILLA_ISO). Run ./00_download_windows_iso.sh first."
    exit 1
fi
if [ ! -f "$SIGNED_EFI" ]; then
    echo "[-] Error: Custom-signed bootloader missing. Run ./05_sign_custom_winboot.sh first."
    exit 1
fi
if [ ! -f autounattend.xml ]; then
    echo "[-] Error: autounattend.xml is not in the repository root."
    exit 1
fi

mkdir -p workspace tmp_iso_extract
echo "[*] STEP 1: Extracting media directory trees via xorriso..."
xorriso -osirrox on -indev "$VANILLA_ISO" -extract / tmp_iso_extract

echo "[*] STEP 2: Applying signatures and patching operational boot files..."
cp "$SIGNED_EFI" tmp_iso_extract/efi/boot/bootx64.efi
mkdir -p tmp_iso_extract/efi/microsoft/boot
cp "$SIGNED_EFI" tmp_iso_extract/efi/microsoft/boot/cdboot.efi

echo "[*] STEP 3: Injecting hardware check bypass answer file..."
cp autounattend.xml tmp_iso_extract/

echo "[*] STEP 4: Compiling patched image..."
xorriso -as mkisofs \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot \
    -e efi/boot/bootx64.efi \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -volid "VAULT_LAB" \
    -o "$PATCHED_ISO" \
    tmp_iso_extract/

if [ "$KEEP_TREE" -eq 0 ]; then
    rm -rf tmp_iso_extract
    echo "[*] Intermediate tree removed. Re-run with --keep-tree before 13_patch_winpe_image.sh."
else
    echo "[*] tmp_iso_extract/ retained for WinPE injection."
fi
echo -e "\n[++] SUCCESS: Patch cycle complete. Target ready: $PATCHED_ISO"
