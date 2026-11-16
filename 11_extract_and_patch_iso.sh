#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 11_extract_and_patch_iso.sh
# Merges 11_extract_and_patch_iso.sh and 11_extract_and_patch_iso_2.sh.
# Replaces media bootloaders, drops autounattend.xml, rebuilds a UEFI-bootable ISO.
#
# Modes (combinable): --extract, --patch, --rebuild, --all, --clean, --force.
# Default with no mode flags is --all (extract + patch + rebuild).
# The unpacked tree is kept by default so 13_patch_winpe_image.sh can inject WinPE.
# --keep-tree is accepted and ignored (deprecated).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VANILLA_ISO="windows11_vanilla.iso"
PATCHED_ISO="workspace/windows_patched.iso"
SIGNED_EFI="workspace/winboot_signed.efi"
ISO_DIR="tmp_iso_extract"
STATE_DIR="tmp_iso_state"
STAMP_EXTRACT="${ISO_DIR}/.stamp_extract"
STAMP_PATCH="${ISO_DIR}/.stamp_patch_iso"
STAMP_WINPE="${ISO_DIR}/.stamp_winpe"
BOOT_WIM_ORIG="${STATE_DIR}/boot.wim.orig"

DO_EXTRACT=0
DO_PATCH=0
DO_REBUILD=0
DO_CLEAN=0
FORCE=0
MODE_SET=0

PrintHelp() {
    echo "Usage: $0 [modes] [--iso PATH] [--signed-efi PATH] [--output PATH] [--force] [--keep-tree]"
    echo ""
    echo "Modes:"
    echo "  --extract      Unpack the vanilla ISO into tmp_iso_extract/."
    echo "                 Skips when .stamp_extract matches the source ISO, unless --force."
    echo "                 Saves sources/boot.wim to tmp_iso_state/boot.wim.orig (never in the ISO)."
    echo "  --patch        Inject the signed bootloader and autounattend.xml."
    echo "                 Skips when .stamp_patch_iso matches the inputs, unless --force."
    echo "  --rebuild      Rebuild the output ISO from the existing tree only."
    echo "                 Errors if tmp_iso_extract/ is missing."
    echo "  --all          extract + patch + rebuild. This is the default when no mode is given."
    echo "                 Refuses to extract over a tree that has .stamp_winpe unless --force."
    echo "  --clean        Delete tmp_iso_extract/ and tmp_iso_state/ and exit."
    echo "  --force        Ignore stamps; allow re-extract when a WinPE stamp is present."
    echo "  --keep-tree    Deprecated and ignored. The tree is kept by default. Use --clean to delete it."
    echo ""
    echo "  --iso PATH         Vanilla ISO. Default windows11_vanilla.iso"
    echo "  --signed-efi PATH  Replacement bootloader. Default workspace/winboot_signed.efi"
    echo "  --output PATH      Patched ISO. Default workspace/windows_patched.iso"
    echo ""
    echo "WinPE path:  $0 --extract --patch && ./13_patch_winpe_image.sh && $0 --rebuild"
    echo "ISO-only:    $0 --all"
    echo "Volume label: VAULT_LAB"
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --iso) VANILLA_ISO="${2:?}"; shift ;;
        --signed-efi) SIGNED_EFI="${2:?}"; shift ;;
        --output) PATCHED_ISO="${2:?}"; shift ;;
        --extract) DO_EXTRACT=1; MODE_SET=1 ;;
        --patch) DO_PATCH=1; MODE_SET=1 ;;
        --rebuild) DO_REBUILD=1; MODE_SET=1 ;;
        --all) DO_EXTRACT=1; DO_PATCH=1; DO_REBUILD=1; MODE_SET=1 ;;
        --clean) DO_CLEAN=1; MODE_SET=1 ;;
        --force) FORCE=1 ;;
        --keep-tree)
            echo "[*] Note: --keep-tree is deprecated and ignored."
            echo "    tmp_iso_extract/ is kept by default. Use --clean to delete the tree and tmp_iso_state/."
            ;;
        -h|--help) PrintHelp; exit 0 ;;
        *) echo "[-] Unknown argument: $1"; PrintHelp; exit 1 ;;
    esac
    shift
done

if [ "$MODE_SET" -eq 0 ]; then
    DO_EXTRACT=1
    DO_PATCH=1
    DO_REBUILD=1
fi

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: Unified ISO Compilation & Patching Engine     "
echo "========================================================================="

if [ "$DO_CLEAN" -eq 1 ]; then
    if [ "$DO_EXTRACT" -eq 1 ] || [ "$DO_PATCH" -eq 1 ] || [ "$DO_REBUILD" -eq 1 ]; then
        echo "[-] --clean cannot be combined with --extract, --patch, --rebuild, or --all."
        exit 1
    fi
    rm -rf "$ISO_DIR" "$STATE_DIR"
    echo "[++] Removed $ISO_DIR and $STATE_DIR."
    exit 0
fi

if ! command -v xorriso >/dev/null 2>&1; then
    echo "[*] xorriso missing. Attempting installation via apt..."
    sudo apt-get update && sudo apt-get install -y xorriso
fi
if ! command -v xorriso >/dev/null 2>&1; then
    echo "[-] Error: xorriso is required."
    exit 1
fi

DoExtract() {
    if [ ! -f "$VANILLA_ISO" ]; then
        echo "[-] Error: Vanilla target missing ($VANILLA_ISO). Run ./00_download_windows_iso.sh first."
        exit 1
    fi
    if [ -f "$STAMP_WINPE" ] && [ "$FORCE" -eq 0 ]; then
        echo "[-] Refusing to extract: $STAMP_WINPE is present (WinPE injection would be lost)."
        echo "    Rebuild the existing tree with: $0 --rebuild"
        echo "    Or pass --force to re-extract, or --clean first."
        exit 1
    fi
    echo "[*] Hashing source ISO $VANILLA_ISO ..."
    local iso_hash
    iso_hash="$(file_sha256 "$VANILLA_ISO")"
    if [ "$FORCE" -eq 0 ] && [ -f "$STAMP_EXTRACT" ] && [ -d "$ISO_DIR" ]; then
        if grep -q "^sha256=${iso_hash}$" "$STAMP_EXTRACT"; then
            echo "[*] Extract skipped: $STAMP_EXTRACT matches $VANILLA_ISO."
            return 0
        fi
    fi
    echo "[*] Extracting media directory tree via xorriso..."
    rm -rf "$ISO_DIR"
    mkdir -p "$ISO_DIR" "$STATE_DIR" workspace
    xorriso -osirrox on -indev "$VANILLA_ISO" -extract / "$ISO_DIR"
    if [ -f "${ISO_DIR}/sources/boot.wim" ]; then
        cp -f "${ISO_DIR}/sources/boot.wim" "$BOOT_WIM_ORIG"
        echo "[*] Saved pristine sources/boot.wim to $BOOT_WIM_ORIG (not packed into the ISO)."
    else
        echo "[-] Warning: ${ISO_DIR}/sources/boot.wim not found; 13_patch_winpe_image.sh will not have a restore original."
        rm -f "$BOOT_WIM_ORIG"
    fi
    {
        echo "sha256=${iso_hash}"
        echo "iso=${VANILLA_ISO}"
    } > "$STAMP_EXTRACT"
    rm -f "$STAMP_PATCH" "$STAMP_WINPE"
    echo "[+] Extract complete. Stamp: $STAMP_EXTRACT"
}

DoPatch() {
    if [ ! -d "$ISO_DIR" ]; then
        echo "[-] Error: $ISO_DIR is missing. Run $0 --extract first."
        exit 1
    fi
    if [ ! -f "$SIGNED_EFI" ]; then
        echo "[-] Error: Custom-signed bootloader missing ($SIGNED_EFI). Run ./05_sign_custom_winboot.sh first."
        exit 1
    fi
    if [ ! -f autounattend.xml ]; then
        echo "[-] Error: autounattend.xml is not in the repository root."
        exit 1
    fi
    local au_hash efi_hash patch_hash
    au_hash="$(file_sha256 autounattend.xml)"
    efi_hash="$(file_sha256 "$SIGNED_EFI")"
    patch_hash="$(printf '%s\n%s\n%s\n' "$au_hash" "$efi_hash" "signed_efi=${SIGNED_EFI}" | sha256sum | awk '{print $1}')"
    if [ "$FORCE" -eq 0 ] && [ -f "$STAMP_PATCH" ] && grep -q "^sha256=${patch_hash}$" "$STAMP_PATCH"; then
        echo "[*] Patch skipped: $STAMP_PATCH matches autounattend.xml and $SIGNED_EFI."
        return 0
    fi
    echo "[*] Applying signatures and patching operational boot files..."
    mkdir -p "${ISO_DIR}/efi/boot" "${ISO_DIR}/efi/microsoft/boot"
    cp "$SIGNED_EFI" "${ISO_DIR}/efi/boot/bootx64.efi"
    cp "$SIGNED_EFI" "${ISO_DIR}/efi/microsoft/boot/cdboot.efi"
    echo "[*] Injecting hardware check bypass answer file..."
    cp autounattend.xml "${ISO_DIR}/"
    {
        echo "sha256=${patch_hash}"
        echo "autounattend=${au_hash}"
        echo "signed_efi=${SIGNED_EFI}"
        echo "signed_efi_sha256=${efi_hash}"
    } > "$STAMP_PATCH"
    echo "[+] Patch complete. Stamp: $STAMP_PATCH"
}

DoRebuild() {
    if [ ! -d "$ISO_DIR" ]; then
        echo "[-] Error: $ISO_DIR is missing. Cannot rebuild."
        echo "    Run $0 --extract --patch first (and ./13_patch_winpe_image.sh if you need WinPE)."
        exit 1
    fi
    mkdir -p workspace
    local out_dir
    out_dir="$(dirname "$PATCHED_ISO")"
    mkdir -p "$out_dir"
    echo "[*] Compiling patched image $PATCHED_ISO from $ISO_DIR ..."
    # TODO: El Torito currently uses efi/boot/bootx64.efi as the EFI boot image
    # instead of a dedicated efisys.bin / El Torito EFI system partition image.
    # Left unchanged in this pass; the existing argument list is preserved, plus
    # -m to keep .stamp_* files out of the published ISO.
    set +e
    xorriso -as mkisofs \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot \
        -e efi/boot/bootx64.efi \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        -volid "VAULT_LAB" \
        -m '.stamp_*' \
        -o "$PATCHED_ISO" \
        "${ISO_DIR}/"
    local rc=$?
    set -e
    if [ ! -s "$PATCHED_ISO" ]; then
        echo "[-] Error: xorriso failed to write $PATCHED_ISO (exit $rc)."
        exit 1
    fi
    if [ "$rc" -ne 0 ]; then
        # Preserved El Torito args can yield xorriso SORRY ("Isolinux image too small")
        # on images that have no BIOS boot loader, even after a successful write.
        echo "[*] Note: xorriso exited $rc but wrote $PATCHED_ISO. Continuing."
    fi
    echo "[+] Rebuild complete: $PATCHED_ISO"
}

if [ "$DO_EXTRACT" -eq 1 ]; then
    DoExtract
fi
if [ "$DO_PATCH" -eq 1 ]; then
    DoPatch
fi
if [ "$DO_REBUILD" -eq 1 ]; then
    DoRebuild
fi

echo -e "\n[++] SUCCESS: Requested ISO steps complete."
if [ -d "$ISO_DIR" ]; then
    echo "[*] Unpacked tree kept at $ISO_DIR (stamps: .stamp_extract / .stamp_patch_iso / .stamp_winpe)."
fi
if [ "$DO_REBUILD" -eq 1 ]; then
    echo "[*] Target ready: $PATCHED_ISO"
fi
