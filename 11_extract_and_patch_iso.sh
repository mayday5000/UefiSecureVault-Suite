#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 11_extract_and_patch_iso.sh
# Merges 11_extract_and_patch_iso.sh and 11_extract_and_patch_iso_2.sh.
# Replaces media bootloaders, drops autounattend.xml, and rebuilds a Windows-style
# UEFI (and optional BIOS) El Torito ISO.
#
# Modes (combinable): --extract, --patch, --rebuild, --all, --clean, --force.
# Default with no mode flags is --all (extract + patch + rebuild).
# The unpacked tree is kept by default so 13_patch_winpe_image.sh can inject WinPE.
# --keep-tree is accepted and ignored (deprecated).
set -euo pipefail
# mkfs.vfat lives in /usr/sbin on Debian.
export PATH="/usr/local/bin:/usr/sbin:/sbin:${PATH}"

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
EFI_ELTORITO="auto"
SPLIT_WIM=0
# ISO 9660 level-3 practical file-size ceiling used to decide when to split install.wim.
# Override with --iso9660-max-file BYTES or USV_ISO9660_MAX_FILE (used by tests).
if [ -n "${USV_ISO9660_MAX_FILE:-}" ]; then
    ISO9660_MAX_FILE="$USV_ISO9660_MAX_FILE"
else
    ISO9660_MAX_FILE=$((4 * 1024 * 1024 * 1024 - 32 * 1024))
fi
UDF_ENCODER=""

PrintHelp() {
    echo "Usage: $0 [modes] [--iso PATH] [--signed-efi PATH] [--output PATH] [--force] [--keep-tree]"
    echo "       [--efi-eltorito auto|noprompt|prompt|PATH] [--split-wim] [--iso9660-max-file BYTES]"
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
    echo "  --efi-eltorito MODE   EFI El Torito image (default auto):"
    echo "                     auto      efisys_noprompt.bin, else efisys.bin, else a generated ESP"
    echo "                     noprompt  efi/microsoft/boot/efisys_noprompt.bin (error if missing)"
    echo "                     prompt    efi/microsoft/boot/efisys.bin (error if missing)"
    echo "                     PATH      A file in the unpacked tree, or an absolute path copied in"
    echo "  --split-wim        Split sources/install.wim to install.swm with wimlib, even when a"
    echo "                     UDF-capable mkisofs/genisoimage/xorriso is available."
    echo "                     A too-large install.wim is also split automatically when no UDF"
    echo "                     encoder is available."
    echo "  --iso9660-max-file BYTES"
    echo "                     File-size threshold for the auto-split / UDF decision. Default is"
    echo "                     4 GiB minus 32 KiB, or \$USV_ISO9660_MAX_FILE when that is set."
    echo ""
    echo "WinPE path:  $0 --extract --patch && ./13_patch_winpe_image.sh && $0 --rebuild"
    echo "ISO-only:    $0 --all"
    echo "Volume label: VAULT_LAB"
    echo "Rebuild uses efi/microsoft/boot/efisys_noprompt.bin or efisys.bin as the EFI El Torito"
    echo "image (-e ... -no-emul-boot). BIOS boot is added from boot/etfsboot.com when present"
    echo "(-b ... -no-emul-boot -boot-load-size 8). If no efisys* image exists, a FAT ESP"
    echo "containing efi/boot/bootx64.efi is generated and used instead. install.wim files over"
    echo "the ISO 9660 size limit need UDF. If this xorriso has no -udf, 11 uses"
    echo "genisoimage/mkisofs -udf when those tools are installed; otherwise the WIM is"
    echo "split to .swm. Tests may lower the threshold with --iso9660-max-file."
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --iso) VANILLA_ISO="${2:?}"; shift ;;
        --signed-efi) SIGNED_EFI="${2:?}"; shift ;;
        --output) PATCHED_ISO="${2:?}"; shift ;;
        --efi-eltorito) EFI_ELTORITO="${2:?}"; shift ;;
        --split-wim) SPLIT_WIM=1 ;;
        --iso9660-max-file)
            ISO9660_MAX_FILE="${2:?--iso9660-max-file requires a byte count}"
            shift
            ;;
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

case "$ISO9660_MAX_FILE" in
    ''|*[!0-9]*)
        echo "[-] --iso9660-max-file must be a positive byte count, got: $ISO9660_MAX_FILE"
        exit 1
        ;;
esac
if [ "$ISO9660_MAX_FILE" -lt 1 ]; then
    echo "[-] --iso9660-max-file must be a positive byte count, got: $ISO9660_MAX_FILE"
    exit 1
fi

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

xorriso_has_udf() {
    # This Debian xorriso 1.5.6 build does not advertise -udf under -as mkisofs.
    # Capture help into a variable: grep -q in a pipefail pipeline can SIGPIPE
    # the producer and falsely report "no -udf".
    command -v xorriso >/dev/null 2>&1 || return 1
    local help
    help="$(xorriso -as mkisofs -help 2>&1 || true)"
    case "$help" in
        *'-udf'*) return 0 ;;
    esac
    return 1
}

# Prefer xorriso when it can emit UDF; otherwise genisoimage/mkisofs -udf.
detect_udf_encoder() {
    UDF_ENCODER=""
    if xorriso_has_udf; then
        UDF_ENCODER="xorriso"
        return 0
    fi
    local cmd help
    for cmd in genisoimage mkisofs; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        help="$("$cmd" -help 2>&1 || true)"
        case "$help" in
            *'-udf'*)
                UDF_ENCODER="$cmd"
                return 0
                ;;
        esac
    done
    return 1
}

rebuild_with_udf_mkisofs() {
    local args=(
        -iso-level 3
        -J
        -joliet-long
        -R
        -V "VAULT_LAB"
        -udf
        -allow-limited-size
        -m '.stamp_*'
    )
    if [ -f "${ISO_DIR}/boot/etfsboot.com" ]; then
        args+=(-b boot/etfsboot.com -no-emul-boot -boot-load-size 8 -eltorito-alt-boot)
        echo "[*] BIOS El Torito image: boot/etfsboot.com"
    fi
    args+=(-e "$REBUILD_EFI_REL" -no-emul-boot)
    args+=(-o "$PATCHED_ISO" "${ISO_DIR}/")
    echo "[*] Compiling $PATCHED_ISO with $UDF_ENCODER -udf ..."
    set +e
    "$UDF_ENCODER" "${args[@]}"
    local rc=$?
    set -e
    if [ ! -s "$PATCHED_ISO" ]; then
        echo "[-] Error: $UDF_ENCODER failed to write $PATCHED_ISO (exit $rc)."
        exit 1
    fi
    if [ "$rc" -ne 0 ]; then
        echo "[*] Note: $UDF_ENCODER exited $rc but wrote $PATCHED_ISO. Continuing."
    fi
    echo "[+] Rebuild complete: $PATCHED_ISO (UDF via $UDF_ENCODER)"
}

make_esp_image() {
    local dest="$1"
    local bootx64="$2"
    local dir
    dir="$(dirname "$dest")"
    mkdir -p "$dir"
    if [ ! -f "$bootx64" ]; then
        echo "[-] Error: cannot generate an ESP El Torito image; $bootx64 is missing."
        exit 1
    fi
    echo "[*] Generating a FAT ESP El Torito image at $dest from $bootx64"
    dd if=/dev/zero of="$dest" bs=1M count=2 status=none
    if command -v mkfs.vfat >/dev/null 2>&1; then
        mkfs.vfat -n EFIBOOT "$dest" >/dev/null
    else
        echo "[-] Error: mkfs.vfat is required to generate an ESP image (dosfstools)."
        exit 1
    fi
    if ! command -v mmd >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
        echo "[-] Error: mtools (mmd/mcopy) is required to generate an ESP image."
        exit 1
    fi
    mmd -i "$dest" ::EFI
    mmd -i "$dest" ::EFI/BOOT
    mcopy -i "$dest" -D o "$bootx64" ::EFI/BOOT/BOOTX64.EFI
}

# Resolve the EFI El Torito image path relative to ISO_DIR, generating an ESP if needed.
# Sets REBUILD_EFI_REL.
refresh_eltorito_esp() {
    # Official Windows efisys.bin is a FAT ESP that contains its own
    # EFI/BOOT/BOOTX64.EFI. After  --patch  replaces the tree's
    # efi/boot/bootx64.efi, copy that loader into the El Torito image too.
    local img="${ISO_DIR}/${REBUILD_EFI_REL}"
    local bootx64="${ISO_DIR}/efi/boot/bootx64.efi"
    local nsh="${ISO_DIR}/startup.nsh"
    if [ ! -f "$img" ] || [ ! -f "$bootx64" ]; then
        return 0
    fi
    if ! command -v mdir >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
        echo "[*] mtools not found; leaving $REBUILD_EFI_REL unchanged."
        return 0
    fi
    if ! mdir -i "$img" :: >/dev/null 2>&1; then
        echo "[*] $REBUILD_EFI_REL is not a FAT image; not injecting bootx64.efi."
        return 0
    fi
    mmd -i "$img" ::EFI >/dev/null 2>&1 || true
    mmd -i "$img" ::EFI/BOOT >/dev/null 2>&1 || true
    if mcopy -i "$img" -D o "$bootx64" ::EFI/BOOT/BOOTX64.EFI; then
        echo "[*] Injected $bootx64 into $REBUILD_EFI_REL as EFI/BOOT/BOOTX64.EFI"
    else
        echo "[-] Warning: could not inject bootx64.efi into $REBUILD_EFI_REL"
        return 0
    fi
    if [ -f "$nsh" ]; then
        mcopy -i "$img" -D o "$nsh" ::startup.nsh || true
    fi
}

resolve_efi_eltorito() {
    local mode="$EFI_ELTORITO"
    local noprompt="${ISO_DIR}/efi/microsoft/boot/efisys_noprompt.bin"
    local prompt="${ISO_DIR}/efi/microsoft/boot/efisys.bin"
    local bootx64="${ISO_DIR}/efi/boot/bootx64.efi"
    local generated="${ISO_DIR}/efi/microsoft/boot/efisys_lab.bin"
    REBUILD_EFI_REL=""

    if [ "$mode" = "auto" ]; then
        if [ -f "$noprompt" ]; then
            REBUILD_EFI_REL="efi/microsoft/boot/efisys_noprompt.bin"
        elif [ -f "$prompt" ]; then
            REBUILD_EFI_REL="efi/microsoft/boot/efisys.bin"
        else
            mkdir -p "${ISO_DIR}/efi/microsoft/boot"
            make_esp_image "$generated" "$bootx64"
            REBUILD_EFI_REL="efi/microsoft/boot/efisys_lab.bin"
        fi
    elif [ "$mode" = "noprompt" ]; then
        if [ ! -f "$noprompt" ]; then
            echo "[-] Error: --efi-eltorito noprompt requested but $noprompt is missing."
            exit 1
        fi
        REBUILD_EFI_REL="efi/microsoft/boot/efisys_noprompt.bin"
    elif [ "$mode" = "prompt" ]; then
        if [ ! -f "$prompt" ]; then
            echo "[-] Error: --efi-eltorito prompt requested but $prompt is missing."
            exit 1
        fi
        REBUILD_EFI_REL="efi/microsoft/boot/efisys.bin"
    else
        # A path: prefer one already inside the tree; otherwise copy it in.
        local src="$mode"
        if [ -f "${ISO_DIR}/${mode#/}" ]; then
            REBUILD_EFI_REL="${mode#./}"
            REBUILD_EFI_REL="${REBUILD_EFI_REL#"$ISO_DIR"/}"
        elif [ -f "$src" ]; then
            mkdir -p "${ISO_DIR}/efi/microsoft/boot"
            cp "$src" "${ISO_DIR}/efi/microsoft/boot/efisys_custom.bin"
            REBUILD_EFI_REL="efi/microsoft/boot/efisys_custom.bin"
        else
            echo "[-] Error: --efi-eltorito path not found: $src"
            exit 1
        fi
    fi
    echo "[*] EFI El Torito image: $REBUILD_EFI_REL"
}

maybe_split_install_wim() {
    local wim="${ISO_DIR}/sources/install.wim"
    [ -f "$wim" ] || return 0
    local size
    size=$(stat -c%s "$wim")
    if [ "$size" -le "$ISO9660_MAX_FILE" ] && [ "$SPLIT_WIM" -eq 0 ]; then
        return 0
    fi
    # Prefer UDF when an encoder exists, unless the caller forced a split.
    if [ "$SPLIT_WIM" -eq 0 ] && detect_udf_encoder; then
        echo "[*] sources/install.wim is $size bytes; using $UDF_ENCODER -udf (no split)."
        REBUILD_USE_UDF=1
        return 0
    fi
    if [ "$SPLIT_WIM" -eq 1 ]; then
        echo "[*] --split-wim: splitting sources/install.wim ($size bytes) into .swm parts."
    else
        echo "[*] sources/install.wim is $size bytes, over the ISO 9660 file-size limit, and no"
        echo "    UDF-capable xorriso/genisoimage/mkisofs was found. Splitting with wimlib."
    fi
    if ! command -v wimlib-imagex >/dev/null 2>&1; then
        echo "[-] Error: wimlib-imagex is required to split a large install.wim."
        echo "    Install wimtools, or rebuild with a UDF-capable mkisofs/genisoimage."
        exit 1
    fi
    rm -f "${ISO_DIR}/sources/install.swm" "${ISO_DIR}/sources/"install*.swm
    # wimlib-imagex split takes a megabyte count (integer or float), not a
    # byte/KiB suffix. Default 3800 MiB stays under the ISO 9660 ceiling.
    # A lowered --iso9660-max-file (tests) uses a fractional MiB part size.
    # A single uncompressed WIM resource may still land in one part larger
    # than that size; the split path is still exercised (install.wim -> .swm).
    local part
    if [ "$ISO9660_MAX_FILE" -ge $((3800 * 1024 * 1024)) ]; then
        part=3800
    else
        part="$(awk -v b="$ISO9660_MAX_FILE" 'BEGIN {
            mib = (b - 32768) / (1024 * 1024)
            if (mib < 0.05) mib = 0.05
            printf "%.3f", mib
        }')"
    fi
    echo "[*] wimlib-imagex split part size: ${part} MiB (ISO 9660 threshold $ISO9660_MAX_FILE bytes)"
    wimlib-imagex split "$wim" "${ISO_DIR}/sources/install.swm" "$part"
    rm -f "$wim"
    echo "[+] install.wim split; Windows Setup will read install.swm / install2.swm / ..."
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

    REBUILD_USE_UDF=0
    maybe_split_install_wim
    resolve_efi_eltorito
    refresh_eltorito_esp

    local xor_args=(
        -as mkisofs
        -iso-level 3
        -J
        -joliet-long
        -R
        -volid "VAULT_LAB"
        -m '.stamp_*'
    )
    if [ "$REBUILD_USE_UDF" -eq 1 ] && [ -n "$UDF_ENCODER" ] && [ "$UDF_ENCODER" != "xorriso" ]; then
        rebuild_with_udf_mkisofs
        return
    fi
    if [ "$REBUILD_USE_UDF" -eq 1 ]; then
        xor_args+=(-udf)
        echo "[*] Adding -udf so a large install.wim can be stored."
    fi

    local have_bios=0
    if [ -f "${ISO_DIR}/boot/etfsboot.com" ]; then
        have_bios=1
        xor_args+=(-b boot/etfsboot.com -no-emul-boot -boot-load-size 8)
        echo "[*] BIOS El Torito image: boot/etfsboot.com"
    fi
    if [ "$have_bios" -eq 1 ]; then
        xor_args+=(-eltorito-alt-boot)
    fi
    xor_args+=(-e "$REBUILD_EFI_REL" -no-emul-boot -isohybrid-gpt-basdat)
    xor_args+=(-o "$PATCHED_ISO" "${ISO_DIR}/")

    set +e
    xorriso "${xor_args[@]}"
    local rc=$?
    set -e
    if [ ! -s "$PATCHED_ISO" ]; then
        echo "[-] Error: xorriso failed to write $PATCHED_ISO (exit $rc)."
        exit 1
    fi
    if [ "$rc" -ne 0 ]; then
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
