#!/usr/bin/env bash
# UefiSecureVault-Suite — 12_run_patched_iso_qemu.sh
# Boots the patched Windows ISO on a persistent qcow2 disk with the lab OVMF
# pair. VBS/HV enlightenments default to auto (on when KVM + nested are
# available). --no-nested drops them. Firmware is staged by this script;
# a prior 02_run_qemu.sh run is no longer required, but an existing
# OVMF_VARS.fd enrollment at the repo root is migrated when safe.
set -euo pipefail

USV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/qemu_common.sh
source "$USV_ROOT/scripts/qemu_common.sh"

cd "$USV_ROOT"

PATCHED_ISO="workspace/windows_patched.iso"
VIRT_HDD="workspace/windows_virtual_disk.qcow2"
USV_MEM=4096
USV_SMP=4
USV_VM_NAME="windows"
USV_VBS=auto
USV_BOOT_ORDER="${USV_BOOT_ORDER:-order=d}"

PrintHelp() {
    echo "Usage: $0 [patched.iso] [--no-nested] [--memory MB] [--smp N] [--disk PATH] [common QEMU lab flags]"
    echo "Default ISO:  workspace/windows_patched.iso"
    echo "Default disk: workspace/windows_virtual_disk.qcow2 (created at 64G if missing)"
    echo "--no-nested   Disable VBS/HV enlightenments (firmware-only experiments)."
    echo "--memory MB   Guest RAM. Default 4096."
    echo "--smp N       Guest vCPUs. Default 4."
    echo "--disk PATH   Persistent qcow2 disk path."
    echo
    qemu_common_usage
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-nested)
            USV_VBS=off
            shift
            ;;
        --memory)
            USV_MEM="${2:?}"
            shift 2
            ;;
        --smp)
            USV_SMP="${2:?}"
            shift 2
            ;;
        --disk)
            VIRT_HDD="${2:?}"
            shift 2
            ;;
        -h|--help)
            PrintHelp
            exit 0
            ;;
        *)
            if qemu_common_parse "$@"; then
                shift "$USV_PARSE_SHIFT"
            elif [ -f "$1" ] || [[ "$1" == *.iso ]]; then
                PATCHED_ISO="$1"
                shift
            else
                echo "[-] Unknown argument: $1"
                PrintHelp
                exit 1
            fi
            ;;
    esac
done

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: patched ISO runner"
echo "========================================================================="

if [ "$USV_DRY_RUN" -ne 1 ] && [ ! -f "$PATCHED_ISO" ]; then
    echo "[-] Error: patched installation media missing: $PATCHED_ISO"
    echo "    Run 11_extract_and_patch_iso.sh first."
    exit 1
fi
if [ "$USV_DRY_RUN" -eq 1 ] && [ ! -f "$PATCHED_ISO" ]; then
    echo "[*] --dry-run: $PATCHED_ISO is not present; the command still shows the ISO path."
fi

mkdir -p "$(dirname "$VIRT_HDD")"
if [ ! -f "$VIRT_HDD" ]; then
    if [ "$USV_DRY_RUN" -eq 1 ]; then
        echo "[*] --dry-run: would create 64G qcow2 at $VIRT_HDD"
    else
        echo "[*] Initializing empty 64GB QCOW2 virtual hard drive image..."
        qemu-img create -f qcow2 "$VIRT_HDD" 64G
    fi
fi

qemu_common_init

USV_EXTRA_ARGS=(
    -drive "file=$VIRT_HDD,if=virtio,format=qcow2"
    -drive "file=$PATCHED_ISO,media=cdrom,format=raw"
)
if [ "$USV_NOGRAPHIC" -ne 1 ]; then
    USV_EXTRA_ARGS+=(-vga std -device intel-hda -device hda-output)
fi

qemu_prepare
qemu_exec
