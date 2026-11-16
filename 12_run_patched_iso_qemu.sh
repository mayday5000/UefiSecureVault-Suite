#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 12_run_patched_iso_qemu.sh
# Nested Hyper-V capable runner. Absorbs qemu_nested.sh enlightenment flags.
set -euo pipefail

PATCHED_ISO="${1:-workspace/windows_patched.iso}"
VIRT_HDD="workspace/windows_virtual_disk.qcow2"
MEM=4096
SMP=4
NESTED=1

PrintHelp() {
    echo "Usage: $0 [patched.iso] [--no-nested] [--memory MB] [--smp N] [--disk PATH]"
    echo "Default ISO:  workspace/windows_patched.iso"
    echo "Default disk: workspace/windows_virtual_disk.qcow2 (created at 64G if missing)"
    echo "--no-nested   Drop Hyper-V enlightenments (firmware-only experiments)."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-nested) NESTED=0 ;;
        --memory) MEM="${2:?}"; shift ;;
        --smp) SMP="${2:?}"; shift ;;
        --disk) VIRT_HDD="${2:?}"; shift ;;
        -h|--help) PrintHelp; exit 0 ;;
        *)
            if [ -f "$1" ] || [[ "$1" == *.iso ]]; then PATCHED_ISO="$1"; else
                echo "[-] Unknown argument: $1"; PrintHelp; exit 1
            fi
            ;;
    esac
    shift
done

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: Nested Hyper-V Virtualization Runner          "
echo "========================================================================="

if [ ! -f "$PATCHED_ISO" ]; then
    echo "[-] Error: Patched installation media missing. Run 11_extract_and_patch_iso.sh first."
    exit 1
fi
if [ ! -f OVMF_CODE.fd ] || [ ! -f OVMF_VARS.fd ]; then
    echo "[-] Error: OVMF_CODE.fd / OVMF_VARS.fd missing. Run 02_run_qemu.sh once to stage firmware."
    exit 1
fi
if [ ! -f "$VIRT_HDD" ]; then
    echo "[*] Initializing empty 64GB QCOW2 virtual hard drive image..."
    qemu-img create -f qcow2 "$VIRT_HDD" 64G
fi

CPU="host"
if [ "$NESTED" -eq 1 ]; then
    echo "[*] Passing extended Hyper-V instructions to instantiate VTL 0/1 security barriers..."
    CPU="host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,hv_stimer,hv_synic,hv_runtime,hv_vpindex"
fi

qemu-system-x86_64 \
    -machine q35,smm=on \
    -cpu "$CPU" \
    -enable-kvm \
    -smp "$SMP" \
    -m "$MEM" \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
    -drive file="$VIRT_HDD",if=virtio,format=qcow2 \
    -drive file="$PATCHED_ISO",media=cdrom,format=raw \
    -vga std \
    -device intel-hda -device hda-output
