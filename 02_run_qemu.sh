#!/usr/bin/env bash
# UefiSecureVault-Suite — 02_run_qemu.sh
# Boots an OVMF shell with a mutable NVRAM store and the workspace FAT volume on FS0:.
# Shared lab flags live in scripts/qemu_common.sh. --nested still forces VBS/HV
# enlightenments and raises the default guest to 4096 MiB / 4 vCPUs.
set -euo pipefail

USV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/qemu_common.sh
source "$USV_ROOT/scripts/qemu_common.sh"

cd "$USV_ROOT"

USV_MEM=2048
USV_SMP=1
USV_VM_NAME="shell"
USV_VBS=auto
NESTED=0

PrintHelp() {
    echo "Usage: $0 [--nested] [--memory MB] [--smp N] [common QEMU lab flags]"
    echo "  --nested     Force VBS/HV enlightenments (former qemu_nested.sh)."
    echo "               Also sets memory=4096 and smp=4 unless already overridden"
    echo "               by a later --memory / --smp."
    echo "  --memory MB  Guest RAM. Default 2048 (4096 with --nested)."
    echo "  --smp N      Guest vCPUs. Default 1 (4 with --nested)."
    echo
    echo "Mounts ./workspace as a FAT volume visible to the UEFI shell as FS0:."
    echo "Firmware is staged at workspace/ovmf/CODE.fd and VARS.fd (and copied"
    echo "to ./OVMF_CODE.fd and ./OVMF_VARS.fd for compatibility)."
    echo
    qemu_common_usage
}

while [ $# -gt 0 ]; do
    case "$1" in
        --nested)
            NESTED=1
            USV_VBS=on
            USV_MEM=4096
            USV_SMP=4
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
        -h|--help)
            PrintHelp
            exit 0
            ;;
        *)
            if qemu_common_parse "$@"; then
                shift "$USV_PARSE_SHIFT"
            else
                echo "[-] Unknown argument: $1"
                PrintHelp
                exit 1
            fi
            ;;
    esac
done

echo "========================================================================="
echo "[+] STEP 1: UEFI shell runner (QEMU + OVMF)"
echo "========================================================================="
if [ "$NESTED" -eq 1 ]; then
    echo "[*] --nested: forcing VBS/HV enlightenments, default shape 4096 MiB / 4 vCPUs."
fi

mkdir -p workspace
qemu_common_init

USV_EXTRA_ARGS=(
    -drive "file=fat:rw:$USV_WORKSPACE,format=raw"
    -net none
)
if [ "$USV_NOGRAPHIC" -ne 1 ]; then
    USV_EXTRA_ARGS+=(-vga std)
fi

qemu_prepare
qemu_exec
