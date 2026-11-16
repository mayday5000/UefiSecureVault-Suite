#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 02_run_qemu.sh
# Boots an OVMF shell with a mutable NVRAM store and the workspace FAT volume on FS0:.
# Absorbs qemu_nested.sh: pass --nested when the next stage must expose Hyper-V enlightenment bits.
set -euo pipefail

NESTED=0
MEM=2048
SMP=1
PrintHelp() {
    echo "Usage: $0 [--nested] [--memory MB] [--smp N]"
    echo "  --nested     Enable Hyper-V CPU enlightenments (former qemu_nested.sh)."
    echo "  --memory MB  Guest RAM. Default 2048. Nested Windows wants 4096."
    echo "  --smp N      Guest vCPUs. Default 1, or 4 when --nested is set."
    echo "Mounts ./workspace as a FAT volume visible to the UEFI shell as FS0:."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --nested) NESTED=1; MEM=4096; SMP=4 ;;
        --memory) MEM="${2:?}"; shift ;;
        --smp) SMP="${2:?}"; shift ;;
        -h|--help) PrintHelp; exit 0 ;;
        *) echo "[-] Unknown argument: $1"; PrintHelp; exit 1 ;;
    esac
    shift
done

echo "========================================================================="
echo "[+] STEP 1: Checking virtualization toolchain prerequisites..."
echo "========================================================================="
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo "[*] QEMU x86_64 emulator missing. Installing..."
    sudo apt-get update && sudo apt-get install -y qemu-system-x86 ovmf
fi

echo -e "\n========================================================================="
echo "[+] STEP 2: Locating and mounting secure OVMF firmware images..."
echo "========================================================================="
OVMF_SRC_CODE="/usr/share/OVMF/OVMF_CODE.ms.fd"
if [ ! -f "$OVMF_SRC_CODE" ]; then
    OVMF_SRC_CODE="/usr/share/OVMF/OVMF_CODE.fd"
fi
if [ ! -f "$OVMF_SRC_CODE" ]; then
    OVMF_SRC_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
fi
echo "[*] Using OVMF Code Image Base: $OVMF_SRC_CODE"
cp "$OVMF_SRC_CODE" ./OVMF_CODE.fd

if [ ! -f "OVMF_VARS.fd" ]; then
    echo "[*] Initializing clean NVRAM variables template map..."
    if [ -f /usr/share/OVMF/OVMF_VARS.fd ]; then
        cp /usr/share/OVMF/OVMF_VARS.fd ./OVMF_VARS.fd
    elif [ -f /usr/share/OVMF/OVMF_VARS_4M.fd ]; then
        cp /usr/share/OVMF/OVMF_VARS_4M.fd ./OVMF_VARS.fd
    else
        echo "[-] Error: OVMF_VARS template not found under /usr/share/OVMF."
        exit 1
    fi
fi

mkdir -p workspace
echo "[*] Mounting local directory './workspace' as file index target 'FS0:'"
echo "[*] Instantiating Secure Boot tracking hardware structures..."

CPU_FLAGS=(-cpu host)
if [ "$NESTED" -eq 1 ]; then
    echo "[*] Nested mode: passing hv_relaxed,hv_vapic,hv_time,hv_stimer,hv_synic,hv_runtime,hv_vpindex"
    CPU_FLAGS=(-cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,hv_stimer,hv_synic,hv_runtime,hv_vpindex)
fi

qemu-system-x86_64 \
    -machine q35,smm=on \
    "${CPU_FLAGS[@]}" \
    -enable-kvm \
    -smp "$SMP" \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
    -drive file=fat:rw:workspace,format=raw \
    -net none \
    -m "$MEM" \
    -vga std
