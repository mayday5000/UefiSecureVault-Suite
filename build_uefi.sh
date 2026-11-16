#!/usr/bin/env bash
# UefiSecureVault-Suite — build_uefi.sh
# Always probes the host. If the toolchain is incomplete, installs the missing
# packages (QEMU, OVMF, EDK2 build dependencies, signing tools). Clones EDK2
# only when EDK2_ROOT does not already contain a tree. Builds BaseTools if
# needed, then compiles SecureManagerApp.efi and SignatureParserApp.efi into
# ./workspace.
#
# Usage:
#   ./build_uefi.sh
#
# Environment:
#   EDK2_ROOT         default $HOME/src/edk2
#   EDK2_TAG          default edk2-stable202508  (used only when cloning)
#   TARGET_ARCH       default X64
#   TARGET_TOOLCHAIN  default GCC5
#   BUILD_TARGET      default DEBUG
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

EDK2_ROOT="${EDK2_ROOT:-${HOME}/src/edk2}"
EDK2_TAG="${EDK2_TAG:-edk2-stable202508}"
TARGET_ARCH="${TARGET_ARCH:-X64}"
TARGET_TOOLCHAIN="${TARGET_TOOLCHAIN:-GCC5}"
BUILD_TARGET="${BUILD_TARGET:-DEBUG}"

if [ "$#" -ne 0 ]; then
    echo "[-] build_uefi.sh takes no arguments."
    echo "    Incomplete toolchains are installed automatically."
    echo "    An existing tree at EDK2_ROOT is reused and not cloned."
    exit 1
fi

PASS=0
FAIL=0
report() {
    local state="$1" name="$2" detail="${3:-}"
    if [ "$state" = "ok" ]; then
        printf "  [ok]   %s %s\n" "$name" "$detail"
        PASS=$((PASS + 1))
    else
        printf "  [miss] %s %s\n" "$name" "$detail"
        FAIL=$((FAIL + 1))
    fi
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

need_cmd() {
    if has_cmd "$1"; then
        report ok "$1" "($(command -v "$1"))"
    else
        report miss "$1"
    fi
}

find_ovmf() {
    OVMF_CODE=""
    OVMF_VARS=""
    local candidate
    for candidate in \
        /usr/share/OVMF/OVMF_CODE_4M.fd \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/OVMF/OVMF_CODE.ms.fd \
        /usr/share/ovmf/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /usr/share/qemu/OVMF_CODE.fd
    do
        if [ -f "$candidate" ]; then
            OVMF_CODE="$candidate"
            break
        fi
    done
    for candidate in \
        /usr/share/OVMF/OVMF_VARS_4M.fd \
        /usr/share/OVMF/OVMF_VARS.fd \
        /usr/share/ovmf/OVMF_VARS.fd \
        /usr/share/edk2/ovmf/OVMF_VARS.fd \
        /usr/share/qemu/OVMF_VARS.fd
    do
        if [ -f "$candidate" ]; then
            OVMF_VARS="$candidate"
            break
        fi
    done
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

PM=""
if has_cmd apt-get; then
    PM="apt"
elif has_cmd dnf; then
    PM="dnf"
elif has_cmd pacman; then
    PM="pacman"
fi

echo "========================================================================="
echo "[+] UEFI Secure Vault — environment probe"
echo "========================================================================="
echo "[*] Repository : $ROOT"
echo "[*] EDK2_ROOT  : $EDK2_ROOT"
echo "[*] Package mgr: ${PM:-none}"
echo "[*] Arch/tool  : ${TARGET_ARCH} / ${TARGET_TOOLCHAIN} / ${BUILD_TARGET}"
echo
echo "[*] Host commands"
need_cmd gcc
need_cmd g++
need_cmd make
need_cmd python3
need_cmd git
need_cmd nasm
need_cmd iasl
need_cmd uuidgen
need_cmd openssl
need_cmd xxd
need_cmd qemu-system-x86_64
need_cmd qemu-img

echo
echo "[*] OVMF firmware images"
find_ovmf
if [ -n "$OVMF_CODE" ]; then report ok "OVMF_CODE" "($OVMF_CODE)"; else report miss "OVMF_CODE"; fi
if [ -n "$OVMF_VARS" ]; then report ok "OVMF_VARS" "($OVMF_VARS)"; else report miss "OVMF_VARS"; fi

echo
echo "[*] Signing and list tools"
need_cmd cert-to-efi-sig-list
need_cmd sbattach
need_cmd pesign

echo
echo "[*] Suite sources"
for src in \
    uefi/SecureManagerApp/SecureManagerApp.c \
    uefi/SecureManagerApp/SecureManagerApp.inf \
    uefi/SignatureParserApp/SignatureParserApp.c \
    uefi/SignatureParserApp/SignatureParserApp.inf
do
    if [ -f "$ROOT/$src" ]; then report ok "$src"; else report miss "$src"; fi
done

echo
echo "[*] Probe summary: ${PASS} present, ${FAIL} missing"

for src in \
    uefi/SecureManagerApp/SecureManagerApp.c \
    uefi/SecureManagerApp/SecureManagerApp.inf \
    uefi/SignatureParserApp/SignatureParserApp.c \
    uefi/SignatureParserApp/SignatureParserApp.inf
do
    if [ ! -f "$ROOT/$src" ]; then
        echo "[-] Suite source missing: $src"
        exit 1
    fi
done

install_packages() {
    case "$PM" in
        apt)
            $SUDO apt-get update
            $SUDO apt-get install -y \
                build-essential uuid-dev nasm acpica-tools \
                python3 git gcc g++ make \
                qemu-system-x86 qemu-utils ovmf \
                openssl xxd uuid-runtime \
                efitools sbsigntools pesign
            $SUDO apt-get install -y iasl python3-distutils 2>/dev/null || true
            ;;
        dnf)
            $SUDO dnf install -y \
                gcc gcc-c++ make git python3 nasm acpica-tools \
                qemu-system-x86 qemu-img edk2-ovmf \
                openssl util-linux \
                efitools sbsigntools pesign
            ;;
        pacman)
            $SUDO pacman -Sy --needed --noconfirm \
                base-devel git python nasm acpica \
                qemu-system-x86 edk2-ovmf \
                openssl util-linux \
                sbsigntools
            ;;
        *)
            echo "[-] No supported package manager (apt-get, dnf, pacman)."
            exit 1
            ;;
    esac
}

if ! has_cmd gcc || ! has_cmd g++ || ! has_cmd make || ! has_cmd python3 \
    || ! has_cmd git || ! has_cmd nasm || ! has_cmd iasl \
    || ! has_cmd openssl || ! has_cmd qemu-system-x86_64 || ! has_cmd qemu-img \
    || ! has_cmd cert-to-efi-sig-list || ! has_cmd sbattach || ! has_cmd pesign \
    || [ -z "$OVMF_CODE" ] || [ -z "$OVMF_VARS" ]; then
    echo
    echo "[*] Toolchain incomplete. Installing missing packages."
    install_packages
    find_ovmf
    for cmd in gcc g++ make python3 git nasm iasl openssl qemu-system-x86_64 qemu-img \
               cert-to-efi-sig-list sbattach pesign; do
        if ! has_cmd "$cmd"; then
            echo "[-] '$cmd' still missing after package install."
            exit 1
        fi
    done
    if [ -z "$OVMF_CODE" ] || [ -z "$OVMF_VARS" ]; then
        echo "[-] OVMF images still not found after package install."
        exit 1
    fi
    echo "[+] Host toolchain is present."
fi

if [ -f "$EDK2_ROOT/edksetup.sh" ]; then
    echo "[*] EDK2 already present at $EDK2_ROOT. Skipping clone."
else
    echo "[*] Cloning EDK2 (${EDK2_TAG}) into $EDK2_ROOT"
    mkdir -p "$(dirname "$EDK2_ROOT")"
    git clone --depth 1 --branch "$EDK2_TAG" https://github.com/tianocore/edk2.git "$EDK2_ROOT"
    git -C "$EDK2_ROOT" submodule update --init --depth 1
fi

if [ ! -f "$EDK2_ROOT/edksetup.sh" ]; then
    echo "[-] $EDK2_ROOT does not look like an EDK2 tree (edksetup.sh missing)."
    exit 1
fi

echo "[*] Building EDK2 BaseTools if GenFw is not already built"
export EDK_TOOLS_PATH="${EDK2_ROOT}/BaseTools"
export PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"
if [ ! -x "${EDK_TOOLS_PATH}/Source/C/bin/GenFw" ]; then
    make -C "${EDK_TOOLS_PATH}" -j"$(nproc)"
else
    echo "[*] BaseTools already built. Skipping."
fi

echo "[*] Staging SecureManagerApp and SignatureParserApp into the EDK2 tree"
APPS="${EDK2_ROOT}/MdeModulePkg/Application"
mkdir -p "${APPS}/SecureManagerApp" "${APPS}/SignatureParserApp"
cp "$ROOT/uefi/SecureManagerApp/SecureManagerApp.c" \
   "$ROOT/uefi/SecureManagerApp/SecureManagerApp.inf" \
   "${APPS}/SecureManagerApp/"
cp "$ROOT/uefi/SignatureParserApp/SignatureParserApp.c" \
   "$ROOT/uefi/SignatureParserApp/SignatureParserApp.inf" \
   "${APPS}/SignatureParserApp/"

DSC="${EDK2_ROOT}/MdeModulePkg/MdeModulePkg.dsc"
for comp in \
    "MdeModulePkg/Application/SecureManagerApp/SecureManagerApp.inf" \
    "MdeModulePkg/Application/SignatureParserApp/SignatureParserApp.inf"
do
    if ! grep -qF "$comp" "$DSC"; then
        printf '\n%s\n' "$comp" >> "$DSC"
        echo "[*] Appended $comp"
    fi
done

echo "[*] Compiling both UEFI applications"
(
    cd "$EDK2_ROOT"
    # shellcheck disable=SC1091
    source edksetup.sh BaseTools
    build -a "$TARGET_ARCH" -t "$TARGET_TOOLCHAIN" -b "$BUILD_TARGET" \
          -p MdeModulePkg/MdeModulePkg.dsc \
          -m MdeModulePkg/Application/SecureManagerApp/SecureManagerApp.inf
    build -a "$TARGET_ARCH" -t "$TARGET_TOOLCHAIN" -b "$BUILD_TARGET" \
          -p MdeModulePkg/MdeModulePkg.dsc \
          -m MdeModulePkg/Application/SignatureParserApp/SignatureParserApp.inf
)

OUT_DIR="${EDK2_ROOT}/Build/MdeModule/${BUILD_TARGET}_${TARGET_TOOLCHAIN}/${TARGET_ARCH}"
if [ ! -f "${OUT_DIR}/SecureManagerApp.efi" ] || [ ! -f "${OUT_DIR}/SignatureParserApp.efi" ]; then
    echo "[-] Build finished but the .efi products were not found in ${OUT_DIR}"
    exit 1
fi
mkdir -p "$ROOT/workspace" "$ROOT/uefi/build"
cp "${OUT_DIR}/SecureManagerApp.efi" "$ROOT/uefi/build/"
cp "${OUT_DIR}/SignatureParserApp.efi" "$ROOT/uefi/build/"
cp "${OUT_DIR}/SecureManagerApp.efi" "$ROOT/workspace/"
cp "${OUT_DIR}/SignatureParserApp.efi" "$ROOT/workspace/"

if [ ! -f "$ROOT/OVMF_CODE.fd" ]; then
    cp "$OVMF_CODE" "$ROOT/OVMF_CODE.fd"
    echo "[*] Staged OVMF_CODE.fd from $OVMF_CODE"
fi
if [ ! -f "$ROOT/OVMF_VARS.fd" ]; then
    cp "$OVMF_VARS" "$ROOT/OVMF_VARS.fd"
    echo "[*] Staged a clean OVMF_VARS.fd from $OVMF_VARS"
else
    echo "[*] Existing OVMF_VARS.fd kept (enrollments are not wiped)."
fi

echo
echo "========================================================================="
echo "[++] UEFI applications staged:"
echo "     $ROOT/uefi/build/SecureManagerApp.efi"
echo "     $ROOT/uefi/build/SignatureParserApp.efi"
echo "[*] Copies also placed in workspace/ for the QEMU shell."
echo "[*] Next: ./02_run_qemu.sh   then   FS0:  SecureManagerApp.efi"
echo "========================================================================="
