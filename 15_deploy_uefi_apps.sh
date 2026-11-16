#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 15_deploy_uefi_apps.sh
# Former deploy_suite.sh. Copies the merged UEFI apps into an EDK2 tree and builds them.
set -euo pipefail

EDK2_ROOT="${EDK2_ROOT:-${HOME}/src/edk2}"
TARGET_ARCH="${TARGET_ARCH:-X64}"
TARGET_TOOLCHAIN="${TARGET_TOOLCHAIN:-GCC5}"
BUILD_TARGET="${BUILD_TARGET:-DEBUG}"

PrintHelp() {
    echo "Usage: EDK2_ROOT=/path/to/edk2 $0"
    echo "Environment overrides:"
    echo "  EDK2_ROOT         Default \$HOME/src/edk2"
    echo "  TARGET_ARCH       Default X64"
    echo "  TARGET_TOOLCHAIN  Default GCC5"
    echo "  BUILD_TARGET      Default DEBUG"
}

if [ "${1:-}" == "-h" ] || [ "${1:-}" == "--help" ]; then
    PrintHelp
    exit 0
fi

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: Automated Compilation & Deployment Engine     "
echo "========================================================================="

mkdir -p workspace/certs
if [ ! -f workspace/certs/PK.key ] && [ -f ./01_setup_certs.sh ]; then
    echo "[*] Cryptographic key materials missing. Running setup script..."
    ./01_setup_certs.sh
fi

if [ ! -d "$EDK2_ROOT" ]; then
    echo "[-] Error: EDK2 framework path location not found at $EDK2_ROOT"
    echo "    Export EDK2_ROOT to your edk2 checkout and retry."
    exit 1
fi

echo "[*] STEP 1: Synchronizing merged sources into the EDK2 directory map..."
APPS_SRC_DIR="${EDK2_ROOT}/MdeModulePkg/Application"
mkdir -p "${APPS_SRC_DIR}/SecureManagerApp" "${APPS_SRC_DIR}/SignatureParserApp"
cp uefi/SecureManagerApp/SecureManagerApp.c uefi/SecureManagerApp/SecureManagerApp.inf \
   "${APPS_SRC_DIR}/SecureManagerApp/"
cp uefi/SignatureParserApp/SignatureParserApp.c uefi/SignatureParserApp/SignatureParserApp.inf \
   "${APPS_SRC_DIR}/SignatureParserApp/"

# Append component lines if the package DSC does not already name them.
DSC="${EDK2_ROOT}/MdeModulePkg/MdeModulePkg.dsc"
for comp in \
    "MdeModulePkg/Application/SecureManagerApp/SecureManagerApp.inf" \
    "MdeModulePkg/Application/SignatureParserApp/SignatureParserApp.inf"
do
    if ! grep -q "$comp" "$DSC"; then
        printf '\n%s\n' "$comp" >> "$DSC"
        echo "[*] Appended $comp to MdeModulePkg.dsc"
    fi
done

echo "[*] STEP 2: Initializing EDK2 compilation environment toolchain..."
cd "$EDK2_ROOT"
export EDK_TOOLS_PATH="${EDK2_ROOT}/BaseTools"
# shellcheck disable=SC1091
source edksetup.sh BaseTools

build -a "$TARGET_ARCH" -t "$TARGET_TOOLCHAIN" -b "$BUILD_TARGET" \
      -p MdeModulePkg/MdeModulePkg.dsc \
      -m MdeModulePkg/Application/SecureManagerApp/SecureManagerApp.inf
build -a "$TARGET_ARCH" -t "$TARGET_TOOLCHAIN" -b "$BUILD_TARGET" \
      -p MdeModulePkg/MdeModulePkg.dsc \
      -m MdeModulePkg/Application/SignatureParserApp/SignatureParserApp.inf

OUTPUT_BIN_DIR="${EDK2_ROOT}/Build/MdeModule/${BUILD_TARGET}_${TARGET_TOOLCHAIN}/${TARGET_ARCH}"
cd - >/dev/null

if [ -f "${OUTPUT_BIN_DIR}/SecureManagerApp.efi" ] && [ -f "${OUTPUT_BIN_DIR}/SignatureParserApp.efi" ]; then
    cp "${OUTPUT_BIN_DIR}/SecureManagerApp.efi" workspace/
    cp "${OUTPUT_BIN_DIR}/SignatureParserApp.efi" workspace/
    echo "[++] SUCCESS: Binary components deployed to ./workspace/"
else
    echo "[-] Error: Build completed but output .efi targets were not found."
    exit 1
fi
echo "[++] DEPLOYMENT IMMINENT: Run ./02_run_qemu.sh to begin validation testing"
