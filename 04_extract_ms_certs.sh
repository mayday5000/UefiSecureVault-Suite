#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 04_extract_ms_certs.sh
# Detaches the Authenticode PKCS#7 certificate table from a captured winboot.efi.
set -euo pipefail

SRC="${1:-workspace/winboot.efi}"
if [ "$SRC" == "-h" ] || [ "$SRC" == "--help" ]; then
    echo "Usage: $0 [path_to_winboot.efi]"
    echo "Default input: workspace/winboot.efi"
    echo "Output: workspace/certs/extracted/ms_winboot_signature.p7b"
    exit 0
fi

echo "========================================================================="
echo "[+] SECURE VAULT: Extracting Certificates from $(basename "$SRC")..."
echo "========================================================================="

if [ ! -f "$SRC" ]; then
    echo "[-] Error: Place an original, unmodified bootloader at '$SRC'."
    echo "    Typical capture: mount the ISO and copy efi/boot/bootx64.efi to workspace/winboot.efi"
    exit 1
fi

if ! command -v sbattach &> /dev/null; then
    echo "[*] sbsigntools missing. Installing..."
    sudo apt-get update && sudo apt-get install -y sbsigntools
fi

mkdir -p workspace/certs/extracted
sbattach --detach workspace/certs/extracted/ms_winboot_signature.p7b "$SRC"

echo -e "\n[++] SUCCESS: Original signature package isolated."
echo "[++] Output Location: ./workspace/certs/extracted/ms_winboot_signature.p7b"
echo "[*] Parse this file in QEMU with SignatureParserApp.efi, or unwrap it with 07_extract_certs_to_esl.sh."
