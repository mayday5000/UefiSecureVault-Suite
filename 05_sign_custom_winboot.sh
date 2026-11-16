#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 05_sign_custom_winboot.sh
# Strips the vendor Authenticode trailer and reseals the loader with the laboratory db key.
set -euo pipefail

IN_EFI="${1:-workspace/winboot.efi}"
if [ "$IN_EFI" == "-h" ] || [ "$IN_EFI" == "--help" ]; then
    echo "Usage: $0 [path_to_unsigned_or_vendor_efi]"
    echo "Default input:  workspace/winboot.efi"
    echo "Outputs:        workspace/winboot_custom.efi  (signature removed)"
    echo "                workspace/winboot_signed.efi  (db-signed)"
    exit 0
fi

echo "========================================================================="
echo "[+] SECURE VAULT: Generating Custom-Signed winboot.efi..."
echo "========================================================================="

if [ ! -f workspace/certs/db.key ] || [ ! -f workspace/certs/db.crt ]; then
    echo "[-] Error: Custom key material missing. Run 01_setup_certs.sh first."
    exit 1
fi
if [ ! -f "$IN_EFI" ]; then
    echo "[-] Error: Target executable '$IN_EFI' not found."
    exit 1
fi
if ! command -v pesign &> /dev/null || ! command -v sbattach &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y pesign sbsigntools
fi

echo "[*] Initializing clean workspace binary copy..."
cp "$IN_EFI" workspace/winboot_custom.efi
echo "[*] Clearing original signature allocations via sbattach --remove..."
sbattach --remove workspace/winboot_custom.efi

echo "[*] Applying the custom 'db' cryptographic certificate seal..."
mkdir -p workspace/certs/nss_temp
certutil -N -d workspace/certs/nss_temp --empty-password 2>/dev/null || true
openssl pkcs12 -export -out workspace/certs/nss_temp/db.p12 \
    -inkey workspace/certs/db.key -in workspace/certs/db.crt \
    -name "Custom Test Signer" -passout pass: 2>/dev/null
pk12util -i workspace/certs/nss_temp/db.p12 -d workspace/certs/nss_temp -W "" 2>/dev/null

pesign -n workspace/certs/nss_temp \
       -c "Custom Test Signer" \
       -s \
       -i workspace/winboot_custom.efi \
       -o workspace/winboot_signed.efi

rm -rf workspace/certs/nss_temp
echo -e "\n[++] SUCCESS: Custom-signed UEFI app generated successfully."
echo "[++] Output Target Location: ./workspace/winboot_signed.efi"
