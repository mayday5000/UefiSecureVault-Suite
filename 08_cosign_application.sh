#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 08_cosign_application.sh
# Appends a second independent Authenticode signer. Does not strip the first trailer.
set -euo pipefail

INPUT_EXE="${1:-workspace/winboot_signed.efi}"
OUTPUT_EXE="${2:-workspace/winboot_cosigned.efi}"
if [ "$INPUT_EXE" == "-h" ] || [ "$INPUT_EXE" == "--help" ]; then
    echo "Usage: $0 [input_signed.efi] [output_cosigned.efi]"
    echo "Defaults: workspace/winboot_signed.efi -> workspace/winboot_cosigned.efi"
    echo "Creates workspace/certs/secondary/vendor2.key if it does not exist."
    exit 0
fi

echo "========================================================================="
echo "       UefiSecureVault-Suite: Multi-Signature Co-Signing Engine          "
echo "========================================================================="

if [ ! -f "$INPUT_EXE" ]; then
    echo "[-] Error: Base signed executable missing: $INPUT_EXE"
    echo "    Generate the first signature via 05_sign_custom_winboot.sh first."
    exit 1
fi

mkdir -p workspace/certs/secondary
if [ ! -f workspace/certs/secondary/vendor2.key ]; then
    echo "[*] Creating secondary independent certificate authority keys..."
    openssl genrsa -out workspace/certs/secondary/vendor2.key 2048 2>/dev/null
    openssl req -new -x509 -sha256 -key workspace/certs/secondary/vendor2.key \
        -out workspace/certs/secondary/vendor2.crt -days 365 \
        -subj "/CN=Secondary Independent Co-Signer Authority/" 2>/dev/null
fi

mkdir -p workspace/certs/nss_secondary
certutil -N -d workspace/certs/nss_secondary --empty-password 2>/dev/null || true
openssl pkcs12 -export -out workspace/certs/nss_secondary/vendor2.p12 \
    -inkey workspace/certs/secondary/vendor2.key \
    -in workspace/certs/secondary/vendor2.crt \
    -name "CoSignerKey" -passout pass: 2>/dev/null
pk12util -i workspace/certs/nss_secondary/vendor2.p12 -d workspace/certs/nss_secondary -W "" 2>/dev/null

echo "[*] Merging secondary signature block into the executable certificate table..."
pesign -n workspace/certs/nss_secondary \
       -c "CoSignerKey" \
       -s \
       -i "$INPUT_EXE" \
       -o "$OUTPUT_EXE"

rm -rf workspace/certs/nss_secondary
echo -e "\n[++] SUCCESS: Co-signed binary generated at: $OUTPUT_EXE"
sbverify --list "$OUTPUT_EXE" || true
