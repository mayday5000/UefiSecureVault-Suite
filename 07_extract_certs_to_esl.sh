#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 07_extract_certs_to_esl.sh
# Unwraps the detached PKCS#7 from 04 and packs the public cert into an .esl.
set -euo pipefail

P7B_FILE="${1:-workspace/certs/extracted/ms_winboot_signature.p7b}"
if [ "$P7B_FILE" == "-h" ] || [ "$P7B_FILE" == "--help" ]; then
    echo "Usage: $0 [path_to_signature.p7b]"
    echo "Default: workspace/certs/extracted/ms_winboot_signature.p7b"
    echo "Outputs: workspace/certs/extracted/extracted_ms_db.crt"
    echo "         workspace/certs/extracted/extracted_ms_db.esl"
    exit 0
fi

echo "========================================================================="
echo "    UefiSecureVault-Suite: Public Certificate & ESL Extraction Engine    "
echo "========================================================================="

if [ ! -f "$P7B_FILE" ]; then
    echo "[-] Error: Extracted signature file missing: $P7B_FILE"
    echo "    Execute 04_extract_ms_certs.sh first to isolate the .p7b container."
    exit 1
fi

mkdir -p workspace/certs/extracted
echo "[*] Un-wrapping PKCS#7 envelope to extract clean public X.509 .crt files..."
openssl pkcs7 -inform DER -in "$P7B_FILE" -print_certs -out workspace/certs/extracted/extracted_ms_db.crt

GENERATED_GUID=$(uuidgen)
echo "[*] Converting public certificate into an EFI Signature List (owner $GENERATED_GUID)..."
cert-to-efi-sig-list -g "$GENERATED_GUID" \
    workspace/certs/extracted/extracted_ms_db.crt \
    workspace/certs/extracted/extracted_ms_db.esl

echo "[++] Public Certificate Key extracted: ./workspace/certs/extracted/extracted_ms_db.crt"
echo "[++] Standalone Whitelist ESL compiled: ./workspace/certs/extracted/extracted_ms_db.esl"
echo "[*] Pass extracted_ms_db.esl to SecureManagerApp.efi option 1 to whitelist the vendor signer."
