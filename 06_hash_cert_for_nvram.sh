#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 06_hash_cert_for_nvram.sh
# Produces the 32-byte fingerprint SecureManagerApp and 03_generate_auth_update.sh consume.
set -euo pipefail

PrintHelp() {
    echo "========================================================================="
    echo "       UefiSecureVault-Suite: NVRAM Database Fingerprint Generator       "
    echo "========================================================================="
    echo "Description:"
    echo "  Generates a raw 32-byte binary fingerprint usable for both whitelisting"
    echo "  (db) and blacklisting (dbx) inside the UEFI applications."
    echo ""
    echo "Supported Input Formats:"
    echo "  .cer / .crt   Standalone X.509 public certificates (PEM or DER)."
    echo "  .esl          EFI Signature List. Headers are skipped (28 + 16 bytes)"
    echo "                and the inner certificate bytes are hashed."
    echo "  .efi / other  Raw file bytes are hashed directly (image fingerprint)."
    echo ""
    echo "Usage:"
    echo "  $0 <path_to_file>"
    echo "  $0 -h | --help"
    echo "Output:"
    echo "  workspace/certs/cert_fingerprint.bin"
    echo "  workspace/certs/cert_fingerprint.hex"
    echo "========================================================================="
}

if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    PrintHelp
    exit 0
fi

TARGET_FILE=$1
if [ ! -f "$TARGET_FILE" ]; then
    echo "[-] Error: Specified target resource file not found: $TARGET_FILE"
    exit 1
fi

mkdir -p workspace/certs
echo "[+] SECURE VAULT: Initializing cryptographic extraction pipeline..."
echo "[*] Target Asset: $TARGET_FILE"

FILE_EXT="${TARGET_FILE##*.}"
FILE_EXT=$(echo "$FILE_EXT" | tr 'A-Z' 'a-z')

case "$FILE_EXT" in
    cer|crt)
        echo -e "\n[+] Logic Branch: Standalone X.509 Certificate Detected."
        openssl x509 -in "$TARGET_FILE" -outform DER -out workspace/certs/temp_raw_payload.der
        ;;
    esl)
        echo -e "\n[+] Logic Branch: EFI Signature List (.esl) Package Detected."
        FILE_SIZE=$(wc -c < "$TARGET_FILE")
        if [ "$FILE_SIZE" -le 44 ]; then
            echo "[-] Error: The provided .esl file is malformed or too small."
            exit 1
        fi
        tail -c +45 "$TARGET_FILE" > workspace/certs/temp_raw_payload.der
        echo "[+] Successfully isolated inner certificate bytes from the .esl wrapper."
        ;;
    *)
        echo -e "\n[+] Logic Branch: Raw image/hash target. Fingerprinting file bytes directly."
        cp "$TARGET_FILE" workspace/certs/temp_raw_payload.der
        ;;
esac

HEX_HASH=$(sha256sum workspace/certs/temp_raw_payload.der | cut -d' ' -f1)
echo "[+] Computed Hex String Signature: $HEX_HASH"
echo -n "$HEX_HASH" | xxd -r -p > workspace/certs/cert_fingerprint.bin
echo -n "$HEX_HASH" > workspace/certs/cert_fingerprint.hex
rm -f workspace/certs/temp_raw_payload.der

echo -e "\n[++] SUCCESS: 32-byte signature token created."
echo "[++] Output Location: ./workspace/certs/cert_fingerprint.bin"
