#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 16_verify_signatures.sh
# Added in v2. Host-side OpenSSL checks described in the original tutorial, so the
# PKCS#7 / CMS inspection path is a numbered tool instead of a notebook fragment.
set -euo pipefail

PrintHelp() {
    echo "Usage:"
    echo "  $0 p7b  <file.p7b>                 Print certs from a detached signature."
    echo "  $0 cms  <file.pkcs7> <signed.bin>  Verify a CMS blob against the bytes it signed."
    echo "  $0 x509 <file.crt>                 Print subject, issuer, and SHA-256 fingerprint."
    echo "  $0 esl  <file.esl>                 Hex-dump the first 64 bytes of an EFI Signature List."
}

if [ $# -lt 2 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    PrintHelp
    exit 0
fi

MODE=$1
shift
case "$MODE" in
    p7b)
        openssl pkcs7 -inform DER -in "$1" -print_certs -noout -text
        ;;
    cms)
        openssl cms -verify -inform DER -in "$1" -content "$2" -noverify -out /tmp/vault_cms_payload.bin
        echo "[++] CMS structural verify completed. Payload written to /tmp/vault_cms_payload.bin"
        ;;
    x509)
        openssl x509 -in "$1" -noout -subject -issuer -fingerprint -sha256
        ;;
    esl)
        echo "[*] First 64 bytes of $1 (SignatureType GUID is the first 16, little-endian):"
        xxd -l 64 "$1"
        ;;
    *)
        PrintHelp
        exit 1
        ;;
esac
