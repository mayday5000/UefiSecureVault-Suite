#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 10_simulate_integrity_violation.sh
# Flips bytes inside a valid .auth so PKCS#7 verification must fail and PCR 7 can record it.
set -euo pipefail

VALID_AUTH="${1:-workspace/update_target_db.auth}"
CORRUPTED_AUTH="${2:-workspace/violation_test_corrupted.auth}"
if [ "$VALID_AUTH" == "-h" ] || [ "$VALID_AUTH" == "--help" ]; then
    echo "Usage: $0 [valid.auth] [corrupted.auth]"
    echo "Default input:  workspace/update_target_db.auth"
    echo "Default output: workspace/violation_test_corrupted.auth"
    echo "Builds the input with: ./03_generate_auth_update.sh workspace/certs/cert_fingerprint.bin db --static"
    exit 0
fi

echo "========================================================================="
echo "    UefiSecureVault-Suite: Boot Integrity Violation Simulator            "
echo "========================================================================="

if [ ! -f "$VALID_AUTH" ]; then
    echo "[-] Error: Base signed authenticated payload missing: $VALID_AUTH"
    echo "    Build one first, for example:"
    echo "    ./03_generate_auth_update.sh workspace/certs/cert_fingerprint.bin db --static"
    exit 1
fi

cp "$VALID_AUTH" "$CORRUPTED_AUTH"
SIZE=$(wc -c < "$VALID_AUTH")
SEEK=$((SIZE - 100))
if [ "$SEEK" -lt 0 ]; then SEEK=0; fi
echo "[*] Injecting arbitrary byte flip manipulations into trailing payload at offset $SEEK..."
printf '\xDE\xAD\xBE\xEF' | dd of="$CORRUPTED_AUTH" bs=1 seek="$SEEK" conv=notrunc 2>/dev/null

echo "  1. Run the emulation shell via ./02_run_qemu.sh"
echo "  2. Launch SecureManagerApp.efi"
echo "  3. Select option 2 and load $(basename "$CORRUPTED_AUTH")"
echo "  4. EFI_PKCS7 verification rejects the corrupt bits."
echo "  5. A cryptographic failure can be observed later in the measured-boot log (PCR 7)."
echo "[++] Output Generated: ./$CORRUPTED_AUTH"
