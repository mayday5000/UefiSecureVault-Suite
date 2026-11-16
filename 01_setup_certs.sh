#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 01_setup_certs.sh
# Builds the laboratory Platform Key, Key Exchange Key, and db signer, then wraps each
# public certificate into an EFI Signature List the firmware can enroll.
set -euo pipefail

echo "========================================================================="
echo "[+] STEP 1: Verifying and installing system tool prerequisites..."
echo "========================================================================="
DEPENDENCIES=(openssl uuidgen xxd cert-to-efi-sig-list)
for cmd in "${DEPENDENCIES[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[*] Dependency '$cmd' missing. Attempting installation via apt..."
        sudo apt-get update && sudo apt-get install -y efitools uuid-runtime openssl xxd
        break
    fi
done
echo "[+] All required host tools are installed."

echo -e "\n========================================================================="
echo "[+] STEP 2: Creating workspace directories..."
echo "========================================================================="
mkdir -p workspace/certs
cd workspace

echo -e "\n========================================================================="
echo "[+] STEP 3: Generating Custom Keypair Infrastructure via OpenSSL..."
echo "========================================================================="
echo "[*] Compiling Platform Key (PK)..."
openssl genrsa -out certs/PK.key 2048 2>/dev/null
openssl req -new -x509 -sha256 -key certs/PK.key -out certs/PK.crt -days 365 \
    -subj "/CN=Custom Platform Owner Root CA/" 2>/dev/null

echo "[*] Compiling Key Exchange Key (KEK)..."
openssl genrsa -out certs/KEK.key 2048 2>/dev/null
openssl req -new -x509 -sha256 -key certs/KEK.key -out certs/KEK.crt -days 365 \
    -subj "/CN=Custom Operating System Broker KEK/" 2>/dev/null

echo "[*] Compiling Database Authorization Key (db)..."
openssl genrsa -out certs/db.key 2048 2>/dev/null
openssl req -new -x509 -sha256 -key certs/db.key -out certs/db.crt -days 365 \
    -subj "/CN=Custom Core Executable DB Signer/" 2>/dev/null

echo "[+] Successfully established cryptographic operational keys."

echo -e "\n========================================================================="
echo "[+] STEP 4: Packaging Certificates into binary UEFI Signature Lists (.esl)..."
echo "========================================================================="
PK_UUID=$(uuidgen)
KEK_UUID=$(uuidgen)
DB_UUID=$(uuidgen)

echo "[*] Wrapping PK.crt -> PK.esl (Owner GUID: $PK_UUID)"
cert-to-efi-sig-list -g "$PK_UUID" certs/PK.crt PK.esl
echo "[*] Wrapping KEK.crt -> KEK.esl (Owner GUID: $KEK_UUID)"
cert-to-efi-sig-list -g "$KEK_UUID" certs/KEK.crt KEK.esl
echo "[*] Wrapping db.crt -> db.esl (Owner GUID: $DB_UUID)"
cert-to-efi-sig-list -g "$DB_UUID" certs/db.crt db.esl

echo "[++] SUCCESS: Certificate architecture exported cleanly to workspace directory."
echo "    workspace/PK.esl  workspace/KEK.esl  workspace/db.esl"
echo "    Private keys remain under workspace/certs/ and must never leave the lab host."
