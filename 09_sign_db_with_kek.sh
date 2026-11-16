#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 09_sign_db_with_kek.sh
# Wraps an existing .esl (default workspace/db.esl) in a KEK-signed .auth for User Mode.
set -euo pipefail

ESL_FILE="${1:-workspace/db.esl}"
TARGET_VAR="${2:-db}"
if [ "$ESL_FILE" == "-h" ] || [ "$ESL_FILE" == "--help" ]; then
    echo "Usage: $0 [path_to.esl] [db|dbx]"
    echo "Default: workspace/db.esl db"
    echo "Output:  workspace/update_<var>_secured.auth"
    echo "Timestamp is the static laboratory baseline 2026-10-04 23:15:00."
    echo "For dynamic anti-replay timestamps use 03_generate_auth_update.sh instead."
    exit 0
fi

echo "========================================================================="
echo "   UefiSecureVault-Suite: KEK-Signed Authenticated Whitelist Builder     "
echo "========================================================================="

if [ ! -f workspace/certs/KEK.key ] || [ ! -f workspace/certs/KEK.crt ]; then
    echo "[-] Error: Custom testing KEK material missing. Run 01_setup_certs.sh first."
    exit 1
fi
if [ ! -f "$ESL_FILE" ]; then
    echo "[-] Error: Target signature list '$ESL_FILE' not found."
    exit 1
fi
if [ "$TARGET_VAR" != "db" ] && [ "$TARGET_VAR" != "dbx" ]; then
    echo "[-] Error: target variable must be db or dbx."
    exit 1
fi

cd workspace
echo "[*] Preparing authenticated update envelope structures..."
echo -n "EA070A04171E0000" | xxd -r -p > certs/tmp_timestamp.bin
if [ "$TARGET_VAR" == "db" ]; then
    printf 'd\0b\0' > certs/tmp_varname.bin
else
    printf 'd\0b\0x\0' > certs/tmp_varname.bin
fi
echo "cbb219d73a3d9645a3bcdad00e67656f" | xxd -r -p > certs/tmp_guid.bin
echo "27000000" | xxd -r -p > certs/tmp_attrs.bin

cp "../$ESL_FILE" certs/tmp_payload.esl 2>/dev/null || cp "$ESL_FILE" certs/tmp_payload.esl
cat certs/tmp_varname.bin certs/tmp_guid.bin certs/tmp_attrs.bin certs/tmp_timestamp.bin certs/tmp_payload.esl > certs/tmp_bytes_to_sign.bin

openssl cms -sign -binary \
    -in certs/tmp_bytes_to_sign.bin \
    -signer certs/KEK.crt \
    -inkey certs/KEK.key \
    -outform DER -nocerts -md sha256 \
    -out certs/tmp_signature.pkcs7

OUT="update_${TARGET_VAR}_secured.auth"
cat certs/tmp_timestamp.bin certs/tmp_signature.pkcs7 certs/tmp_payload.esl > "$OUT"
rm -f certs/tmp_*

echo -e "\n[++] SUCCESS: Authenticated update package compiled."
echo "[++] Output Object Path Location: ./workspace/$OUT"
echo "[*] Load this .auth file into SecureManagerApp.efi option 2 under lockdown."
