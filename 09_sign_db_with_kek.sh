#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 09_sign_db_with_kek.sh
# Wraps an existing .esl (default workspace/db.esl) in a KEK-signed .auth for User Mode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/auth2.sh
source "${SCRIPT_DIR}/scripts/lib/auth2.sh"

ESL_FILE="${1:-workspace/db.esl}"
TARGET_VAR="${2:-db}"
if [ "$ESL_FILE" == "-h" ] || [ "$ESL_FILE" == "--help" ]; then
    echo "Usage: $0 [path_to.esl] [db|dbx]"
    echo "Default: workspace/db.esl db"
    echo "Output:  workspace/update_<var>_secured.auth"
    echo "Timestamp is the static laboratory baseline 2026-10-04 23:30:00 UTC"
    echo "(16-byte EFI_TIME; remaining fields are zero)."
    echo "The .auth is an EFI_VARIABLE_AUTHENTICATION_2 envelope:"
    echo "EFI_TIME || WIN_CERTIFICATE_UEFI_GUID (PKCS#7) || ESL."
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

SIGN_CRT="$(readlink -f workspace/certs/KEK.crt)"
SIGN_KEY="$(readlink -f workspace/certs/KEK.key)"
ESL_ABS="$(readlink -f "$ESL_FILE")"

cd workspace
echo "[*] Preparing authenticated update envelope structures..."
auth2_write_static_timestamp certs/tmp_timestamp.bin
if [ "$TARGET_VAR" == "db" ]; then
    printf 'd\0b\0' > certs/tmp_varname.bin
else
    printf 'd\0b\0x\0' > certs/tmp_varname.bin
fi

OUT="update_${TARGET_VAR}_secured.auth"
auth2_wrap_auth certs certs/tmp_varname.bin "$AUTH2_IMAGE_SECURITY_GUID_HEX" \
    certs/tmp_timestamp.bin "$ESL_ABS" \
    "$SIGN_CRT" "$SIGN_KEY" "$OUT"
rm -f certs/tmp_*

echo -e "\n[++] SUCCESS: Authenticated update package compiled."
echo "[++] Output Object Path Location: ./workspace/$OUT"
echo "[*] Load this .auth file into SecureManagerApp.efi option 2 under lockdown."
