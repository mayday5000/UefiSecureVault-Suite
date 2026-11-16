#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 03_generate_auth_update.sh
# Unified authenticated-update builder.
# Merges:
#   03_generate_auth_update.sh                  (hash a binary, wrap as dbx .esl, static time)
#   03_generate_auth_update_2.sh                (fingerprint.bin + db|dbx)
#   03_generate_auth_update_3.sh                (--static | --dynamic)
#   03_generate_auth_update_incremental_date_part.sh  (signed seconds offset)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/auth2.sh
source "${SCRIPT_DIR}/scripts/lib/auth2.sh"

PrintHelp() {
    echo "========================================================================="
    echo "    UefiSecureVault-Suite: Unified Authenticated Update Generator        "
    echo "========================================================================="
    echo "Usage:"
    echo "  $0 <payload> <target_variable> [--static|--dynamic] [time_offset_seconds]"
    echo ""
    echo "Payload:"
    echo "  An EFI Signature List (.esl), wrapped unchanged (use this for PK, KEK,"
    echo "  or db certificate enrollment); a 32-byte fingerprint from"
    echo "  06_hash_cert_for_nvram.sh; or any other file, whose SHA-256 is taken"
    echo "  and wrapped as a SHA-256 list (legacy dbx / binary-revoke path)."
    echo "  A file that is not named .esl is still treated as an ESL when its"
    echo "  SignatureListSize header equals the file size."
    echo ""
    echo "Allowed Target Variables:"
    echo "  db    Authorized whitelist database (append signer/hash)."
    echo "  dbx   Forbidden blacklist database (append revoked signer/hash)."
    echo "  PK    Platform Key (signed by the PK private key, not the KEK)."
    echo "  KEK   Key Exchange Key (signed by the PK private key)."
    echo ""
    echo "Operation mode (default --static):"
    echo "  --static   Fixed baseline timestamp 2026-10-04 23:30:00 UTC"
    echo "             (16-byte EFI_TIME; remaining fields are zero)."
    echo "  --dynamic  Host clock, plus optional signed second offset."
    echo "             Example: -7200 shifts the payload two hours into the past"
    echo "             so SecureManagerApp / firmware dbt counters reject it."
    echo ""
    echo "The output is a UEFI EFI_VARIABLE_AUTHENTICATION_2 .auth: 16-byte EFI_TIME,"
    echo "WIN_CERTIFICATE_UEFI_GUID (revision 0x0200, type 0x0EF1, PKCS#7 CertType),"
    echo "detached CMS SignedData, then the EFI Signature List payload."
    echo ""
    echo "Examples:"
    echo "  $0 workspace/PK.esl PK --static"
    echo "  $0 workspace/KEK.esl KEK --static"
    echo "  $0 workspace/db.esl db --static"
    echo "  $0 workspace/winboot.efi dbx --static"
    echo "  $0 workspace/certs/cert_fingerprint.bin db --dynamic"
    echo "  $0 workspace/certs/cert_fingerprint.bin db --dynamic -7200"
    echo "  $0 -h | --help"
    echo "Output:"
    echo "  ./workspace/update_target_<var>.auth"
    echo "========================================================================="
}

if [ $# -lt 2 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    PrintHelp
    exit 0
fi

PAYLOAD=$1
TARGET_VAR=$2
OP_MODE="--static"
TIME_MODIFIER=0
shift 2
while [ $# -gt 0 ]; do
    case "$1" in
        --static|--dynamic) OP_MODE="$1" ;;
        -h|--help) PrintHelp; exit 0 ;;
        *)
            if [[ "$1" =~ ^-?[0-9]+$ ]]; then
                TIME_MODIFIER="$1"
                OP_MODE="--dynamic"
            else
                echo "[-] Unknown argument: $1"; PrintHelp; exit 1
            fi
            ;;
    esac
    shift
done

if [ ! -f "$PAYLOAD" ]; then
    echo "[-] Error: Payload not found: $PAYLOAD"
    exit 1
fi
PAYLOAD="$(readlink -f "$PAYLOAD")"

case "$TARGET_VAR" in
    db|dbx|PK|KEK) ;;
    *) echo "[-] Error: target must be db, dbx, PK, or KEK."; exit 1 ;;
esac

if [ ! -d workspace/certs ]; then
    echo "[-] Error: Run 01_setup_certs.sh first."
    exit 1
fi

SIGN_CRT="$(readlink -f workspace/certs/KEK.crt)"
SIGN_KEY="$(readlink -f workspace/certs/KEK.key)"
VAR_GUID="$AUTH2_IMAGE_SECURITY_GUID_HEX"
# Write the UTF-16LE name straight to a file. Command substitution would strip NULs.
mkdir -p workspace/certs
case "$TARGET_VAR" in
    db)  printf 'd\0b\0' > workspace/certs/tmp_varname.bin ;;
    dbx) printf 'd\0b\0x\0' > workspace/certs/tmp_varname.bin ;;
    PK)
        printf 'P\0K\0' > workspace/certs/tmp_varname.bin
        SIGN_CRT="$(readlink -f workspace/certs/PK.crt)"
        SIGN_KEY="$(readlink -f workspace/certs/PK.key)"
        VAR_GUID="$AUTH2_GLOBAL_VARIABLE_GUID_HEX"
        ;;
    KEK)
        printf 'K\0E\0K\0' > workspace/certs/tmp_varname.bin
        SIGN_CRT="$(readlink -f workspace/certs/PK.crt)"
        SIGN_KEY="$(readlink -f workspace/certs/PK.key)"
        VAR_GUID="$AUTH2_GLOBAL_VARIABLE_GUID_HEX"
        ;;
esac

if [ ! -f "$SIGN_KEY" ] || [ ! -f "$SIGN_CRT" ]; then
    echo "[-] Error: Signing material missing ($SIGN_KEY). Run 01_setup_certs.sh first."
    exit 1
fi

mkdir -p workspace/certs
echo "[+] SECURE VAULT: Initializing Unified .auth Signer Engine..."
echo "[*] Input Payload: $PAYLOAD"
echo "[*] Target NVRAM Location: $TARGET_VAR"
echo "[*] Signer: $(basename "$SIGN_CRT")"

cd workspace

PAYLOAD_SIZE=$(wc -c < "$PAYLOAD" | tr -d ' [:space:]')
IS_ESL=0
case "$PAYLOAD" in
    *.esl|*.ESL) IS_ESL=1 ;;
esac
if [ "$IS_ESL" -eq 0 ] && [ "$PAYLOAD_SIZE" -ge 28 ]; then
    # EFI_SIGNATURE_LIST.SignatureListSize is a UINT32 LE at offset 16.
    LIST_SIZE=$(od -An -t u4 -N 4 -j 16 "$PAYLOAD" | tr -d '[:space:]')
    if [ -n "$LIST_SIZE" ] && [ "$LIST_SIZE" -eq "$PAYLOAD_SIZE" ]; then
        IS_ESL=1
    fi
fi

if [ "$IS_ESL" -eq 1 ]; then
    cp "$PAYLOAD" certs/tmp_payload.esl
    echo "[*] Payload is an EFI Signature List ($PAYLOAD_SIZE bytes); wrapping it unchanged."
else
    # Fingerprints are already 32 raw bytes. Anything else is hashed (legacy binary-revoke path).
    if [ "$PAYLOAD_SIZE" -eq 32 ]; then
        cp "$PAYLOAD" certs/target_hash.bin
        echo "[*] Payload already a 32-byte fingerprint."
    else
        RAW_HASH=$(sha256sum "$PAYLOAD" | cut -d' ' -f1)
        echo "[*] Target Binary Content Signature Digest: $RAW_HASH"
        echo -n "$RAW_HASH" | xxd -r -p > certs/target_hash.bin
    fi
fi

if [ "$OP_MODE" == "--static" ]; then
    echo "[*] Operational Mode: Static Baseline Timeline Enforced."
    echo "[*] EFI_TIME: 2026-10-04 23:30:00 UTC (16-byte structure, trailing fields zero)."
    auth2_write_static_timestamp certs/tmp_timestamp.bin
else
    TARGET_EPOCH=$(($(date +%s) + TIME_MODIFIER))
    FORMATTED_DISPLAY=$(date -d "@$TARGET_EPOCH" -u +"%Y-%m-%d %H:%M:%S UTC")
    echo "[*] Operational Mode: Dynamic Real-Time Counter Enforced."
    echo "[*] Targeted Virtual Time Flag: $FORMATTED_DISPLAY (offset ${TIME_MODIFIER}s)"
    YEAR_HEX=$(printf "%04X" "$(date -d "@$TARGET_EPOCH" -u +%-Y)")
    LE_YEAR="${YEAR_HEX:2:2}${YEAR_HEX:0:2}"
    MONTH_HEX=$(printf "%02X" "$(date -d "@$TARGET_EPOCH" -u +%-m)")
    DAY_HEX=$(printf "%02X" "$(date -d "@$TARGET_EPOCH" -u +%-d)")
    HOUR_HEX=$(printf "%02X" "$(date -d "@$TARGET_EPOCH" -u +%-H)")
    MIN_HEX=$(printf "%02X" "$(date -d "@$TARGET_EPOCH" -u +%-M)")
    SEC_HEX=$(printf "%02X" "$(date -d "@$TARGET_EPOCH" -u +%-S)")
    # 16-byte EFI_TIME: Year LE, Month, Day, Hour, Minute, Second, Pad1,
    # Nanosecond, TimeZone, Daylight, Pad2 (all remaining fields zero).
    TIMESTAMP_HEX="${LE_YEAR}${MONTH_HEX}${DAY_HEX}${HOUR_HEX}${MIN_HEX}${SEC_HEX}000000000000000000"
    echo -n "$TIMESTAMP_HEX" | xxd -r -p > certs/tmp_timestamp.bin
fi

if [ "$IS_ESL" -ne 1 ]; then
    # EFI_SIGNATURE_LIST header for SHA-256: type GUID + ListSize 0x4C + HeaderSize 0 + SigSize 0x30
    echo "2616c4c14c509240aca941f9369343284c0000000000000030000000" | xxd -r -p > certs/tmp_esl_hdr.bin
    uuidgen | tr -d '-' | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(.*\)/\4\3\2\1\6\5\8\7\9/' | xxd -r -p > certs/tmp_owner.bin
    cat certs/tmp_esl_hdr.bin certs/tmp_owner.bin certs/target_hash.bin > certs/tmp_payload.esl
fi

# tmp_varname.bin was already written before cd workspace

OUTPUT_NAME="update_target_${TARGET_VAR}.auth"
auth2_wrap_auth certs certs/tmp_varname.bin "$VAR_GUID" \
    certs/tmp_timestamp.bin certs/tmp_payload.esl \
    "$SIGN_CRT" "$SIGN_KEY" "$OUTPUT_NAME"
rm -f certs/tmp_* certs/target_hash.bin

echo -e "\n[++] SUCCESS: Authenticated container created smoothly."
echo "[++] Output Object Location Path: ./workspace/$OUTPUT_NAME"
