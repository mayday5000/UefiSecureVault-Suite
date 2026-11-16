#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 03_generate_auth_update.sh
# Unified authenticated-update builder.
# Merges:
#   03_generate_auth_update.sh                  (hash a binary, wrap as dbx .esl, static time)
#   03_generate_auth_update_2.sh                (fingerprint.bin + db|dbx)
#   03_generate_auth_update_3.sh                (--static | --dynamic)
#   03_generate_auth_update_incremental_date_part.sh  (signed seconds offset)
set -euo pipefail

PrintHelp() {
    echo "========================================================================="
    echo "    UefiSecureVault-Suite: Unified Authenticated Update Generator        "
    echo "========================================================================="
    echo "Usage:"
    echo "  $0 <payload> <target_variable> [--static|--dynamic] [time_offset_seconds]"
    echo ""
    echo "Payload:"
    echo "  A 32-byte fingerprint (.bin) produced by 06_hash_cert_for_nvram.sh,"
    echo "  OR any file whose SHA-256 will be taken and wrapped (legacy dbx path)."
    echo ""
    echo "Allowed Target Variables:"
    echo "  db    Authorized whitelist database (append signer/hash)."
    echo "  dbx   Forbidden blacklist database (append revoked signer/hash)."
    echo "  PK    Platform Key (signed by the PK private key, not the KEK)."
    echo "  KEK   Key Exchange Key (signed by the PK private key)."
    echo ""
    echo "Operation mode (default --static):"
    echo "  --static   Fixed baseline timestamp 2026-10-04 23:15:00."
    echo "  --dynamic  Host clock, plus optional signed second offset."
    echo "             Example: -7200 shifts the payload two hours into the past"
    echo "             so SecureManagerApp / firmware dbt counters reject it."
    echo ""
    echo "Examples:"
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

case "$TARGET_VAR" in
    db|dbx|PK|KEK) ;;
    *) echo "[-] Error: target must be db, dbx, PK, or KEK."; exit 1 ;;
esac

if [ ! -d workspace/certs ]; then
    echo "[-] Error: Run 01_setup_certs.sh first."
    exit 1
fi

SIGN_CRT="workspace/certs/KEK.crt"
SIGN_KEY="workspace/certs/KEK.key"
VAR_GUID="cbb219d73a3d9645a3bcdad00e67656f"   # EFI_IMAGE_SECURITY_DATABASE_GUID
case "$TARGET_VAR" in
    db)  VAR_UTF16=$(printf 'd\0b\0') ;;
    dbx) VAR_UTF16=$(printf 'd\0b\0x\0') ;;
    PK)
        VAR_UTF16=$(printf 'P\0K\0')
        SIGN_CRT="workspace/certs/PK.crt"
        SIGN_KEY="workspace/certs/PK.key"
        VAR_GUID="61df4e8eca9311d2aa0d00e098032b8c"  # EFI_GLOBAL_VARIABLE
        ;;
    KEK)
        VAR_UTF16=$(printf 'K\0E\0K\0')
        SIGN_CRT="workspace/certs/PK.crt"
        SIGN_KEY="workspace/certs/PK.key"
        VAR_GUID="61df4e8eca9311d2aa0d00e098032b8c"
        ;;
esac

if [ ! -f "$SIGN_KEY" ] || [ ! -f "$SIGN_CRT" ]; then
    echo "[-] Error: Signing material missing ($SIGN_KEY). Run 01_setup_certs.sh first."
    exit 1
fi

mkdir -p workspace/certs
cd workspace
echo "[+] SECURE VAULT: Initializing Unified .auth Signer Engine..."
echo "[*] Input Payload: $PAYLOAD"
echo "[*] Target NVRAM Location: $TARGET_VAR"
echo "[*] Signer: $(basename "$SIGN_CRT")"

# Fingerprints are already 32 raw bytes. Anything else is hashed (legacy binary-revoke path).
PAYLOAD_ABS=$(readlink -f "../$PAYLOAD" 2>/dev/null || realpath "../$PAYLOAD")
PAYLOAD_SIZE=$(wc -c < "$PAYLOAD_ABS")
if [ "$PAYLOAD_SIZE" -eq 32 ]; then
    cp "$PAYLOAD_ABS" certs/target_hash.bin
    echo "[*] Payload already a 32-byte fingerprint."
else
    RAW_HASH=$(sha256sum "$PAYLOAD_ABS" | cut -d' ' -f1)
    echo "[*] Target Binary Content Signature Digest: $RAW_HASH"
    echo -n "$RAW_HASH" | xxd -r -p > certs/target_hash.bin
fi

if [ "$OP_MODE" == "--static" ]; then
    TIMESTAMP_HEX="EA070A04171E0000"   # 2026-10-04 23:15:00
    echo "[*] Operational Mode: Static Baseline Timeline Enforced."
    echo -n "$TIMESTAMP_HEX" | xxd -r -p > certs/tmp_timestamp.bin
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
    TIMESTAMP_HEX="${LE_YEAR}${MONTH_HEX}${DAY_HEX}${HOUR_HEX}${MIN_HEX}${SEC_HEX}00"
    echo -n "$TIMESTAMP_HEX" | xxd -r -p > certs/tmp_timestamp.bin
fi

# EFI_SIGNATURE_LIST header for SHA-256: type GUID + ListSize 0x4C + HeaderSize 0 + SigSize 0x30
echo "2616c4c14c509240aca941f9369343284c0000000000000030000000" | xxd -r -p > certs/tmp_esl_hdr.bin
echo "$(uuidgen | tr -d '-' | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(.*\)/\4\3\2\1\6\5\8\7\9/')" | xxd -r -p > certs/tmp_owner.bin
cat certs/tmp_esl_hdr.bin certs/tmp_owner.bin certs/target_hash.bin > certs/tmp_payload.esl

printf '%s' "$VAR_UTF16" > certs/tmp_varname.bin
echo -n "$VAR_GUID" | xxd -r -p > certs/tmp_guid.bin
echo "27000000" | xxd -r -p > certs/tmp_attrs.bin   # NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE

cat certs/tmp_varname.bin certs/tmp_guid.bin certs/tmp_attrs.bin certs/tmp_timestamp.bin certs/tmp_payload.esl > certs/tmp_bytes_to_sign.bin

openssl cms -sign -binary \
    -in certs/tmp_bytes_to_sign.bin \
    -signer "$SIGN_CRT" \
    -inkey "$SIGN_KEY" \
    -outform DER \
    -nocerts -md sha256 \
    -out certs/tmp_signature.pkcs7

OUTPUT_NAME="update_target_${TARGET_VAR}.auth"
cat certs/tmp_timestamp.bin certs/tmp_signature.pkcs7 certs/tmp_payload.esl > "$OUTPUT_NAME"
rm -f certs/tmp_* certs/target_hash.bin

echo -e "\n[++] SUCCESS: Authenticated container created smoothly."
echo "[++] Output Object Location Path: ./workspace/$OUTPUT_NAME"
