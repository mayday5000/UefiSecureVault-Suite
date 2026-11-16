# Shared EFI_VARIABLE_AUTHENTICATION_2 helpers for UefiSecureVault-Suite.
# Sourced by 03_generate_auth_update.sh and 09_sign_db_with_kek.sh.
#
# An .auth file is:
#   EFI_TIME (16 bytes)
#   WIN_CERTIFICATE_UEFI_GUID {
#     dwLength          UINT32 LE = 4+2+2+16+len(PKCS7)
#     wRevision         UINT16 LE = 0x0200
#     wCertificateType  UINT16 LE = 0x0EF1  (WIN_CERT_TYPE_EFI_GUID)
#     CertType          EFI_CERT_TYPE_PKCS7_GUID
#     CertData          PKCS#7 SignedData DER (detached, no signed attributes)
#   }
#   EFI_SIGNATURE_LIST payload
#
# The PKCS#7 is computed over:
#   VariableName (UTF-16LE, no trailing NUL; matches sign-efi-sig-list)
#   || VendorGuid
#   || Attributes (UINT32 LE)
#   || EFI_TIME
#   || ESL
# shellcheck shell=bash

# EFI_CERT_TYPE_PKCS7_GUID {4aafd29d-68df-49ee-8aa9-347d375665a7} in mixed-endian bytes.
export AUTH2_PKCS7_CERT_TYPE_GUID_HEX="9dd2af4adf68ee498aa9347d375665a7"
# EFI_IMAGE_SECURITY_DATABASE_GUID {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
export AUTH2_IMAGE_SECURITY_GUID_HEX="cbb219d73a3d9645a3bcdad00e67656f"
# EFI_GLOBAL_VARIABLE {8BE4DF61-93CA-11d2-AA0D-00E098032B8C}
export AUTH2_GLOBAL_VARIABLE_GUID_HEX="61dfe48bca93d211aa0d00e098032b8c"
# NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE_ACCESS
export AUTH2_ATTRS_HEX="27000000"
# Static laboratory EFI_TIME: 2026-10-04 23:30:00 UTC, Pad1/Nanosecond/TimeZone/Daylight/Pad2 zero.
# The first eight bytes match the historical packing EA 07 0A 04 17 1E 00 00 (minute 0x1E = 30).
export AUTH2_STATIC_EFI_TIME_HEX="EA070A04171E00000000000000000000"

auth2_hex_to_bin() {
    local hex="$1"
    local out="$2"
    echo -n "$hex" | xxd -r -p > "$out"
}

auth2_uint32_le_hex() {
    local value="$1"
    local hex
    printf -v hex '%08x' "$value"
    printf '%s%s%s%s' "${hex:6:2}" "${hex:4:2}" "${hex:2:2}" "${hex:0:2}"
}

auth2_write_static_timestamp() {
    auth2_hex_to_bin "$AUTH2_STATIC_EFI_TIME_HEX" "$1"
}

# auth2_wrap_auth WORKDIR VARNAME_BIN GUID_HEX TIMESTAMP_BIN ESL SIGNER_CRT SIGNER_KEY OUTPUT_AUTH
# VARNAME_BIN is a file containing the UTF-16LE variable name with no trailing NUL.
auth2_wrap_auth() {
    local workdir="$1"
    local varname_bin="$2"
    local guid_hex="$3"
    local timestamp_bin="$4"
    local esl="$5"
    local signer_crt="$6"
    local signer_key="$7"
    local output_auth="$8"
    local guid_bin attrs_bin tbs pkcs7 hdr pkcs7_len dw_length

    mkdir -p "$workdir"
    guid_bin="${workdir}/tmp_guid.bin"
    attrs_bin="${workdir}/tmp_attrs.bin"
    tbs="${workdir}/tmp_bytes_to_sign.bin"
    pkcs7="${workdir}/tmp_signature.pkcs7"
    hdr="${workdir}/tmp_wincert.bin"

    auth2_hex_to_bin "$guid_hex" "$guid_bin"
    auth2_hex_to_bin "$AUTH2_ATTRS_HEX" "$attrs_bin"

    cat "$varname_bin" "$guid_bin" "$attrs_bin" "$timestamp_bin" "$esl" > "$tbs"

    # Include the signer certificate (sign-efi-sig-list does too). OVMF
    # rejects a Setup Mode PK .auth when the PKCS#7 is built with -nocerts.
    openssl cms -sign -binary \
        -in "$tbs" \
        -signer "$signer_crt" \
        -inkey "$signer_key" \
        -outform DER \
        -noattr -nosmimecap -md sha256 \
        -out "$pkcs7"

    python3 "$(dirname "${BASH_SOURCE[0]}")/cms_to_signed_data.py" "$pkcs7"

    pkcs7_len=$(wc -c < "$pkcs7" | tr -d ' [:space:]')
    dw_length=$((4 + 2 + 2 + 16 + pkcs7_len))
    # One xxd invocation so the header is not truncated by repeated > redirects.
    echo -n "$(auth2_uint32_le_hex "$dw_length")0002f10e${AUTH2_PKCS7_CERT_TYPE_GUID_HEX}" | xxd -r -p > "$hdr"

    cat "$timestamp_bin" "$hdr" "$pkcs7" "$esl" > "$output_auth"
}
