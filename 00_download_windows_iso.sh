#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 00_download_windows_iso.sh
# Pulls a vanilla Windows evaluation ISO used as the chain-of-custody baseline.
set -euo pipefail

PrintHelp() {
    echo "========================================================================="
    echo "       UefiSecureVault-Suite: Automated Windows ISO Downloader           "
    echo "========================================================================="
    echo "Usage:"
    echo "  $0 --win10   Pull vanilla Windows 10 Pro/Enterprise evaluation ISO"
    echo "  $0 --win11   Pull vanilla Windows 11 Pro/Enterprise evaluation ISO"
    echo ""
    echo "Optional:"
    echo "  --url <https://...>   Override the CDN URL (the stock placeholders"
    echo "                        point at microsoft.com and must be replaced"
    echo "                        with a real evaluation ISO URL before a live pull)."
    echo "  -h | --help           Show this help."
    echo "Outputs:"
    echo "  ./windows10_vanilla.iso    or    ./windows11_vanilla.iso"
    echo "========================================================================="
}

URL_OVERRIDE=""
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --win10) TARGET="win10" ;;
        --win11) TARGET="win11" ;;
        --url) URL_OVERRIDE="${2:-}"; shift ;;
        -h|--help) PrintHelp; exit 0 ;;
        *) echo "[-] Unknown argument: $1"; PrintHelp; exit 1 ;;
    esac
    shift
done

if [ -z "$TARGET" ]; then PrintHelp; exit 1; fi

mkdir -p workspace

case "$TARGET" in
    win10)
        ISO_URL="${URL_OVERRIDE:-https://microsoft.com}"
        OUT_NAME="windows10_vanilla.iso"
        echo "[+] Contacting evaluation CDN for Windows 10 Pro/Ent..."
        ;;
    win11)
        ISO_URL="${URL_OVERRIDE:-https://microsoft.com}"
        OUT_NAME="windows11_vanilla.iso"
        echo "[+] Contacting evaluation CDN for Windows 11 Pro/Ent..."
        ;;
esac

echo "[*] Commencing block stream download sequence..."
echo "[*] URL: $ISO_URL"
curl -L -# -o "$OUT_NAME" "$ISO_URL"
echo -e "\n[++] SUCCESS: Original verification media saved to disk: ./$OUT_NAME"
