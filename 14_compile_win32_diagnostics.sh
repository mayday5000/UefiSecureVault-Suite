#!/usr/bin/env bash
# UefiSecureVault-Suite v2 — 14_compile_win32_diagnostics.sh
# Cross-compiles every Win32 laboratory binary. Host-native Windows builds are also accepted.
set -euo pipefail

echo "========================================================================="
echo "[+] UefiSecureVault-Suite: Win32 Diagnostics Cross-Compiler Engine        "
echo "========================================================================="

if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[*] MinGW-w64 cross-compiler missing. Installing toolchain package via apt..."
    sudo apt-get update && sudo apt-get install -y g++-mingw-w64-x86-64
fi

mkdir -p workspace
CXX="x86_64-w64-mingw32-g++ -O2 -static -Wall -municode"

compile_one() {
    local src="$1"
    local out="$2"
    shift 2
    if [ ! -f "$src" ]; then
        echo "[-] Warning: $src not found. Skipping."
        return 0
    fi
    echo "[*] Cross-compiling $src -> $out"
    # shellcheck disable=SC2086
    $CXX "$src" -o "$out" "$@"
    echo "[+] Successfully compiled $(basename "$out")"
}

compile_one win32/VerifyRuntimeBoundaries.cpp workspace/VerifyRuntimeBoundaries.exe
compile_one win32/AuditMeasuredBootLog.cpp workspace/AuditMeasuredBootLog.exe -ltbs -lcrypt32
compile_one win32/LowLevelBootTools.cpp workspace/LowLevelBootTools.exe -lwintrust -lcrypt32 -lole32
compile_one win32/ParseSmBios.cpp workspace/ParseSmBios.exe
compile_one win32/WinVerifyTrust.cpp workspace/WinVerifyTrust.exe -lwintrust
compile_one win32/DumpNtfsVolume.cpp workspace/DumpNtfsVolume.exe

echo -e "\n[++] SUCCESS: Win32 user-mode executables staged inside ./workspace."
echo "[*] Ready for integration into the WinPE image matrix using 13_patch_winpe_image.sh."
