#!/usr/bin/env bash
# Build tests/efi/UsvAuthSet.efi with Debian gnu-efi.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/UsvAuthSet.efi}"
HELLO_OUT="${2:-$(dirname "$OUT")/UsvHello.efi}"
INC="${EFI_INC:-/usr/include/efi}"
ARCH="${EFI_ARCH:-x86_64}"
LIBDIR="${EFI_LIBDIR:-/usr/lib}"
CRT="${LIBDIR}/crt0-efi-${ARCH}.o"
LDS="${LIBDIR}/elf_${ARCH}_efi.lds"

if [ ! -f "$INC/$ARCH/efibind.h" ] || [ ! -f "$CRT" ] || [ ! -f "$LDS" ]; then
    echo "[-] gnu-efi headers/crt not found (install the gnu-efi package)." >&2
    exit 2
fi
if ! command -v gcc >/dev/null 2>&1 || ! command -v ld >/dev/null 2>&1 || ! command -v objcopy >/dev/null 2>&1; then
    echo "[-] gcc, ld, and objcopy are required to build UsvAuthSet.efi." >&2
    exit 2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
obj="$workdir/UsvAuthSet.o"
so="$workdir/UsvAuthSet.so"

# -DGNU_EFI_USE_MS_ABI makes EFIAPI = ms_abi so Boot/Runtime service
# calls match the firmware. Debian's prebuilt crt0/_entry still call
# efi_main with the SysV ABI, so efi_main itself must not be EFIAPI.
CFLAGS=(
    -I"$INC" -I"$INC/$ARCH"
    -fpic -ffreestanding -fno-stack-protector -fno-stack-check
    -fshort-wchar -mno-red-zone -maccumulate-outgoing-args
    -DGNU_EFI_USE_MS_ABI
    -Wall -Wextra -Wno-unused-parameter
)

gcc "${CFLAGS[@]}" -c "$HERE/UsvAuthSet.c" -o "$obj"
ld -nostdlib -znocombreloc -T "$LDS" -shared -Bsymbolic \
    "$CRT" "$obj" -o "$so" -L "$LIBDIR" -lefi -lgnuefi
objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym \
    -j .rel -j .rela -j .rel.* -j .rela.* -j .reloc \
    --target=efi-app-${ARCH} "$so" "$OUT"
echo "[+] built $OUT ($(wc -c < "$OUT") bytes)"

if [ -f "$HERE/UsvHello.c" ]; then
    gcc "${CFLAGS[@]}" -c "$HERE/UsvHello.c" -o "$workdir/UsvHello.o"
    ld -nostdlib -znocombreloc -T "$LDS" -shared -Bsymbolic \
        "$CRT" "$workdir/UsvHello.o" -o "$workdir/UsvHello.so" -L "$LIBDIR" -lefi -lgnuefi
    objcopy -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym \
        -j .rel -j .rela -j .rel.* -j .rela.* -j .reloc \
        --target=efi-app-${ARCH} "$workdir/UsvHello.so" "$HELLO_OUT"
    echo "[+] built $HELLO_OUT ($(wc -c < "$HELLO_OUT") bytes)"
fi
