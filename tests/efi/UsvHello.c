#include <efi.h>

/*
 * Tiny signed/unsigned probe app for the OVMF enrollment tests.
 *
 * Debian's gnu-efi _entry (libefi) calls efi_main with the SysV ABI
 * (RDI/RSI). Do not mark efi_main EFIAPI when compiling with
 * -DGNU_EFI_USE_MS_ABI: that would make it expect RCX/RDX, so
 * SystemTable would be garbage, OutputString would be skipped or
 * #PF, and a later Exit/ret would hang the Shell. Boot-service
 * function pointers remain EFIAPI via GNU_EFI_USE_MS_ABI.
 *
 * Return EFI_SUCCESS and let _entry/crt0 return to the Shell; do not
 * call BootServices->Exit from here.
 */
EFI_STATUS
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    (void)ImageHandle;
    if (SystemTable && SystemTable->ConOut && SystemTable->ConOut->OutputString)
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"USV_HELLO_OK\r\n");
    return EFI_SUCCESS;
}
