#include <efi.h>
#include <efilib.h>

EFI_STATUS
EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    InitializeLib(ImageHandle, SystemTable);
    ST->ConOut->OutputString(ST->ConOut, L"USV_HELLO_OK\r\n");
    BS->Exit(ImageHandle, EFI_SUCCESS, 0, NULL);
    return EFI_SUCCESS;
}
