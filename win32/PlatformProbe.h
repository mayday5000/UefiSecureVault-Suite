#pragma once
// Shared host probe for the Win32 diagnostics. No extra link library:
// firmware type comes from kernel32, TPM presence from a runtime load of tbs.dll.

#include <windows.h>
#include <iostream>

inline void PrintWin32Error(const wchar_t* what, DWORD err) {
    std::wcerr << L"[-] " << what << L" failed. Error " << err;
    if (err == ERROR_INVALID_FUNCTION)
        std::wcerr << L" (ERROR_INVALID_FUNCTION: this boot has no UEFI runtime variable interface)";
    else if (err == ERROR_PATH_NOT_FOUND)
        std::wcerr << L" (ERROR_PATH_NOT_FOUND: path is not present; a legacy boot has no EFI System Partition link)";
    else if (err == ERROR_FILE_NOT_FOUND)
        std::wcerr << L" (ERROR_FILE_NOT_FOUND)";
    else if (err == ERROR_ACCESS_DENIED)
        std::wcerr << L" (ERROR_ACCESS_DENIED: elevate this console)";
    else if (err == ERROR_PRIVILEGE_NOT_HELD)
        std::wcerr << L" (ERROR_PRIVILEGE_NOT_HELD: SeSystemEnvironmentPrivilege is not enabled)";
    else if (err == 1314)
        std::wcerr << L" (privilege not held)";
    std::wcerr << L"\n";
}

struct PlatformStatus {
    bool uefi;
    bool tpm;
    const wchar_t* firmwareName;
};

inline PlatformStatus ProbePlatform() {
    PlatformStatus s{false, false, L"unknown"};
    typedef BOOL (WINAPI* GetFirmwareTypeFn)(PFIRMWARE_TYPE);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    auto getFirmwareType = kernel ? (GetFirmwareTypeFn)GetProcAddress(kernel, "GetFirmwareType") : NULL;
    if (getFirmwareType) {
        FIRMWARE_TYPE kind = FirmwareTypeUnknown;
        if (getFirmwareType(&kind)) {
            if (kind == FirmwareTypeUefi) {
                s.uefi = true;
                s.firmwareName = L"Uefi";
            } else if (kind == FirmwareTypeBios) {
                s.firmwareName = L"Bios";
            } else {
                s.firmwareName = L"Unknown";
            }
        }
    }

    HMODULE tbs = LoadLibraryW(L"tbs.dll");
    if (tbs) {
        typedef UINT32 (WINAPI* CreateFn)(void*, void**);
        typedef UINT32 (WINAPI* CloseFn)(void*);
        auto create = (CreateFn)GetProcAddress(tbs, "Tbsi_Context_Create");
        auto closeCtx = (CloseFn)GetProcAddress(tbs, "Tbsip_Context_Close");
        if (create) {
            struct Params { UINT32 version; UINT32 flags; } params;
            params.version = 2;
            params.flags = 1;
            void* ctx = NULL;
            if (create(&params, &ctx) == 0) {
                s.tpm = true;
                if (closeCtx && ctx) closeCtx(ctx);
            }
        }
        FreeLibrary(tbs);
    }
    return s;
}

inline void PrintPlatformProbe() {
    PlatformStatus s = ProbePlatform();
    std::wcout << L"[*] Firmware type : " << s.firmwareName << L"\n";
    std::wcout << L"[*] UEFI runtime  : " << (s.uefi ? L"present" : L"not present") << L"\n";
    std::wcout << L"[*] TPM device    : " << (s.tpm ? L"present" : L"not present") << L"\n";
}

inline bool WantHelp(int argc, wchar_t** argv) {
    if (argc < 2) return true;
    return wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"/?") == 0;
}
