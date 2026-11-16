#include <windows.h>
#include <iostream>
#include "PlatformProbe.h"

// Official architectural Secure Boot namespace GUID matching UEFI specifications
const LPCWSTR SECURE_BOOT_GUID = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

// Interfaces with the local security descriptor table to adjust token rights
bool SetFirmwareEnvironmentPrivilege(BOOL bEnable) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeSystemEnvironmentPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

int wmain(int argc, wchar_t** argv) {
    if (WantHelp(argc, argv)) {
        std::wcout <<
            L"VerifyRuntimeBoundaries.exe\n"
            L"Read the db variable, then attempt an unsigned write to PK.\n"
            L"Requires an elevated token and a UEFI boot.\n"
            L"  --help     This text\n"
            L"  --probe    Print firmware type and TPM presence, then exit\n";
        return argc < 2 ? 1 : 0;
    }
    PrintPlatformProbe();
    if (argc > 1 && wcscmp(argv[1], L"--probe") == 0) return 0;
    PlatformStatus host = ProbePlatform();
    if (!host.uefi) {
        std::wcerr << L"[-] This Windows boot is not UEFI. Firmware variables are not exposed.\n";
        return 1;
    }

    std::wcout << L"=========================================================================\n";
    std::wcout << L"          UEFI SECURE VAULT: KERNEL VARIABLE ACCESS DIAGNOSTIC          \n";
    std::wcout << L"=========================================================================\n\n";

    // 1. Attempt token privilege elevation to talk to NVRAM
    if (!SetFirmwareEnvironmentPrivilege(TRUE)) {
        std::wcerr << L"[-] SYSTEM ERROR: Failed to acquire SE_SYSTEM_ENVIRONMENT_NAME privilege.\n"
                   << L"    Execution require elevated Administrator credentials.\n\n";
        return 1;
    }
    std::wcout << L"[+] Success: Process security token adjusted for system firmware access.\n";

    // 2. GATEWAY AUDIT A: Read Access Verification on Authorized 'db' Whitelist
    std::wcout << L"[*] Auditing Gate A: Attempting read operations against 'db' table...\n";
    DWORD bufferSize = 65536;
    BYTE* readBuffer = new BYTE[bufferSize];

    DWORD bytesRead = GetFirmwareEnvironmentVariableW(L"db", SECURE_BOOT_GUID, readBuffer, bufferSize);
    if (bytesRead > 0) {
        std::wcout << L"[++] ACCESS ALLOWED: Read sequence passed cleanly. Retrieved " << bytesRead << L" bytes.\n";
    } else {
        std::wcerr << L"[-] ACCESS DENIED: Read operation failed. System Error Code: " << GetLastError() << L"\n";
    }
    delete[] readBuffer;

    // 3. GATEWAY AUDIT B: Integrity Isolation Verification on Platform Key 'PK'
    std::wcout << L"\n[*] Auditing Gate B: Attempting unauthenticated write injection to 'PK'...\n";
    BYTE dummyPayload[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    // Pass a raw dummy payload block without proper signed authenticated .auth wrappers
    BOOL writeResult = SetFirmwareEnvironmentVariableW(L"PK", SECURE_BOOT_GUID, dummyPayload, sizeof(dummyPayload));

    if (writeResult) {
        std::wcout << L"[!] RISK ALERT: Unauthenticated write to 'PK' authorized! System is vulnerable.\n";
    } else {
        DWORD lastError = GetLastError();
        std::wcout << L"[++] ISOLATION ENFORCED: Write manipulation rejected by the Windows executive.\n";
        std::wcout << L"     Kernel returned Operation Protection Status Code: " << lastError << L" ";

        if (lastError == ERROR_PRIVILEGE_NOT_HELD || lastError == ERROR_ACCESS_DENIED) {
            std::wcout << L"(Access/Privilege Denied - Variable actively shielded from VTL 0 root context)\n";
        } else {
            std::wcout << L"(Operation Terminated)\n";
        }
    }

    std::wcout << L"\n=========================================================================\n";
    return 0;
}
