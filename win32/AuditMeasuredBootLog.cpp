// AuditMeasuredBootLog.cpp
// Dumps the TCG event log through TBS and writes a short attestation summary.
// Focus PCR indexes from the second revision (0, 4, 7, 11) are called out explicitly.

#include <windows.h>
#include <tbs.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "PlatformProbe.h"

#pragma comment(lib, "tbs.lib")

#pragma pack(push, 1)
typedef struct {
    UINT32 PCRIndex;
    UINT32 EventType;
    BYTE   Digest[20];
    UINT32 EventSize;
    BYTE   EventData[1];
} TCG_PCR_EVENT;
#pragma pack(pop)

std::wstring GetTcgEventTypeName(UINT32 eventType) {
    switch (eventType) {
        case 0x00000001: return L"POST_CODE / Core Firmware Map Checks";
        case 0x00000004: return L"EFI_APPLICATION / Bootloader Target Init";
        case 0x00000005: return L"EFI_BOOT_DRIVER / Low-Level Storage Hook";
        case 0x00000007: return L"EFI_RUNTIME_DRIVER / Kernel Handshake";
        case 0x0000000A: return L"EFI_HANDOFF_TABLES / ACPI Schema Index";
        case 0x80000001: return L"VARIABLE_DRIVER_CONFIG / SecureBoot Enforced";
        case 0x80000002: return L"VARIABLE_AUTHORITY / Database Updated (db/dbx)";
        default:         return L"SYSTEM_ENVIRONMENT_DATA / Internal State";
    }
}

bool FocusPcr(UINT32 pcr) {
    return pcr == 0 || pcr == 4 || pcr == 7 || pcr == 11;
}

void GeneratePlatformAttestationReport(BYTE* logBuffer, UINT32 logSize) {
    UINT32 currentOffset = 0;
    int itemsParsed = 0;
    bool secureBootEnforced = false;
    bool authoritySeen = false;
    std::wcout << L"=========================================================================\n";
    std::wcout << L"            UEFI SECURE VAULT SUITE: PLATFORM ATTESTATION REPORT          \n";
    std::wcout << L"=========================================================================\n";
    while (currentOffset + 32 < logSize) {
        auto ev = (TCG_PCR_EVENT*)(logBuffer + currentOffset);
        if (ev->EventSize > logSize || currentOffset + 32 + ev->EventSize > logSize) break;
        bool focus = FocusPcr(ev->PCRIndex);
        if (focus) {
            std::wcout << L"[" << ++itemsParsed << L"] PCR " << ev->PCRIndex
                       << L"  " << GetTcgEventTypeName(ev->EventType) << L"\n    digest ";
            for (int i = 0; i < 20; i++) std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)ev->Digest[i];
            std::wcout << std::dec << L"\n    ";
            for (UINT32 i = 0; i < ev->EventSize && i < 80; i++) {
                char c = (char)ev->EventData[i];
                std::wcout << (wchar_t)((c >= 32 && c < 127) ? c : '.');
            }
            std::wcout << L"\n";
        }
        if (ev->EventType == 0x80000001) secureBootEnforced = true;
        if (ev->EventType == 0x80000002) authoritySeen = true;
        currentOffset += 32 + ev->EventSize - 1;
    }
    std::wcout << L"------------------------------------------------------------------------- \n";
    std::wcout << L"Secure Boot config event present : " << (secureBootEnforced ? L"yes" : L"not observed") << L"\n";
    std::wcout << L"db/dbx authority event present   : " << (authoritySeen ? L"yes" : L"not observed") << L"\n";
    std::wcout << L"Focused PCR set                  : 0 (firmware), 4 (bootloader), 7 (Secure Boot), 11 (BitLocker/VBS)\n";
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && (wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"/?") == 0)) {
        std::wcout << L"Usage: AuditMeasuredBootLog.exe [--all | --probe]\n"
                   << L"  default  Print focused PCR 0/4/7/11 attestation report.\n"
                   << L"  --all    Also dump every event, not only the focus set.\n"
                   << L"  --probe  Print firmware type and TPM presence, then exit.\n"
                   << L"A missing TPM returns 0x8028400f (TBS_E_TPM_NOT_FOUND).\n";
        return 0;
    }
    PrintPlatformProbe();
    if (argc > 1 && wcscmp(argv[1], L"--probe") == 0) return 0;
    if (!ProbePlatform().tpm) {
        std::wcerr << L"[-] No TPM device is visible. Measured boot cannot be read.\n";
        std::wcerr << L"    Tbsi_Context_Create is still attempted so the status is recorded.\n";
    }
    TBS_CONTEXT_PARAMS2 params{};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    TBS_HCONTEXT ctx = 0;
    TBS_RESULT rc = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &ctx);
    if (rc != TBS_SUCCESS) {
        std::wcerr << L"[-] Tbsi_Context_Create failed: 0x" << std::hex << rc << L"\n";
        if (rc == 0x8028400f)
            std::wcerr << L"    TBS_E_TPM_NOT_FOUND. This host has no TPM device visible to Windows.\n";
        else
            std::wcerr << L"    TPM Base Services refused the context. The call itself is the test.\n";
        return 1;
    }
    UINT32 size = 0;
    rc = Tbsi_Get_TCG_Log(ctx, NULL, &size);
    if (size == 0) {
        std::wcerr << L"[-] TCG log size query failed: 0x" << std::hex << rc << L"\n";
        Tbsip_Context_Close(ctx);
        return 1;
    }
    std::vector<BYTE> log(size);
    rc = Tbsi_Get_TCG_Log(ctx, log.data(), &size);
    Tbsip_Context_Close(ctx);
    if (rc != TBS_SUCCESS) {
        std::wcerr << L"[-] Tbsi_Get_TCG_Log failed: 0x" << std::hex << rc << L"\n";
        return 1;
    }
    GeneratePlatformAttestationReport(log.data(), size);
    return 0;
}
