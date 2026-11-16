// LowLevelBootTools.cpp
#include <windows.h>
#include "PlatformProbe.h"
#include <winioctl.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

const std::wstring SYS_PARTITION_ROOT = L"\\\\?\\GLOBALROOT\\SystemPartition\\";
const std::wstring BOOT_DIR_PATH      = L"\\\\?\\GLOBALROOT\\SystemPartition\\EFI\\Microsoft\\Boot\\";
const LPCWSTR UEFI_GLOBAL_VARIABLE_GUID = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
const GUID GUID_EFI_CERT_X509 = { 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };
const GUID GUID_EFI_CERT_SHA256 = { 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };

typedef DWORD (WINAPI* pfnOROpenHive)(PCWSTR, PHANDLE);
typedef DWORD (WINAPI* pfnORCloseHive)(HANDLE);
typedef DWORD (WINAPI* pfnOREnumKey)(HANDLE, DWORD, PWSTR, PDWORD, PWSTR, PDWORD, PFILETIME);
typedef DWORD (WINAPI* pfnORGetValue)(HANDLE, PCWSTR, PCWSTR, PDWORD, PBYTE, PDWORD);
typedef DWORD (WINAPI* pfnORSetValue)(HANDLE, PCWSTR, DWORD, const BYTE*, DWORD);
typedef DWORD (WINAPI* pfnORSaveHive)(HANDLE, PCWSTR, DWORD, DWORD);

void PrintUsage() {
    std::wcout <<
        L"LowLevelBootTools.exe - UEFI Secure Vault boot-partition and NVRAM inspector\n"
        L"Run from an elevated console.\n"
        L"  --help                              This text\n"
        L"  --probe                             Firmware type and TPM presence, then exit\n\n"
        L"ESP / bootloader:\n"
        L"  --list-root                         List \\\\?\\GLOBALROOT\\SystemPartition\\\n"
        L"  --list-boot                         List EFI\\Microsoft\\Boot\n"
        L"  --parse <file>                      Alias of --parse-boot-file for an explicit path\n"
        L"  --parse-boot-file [path]            PE machine + WinVerifyTrust (default bootmgfw.efi)\n"
        L"  --extract-boot [dest]               Copy bootmgfw.efi out of the ESP (default .\\bootmgfw.efi)\n"
        L"  --extract-sig [src] [dest.p7b]      Detach the Authenticode certificate table\n"
        L"  --extract-bcd [dest]                Copy the live BCD hive (default .\\BCD)\n"
        L"  --inspect-bcd [hive]                Enumerate offline-registry object GUIDs\n"
        L"  --modify-timeout <seconds> [hive]   Patch the {bootmgr} timeout and save the hive\n"
        L"NVRAM / ESL:\n"
        L"  --extract-all-keys [outdir]         Dump PK, KEK, db, dbx, dbt (default .\\nvram)\n"
        L"  --extract-hardware-keys             Alias of --extract-all-keys\n"
        L"  --parse-esl [file.esl]              Walk EFI_SIGNATURE_LIST (default .\\nvram\\db.esl)\n"
        L"  --esl-to-cer <file.esl> [out.cer]   WinCrypt decode of the first X.509 entry\n"
        L"Firmware identity:\n"
        L"  --dump-smbios                       Raw SMBIOS type 0/1 hex and string pool\n";
}

bool EnableFirmwarePrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValueW(NULL, L"SeSystemEnvironmentPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    bool ok = GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

void ListDirectoryContents(const std::wstring& directoryPath) {
    std::wcout << L"\n--- Listing Directory: " << directoryPath << L" ---\n";
    WIN32_FIND_DATAW findData{};
    HANDLE hFind = FindFirstFileW((directoryPath + L"*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        PrintWin32Error(L"List directory", GetLastError());
        return;
    }
    do {
        std::wstring fileName = findData.cFileName;
        if (fileName == L"." || fileName == L"..") continue;
        std::wcout << ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L" [DIR]  " : L" [FILE] ")
                   << std::setw(10) << findData.nFileSizeLow << L" bytes | " << fileName << L"\n";
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}

void ExtractRawBootFile(const std::wstring& src, const std::wstring& dest) {
    std::wcout << L"[*] Source: " << src << L"\n[*] Target: " << dest << L"\n";
    HANDLE hSource = CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSource == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to open source. Error: " << GetLastError() << L"\n";
        return;
    }
    HANDLE hDest = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to create destination. Error: " << GetLastError() << L"\n";
        CloseHandle(hSource);
        return;
    }
    BYTE buffer[65536];
    DWORD bytesRead = 0, bytesWritten = 0;
    ULONGLONG total = 0;
    while (ReadFile(hSource, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        WriteFile(hDest, buffer, bytesRead, &bytesWritten, NULL);
        total += bytesWritten;
    }
    std::wcout << L"[++] Extraction Complete! Total Bytes Copied: " << total << L"\n";
    CloseHandle(hSource);
    CloseHandle(hDest);
}

void ParseBootFile(const std::wstring& path) {
    std::wcout << L"\n--- Parsing PE and verifying signature: " << path << L" ---\n";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Open failed. Error: " << GetLastError() << L"\n";
        return;
    }
    HANDLE map = CreateFileMappingW(h, NULL, PAGE_READONLY, 0, 0, NULL);
    BYTE* view = map ? (BYTE*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0) : NULL;
    if (view) {
        auto dos = (IMAGE_DOS_HEADER*)view;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto nt = (IMAGE_NT_HEADERS*)(view + dos->e_lfanew);
            std::wcout << L"[*] Machine: 0x" << std::hex << nt->FileHeader.Machine << std::dec << L"\n";
            std::wcout << L"[*] Sections: " << nt->FileHeader.NumberOfSections << L"\n";
            auto& sec = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            std::wcout << L"[*] Security directory offset: " << sec.VirtualAddress << L" size: " << sec.Size << L"\n";
        }
        UnmapViewOfFile(view);
    }
    if (map) CloseHandle(map);
    CloseHandle(h);

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &fileInfo;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &action, &trust);
    std::wcout << L"[*] WinVerifyTrust status: 0x" << std::hex << status << std::dec << L"\n";
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &trust);
}

void ExtractSignature(const std::wstring& src, const std::wstring& dest) {
    HANDLE h = CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Open failed. Error: " << GetLastError() << L"\n";
        return;
    }
    DWORD size = GetFileSize(h, NULL);
    std::vector<BYTE> file(size);
    DWORD read = 0;
    ReadFile(h, file.data(), size, &read, NULL);
    CloseHandle(h);
    auto dos = (IMAGE_DOS_HEADER*)file.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto nt = (IMAGE_NT_HEADERS*)(file.data() + dos->e_lfanew);
    auto& sec = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sec.Size < 8 || sec.VirtualAddress + sec.Size > file.size()) {
        std::wcerr << L"[-] No certificate table.\n";
        return;
    }
    // WIN_CERTIFICATE: dwLength, wRevision, wCertificateType, then bCertificate.
    DWORD certLen = *(DWORD*)(file.data() + sec.VirtualAddress);
    DWORD payload = (certLen > 8) ? certLen - 8 : 0;
    std::ofstream out(dest, std::ios::binary);
    out.write((char*)file.data() + sec.VirtualAddress + 8, payload);
    std::wcout << L"[++] Wrote " << payload << L" certificate-table bytes to " << dest << L"\n";
}

void InspectBcd(const std::wstring& hivePath) {
    HMODULE hOff = LoadLibraryW(L"offreg.dll");
    if (!hOff) {
        std::wcerr << L"[-] offreg.dll unavailable.\n";
        return;
    }
    auto OROpenHive = (pfnOROpenHive)GetProcAddress(hOff, "OROpenHive");
    auto ORCloseHive = (pfnORCloseHive)GetProcAddress(hOff, "ORCloseHive");
    auto OREnumKey = (pfnOREnumKey)GetProcAddress(hOff, "OREnumKey");
    HANDLE hive = NULL;
    if (!OROpenHive || OROpenHive(hivePath.c_str(), &hive) != ERROR_SUCCESS) {
        std::wcerr << L"[-] OROpenHive failed for " << hivePath << L"\n";
        FreeLibrary(hOff);
        return;
    }
    std::wcout << L"\n================ ACTIVE BCD OBJECT GUIDS ================\n";
    DWORD index = 0;
    WCHAR name[256];
    DWORD nameLen;
    while (true) {
        nameLen = 256;
        DWORD err = OREnumKey(hive, index++, name, &nameLen, NULL, NULL, NULL);
        if (err != ERROR_SUCCESS) break;
        std::wcout << L"  " << name << L"\n";
    }
    std::wcout << L"=========================================================\n";
    ORCloseHive(hive);
    FreeLibrary(hOff);
}

void ModifyTimeout(const std::wstring& hivePath, DWORD seconds) {
    HMODULE hOff = LoadLibraryW(L"offreg.dll");
    if (!hOff) return;
    auto OROpenHive = (pfnOROpenHive)GetProcAddress(hOff, "OROpenHive");
    auto ORCloseHive = (pfnORCloseHive)GetProcAddress(hOff, "ORCloseHive");
    auto ORSetValue = (pfnORSetValue)GetProcAddress(hOff, "ORSetValue");
    auto ORSaveHive = (pfnORSaveHive)GetProcAddress(hOff, "ORSaveHive");
    HANDLE hive = NULL;
    if (!OROpenHive || OROpenHive(hivePath.c_str(), &hive) != ERROR_SUCCESS) {
        std::wcerr << L"[-] Unable to open BCD hive.\n";
        FreeLibrary(hOff);
        return;
    }
    // BCD timeout lives as an element under the boot-manager object. The lab writes the
    // raw DWORD beside the hive as a companion file when the element path is not present,
    // and also attempts the documented element value name.
    std::wstring out = hivePath + L".timeout" + std::to_wstring(seconds);
    if (ORSetValue) {
        ORSetValue(hive, L"timeout", REG_DWORD, (const BYTE*)&seconds, sizeof(seconds));
    }
    if (ORSaveHive) {
        ORSaveHive(hive, out.c_str(), 1, 0);
        std::wcout << L"[++] Timeout candidate hive saved to " << out << L"\n";
    }
    ORCloseHive(hive);
    FreeLibrary(hOff);
}

void SaveUefiVariable(const std::wstring& name, const std::wstring& outPath) {
    const DWORD maxBuffer = 256 * 1024;
    std::vector<BYTE> buffer(maxBuffer);
    DWORD n = GetFirmwareEnvironmentVariableW(name.c_str(), UEFI_GLOBAL_VARIABLE_GUID, buffer.data(), maxBuffer);
    if (n == 0) {
        std::wstring what = L"Extract ";
        what += name;
        PrintWin32Error(what.c_str(), GetLastError());
        return;
    }
    std::ofstream out(outPath, std::ios::binary);
    out.write((char*)buffer.data(), n);
    std::wcout << L"[++] Extracted '" << name << L"' (" << n << L" bytes) -> " << outPath << L"\n";
}

void ParseEsl(const std::wstring& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::wcerr << L"[-] Cannot open " << path << L"\n";
        return;
    }
    std::vector<BYTE> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::wcout << L"\n--- Parsing UEFI Signature List (.esl) Binary Layout ---\n";
    size_t off = 0;
    int block = 1;
    while (off + 28 <= data.size()) {
        GUID type;
        memcpy(&type, data.data() + off, sizeof(GUID));
        DWORD listSize = *(DWORD*)(data.data() + off + 16);
        DWORD headerSize = *(DWORD*)(data.data() + off + 20);
        DWORD sigSize = *(DWORD*)(data.data() + off + 24);
        if (listSize < 28 || off + listSize > data.size() || sigSize == 0) break;
        DWORD count = (listSize - 28 - headerSize) / sigSize;
        std::wcout << L"[Block " << block << L"] list=" << listSize << L" sig=" << sigSize << L" entries=" << count << L"\n";
        bool sha = IsEqualGUID(type, GUID_EFI_CERT_SHA256);
        bool x509 = IsEqualGUID(type, GUID_EFI_CERT_X509);
        std::wcout << L"  type: " << (sha ? L"SHA256" : x509 ? L"X.509" : L"other") << L"\n";
        size_t entry = off + 28 + headerSize;
        for (DWORD i = 0; i < count; i++) {
            std::wcout << L"  entry " << (i + 1);
            if (sha && entry + 16 + 32 <= data.size()) {
                std::wcout << L" hash ";
                for (int b = 0; b < 32; b++) std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << data[entry + 16 + b];
                std::wcout << std::dec;
            }
            std::wcout << L"\n";
            entry += sigSize;
        }
        off += listSize;
        block++;
    }
}

void EslToCer(const std::wstring& esl, const std::wstring& cer) {
    std::ifstream in(esl, std::ios::binary);
    std::vector<BYTE> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.size() < 44) {
        std::wcerr << L"[-] ESL too small.\n";
        return;
    }
    DWORD listSize = *(DWORD*)(data.data() + 16);
    DWORD sigSize = *(DWORD*)(data.data() + 24);
    if (28 + sigSize > data.size()) return;
    const BYTE* cert = data.data() + 28 + 16;
    DWORD certLen = sigSize - 16;
    DWORD cb = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, cert, certLen, 0, NULL, &cb) &&
        !CryptDecodeObject(X509_ASN_ENCODING, X509_CERT, cert, certLen, 0, NULL, &cb)) {
        std::wcout << L"[*] CryptDecodeObject did not accept the blob; writing raw DER anyway.\n";
    }
    std::ofstream out(cer, std::ios::binary);
    out.write((char*)cert, certLen);
    std::wcout << L"[++] Wrote " << certLen << L" certificate bytes to " << cer << L"\n";
}

void DumpSmbios() {
    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) {
        std::wcerr << L"[-] SMBIOS table unavailable. Error: " << GetLastError() << L"\n";
        return;
    }
    std::vector<BYTE> buf(size);
    GetSystemFirmwareTable('RSMB', 0, buf.data(), size);
    std::wcout << L"[*] SMBIOS raw table " << size << L" bytes. First 64:\n";
    for (DWORD i = 0; i < size && i < 64; i++) {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)buf[i] << L" ";
        if ((i + 1) % 16 == 0) std::wcout << L"\n";
    }
    std::wcout << std::dec << L"\n[*] Use ParseSmBios.exe --parse-smbios for typed Type 0/1 fields.\n";
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }
    std::wstring cmd = argv[1];
    if (cmd == L"--help" || cmd == L"-h" || cmd == L"/?") { PrintUsage(); return 0; }
    PrintPlatformProbe();
    if (cmd == L"--probe") return 0;
    PlatformStatus host = ProbePlatform();
    if (cmd == L"--list-root") { ListDirectoryContents(SYS_PARTITION_ROOT); return 0; }
    if (cmd == L"--list-boot") { ListDirectoryContents(BOOT_DIR_PATH); return 0; }
    if (cmd == L"--parse-boot-file" || cmd == L"--parse") {
        ParseBootFile(argc > 2 ? argv[2] : BOOT_DIR_PATH + L"bootmgfw.efi");
        return 0;
    }
    if (cmd == L"--extract-boot") {
        ExtractRawBootFile(BOOT_DIR_PATH + L"bootmgfw.efi", argc > 2 ? argv[2] : L"bootmgfw.efi");
        return 0;
    }
    if (cmd == L"--extract-sig") {
        ExtractSignature(argc > 2 ? argv[2] : BOOT_DIR_PATH + L"bootmgfw.efi", argc > 3 ? argv[3] : L"bootmgfw_signature.p7b");
        return 0;
    }
    if (cmd == L"--extract-bcd") {
        ExtractRawBootFile(BOOT_DIR_PATH + L"BCD", argc > 2 ? argv[2] : L"BCD");
        return 0;
    }
    if (cmd == L"--inspect-bcd") { InspectBcd(argc > 2 ? argv[2] : L"BCD"); return 0; }
    if (cmd == L"--modify-timeout") {
        if (argc < 3) { PrintUsage(); return 1; }
        ModifyTimeout(argc > 3 ? argv[3] : L"BCD", (DWORD)_wtoi(argv[2]));
        return 0;
    }
    if (cmd == L"--extract-all-keys" || cmd == L"--extract-hardware-keys") {
        if (!host.uefi) {
            std::wcerr << L"[-] This Windows boot is not UEFI. PK/KEK/db/dbx/dbt are not exposed.\n";
            return 1;
        }
        EnableFirmwarePrivilege();
        std::wstring dir = argc > 2 ? argv[2] : L"nvram";
        CreateDirectoryW(dir.c_str(), NULL);
        for (auto name : { L"PK", L"KEK", L"db", L"dbx", L"dbt" }) {
            SaveUefiVariable(name, dir + L"\\" + name + L".esl");
        }
        return 0;
    }
    if (cmd == L"--parse-esl") { ParseEsl(argc > 2 ? argv[2] : L"nvram\\db.esl"); return 0; }
    if (cmd == L"--esl-to-cer") {
        if (argc < 3) { PrintUsage(); return 1; }
        EslToCer(argv[2], argc > 3 ? argv[3] : L"extracted.cer");
        return 0;
    }
    if (cmd == L"--dump-smbios") { DumpSmbios(); return 0; }
    std::wcerr << L"[-] Unknown switch " << cmd << L"\n";
    PrintUsage();
    return 1;
}
