// DumpNtfsVolume.cpp
// The original tutorial described the raw-volume / $MFT path but never shipped a file for it.
// This is that missing tool: open \\.\C:, ask ntfs.sys for volume data, and dump the MFT start.

#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include "PlatformProbe.h"

int wmain(int argc, wchar_t** argv) {
    if (argc < 2 || wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"/?") == 0) {
        std::wcout <<
            L"Usage: DumpNtfsVolume.exe --volume \\\\.\\C: [--bytes N]\n"
            L"       DumpNtfsVolume.exe --probe\n"
            L"Requires an elevated token and FILE_SHARE_READ | FILE_SHARE_WRITE.\n"
            L"Prints MftStartLcn and the first bytes of the $MFT (expect FILE / 46 49 4C 45).\n"
            L"--probe prints firmware type and TPM presence, then exits.\n";
        return argc < 2 ? 1 : 0;
    }
    PrintPlatformProbe();
    if (wcscmp(argv[1], L"--probe") == 0) return 0;
    std::wstring volume = L"\\\\.\\C:";
    DWORD dumpBytes = 256;
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--volume") == 0 && i + 1 < argc) volume = argv[++i];
        else if (wcscmp(argv[i], L"--bytes") == 0 && i + 1 < argc) dumpBytes = (DWORD)_wtoi(argv[++i]);
    }
    HANDLE h = CreateFileW(volume.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        PrintWin32Error(L"Open volume", GetLastError());
        return 1;
    }
    NTFS_VOLUME_DATA_BUFFER info{};
    DWORD returned = 0;
    if (!DeviceIoControl(h, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &info, sizeof(info), &returned, NULL)) {
        std::wcerr << L"[-] FSCTL_GET_NTFS_VOLUME_DATA failed: " << GetLastError() << L"\n";
        CloseHandle(h);
        return 1;
    }
    std::wcout << L"[*] BytesPerCluster " << info.BytesPerCluster << L"\n";
    std::wcout << L"[*] MftStartLcn     " << info.MftStartLcn.QuadPart << L"\n";
    LARGE_INTEGER offset{};
    offset.QuadPart = info.MftStartLcn.QuadPart * info.BytesPerCluster;
    if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN)) {
        std::wcerr << L"[-] SetFilePointerEx failed: " << GetLastError() << L"\n";
        CloseHandle(h);
        return 1;
    }
    std::vector<BYTE> buf(dumpBytes);
    DWORD read = 0;
    ReadFile(h, buf.data(), dumpBytes, &read, NULL);
    CloseHandle(h);
    std::wcout << L"[*] First " << read << L" bytes at $MFT:\n";
    for (DWORD i = 0; i < read; i++) {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)buf[i] << L" ";
        if ((i + 1) % 16 == 0) std::wcout << L"\n";
    }
    std::wcout << std::dec << L"\n";
    if (read >= 4 && buf[0] == 'F' && buf[1] == 'I' && buf[2] == 'L' && buf[3] == 'E') {
        std::wcout << L"[++] FILE magic present. MFT record boundary confirmed.\n";
    }
    return 0;
}
