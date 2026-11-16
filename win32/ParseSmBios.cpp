#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

// Standard SMBIOS 4-Byte Structural Header Definition
#pragma pack(push, 1)
struct SMBIOS_HEADER {
    BYTE Type;
    BYTE Length;
    WORD Handle;
};
#pragma pack(pop)

// Helper logic to cleanly extract strings out of the packed SMBIOS trailing string arrays
std::string GetSMBIOSString(const BYTE* headerStart, BYTE stringIndex) {
    if (stringIndex == 0) return "Not Specified";
    
    // The string pool sits immediately at the end of the formatted structural length block
    const char* stringPoolStart = reinterpret_cast<const char*>(headerStart) + reinterpret_cast<const SMBIOS_HEADER*>(headerStart)->Length;
    
    int currentIdx = 1;
    while (*stringPoolStart != '\0' || *(stringPoolStart + 1) != '\0') {
        if (currentIdx == stringIndex) {
            return std::string(stringPoolStart);
        }
        stringPoolStart += strlen(stringPoolStart) + 1; // Advance past current string null terminator
        currentIdx++;
    }
    return "Unknown Token Reference";
}

// Low-Level Parsing Routine mirroring AMI Viewer logic layouts
void ParseAndDisplaySMBIOS() {
    std::wcout << L"\n=========================================================================\n";
    std::wcout << L"               LOW-LEVEL SMBIOS HARDWARE PROFILE VIEWER                  \n";
    std::wcout << L"=========================================================================\n";

    // 1. Request required system firmware table tracking allocations
    DWORD bytesRequired = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (bytesRequired == 0) {
        std::wcerr << L"[-] Failed to map active system SMBIOS layout. Error: " << GetLastError() << L"\n";
        return;
    }

    std::vector<BYTE> tableBuffer(bytesRequired);
    if (GetSystemFirmwareTable('RSMB', 0, tableBuffer.data(), bytesRequired) == 0) {
        std::wcerr << L"[-] Error retrieving live firmware payload registers.\n";
        return;
    }

    const BYTE* pRawData = tableBuffer.data();
    size_t offset = 8; // RawSMBIOSData preamble: method, major, minor, revision, length

    if (bytesRequired < 8) {
        std::wcerr << L"[-] SMBIOS table shorter than the RawSMBIOSData header.\n";
        return;
    }

    std::cout << std::left 
              << std::setw(10) << "Type" 
              << std::setw(30) << "Hardware Property Field" 
              << "Decoded Firmware Value\n";
    std::cout << std::string(75, '-') << "\n";

    // 2. Loop continuously down raw memory chunks parsing structure blocks
    while (offset + sizeof(SMBIOS_HEADER) < bytesRequired) {
        const BYTE* structStart = pRawData + offset;
        const SMBIOS_HEADER* pHeader = reinterpret_cast<const SMBIOS_HEADER*>(structStart);

        if (pHeader->Length == 0) break; // Safety verification breaker flag

        // --- TYPE 0: BIOS INFORMATION PARSER ---
        if (pHeader->Type == 0) {
            BYTE vendorIdx  = *(structStart + 4);
            BYTE versionIdx = *(structStart + 5);
            BYTE dateIdx    = *(structStart + 8);

            std::cout << std::setw(10) << "[Type 0]" << std::setw(30) << "BIOS Vendor" << GetSMBIOSString(structStart, vendorIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "BIOS Version" << GetSMBIOSString(structStart, versionIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "BIOS Release Date" << GetSMBIOSString(structStart, dateIdx) << "\n";
            std::cout << std::string(75, '.') << "\n";
        }
        // --- TYPE 1: SYSTEM PROFILE AND UNIQUE MACHINE UUIDS ---
        else if (pHeader->Type == 1) {
            BYTE mfIdx   = *(structStart + 4);
            BYTE prodIdx = *(structStart + 5);
            BYTE serIdx  = *(structStart + 7);
            const BYTE* pUuid = structStart + 8; // UUID field starts raw at byte index offset 8

            std::cout << std::setw(10) << "[Type 1]" << std::setw(30) << "System Manufacturer" << GetSMBIOSString(structStart, mfIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "Product Name/Model" << GetSMBIOSString(structStart, prodIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "System Serial Number" << GetSMBIOSString(structStart, serIdx) << "\n";

            // Print the raw Platform UUID structure natively exactly like AMI firmware utilities
            std::cout << std::setw(10) << "" << std::setw(30) << "Platform GUID/UUID" << std::hex;
            for (int i = 0; i < 16; i++) {
                std::cout << std::setw(2) << std::setfill('0') << (int)pUuid[i];
                if (i == 3 || i == 5 || i == 7 || i == 9) std::cout << "-";
            }
            std::cout << std::dec << std::setfill(' ') << "\n";
            std::cout << std::string(75, '.') << "\n";
        }
        // --- TYPE 2: BASEBOARD/MOTHERBOARD DATA ---
        else if (pHeader->Type == 2) {
            BYTE boardMfIdx   = *(structStart + 4);
            BYTE boardProdIdx = *(structStart + 5);
            BYTE boardVerIdx  = *(structStart + 6);

            std::cout << std::setw(10) << "[Type 2]" << std::setw(30) << "Motherboard Manufacturer" << GetSMBIOSString(structStart, boardMfIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "Motherboard Product" << GetSMBIOSString(structStart, boardProdIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "Motherboard Version" << GetSMBIOSString(structStart, boardVerIdx) << "\n";
            std::cout << std::string(75, '.') << "\n";
        }
        // --- TYPE 3: SYSTEM ENCLOSURE / HARDWARE PROFILE DESCRIPTORS ---
        else if (pHeader->Type == 3) {
            BYTE chassisMfIdx = *(structStart + 4);
            BYTE chassisType  = *(structStart + 5);

            std::cout << std::setw(10) << "[Type 3]" << std::setw(30) << "Chassis Manufacturer" << GetSMBIOSString(structStart, chassisMfIdx) << "\n";
            std::cout << std::setw(10) << ""         << std::setw(30) << "Chassis Structural Type" << "Code Flag: 0x" << std::hex << (int)chassisType << std::dec;
            
            // Decipher common standard DMTF enclosure codes
            switch (chassisType & 0x7F) {
                case 0x03: std::cout << " (Desktop)\n"; break;
                case 0x09: std::cout << " (Laptop)\n"; break;
                case 0x0A: std::cout << " (Notebook)\n"; break;
                case 0x0D: std::cout << " (All-in-One)\n"; break;
                case 0x11: std::cout << " & (Main Server Chassis)\n"; break;
                default:   std::cout << " (Other Hardware Profile)\n"; break;
            }
            std::cout << std::string(75, '-') << "\n";
        }

        // 3. CRITICAL STRUCTURAL TRACKING STEP: Skip past the trailing string section boundaries
        // Advance cursor tracking offset past the fixed length formatted block structure
        offset += pHeader->Length;
        
        // Scan step sequentially down the text strings until we clear the double null block marker (\0\0)
        while (offset + 1 < bytesRequired && !(pRawData[offset] == 0 && pRawData[offset + 1] == 0)) {
            offset++;
        }
        offset += 2; // Jump clean across the double null execution block edge boundary
    }
}

#include "PlatformProbe.h"

void PrintUsage() {
    std::wcout << L"ParseSmBios.exe --parse-smbios\n"
               << L"  Walk the live RSMB table and print Type 0 / Type 1 fields.\n"
               << L"ParseSmBios.exe --probe\n"
               << L"  Print firmware type and TPM presence, then exit.\n"
               << L"ParseSmBios.exe --help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2 || wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"/?") == 0) {
        PrintUsage(); return argc < 2 ? 1 : 0;
    }
    PrintPlatformProbe();
    std::wstring flag = argv[1];
    if (flag == L"--probe") return 0;

    if (flag == L"--parse-smbios") {
        ParseAndDisplaySMBIOS();
    } else {
        PrintUsage(); return 1;
    }
    return 0;
}
