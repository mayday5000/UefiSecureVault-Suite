#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/ImageAuthentication.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/FileInfo.h>

// SignatureParserApp
//
// Walks EFI_SIGNATURE_LIST chains inside .esl and .auth files, prints the three-gate
// Secure Boot decision diagram, and reports owner GUIDs plus SHA-256 or X.509 payloads.

#define MAX_FILES 64
#define MAX_FILENAME_LEN 256

CHAR16 FileList[MAX_FILES][MAX_FILENAME_LEN];
UINTN  FileCount = 0;

VOID
LogSecureBootFlowDiagram (
  VOID
  )
{
  Print (L"\n=========================================================================\n");
  Print (L"         UEFI SECURE BOOT ENFORCEMENT ENGINE FLOW SCHEMATIC              \n");
  Print (L"=========================================================================\n");
  Print (L"[ Attempt to Load App.efi ]\n");
  Print (L"            |\n");
  Print (L"            v\n");
  Print (L"  GATE 1: Hash Check against 'dbx'        --> Found? --> [ BLOCK ACCESS ]\n");
  Print (L"            | Not Found\n");
  Print (L"            v\n");
  Print (L"  GATE 2: Certificate Check against 'dbx' --> Found? --> [ BLOCK ACCESS ]\n");
  Print (L"            | Not Found\n");
  Print (L"            v\n");
  Print (L"  GATE 3: Whitelist Verification ('db')   --> Found? --> [ ALLOW EXECUTION ]\n");
  Print (L"            | Not Found\n");
  Print (L"            v\n");
  Print (L"     [ BLOCK ACCESS ]\n");
  Print (L"=========================================================================\n\n");
}

EFI_STATUS
PopulateParserFileList (
  VOID
  )
{
  EFI_STATUS                         Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL    *FileSystem;
  EFI_FILE_PROTOCOL                  *Root;
  UINTN                              BufferSize;
  EFI_FILE_INFO                      *FileInfo;

  FileCount = 0;
  Root = NULL;
  Status = gBS->LocateProtocol (&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&FileSystem);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = FileSystem->OpenVolume (FileSystem, &Root);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  BufferSize = sizeof (EFI_FILE_INFO) + MAX_FILENAME_LEN * sizeof (CHAR16);
  FileInfo = AllocatePool (BufferSize);
  if (FileInfo == NULL) {
    Root->Close (Root);
    return EFI_OUT_OF_RESOURCES;
  }
  while (TRUE) {
    UINTN  CurrentSize = BufferSize;
    UINTN  Len;
    Status = Root->Read (Root, &CurrentSize, FileInfo);
    if (EFI_ERROR (Status) || (CurrentSize == 0)) {
      break;
    }
    if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) != 0) {
      continue;
    }
    Len = StrLen (FileInfo->FileName);
    if (Len < 4) {
      continue;
    }
    if ((StrCmp (&FileInfo->FileName[Len - 4], L".esl") == 0) ||
        (StrCmp (&FileInfo->FileName[Len - 5], L".auth") == 0) ||
        (StrCmp (&FileInfo->FileName[Len - 4], L".cer") == 0) ||
        (StrCmp (&FileInfo->FileName[Len - 4], L".crt") == 0) ||
        (StrCmp (&FileInfo->FileName[Len - 4], L".p7b") == 0)) {
      StrCpyS (FileList[FileCount], MAX_FILENAME_LEN, FileInfo->FileName);
      FileCount++;
      if (FileCount >= MAX_FILES) {
        break;
      }
    }
  }
  FreePool (FileInfo);
  Root->Close (Root);
  return EFI_SUCCESS;
}

UINTN
RunParserScrollMenu (
  VOID
  )
{
  EFI_INPUT_KEY  Key;
  UINTN          SelectedIndex;
  UINTN          Index;

  if (FileCount == 0) {
    Print (L"[-] No .esl / .auth / .cer / .p7b files found on the volume.\n");
    return 0xFFFF;
  }
  SelectedIndex = 0;
  gST->ConOut->EnableCursor (gST->ConOut, FALSE);
  while (TRUE) {
    gST->ConOut->ClearScreen (gST->ConOut);
    Print (L"=== Target EFI Signature Verification Parser File Menu Selection ===\n\n");
    for (Index = 0; Index < FileCount; Index++) {
      if (Index == SelectedIndex) {
        gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGREEN, EFI_BLACK));
        Print (L"  -> [ %s ]\n", FileList[Index]);
        gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
      } else {
        Print (L"     %s \n", FileList[Index]);
      }
    }
    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &Index);
    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if ((Key.ScanCode == SCAN_UP) && (SelectedIndex > 0)) {
      SelectedIndex--;
    }
    if ((Key.ScanCode == SCAN_DOWN) && (SelectedIndex < (FileCount - 1))) {
      SelectedIndex++;
    }
    if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      gST->ConOut->EnableCursor (gST->ConOut, TRUE);
      return SelectedIndex;
    }
  }
}

VOID
DecodeSignaturePayload (
  VOID   *Buffer,
  UINTN  Size
  )
{
  UINT8  *Pointer;
  UINTN  Remainder;

  Pointer = (UINT8 *)Buffer;
  Remainder = Size;
  while (Remainder >= sizeof (EFI_SIGNATURE_LIST)) {
    EFI_SIGNATURE_LIST  *SigList;
    EFI_SIGNATURE_DATA  *SigEntry;
    UINT32              Count;
    UINT32              Index;

    SigList = (EFI_SIGNATURE_LIST *)Pointer;
    if ((SigList->SignatureListSize == 0) || (SigList->SignatureListSize > Remainder) || (SigList->SignatureSize == 0)) {
      Print (L"[-] Malformed signature list. Stopping parse.\n");
      break;
    }
    Print (L"\n[Block Encountered]\n");
    Print (L"  -> List Total Size:    %d bytes\n", SigList->SignatureListSize);
    Print (L"  -> Single Record Size: %d bytes\n", SigList->SignatureSize);
    Print (L"  -> Blueprint Type: ");
    if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Guid)) {
      Print (L"X.509 Cryptographic Certificate\n");
    } else if (CompareGuid (&SigList->SignatureType, &gEfiCertSha256Guid)) {
      Print (L"SHA256 File/Cert Blacklist Hash\n");
    } else {
      Print (L"Custom/Vendor Unique Format\n");
    }
    Count = (SigList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize) / SigList->SignatureSize;
    Print (L"  -> Total Extracted Entries: %d\n", Count);
    SigEntry = (EFI_SIGNATURE_DATA *)(Pointer + sizeof (EFI_SIGNATURE_LIST) + SigList->SignatureHeaderSize);
    for (Index = 0; Index < Count; Index++) {
      Print (L"    [Entry #%d] Owner GUID: %g\n", Index + 1, &SigEntry->SignatureOwner);
      if (CompareGuid (&SigList->SignatureType, &gEfiCertSha256Guid)) {
        UINT32  HashIndex;
        Print (L"      [*]: Hash Payload -> ");
        for (HashIndex = 0; HashIndex < 32; HashIndex++) {
          Print (L"%02X", SigEntry->SignatureData[HashIndex]);
        }
        Print (L"\n");
      } else if (CompareGuid (&SigList->SignatureType, &gEfiCertX509Guid)) {
        Print (L"      [*]: X.509 payload %d bytes (DER, not decoded in firmware).\n", SigList->SignatureSize - sizeof (EFI_GUID));
      }
      SigEntry = (EFI_SIGNATURE_DATA *)((UINT8 *)SigEntry + SigList->SignatureSize);
    }
    Pointer += SigList->SignatureListSize;
    Remainder -= SigList->SignatureListSize;
  }
}

VOID
ParseAuthOrEslFile (
  VOID   *Buffer,
  UINTN  Size
  )
{
  UINT8                        *Ptr;
  WIN_CERTIFICATE_UEFI_GUID    *CertHeader;

  Ptr = (UINT8 *)Buffer;
  if (Size > sizeof (EFI_VARIABLE_AUTHENTICATION_2)) {
    CertHeader = (WIN_CERTIFICATE_UEFI_GUID *)(Ptr + sizeof (EFI_TIME));
    if (CertHeader->Hdr.wCertificateType == WIN_CERT_TYPE_EFI_GUID) {
      UINTN  HeaderOffset;
      Print (L"[+] TARGET DETECTED AS: Signed Authenticated Update Envelope (.auth File Format)\n");
      Print (L"    -> Extracted Wrapper Data Structure Meta info:\n");
      Print (L"       WIN_CERT_UEFI_GUID Struct Size: %d bytes\n", CertHeader->Hdr.dwLength);
      Print (L"       Certificate Format Revision:    0x%04X\n", CertHeader->Hdr.wRevision);
      HeaderOffset = sizeof (EFI_TIME) + CertHeader->Hdr.dwLength;
      Print (L"    -> Internal Enveloped Payload Stream Offset Location: %d bytes\n", HeaderOffset);
      if (Size > HeaderOffset) {
        DecodeSignaturePayload (Ptr + HeaderOffset, Size - HeaderOffset);
        return;
      }
    }
  }
  Print (L"[+] TARGET DETECTED AS: Standard Raw EFI Signature List (.esl File Format)\n");
  DecodeSignaturePayload (Buffer, Size);
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  UINTN                              Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL    *FileSystem;
  EFI_FILE_PROTOCOL                  *Root;
  EFI_FILE_PROTOCOL                  *TargetFile;
  UINTN                              InfoSize;
  EFI_FILE_INFO                      *FileInfo;
  UINT64                             FileSize;
  VOID                               *ReadBuffer;
  UINTN                              ReadSize;
  EFI_INPUT_KEY                      Key;
  UINTN                              EventIdx;

  LogSecureBootFlowDiagram ();
  PopulateParserFileList ();
  Index = RunParserScrollMenu ();
  if (Index == 0xFFFF) {
    return EFI_NOT_FOUND;
  }

  Print (L"[*] Initializing low-level mapping analysis parameters for: %s\n", FileList[Index]);
  Root = NULL;
  TargetFile = NULL;
  gBS->LocateProtocol (&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&FileSystem);
  FileSystem->OpenVolume (FileSystem, &Root);
  if (Root->Open (Root, &TargetFile, FileList[Index], EFI_FILE_MODE_READ, 0) == EFI_SUCCESS) {
    InfoSize = sizeof (EFI_FILE_INFO) + MAX_FILENAME_LEN * sizeof (CHAR16);
    FileInfo = AllocatePool (InfoSize);
    TargetFile->GetInfo (TargetFile, &gEfiFileInfoGuid, &InfoSize, FileInfo);
    FileSize = FileInfo->FileSize;
    FreePool (FileInfo);
    ReadBuffer = AllocatePool ((UINTN)FileSize);
    ReadSize = (UINTN)FileSize;
    TargetFile->Read (TargetFile, &ReadSize, ReadBuffer);
    ParseAuthOrEslFile (ReadBuffer, ReadSize);
    FreePool (ReadBuffer);
    TargetFile->Close (TargetFile);
  }
  if (Root != NULL) {
    Root->Close (Root);
  }
  Print (L"\nPress any key to drop back to shell command execution console...\n");
  gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIdx);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  return EFI_SUCCESS;
}
