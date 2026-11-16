#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/FileInfo.h>

// SecureManagerApp
//
// Operational pathways:
//   [1] Setup Mode enrollment of an .esl into PK, KEK, db, or dbx
//   [2] User Mode injection of a time-based authenticated .auth packet
//   [3] Blacklist manager (X.509 .cer/.crt or raw 32-byte SHA-256 .bin/.hash)
//   [4] Emergency factory wipe of PK, KEK, db, dbx
//   [T] Live dbt anti-replay timestamp counters
//   [Q] Exit

#define MAX_FILES 64
#define MAX_FILENAME_LEN 256

CHAR16 FileList[MAX_FILES][MAX_FILENAME_LEN];
UINTN  FileCount = 0;

EFI_STATUS
PopulateFilteredFileList (
  CHAR16  *ExtensionMatch
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
    Status = Root->Read (Root, &CurrentSize, FileInfo);
    if (EFI_ERROR (Status) || (CurrentSize == 0)) {
      break;
    }
    if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == 0) {
      UINTN  Len = StrLen (FileInfo->FileName);
      UINTN  ExtLen = StrLen (ExtensionMatch);
      if ((Len > ExtLen) && (StrCmp (&(FileInfo->FileName[Len - ExtLen]), ExtensionMatch) == 0)) {
        StrCpyS (FileList[FileCount], MAX_FILENAME_LEN, FileInfo->FileName);
        FileCount++;
        if (FileCount >= MAX_FILES) {
          break;
        }
      }
    }
  }

  FreePool (FileInfo);
  Root->Close (Root);
  return EFI_SUCCESS;
}

UINTN
RunInteractiveScrollMenu (
  CHAR16  *MenuTitle
  )
{
  EFI_INPUT_KEY  Key;
  UINTN          SelectedIndex;
  UINTN          Index;

  if (FileCount == 0) {
    Print (L"[-] No selectable files matching requirements found on volume.\n");
    return 0xFFFF;
  }

  SelectedIndex = 0;
  gST->ConOut->EnableCursor (gST->ConOut, FALSE);
  while (TRUE) {
    gST->ConOut->ClearScreen (gST->ConOut);
    Print (L"=== %s ===\n", MenuTitle);
    Print (L"(Use Arrow Keys to navigate, Enter to lock target configuration parameters)\n\n");
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
      gST->ConOut->ClearScreen (gST->ConOut);
      gST->ConOut->EnableCursor (gST->ConOut, TRUE);
      return SelectedIndex;
    }
  }
}

VOID
PrintSecureBootState (
  VOID
  )
{
  UINT8  SetupMode;
  UINTN  Size;

  SetupMode = 0;
  Size = sizeof (SetupMode);
  gRT->GetVariable (L"SetupMode", &gEfiGlobalVariableGuid, NULL, &Size, &SetupMode);

  Print (L"\n==================================================\n");
  if (SetupMode == 1) {
    Print (L"[*] CURRENT SYSTEM STATE: [ SETUP MODE ]\n");
    Print (L"    -> Path Routing Rule Architecture Layout:\n");
    Print (L"       [ SETUP MODE ] (Open unauthenticated writes available)\n");
    Print (L"                    |\n");
    Print (L"                    |--> Enrolling standard test '.esl' keys succeeds natively...\n");
    Print (L"                    v\n");
    Print (L"              Enrolling 'PK' locks interface gates and transitions state.\n");
  } else {
    Print (L"[*] CURRENT SYSTEM STATE: [ USER MODE ]\n");
    Print (L"    -> Security Enforcement Restrictions Active:\n");
    Print (L"       [ USER MODE ] (Firmware locked down. Standard writes blocked!)\n");
    Print (L"                   |\n");
    Print (L"                   '--> Edits require signed, Authenticated Update Packages (.auth).\n");
  }
  Print (L"==================================================\n\n");
}

VOID
PrintLiveTimestampCounters (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *DbtBuffer;
  UINTN       DbtSize;
  UINT8       *Ptr;
  UINTN       Remainder;
  UINT32      BlockIdx;

  Print (L"\n--- Querying Live NVRAM Security Timestamp Counters ---\n");
  DbtBuffer = NULL;
  DbtSize = 0;
  Status = gRT->GetVariable (L"dbt", &gEfiImageSecurityDatabaseGuid, NULL, &DbtSize, NULL);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    DbtBuffer = AllocatePool (DbtSize);
    if (DbtBuffer != NULL) {
      Status = gRT->GetVariable (L"dbt", &gEfiImageSecurityDatabaseGuid, NULL, &DbtSize, DbtBuffer);
      if (Status == EFI_SUCCESS) {
        Ptr = (UINT8 *)DbtBuffer;
        Remainder = DbtSize;
        BlockIdx = 1;
        while (Remainder >= sizeof (EFI_SIGNATURE_LIST)) {
          EFI_SIGNATURE_LIST  *SigList;
          UINT32              Count;
          EFI_SIGNATURE_DATA  *SigEntry;
          UINT32              Entry;

          SigList = (EFI_SIGNATURE_LIST *)Ptr;
          if ((SigList->SignatureListSize == 0) || (SigList->SignatureSize == 0)) {
            break;
          }
          Count = (SigList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize) / SigList->SignatureSize;
          Print (L"  [Timestamp Block #%d] Found %d Sync Entries:\n", BlockIdx, Count);
          SigEntry = (EFI_SIGNATURE_DATA *)(Ptr + sizeof (EFI_SIGNATURE_LIST) + SigList->SignatureHeaderSize);
          for (Entry = 0; Entry < Count; Entry++) {
            EFI_TIME  *FirmwareTime;
            FirmwareTime = (EFI_TIME *)(SigEntry->SignatureData);
            Print (L"    -> Entry %d Registered Anti-Replay Version Matrix: ", Entry + 1);
            Print (
              L"%04d-%02d-%02d %02d:%02d:%02d GMT\n",
              FirmwareTime->Year,
              FirmwareTime->Month,
              FirmwareTime->Day,
              FirmwareTime->Hour,
              FirmwareTime->Minute,
              FirmwareTime->Second
              );
            SigEntry = (EFI_SIGNATURE_DATA *)((UINT8 *)SigEntry + SigList->SignatureSize);
          }
          Ptr += SigList->SignatureListSize;
          Remainder -= SigList->SignatureListSize;
          BlockIdx++;
        }
      }
      FreePool (DbtBuffer);
    }
  }

  if ((DbtSize == 0) || (Status == EFI_NOT_FOUND)) {
    Print (L"  [*] Status: Uninitialized. (No authenticated .auth updates have modified variables yet).\n");
    Print (L"  [*] Default Anti-Replay Baseline Reset Value: 0000-00-00 00:00:00\n");
  }
  Print (L"-------------------------------------------------------\n\n");
}

EFI_STATUS
ReadWholeFile (
  CHAR16  *Filename,
  VOID    **Buffer,
  UINTN   *BufferSize
  )
{
  EFI_STATUS                         Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL    *FileSystem;
  EFI_FILE_PROTOCOL                  *Root;
  EFI_FILE_PROTOCOL                  *TargetFile;
  UINTN                              InfoSize;
  EFI_FILE_INFO                      *FileInfo;
  UINTN                              ReadSize;

  *Buffer = NULL;
  *BufferSize = 0;
  Root = NULL;
  TargetFile = NULL;
  Status = gBS->LocateProtocol (&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&FileSystem);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = FileSystem->OpenVolume (FileSystem, &Root);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = Root->Open (Root, &TargetFile, Filename, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) {
    Root->Close (Root);
    return Status;
  }

  InfoSize = sizeof (EFI_FILE_INFO) + MAX_FILENAME_LEN * sizeof (CHAR16);
  FileInfo = AllocatePool (InfoSize);
  if (FileInfo == NULL) {
    TargetFile->Close (TargetFile);
    Root->Close (Root);
    return EFI_OUT_OF_RESOURCES;
  }
  Status = TargetFile->GetInfo (TargetFile, &gEfiFileInfoGuid, &InfoSize, FileInfo);
  if (EFI_ERROR (Status)) {
    FreePool (FileInfo);
    TargetFile->Close (TargetFile);
    Root->Close (Root);
    return Status;
  }
  *BufferSize = (UINTN)FileInfo->FileSize;
  FreePool (FileInfo);
  *Buffer = AllocatePool (*BufferSize);
  if (*Buffer == NULL) {
    TargetFile->Close (TargetFile);
    Root->Close (Root);
    return EFI_OUT_OF_RESOURCES;
  }
  ReadSize = *BufferSize;
  Status = TargetFile->Read (TargetFile, &ReadSize, *Buffer);
  *BufferSize = ReadSize;
  TargetFile->Close (TargetFile);
  Root->Close (Root);
  return Status;
}

EFI_STATUS
ExecuteKeyEnrollment (
  CHAR16  *Filename,
  CHAR16  *VariableName,
  EFI_GUID *VendorGuid
  )
{
  EFI_STATUS  Status;
  VOID        *Buffer;
  UINTN       BufferSize;
  UINT32      Attributes;

  Print (L"[+] Initiating Setup Mode Variable Enrollment Sequence: %s -> %s\n", Filename, VariableName);
  Status = ReadWholeFile (Filename, &Buffer, &BufferSize);
  if (EFI_ERROR (Status)) {
    Print (L"[-] Failed to read %s: %r\n", Filename, Status);
    return Status;
  }
  Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
  Status = gRT->SetVariable (VariableName, VendorGuid, Attributes, BufferSize, Buffer);
  if (EFI_ERROR (Status)) {
    Print (L"[-] Enrollment rejected. Status: %r\n", Status);
    Print (L"    Setup Mode accepts raw .esl writes. User Mode requires an .auth packet (option 2).\n");
  } else {
    Print (L"[++] SUCCESS: %s enrolled (%d bytes).\n", VariableName, BufferSize);
  }
  FreePool (Buffer);
  return Status;
}

EFI_STATUS
ExecuteAuthUpdate (
  CHAR16  *Filename,
  CHAR16  *VariableName,
  EFI_GUID *VendorGuid
  )
{
  EFI_STATUS  Status;
  VOID        *Buffer;
  UINTN       BufferSize;
  UINT32      Attributes;

  Print (L"[+] Dispatching Cryptographically Authenticated Update Packet: %s -> %s\n", Filename, VariableName);
  Status = ReadWholeFile (Filename, &Buffer, &BufferSize);
  if (EFI_ERROR (Status)) {
    Print (L"[-] Failed to read %s: %r\n", Filename, Status);
    return Status;
  }
  Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
               EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
  Status = gRT->SetVariable (VariableName, VendorGuid, Attributes, BufferSize, Buffer);
  if (EFI_ERROR (Status)) {
    Print (L"[-] Authenticated update rejected. Status: %r\n", Status);
    Print (L"    EFI_SECURITY_VIOLATION usually means a bad signature or a dbt rollback.\n");
  } else {
    Print (L"[++] SUCCESS: Authenticated update applied to %s.\n", VariableName);
  }
  FreePool (Buffer);
  return Status;
}

VOID
GenerateAndAppendDbxRevocation (
  VOID      *PayloadBuffer,
  UINTN     PayloadSize,
  EFI_GUID  *SigTypeGuid,
  UINT32    SingleRecordSize
  )
{
  EFI_STATUS          Status;
  EFI_SIGNATURE_LIST  *NewEslBlock;
  UINTN               NewEslSize;
  UINT8               *CombinedBuffer;
  UINTN               CombinedBufferSize;
  VOID                *ExistingDbxBuffer;
  UINTN               ExistingDbxSize;
  EFI_SIGNATURE_DATA  *SigData;
  UINT32              Attributes;

  ExistingDbxBuffer = NULL;
  ExistingDbxSize = 0;
  Status = gRT->GetVariable (L"dbx", &gEfiImageSecurityDatabaseGuid, NULL, &ExistingDbxSize, NULL);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    ExistingDbxBuffer = AllocatePool (ExistingDbxSize);
    if (ExistingDbxBuffer != NULL) {
      Status = gRT->GetVariable (L"dbx", &gEfiImageSecurityDatabaseGuid, NULL, &ExistingDbxSize, ExistingDbxBuffer);
      if (EFI_ERROR (Status)) {
        Print (L"[-] Error reading existing DBX variable data stream.\n");
        FreePool (ExistingDbxBuffer);
        ExistingDbxBuffer = NULL;
        ExistingDbxSize = 0;
      } else {
        Print (L"[*] Located existing DBX variable payload array: %d bytes.\n", ExistingDbxSize);
      }
    }
  }

  NewEslSize = sizeof (EFI_SIGNATURE_LIST) + SingleRecordSize;
  NewEslBlock = AllocateZeroPool (NewEslSize);
  if (NewEslBlock == NULL) {
    if (ExistingDbxBuffer != NULL) {
      FreePool (ExistingDbxBuffer);
    }
    return;
  }
  CopyGuid (&NewEslBlock->SignatureType, SigTypeGuid);
  NewEslBlock->SignatureListSize = (UINT32)NewEslSize;
  NewEslBlock->SignatureHeaderSize = 0;
  NewEslBlock->SignatureSize = SingleRecordSize;
  SigData = (EFI_SIGNATURE_DATA *)(NewEslBlock + 1);
  // Laboratory owner GUID, fixed so repeated lab runs stay comparable.
  SigData->SignatureOwner.Data1 = 0xA5A5A5A5;
  CopyMem (SigData->SignatureData, PayloadBuffer, PayloadSize);

  CombinedBufferSize = ExistingDbxSize + NewEslSize;
  CombinedBuffer = AllocatePool (CombinedBufferSize);
  if (CombinedBuffer == NULL) {
    FreePool (NewEslBlock);
    if (ExistingDbxBuffer != NULL) {
      FreePool (ExistingDbxBuffer);
    }
    return;
  }
  if (ExistingDbxBuffer != NULL) {
    CopyMem (CombinedBuffer, ExistingDbxBuffer, ExistingDbxSize);
  }
  CopyMem (CombinedBuffer + ExistingDbxSize, NewEslBlock, NewEslSize);
  Print (L"[*] Merged structural payloads into unified write block array: %d bytes total.\n", CombinedBufferSize);

  Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
  Status = gRT->SetVariable (L"dbx", &gEfiImageSecurityDatabaseGuid, Attributes, CombinedBufferSize, CombinedBuffer);
  if (Status == EFI_SUCCESS) {
    Print (L"[++] SUCCESS: Target entry cleanly appended to the hardware 'dbx' database list!\n");
  } else {
    Print (L"[-] FAILED: Secure variable array modification rejected. Status: %r\n", Status);
  }

  FreePool (NewEslBlock);
  FreePool (CombinedBuffer);
  if (ExistingDbxBuffer != NULL) {
    FreePool (ExistingDbxBuffer);
  }
}

VOID
ProcessFileForBlacklist (
  CHAR16   *Filename,
  BOOLEAN  IsHashMode
  )
{
  EFI_STATUS  Status;
  VOID        *ReadBuffer;
  UINTN       FileSize;

  Status = ReadWholeFile (Filename, &ReadBuffer, &FileSize);
  if (EFI_ERROR (Status)) {
    Print (L"[-] Unable to read blacklist candidate %s: %r\n", Filename, Status);
    return;
  }
  if (IsHashMode) {
    Print (L"[+] Selected File Identifies as a Raw SHA256 Signature Hash Block File.\n");
    if (FileSize != 32) {
      Print (L"[-] Error: Raw SHA256 binary validation blocks must measure exactly 32 bytes.\n");
    } else {
      GenerateAndAppendDbxRevocation (ReadBuffer, FileSize, &gEfiCertSha256Guid, 48);
    }
  } else {
    Print (L"[+] Selected File Identifies as an X.509 Certificate Profile Signer File.\n");
    GenerateAndAppendDbxRevocation (ReadBuffer, FileSize, &gEfiCertX509Guid, (UINT32)(16 + FileSize));
  }
  FreePool (ReadBuffer);
}

VOID
RunBlacklistManagerMenu (
  VOID
  )
{
  EFI_INPUT_KEY  Key;
  UINTN          SelectionIdx;
  UINTN          EventIdx;

  gST->ConOut->ClearScreen (gST->ConOut);
  Print (L"=== UefiSecureVault Revocation / Blacklist Configuration Manager ===\n\n");
  Print (L"Select Revocation Entry Method:\n");
  Print (L"  [1] Blacklist via X.509 Certificate File Selection (.cer / .crt)\n");
  Print (L"  [2] Blacklist via Pre-Calculated Binary SHA256 Hash File (.bin / .hash)\n");
  gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIdx);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  if (Key.UnicodeChar == L'1') {
    PopulateFilteredFileList (L".cer");
    if (FileCount == 0) {
      PopulateFilteredFileList (L".crt");
    }
    SelectionIdx = RunInteractiveScrollMenu (L"Select Target X.509 Certificate File to Blacklist");
    if (SelectionIdx != 0xFFFF) {
      ProcessFileForBlacklist (FileList[SelectionIdx], FALSE);
    }
  } else if (Key.UnicodeChar == L'2') {
    PopulateFilteredFileList (L".bin");
    if (FileCount == 0) {
      PopulateFilteredFileList (L".hash");
    }
    SelectionIdx = RunInteractiveScrollMenu (L"Select Target Raw 32-Byte SHA256 Hash File to Blacklist");
    if (SelectionIdx != 0xFFFF) {
      ProcessFileForBlacklist (FileList[SelectionIdx], TRUE);
    }
  } else {
    Print (L"[-] Aborted: Menu selection parameters out of range boundaries.\n");
  }
}

VOID
ExecuteEmergencyDatabaseWipe (
  VOID
  )
{
  EFI_STATUS  Status;

  Print (L"[!] WARNING: Initializing Secure NVRAM Database Hard Clear Routine...\n");
  Print (L"[*] Clearing 'dbx' Blacklist entries context pools...\n");
  gRT->SetVariable (L"dbx", &gEfiImageSecurityDatabaseGuid, 0, 0, NULL);
  Print (L"[*] Clearing 'db' Whitelist entries context pools...\n");
  gRT->SetVariable (L"db", &gEfiImageSecurityDatabaseGuid, 0, 0, NULL);
  Print (L"[*] Clearing 'KEK' Key Exchange certificate sets...\n");
  gRT->SetVariable (L"KEK", &gEfiGlobalVariableGuid, 0, 0, NULL);
  Print (L"[*] Detaching Platform Owner key configuration tokens ('PK')...\n");
  Status = gRT->SetVariable (L"PK", &gEfiGlobalVariableGuid, 0, 0, NULL);
  Print (L"\n--------------------------------------------------\n");
  if (Status == EFI_SUCCESS) {
    Print (L"[++] SUCCESS: NVRAM environment variables swept cleanly. System returned to default state.\n");
  } else {
    Print (L"[-] FAILURE: Wipe operation rejected. Status: %r\n", Status);
    Print (L"    (Note: If system is in USER MODE, variable deletion requires a fully signed PK authentication wrapper).\n");
  }
  Print (L"--------------------------------------------------\n");
}

CHAR16
PromptVariableTarget (
  VOID
  )
{
  EFI_INPUT_KEY  Key;
  UINTN          EventIdx;

  Print (L"Select destination variable:\n");
  Print (L"  [P] PK     [K] KEK     [D] db     [X] dbx\n");
  gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIdx);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  return Key.UnicodeChar;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_INPUT_KEY  Key;
  UINTN          SelectionIdx;
  UINTN          EventIdx;
  CHAR16         Which;

  while (TRUE) {
    gST->ConOut->ClearScreen (gST->ConOut);
    Print (L"[+] UefiSecureVault Main Management Interface Console...\n");
    PrintSecureBootState ();
    PrintLiveTimestampCounters ();
    Print (L"Select Operational Control Pathway:\n");
    Print (L"  [1] Deploy Whitelist Keys (Setup Mode - Requires .esl files)\n");
    Print (L"  [2] Inject Signed Variable Update (User Mode - Requires .auth files)\n");
    Print (L"  [3] Blacklist Manager (Revoke via Certificate or Hash entries)\n");
    Print (L"  [4] Emergency Factory Variables Reset Engine (Wipe NVRAM Registers)\n");
    Print (L"  [T] Refresh Live Timestamp Counters only\n");
    Print (L"  [Q] Exit Application\n\n");

    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIdx);
    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);

    if (Key.UnicodeChar == L'1') {
      PopulateFilteredFileList (L".esl");
      SelectionIdx = RunInteractiveScrollMenu (L"Select Target .esl Key Signature List Asset File");
      if (SelectionIdx != 0xFFFF) {
        Which = PromptVariableTarget ();
        if ((Which == L'P') || (Which == L'p')) {
          ExecuteKeyEnrollment (FileList[SelectionIdx], L"PK", &gEfiGlobalVariableGuid);
        } else if ((Which == L'K') || (Which == L'k')) {
          ExecuteKeyEnrollment (FileList[SelectionIdx], L"KEK", &gEfiGlobalVariableGuid);
        } else if ((Which == L'D') || (Which == L'd')) {
          ExecuteKeyEnrollment (FileList[SelectionIdx], L"db", &gEfiImageSecurityDatabaseGuid);
        } else if ((Which == L'X') || (Which == L'x')) {
          ExecuteKeyEnrollment (FileList[SelectionIdx], L"dbx", &gEfiImageSecurityDatabaseGuid);
        }
      }
    } else if (Key.UnicodeChar == L'2') {
      PopulateFilteredFileList (L".auth");
      SelectionIdx = RunInteractiveScrollMenu (L"Select Target .auth Signed Enveloped Object File");
      if (SelectionIdx != 0xFFFF) {
        Which = PromptVariableTarget ();
        if ((Which == L'P') || (Which == L'p')) {
          ExecuteAuthUpdate (FileList[SelectionIdx], L"PK", &gEfiGlobalVariableGuid);
        } else if ((Which == L'K') || (Which == L'k')) {
          ExecuteAuthUpdate (FileList[SelectionIdx], L"KEK", &gEfiGlobalVariableGuid);
        } else if ((Which == L'D') || (Which == L'd')) {
          ExecuteAuthUpdate (FileList[SelectionIdx], L"db", &gEfiImageSecurityDatabaseGuid);
        } else if ((Which == L'X') || (Which == L'x')) {
          ExecuteAuthUpdate (FileList[SelectionIdx], L"dbx", &gEfiImageSecurityDatabaseGuid);
        }
      }
    } else if (Key.UnicodeChar == L'3') {
      RunBlacklistManagerMenu ();
    } else if (Key.UnicodeChar == L'4') {
      ExecuteEmergencyDatabaseWipe ();
    } else if ((Key.UnicodeChar == L'T') || (Key.UnicodeChar == L't')) {
      PrintLiveTimestampCounters ();
    } else if ((Key.UnicodeChar == L'q') || (Key.UnicodeChar == L'Q')) {
      break;
    } else {
      Print (L"[-] Operation canceled: Choice parameters out of range bounds.\n");
    }

    Print (L"\nPress any key to return to main console selection grid...");
    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIdx);
    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  }
  return EFI_SUCCESS;
}
