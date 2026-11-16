# Diagram sources (Mermaid)

Text sources for the assets in this suite. Paste any block into a Mermaid renderer (GitHub, mermaid.live, VS Code Mermaid preview) to re-draw the diagram.

Dark theme is assumed. The original images used a navy background with cyan and white text.

## 01-boot-chain

```mermaid
flowchart LR
    FW[UEFI Firmware] --> BM[Windows Boot Manager<br/>bootmgfw.efi]
    BM --> BCD[Boot Configuration Data<br/>BCD]
    BCD --> OL[Windows OS Loader<br/>winload.efi]
    OL --> NT[ntoskrnl.exe]
    BM -.-> ESP[EFI System Partition<br/>FAT32]
```

## 02-execution-phases

```mermaid
flowchart TB
    subgraph Host
        S[Host scripts<br/>certs, .auth, ISO]
    end
    subgraph QEMU
        O[OVMF shell<br/>FS0:]
        A[SecureManagerApp.efi<br/>SignatureParserApp.efi]
    end
    subgraph WinPE
        W[WinPE cmd.exe<br/>VerifyRuntimeBoundaries<br/>AuditMeasuredBootLog]
    end
    subgraph Windows
        D[Full Windows<br/>VBS / VTL 0-1]
    end
    S --> O --> A
    S --> W --> D
```

## 03-enrollment-order

```mermaid
flowchart LR
    SM[Setup Mode<br/>unauthenticated writes OK]
    DB[Enroll db]
    KEK[Enroll KEK]
    PK[Enroll PK]
    UM[User Mode<br/>signed .auth required]
    SM --> DB --> KEK --> PK --> UM
```

## 04-vtl-architecture

```mermaid
flowchart TB
    subgraph VTL0[VTL 0 — Normal Windows]
        U[user mode]
        K[ntoskrnl.exe]
    end
    subgraph VTL1[VTL 1 — Secure Kernel]
        SK[securekernel.exe]
        CI[Code Integrity]
        CG[Credential Guard]
    end
    HV[Hyper-V]
    VTL0 -->|VMCALL| VTL1
    HV --- VTL0
    HV --- VTL1
```

## 05-physical-keys-to-qemu

```mermaid
flowchart LR
    H[Physical Windows host]
    E[LowLevelBootTools.exe<br/>--extract-all-keys]
    F[PK.esl KEK.esl]
    W[workspace/]
    Q[QEMU + OVMF<br/>FS0:]
    A[SecureManagerApp.efi<br/>Option 1 enroll]
    H --> E --> F --> W --> Q --> A
```

## 06-boot-manager-policy

```mermaid
flowchart TB
    BM[Boot Manager]
    SB{SecureBoot == 1?}
    SM{SetupMode?}
    POL[Force integrity policy<br/>unsigned drivers blocked<br/>BCD debug flags ignored]
    BM --> SB
    SB -->|yes| POL
    SB -->|no| OK[honor BCD flags]
    POL --> SM
```

## 07-nvram-vtl-isolation

```mermaid
flowchart LR
    V0[VTL 0<br/>VerifyRuntimeBoundaries.exe]
    NT[ntoskrnl.exe]
    HV[Hypervisor EPT trap]
    V1[VTL 1<br/>securekernel.exe]
    NV[NVRAM]
    V0 -->|SetFirmwareEnvironmentVariableW| NT --> HV --> V1 --> NV
    V1 -.->|status only| V0
```

## 08-credential-guard

```mermaid
flowchart LR
    L0[lsass.exe<br/>VTL 0 proxy]
    NT[ntoskrnl.exe]
    HV[VMCALL]
    L1[lsaiso.exe<br/>VTL 1 secrets]
    L0 --> NT --> HV --> L1
    L1 -.->|token only| L0
```

## 09-ept-translation

```mermaid
flowchart LR
    GVA[Guest virtual] --> GPT[Guest page tables] --> GPA[Guest physical]
    GPA --> EPT[Hyper-V EPT] --> HPA[Host physical]
    EPT -.-> PERM[R W X U/S bits<br/>owned by hypervisor]
```

## 10-hvci-wx

```mermaid
flowchart LR
    subgraph Bad[Denied]
        WX[Writable + Executable]
    end
    subgraph Good[Allowed]
        X[Executable, not writable]
        W[Writable, not executable]
    end
    WX -->|EPT violation| HV[Hypervisor]
    HV --> X
    HV --> W
```

## 11-esp

```mermaid
flowchart TB
    FW[UEFI Firmware<br/>reads this first]
    LL[LowLevelBootTools.exe<br/>opens via GLOBALROOT SystemPartition]
    subgraph Disk
        ESP[ESP FAT32 100-300MB<br/>bootmgfw.efi<br/>BCD<br/>EFI/Microsoft/Boot/]
        MSR[MSR]
        OS[Windows OS NTFS]
    end
    FW --> ESP
    LL --> ESP
```

## 12-vbs

```mermaid
flowchart TB
    subgraph V0[VTL 0]
        VR[VerifyRuntimeBoundaries.exe]
        AM[AuditMeasuredBootLog.exe]
    end
    subgraph V1[VTL 1]
        SK[Secure Kernel]
    end
    HV[Hyper-V]
    VR -->|blocked unsigned PK write| V1
    HV --- V0
    HV --- V1
```

## 14-winpe

```mermaid
flowchart LR
    ISO[ISO / boot.wim] --> PE[WinPE boot]
    PE --> INJ[winpeshl.ini injects<br/>VerifyRuntimeBoundaries.exe<br/>AuditMeasuredBootLog.exe]
    INJ --> CMD[elevated cmd.exe<br/>before full Windows]
```

## 15-secure-boot-databases

```mermaid
flowchart LR
    PK[1 PK<br/>Platform Key<br/>root of trust]
    KEK[2 KEK<br/>Key Exchange Key]
    DB[3 db<br/>whitelist]
    DBX[4 dbx<br/>blacklist]
    APP[SecureManagerApp.efi<br/>injects .auth]
    PK --> KEK --> DB --> DBX
    APP -.->|signed updates| DB
    APP -.->|signed updates| DBX
```

## 16-measured-boot-tpm

```mermaid
flowchart LR
    F[Firmware] --> P0[PCR 0]
    B[bootmgr] --> P4[PCR 4]
    P[Secure Boot policy<br/>PK KEK db dbx] --> P7[PCR 7]
    V[VBS / BitLocker] --> P11[PCR 11]
    P0 --> LOG[TCG event log]
    P4 --> LOG
    P7 --> LOG
    P11 --> LOG
    LOG --> AUD[AuditMeasuredBootLog.exe<br/>Tbsi_Get_TCG_Log]
    NOTE[no TPM: 0x8028400f]
```

## 17-qemu-ovmf-nvram

```mermaid
flowchart LR
    subgraph QEMU
        CODE[OVMF_CODE.fd<br/>read-only firmware]
        VARS[OVMF_VARS.fd<br/>mutable NVRAM<br/>PK KEK db dbx dbt]
    end
    subgraph FS0[workspace FAT as FS0:]
        SM[SecureManagerApp.efi]
        SP[SignatureParserApp.efi]
    end
    VARS --> SM
    VARS --> SP
```

## 18-win32-tools-touching

```mermaid
flowchart LR
    subgraph ESP[ESP FAT32]
        LL[LowLevelBootTools.exe<br/>--list-boot --extract-boot --extract-bcd]
    end
    subgraph NVRAM[NVRAM variables]
        VR[VerifyRuntimeBoundaries.exe<br/>read db, write PK]
    end
    subgraph Other
        PS[ParseSmBios.exe<br/>RSMB table]
        DN[DumpNtfsVolume.exe<br/>$MFT]
    end
```

## 19-image-loader-gates

```mermaid
flowchart LR
    S1[01_setup_certs] --> S2[03_generate_auth]
    S2 --> S3[05_sign_custom_winboot]
    S3 --> ISO[11_extract_and_patch_iso]
    ISO --> Q[QEMU boot]
    Q --> G[Image Loader<br/>db / dbx checks]
    G --> LOAD[load bootmgfw.efi]
```

## 20-signature-lists-keys

```mermaid
flowchart TB
    subgraph ESL[.esl structure]
        H[SignatureType GUID<br/>list size<br/>header size<br/>signature size]
        E1[X.509 entry<br/>owner GUID + DER]
        E2[SHA-256 entry<br/>owner GUID + 32 bytes]
    end
    subgraph Reads
        SIG[LowLevelBootTools --extract-sig<br/>cert table in PE]
        KEYS[LowLevelBootTools --extract-all-keys<br/>NVRAM databases]
        APP[SignatureParserApp.efi<br/>walks ESL file]
    end
```

## 21-authenticated-packets

```mermaid
flowchart TB
    T[EFI_TIME<br/>static or dynamic + offset]
    C[WIN_CERTIFICATE_UEFI_GUID<br/>PKCS#7]
    P[ESL payload]
    T --> C --> P
    GEN[03_generate_auth_update.sh<br/>09_sign_db_with_kek.sh] --> T
    VIO[10_simulate_integrity_violation.sh<br/>writes DE AD BE EF] -.-> P
    DBT[dbt counter rejects older timestamp]
```

## 22-media-winpe-long-path

```mermaid
flowchart TD
    A[01_setup_certs.sh] --> B[deploy_suite.sh]
    B --> C[02_run_qemu.sh<br/>enroll into OVMF_VARS.fd]
    C --> D[11_extract_and_patch_iso.sh]
    D --> E[13_patch_winpe_image.sh<br/>inject tools + winpeshl.ini]
    E --> F[12_run_patched_iso_qemu.sh]
```

## 23-image-loader-gates

```mermaid
flowchart TD
    START[Attempt to Load App.efi]
    G1{GATE 1<br/>hash in dbx?}
    G2{GATE 2<br/>certificate in dbx?}
    G3{GATE 3<br/>signer or hash in db?}
    B1[BLOCK]
    B2[BLOCK]
    ALLOW[ALLOW]
    B3[BLOCK]
    START --> G1
    G1 -->|yes| B1
    G1 -->|no| G2
    G2 -->|yes| B2
    G2 -->|no| G3
    G3 -->|yes| ALLOW
    G3 -->|no| B3
```
