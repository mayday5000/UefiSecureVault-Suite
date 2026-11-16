# Third-Party Notices

UefiSecureVault-Suite is licensed under the [MIT License](LICENSE). Copyright (c) 2026 Damian Andres Ulanowicz.

Some parts of this repository come from, or are built against, third-party work under its own terms. Those terms apply to those parts.

## Microsoft WinVerifyTrust sample

`win32/WinVerifyTrust.cpp` is based on the Microsoft documentation sample "Example C Program: Verifying the Signature of a PE File". The original Microsoft copyright line is kept in the file:

```
Copyright (C) Microsoft. All rights reserved.
```

Microsoft publishes the code samples in its documentation under the MIT License. The changes made in this repository are licensed under the [MIT License](LICENSE).

## EDK II (TianoCore)

The UEFI applications in `uefi/` are built inside an EDK II tree (`MdeModulePkg`) and include EDK II headers and libraries. `build_uefi.sh` clones EDK II from https://github.com/tianocore/edk2 at build time. EDK II is not included in this repository. It is licensed under the BSD-2-Clause-Patent license:

```
SPDX-License-Identifier: BSD-2-Clause-Patent
```

See https://github.com/tianocore/edk2/blob/master/License.txt. A binary built with EDK II libraries carries that license for the EDK II parts.

## External tools invoked, not distributed

The scripts call these tools from the host. None of them is included in this repository, and each keeps its own license:

| Tool | Used for | License |
|---|---|---|
| QEMU | virtual machine | GPL-2.0 |
| OVMF (EDK II) | UEFI firmware for QEMU | BSD-2-Clause-Patent |
| OpenSSL | keys, certificates, CMS | Apache-2.0 (3.x) |
| efitools | `cert-to-efi-sig-list` (`.esl` generation) | GPL-2.0 |
| sbsigntools | `sbattach` | GPL-3.0 |
| pesign / NSS | PE signing (`pesign`, `certutil`, `pk12util`) | GPL-2.0 / MPL-2.0 |
| xorriso | ISO extract and rebuild | GPL-3.0 |
| wimlib | `boot.wim` patching | GPL-3.0 / LGPL-3.0 |
| MinGW-w64 | Win32 cross-compilation | ZPL-2.1 / public domain runtime |

`11_extract_and_patch_iso.sh` rebuilds the ISO with `xorriso -as mkisofs` (xorriso's mkisofs compatibility mode). Standalone `mkisofs` and `genisoimage` are not invoked. Authenticated variable updates are built with OpenSSL CMS, not `sign-efi-sig-list`.

## Windows media and Microsoft certificates

Windows evaluation ISOs, `bootmgfw.efi`, and Microsoft certificate chains extracted by the scripts belong to Microsoft and are subject to Microsoft's license terms. They are lab state, not part of this repository, and `.gitignore` keeps them out of commits.
