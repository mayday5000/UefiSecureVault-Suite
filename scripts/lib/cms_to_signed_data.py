#!/usr/bin/env python3
"""Unwrap a CMS ContentInfo DER blob to a bare PKCS#7 SignedData SEQUENCE.

openssl cms -sign emits ContentInfo. OVMF and sign-efi-sig-list use the inner
SignedData. The file is rewritten in place when a wrapper is present.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    val = int.from_bytes(data[i + 1 : i + 1 + n], "big")
    return val, i + 1 + n


def to_signed_data(data: bytes) -> bytes:
    if not data or data[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    _, i = _len(data, 1)
    if i < len(data) and data[i] == 0x06:
        length, i = _len(data, i + 1)
        i += length
        if i >= len(data) or data[i] != 0xA0:
            raise ValueError("CMS ContentInfo missing explicit [0] SignedData")
        _, i = _len(data, i + 1)
        data = data[i:]
        if not data or data[0] != 0x30:
            raise ValueError("inner SignedData is not a SEQUENCE")
    return data


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: cms_to_signed_data.py FILE", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    path.write_bytes(to_signed_data(path.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
