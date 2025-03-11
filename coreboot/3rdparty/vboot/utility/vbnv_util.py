#!/usr/bin/env python3
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility for vboot nvdata (nvram, nvstorage)."""

import argparse


NVDATA_SIZE = 16


def get_crc8(data, size):
    """Calculate CRC-8."""
    # CRC-8 ITU version, with x^8 + x^2 + x + 1 polynomial.
    # Note that result will evaluate to zero for a buffer of all zeroes.
    crc = 0

    # Calculate CRC-8 directly.  A table-based algorithm would be faster,
    # but for only a few bytes it isn't worth the code size.
    for i in range(size):
        crc ^= data[i] << 8
        for _ in range(8):
            if crc & 0x8000:
                crc ^= 0x1070 << 3
            crc = (crc << 1) & 0xFFFFFFFF

    return (crc >> 8) % 256


def verify_crc8(entry):
    """Verify CRC-8 of `entry`."""
    assert len(entry) == NVDATA_SIZE
    expected_crc8 = get_crc8(entry, NVDATA_SIZE - 1)
    crc8 = entry[NVDATA_SIZE - 1]
    return crc8 == expected_crc8


def process_entry(entry, offset):
    """Process an nvdata entry."""
    data = " ".join(f"{x:02x}" for x in entry)
    if all(x == 0xFF for x in entry):
        result = "EMPTY"
    else:
        is_valid = verify_crc8(entry)
        result = "VALID" if is_valid else "CRC ERROR"
    print(f"{offset:08x}  {data}  {result}")


def dump(nvdata_file):
    """Show the content of `nvdata_file`."""
    with open(nvdata_file, "rb") as f:
        nvdata = f.read()
    assert len(nvdata) % NVDATA_SIZE == 0
    for i in range(len(nvdata) // NVDATA_SIZE):
        offset = i * NVDATA_SIZE
        entry = nvdata[offset : offset + NVDATA_SIZE]
        process_entry(entry, offset)


def verify_hex_entry(hex_string):
    """Verify an nvdata entry."""
    values = []
    for s in hex_string.split():
        s = s.removeprefix("0x")
        for i in range(0, len(s), 2):
            value = int(s[i : i + 2], 16)
            values.append(value)
    if len(values) != NVDATA_SIZE:
        raise ValueError(
            f"Hex string should contain {NVDATA_SIZE} bytes"
            f", {len(values)} found"
        )

    entry = bytes(values)
    is_valid = verify_crc8(entry)
    print("VALID" if is_valid else "INVALID")


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="RW_NVRAM file to dump")
    group.add_argument(
        "--hex",
        help=(
            f"Hex string of {NVDATA_SIZE} bytes to verify (for example"
            " '50 40 00 00 00 02 00 02  00 fe ff 00 00 ff ff 60')"
        ),
    )

    args = parser.parse_args()
    if args.file:
        dump(args.file)
    elif args.hex:
        verify_hex_entry(args.hex)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
