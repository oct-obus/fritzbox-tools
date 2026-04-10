#!/usr/bin/env python3
"""
Fritz!Box .export file patcher.

Patches the FirmwareVersion header in a Fritz!Box export file and recalculates
the CRC32 checksum to match AVM's structured checksum algorithm.

Usage:
    python3 export_patcher.py input.export -f 154.08.22 -o patched.export
    python3 export_patcher.py input.export --firmware 154.08.22

The CRC32 algorithm processes the file structurally:
  - Header lines: CRC(key) + CRC(value) + CRC(\\0) for each key=value pair
  - Section markers: CRC(path) + CRC(\\0) for CFGFILE/B64FILE/etc section names
  - CFGFILE body: CRC of each line (with double-backslash → single), skip last line
  - B64FILE body: CRC of base64-decoded binary per line
  - BINFILE body: CRC of hex-decoded binary per line
Based on PeterPawn's decoder (GPL-2.0-or-later).
"""

from __future__ import annotations

import argparse
import base64
import re
import sys


# ---------------------------------------------------------------------------
# CRC-32 (standard polynomial 0xEDB88320, reflected)
# ---------------------------------------------------------------------------
class CRC32:
    def __init__(self):
        self.table = [0] * 256
        for i in range(256):
            v = i
            for _ in range(8):
                if v & 1:
                    v = (v >> 1) ^ 0xEDB88320
                else:
                    v >>= 1
            self.table[i] = v
        self.value = 0xFFFFFFFF

    def update(self, data: bytes):
        for b in data:
            self.value = (self.value >> 8) ^ self.table[(self.value & 0xFF) ^ b]

    def finalize(self) -> int:
        return (~self.value) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# AVM export file CRC computation
# ---------------------------------------------------------------------------
def compute_export_crc(lines: list[str]) -> int:
    """Compute the AVM-style CRC32 for an export file.

    The algorithm processes the file structurally, matching the firmware's
    computeExportFileChecksum() function.
    """
    crc = CRC32()

    NO_OUTPUT, IN_HEADER, IN_TEXTFILE, IN_BINFILE, IN_B64FILE = range(5)
    state = NO_OUTPUT
    last_line: bytes | None = None

    for raw_line in lines:
        line = raw_line.rstrip("\n").rstrip("\r")
        line_with_nl = line + "\n"

        if line.startswith("**** "):
            marker = line[5:]

            if marker.startswith("END OF FILE"):
                state = NO_OUTPUT
                continue

            if marker.startswith("END OF EXPORT"):
                # Flush pending text line before finalizing
                break

            if marker.startswith("FRITZ"):
                state = IN_HEADER
                last_line = None
                continue

            if marker.startswith("CFGFILE:"):
                # Flush pending text line from previous section
                if state == IN_TEXTFILE and last_line is not None:
                    _crc_textfile_line(crc, last_line)
                    last_line = None

                path = marker[8:].rstrip()
                crc.update(path.encode("utf-8"))
                crc.update(b"\x00")
                state = IN_TEXTFILE
                last_line = None
                continue

            for prefix, pstate in [
                ("BINFILE:", IN_BINFILE),
                ("CRYPTEDBINFILE:", IN_BINFILE),
                ("B64FILE:", IN_B64FILE),
                ("CRYPTEDB64FILE:", IN_B64FILE),
            ]:
                if marker.startswith(prefix):
                    # Flush pending text line
                    if state == IN_TEXTFILE and last_line is not None:
                        _crc_textfile_line(crc, last_line)
                        last_line = None

                    path = marker[len(prefix):].rstrip()
                    crc.update(path.encode("utf-8"))
                    crc.update(b"\x00")
                    state = pstate
                    break

            continue

        # Non-marker lines
        if state == IN_HEADER:
            if "=" in line:
                key, _, value = line.partition("=")
                crc.update(key.encode("utf-8"))
                crc.update(value.encode("utf-8"))
                crc.update(b"\x00")

        elif state == IN_TEXTFILE:
            # Delayed processing: CRC the *previous* line, hold current
            if last_line is not None:
                _crc_textfile_line(crc, last_line)
            last_line = line_with_nl.encode("utf-8")

        elif state == IN_B64FILE:
            # Decode base64 and CRC the binary
            stripped = line.strip()
            if stripped:
                try:
                    binary = base64.b64decode(stripped)
                    crc.update(binary)
                except Exception:
                    pass

        elif state == IN_BINFILE:
            # Decode hex and CRC the binary
            stripped = line.strip()
            if stripped:
                try:
                    binary = bytes.fromhex(stripped)
                    crc.update(binary)
                except Exception:
                    pass

    return crc.finalize()


def _crc_textfile_line(crc: CRC32, data: bytes):
    """Process a CFGFILE text line for CRC: collapse double backslashes to single."""
    i = 0
    while i < len(data):
        if i + 1 < len(data) and data[i] == 0x5C and data[i + 1] == 0x5C:
            # Double backslash → single in CRC
            crc.update(bytes([0x5C]))
            i += 2
        else:
            crc.update(bytes([data[i]]))
            i += 1


# ---------------------------------------------------------------------------
# Patch and write
# ---------------------------------------------------------------------------
def patch_export(
    input_path: str,
    output_path: str,
    firmware_version: str | None = None,
    verbose: bool = False,
) -> None:
    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    if not lines:
        print("Error: empty file", file=sys.stderr)
        sys.exit(1)

    # Find and patch FirmwareVersion
    patched = False
    for i, line in enumerate(lines):
        stripped = line.rstrip("\n").rstrip("\r")
        if stripped.startswith("FirmwareVersion=") and firmware_version:
            old_ver = stripped.split("=", 1)[1]
            lines[i] = f"FirmwareVersion={firmware_version}\n"
            print(f"  Patched FirmwareVersion: {old_ver} → {firmware_version}")
            patched = True
            break
        if stripped.startswith("****") and not stripped.startswith("**** FRITZ"):
            break  # Past header

    if firmware_version and not patched:
        print("Warning: FirmwareVersion= not found in header", file=sys.stderr)

    # Compute new CRC
    new_crc = compute_export_crc(lines)
    new_crc_hex = f"{new_crc:08X}"
    if verbose:
        print(f"  Computed CRC32: {new_crc_hex}")

    # Replace CRC in the last line
    end_re = re.compile(r"(\*{4}\s+END OF EXPORT\s+)([0-9A-Fa-f]{8})(\s+\*{4})")
    replaced = False
    for i in range(len(lines) - 1, max(len(lines) - 5, -1), -1):
        m = end_re.search(lines[i])
        if m:
            old_crc = m.group(2)
            lines[i] = end_re.sub(rf"\g<1>{new_crc_hex}\3", lines[i])
            print(f"  Patched CRC32: {old_crc} → {new_crc_hex}")
            replaced = True
            break

    if not replaced:
        print("Warning: END OF EXPORT line not found — CRC not updated", file=sys.stderr)

    # Write output
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(lines)

    print(f"  Written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Fritz!Box .export file patcher — change firmware version and recalculate CRC",
    )
    parser.add_argument("input_file", help="Path to input .export file")
    parser.add_argument(
        "-f", "--firmware",
        required=True,
        help="Target firmware version (e.g. 154.08.22)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: input_patched.export)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed info",
    )

    args = parser.parse_args()
    output = args.output
    if not output:
        base = args.input_file.rsplit(".", 1)
        output = base[0] + "_patched." + (base[1] if len(base) > 1 else "export")

    patch_export(args.input_file, output, args.firmware, args.verbose)


if __name__ == "__main__":
    main()
