#!/usr/bin/env python3
"""
Fritz!Box .export file parser and decryptor.

Parses AVM Fritz!Box configuration export files, decrypts encrypted sections
(CRYPTEDB64FILE, CRYPTEDBINFILE), decodes base64 sections (B64FILE), decodes
$$$$-encoded credentials, verifies the CRC32 footer, and optionally extracts
all sections to an output directory.

Supports:
  - Password-protected exports (password via -p flag)
  - Passwordless exports (device serial + MAC via --serial/--maca flags)
  - $$$$-encoded credential decryption (two-stage AES-256-CBC)
  - avmnexus/boxcert sections with hardcoded AES-128 key

$$$$-encoding:
  1. Password= header contains a random export key, encrypted with a bootstrap key
  2. Bootstrap key = MD5(password)[:16] + 16×0x00 (password-protected exports)
     or MD5(serial + "\\n" + maca + "\\n")[:16] + 16×0x00 (passwordless exports)
  3. Each $$$$-value: AVM-Base32-decode → [16-byte IV | AES-256-CBC ciphertext]
  4. Decrypted format: [4-byte MD5 check | 4-byte BE length | plaintext data]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Crypto backend – prefer `cryptography`, fall back to warning
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def _aes_cbc_decrypt_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """AES-CBC decrypt without PKCS7 unpadding (for $$$$-encoded values)."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

    def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        raise RuntimeError(
            "The 'cryptography' package is required for decryption. "
            "Install it with: pip install cryptography"
        )

    def _aes_cbc_decrypt_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        raise RuntimeError(
            "The 'cryptography' package is required for decryption. "
            "Install it with: pip install cryptography"
        )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PASSWORD = "Xy!9>5fkv8f:-?vfv"
AVM_B32_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

# Hardcoded AES-128 key for avmnexus / boxcert sections
AVMNEXUS_KEY = bytes([
    0x71, 0x77, 0x65, 0x72, 0x61, 0x73, 0x64, 0x78,
    0x76, 0x6C, 0xFC, 0x30, 0x33, 0x6E, 0x63, 0x00,
])

SECTION_RE = re.compile(
    r"^\*{4}\s+"
    r"(CFGFILE|B64FILE|CRYPTEDB64FILE|BINFILE|CRYPTEDBINFILE)"
    r":(.+)$"
)

HEADER_START_RE = re.compile(r"^\*{4}\s+FRITZ!Box\b")
END_OF_FILE_RE = re.compile(r"^\*{4}\s+END OF FILE\s+\*{4}")
END_OF_EXPORT_RE = re.compile(r"^\*{4}\s+END OF EXPORT\s+([0-9A-Fa-f]{8})\s+\*{4}")

IMPORT_KEY_RE = re.compile(r"/\*ImportKey=([0-9A-Fa-f]+)\*/")


# ---------------------------------------------------------------------------
# AVM Base32 encoding (charset: A-Z, 1-6 instead of standard 2-7)
# ---------------------------------------------------------------------------
def avm_b32_decode(data: str) -> bytes:
    """Decode AVM's custom Base32 encoding."""
    result = bytearray()
    buf = 0
    bits = 0
    for ch in data:
        idx = AVM_B32_CHARSET.find(ch)
        if idx < 0:
            continue
        buf = (buf << 5) | idx
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((buf >> bits) & 0xFF)
    return bytes(result)


# ---------------------------------------------------------------------------
# $$$$-encoded credential decryption
# ---------------------------------------------------------------------------
def derive_bootstrap_key(
    password: Optional[str] = None,
    serial: Optional[str] = None,
    maca: Optional[str] = None,
) -> Optional[bytes]:
    """Derive the 32-byte bootstrap key for decrypting the Password= header.

    For password-protected exports: MD5(password)[:16] + 16×0x00
    For passwordless exports: MD5(serial + "\\n" + maca + "\\n")[:16] + 16×0x00
    Returns None if insufficient info is provided.
    """
    if password is not None:
        md5 = hashlib.md5(password.encode("utf-8")).digest()
    elif serial is not None and maca is not None:
        payload = serial + "\n" + maca + "\n"
        md5 = hashlib.md5(payload.encode("utf-8")).digest()
    else:
        return None
    return md5 + b"\x00" * 16


def decrypt_dollar_value(b32_data: str, key: bytes) -> Optional[str]:
    """Decrypt a single $$$$-encoded value (without the $$$$ prefix).

    Returns the plaintext string, or None on failure.
    """
    raw = avm_b32_decode(b32_data)
    if len(raw) < 16:
        return None

    iv = raw[:16]
    ct = raw[16:]
    # Truncate to 16-byte boundary (AES block size); excess bytes are base32 padding
    if len(ct) % 16 != 0:
        ct = ct[: len(ct) - (len(ct) % 16)]
    if len(ct) == 0:
        return None

    try:
        dec = _aes_cbc_decrypt_raw(key, iv, ct)
    except Exception:
        return None

    if len(dec) < 8:
        return None

    # Verify MD5 integrity check (first 4 bytes = MD5(rest)[:4])
    stored_hash = dec[:4]
    calc_hash = hashlib.md5(dec[4:]).digest()[:4]
    if stored_hash != calc_hash:
        return None

    data_length = struct.unpack(">I", dec[4:8])[0]
    data = dec[8:]
    if data_length > len(data):
        return None

    result = data[:data_length]
    return result.rstrip(b"\x00").decode("utf-8", errors="replace")


def derive_export_key(password_field: str, bootstrap_key: bytes) -> Optional[bytes]:
    """Decrypt the Password= header to obtain the per-export encryption key.

    Returns a 32-byte AES key (first 16 bytes of decrypted data + 16×0x00),
    or None on failure.
    """
    b32_data = password_field
    if b32_data.startswith("$$$$"):
        b32_data = b32_data[4:]

    raw = avm_b32_decode(b32_data)
    if len(raw) < 16:
        return None

    iv = raw[:16]
    ct = raw[16:]
    if len(ct) % 16 != 0:
        ct = ct[: len(ct) - (len(ct) % 16)]
    if len(ct) == 0:
        return None

    try:
        dec = _aes_cbc_decrypt_raw(bootstrap_key, iv, ct)
    except Exception:
        return None

    if len(dec) < 8:
        return None

    # Verify MD5
    stored_hash = dec[:4]
    calc_hash = hashlib.md5(dec[4:]).digest()[:4]
    if stored_hash != calc_hash:
        return None

    data_length = struct.unpack(">I", dec[4:8])[0]
    if data_length < 16:
        return None

    key_data = dec[8 : 8 + data_length]
    # Export key = first 16 bytes + 16 zero bytes
    return key_data[:16] + b"\x00" * 16


DOLLAR_RE = re.compile(r'\$\$\$\$[A-Z1-6]+')


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class ExportHeader:
    password_iv: bytes = b""
    fields: dict = field(default_factory=dict)
    raw: str = ""


@dataclass
class Section:
    kind: str          # CFGFILE, B64FILE, CRYPTEDB64FILE, BINFILE, CRYPTEDBINFILE
    path: str          # e.g. /var/flash/ar7.cfg
    raw_body: str = ""
    import_key: str = ""
    decrypted: Optional[bytes] = None
    decode_error: Optional[str] = None


@dataclass
class ExportFile:
    header: ExportHeader = field(default_factory=ExportHeader)
    sections: list[Section] = field(default_factory=list)
    crc_expected: str = ""
    crc_actual: str = ""
    crc_ok: bool = False
    export_key: Optional[bytes] = None  # derived from Password= header
    decoded_credentials: dict = field(default_factory=dict)  # path -> [(key, plaintext)]


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def derive_key(password: str) -> bytes:
    """MD5(password) → 16 bytes, zero-padded to 32 bytes → AES-256 key."""
    md5 = hashlib.md5(password.encode("utf-8")).digest()  # 16 bytes
    return md5 + b"\x00" * 16  # 32 bytes


# ---------------------------------------------------------------------------
# Decrypt helpers
# ---------------------------------------------------------------------------
def _is_avmnexus_path(path: str) -> bool:
    basename = os.path.basename(path)
    return basename in ("avmnexus", "boxcert")


def decrypt_section(
    section: Section,
    aes_key: bytes,
    iv: bytes,
    verbose: bool = False,
) -> None:
    """Decrypt a section in-place, populating section.decrypted or .decode_error."""
    if section.kind in ("CFGFILE",):
        # Strip optional ImportKey comment at the end
        body = section.raw_body
        m = IMPORT_KEY_RE.search(body)
        if m:
            section.import_key = m.group(1)
            body = body[: m.start()].rstrip("\n") + "\n"
        section.decrypted = body.encode("utf-8")
        return

    if section.kind in ("B64FILE", "BINFILE"):
        try:
            section.decrypted = base64.b64decode(section.raw_body)
        except Exception as exc:
            section.decode_error = f"base64 decode failed: {exc}"
        return

    # Encrypted sections: CRYPTEDB64FILE, CRYPTEDBINFILE
    try:
        ciphertext = base64.b64decode(section.raw_body)
    except Exception as exc:
        section.decode_error = f"base64 decode of ciphertext failed: {exc}"
        return

    if not ciphertext:
        section.decode_error = "empty ciphertext"
        return

    # Choose key/iv for avmnexus sections
    if _is_avmnexus_path(section.path):
        key = AVMNEXUS_KEY
        dec_iv = iv[:16]  # still use IV from header, truncated to 16 bytes
        if verbose:
            print(f"  [decrypt] using avmnexus hardcoded AES-128 key for {section.path}")
    else:
        key = aes_key
        dec_iv = iv
        if verbose:
            print(f"  [decrypt] using derived AES-256 key for {section.path}")

    try:
        section.decrypted = _aes_cbc_decrypt(key, dec_iv, ciphertext)
    except Exception as exc:
        section.decode_error = f"decryption failed: {exc}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def parse_export(text: str, verbose: bool = False) -> ExportFile:
    """Parse a Fritz!Box .export file from its full text content."""
    result = ExportFile()
    lines = text.splitlines(keepends=True)
    idx = 0

    # --- Parse header ---
    header_lines: list[str] = []
    while idx < len(lines):
        line = lines[idx].rstrip("\n").rstrip("\r")
        idx += 1

        if HEADER_START_RE.match(line):
            header_lines.append(line)
            continue

        if line.startswith("****"):
            # We've hit the first section marker – rewind
            idx -= 1
            break

        header_lines.append(line)
        if "=" in line:
            key, _, value = line.partition("=")
            result.header.fields[key.strip()] = value.strip()

    result.header.raw = "\n".join(header_lines)

    # Extract IV from Password field
    # For encrypted exports, Password= contains a hex-encoded AES IV.
    # For unencrypted exports, Password= contains the device password in
    # AVM's $$$$-encoded format — not a hex IV.
    pw_hex = result.header.fields.get("Password", "")
    if pw_hex and not pw_hex.startswith("$$$$") and len(pw_hex) >= 32:
        try:
            result.header.password_iv = bytes.fromhex(pw_hex[:32])
        except ValueError:
            if verbose:
                print(f"  [warn] could not decode Password hex: {pw_hex}")
    elif pw_hex and pw_hex.startswith("$$$$"):
        if verbose:
            print("  [info] Password= contains $$$$-encoded device password (unencrypted export)")

    # --- Parse sections ---
    while idx < len(lines):
        line = lines[idx].rstrip("\n").rstrip("\r")

        # End of export?
        m_end = END_OF_EXPORT_RE.match(line)
        if m_end:
            result.crc_expected = m_end.group(1).upper()
            break

        m_eof = END_OF_FILE_RE.match(line)
        if m_eof:
            idx += 1
            continue

        m_sec = SECTION_RE.match(line)
        if m_sec:
            kind = m_sec.group(1)
            path = m_sec.group(2).strip()
            idx += 1
            body_lines: list[str] = []
            while idx < len(lines):
                peek = lines[idx].rstrip("\n").rstrip("\r")
                if peek.startswith("****"):
                    break
                body_lines.append(lines[idx])
                idx += 1
            raw_body = "".join(body_lines)
            # Strip leading/trailing blank lines from body
            raw_body = raw_body.strip("\n").strip("\r\n")
            section = Section(kind=kind, path=path, raw_body=raw_body)
            result.sections.append(section)
            if verbose:
                print(f"  [parse] {kind}:{path} ({len(raw_body)} chars)")
            continue

        idx += 1

    # --- CRC32 verification ---
    # Note: the firmware's CRC includes null terminators from internal string
    # processing that don't appear in the file. Our simple CRC32 of the raw
    # file content may not match. The check still catches truncation/corruption.
    end_marker = "**** END OF EXPORT"
    end_pos = text.find(end_marker)
    if end_pos > 0 and result.crc_expected:
        content_for_crc = text[:end_pos]
        crc_val = binascii.crc32(content_for_crc.encode("latin-1")) & 0xFFFFFFFF
        result.crc_actual = f"{crc_val:08X}"
        result.crc_ok = result.crc_actual == result.crc_expected.upper()

    return result


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------
def process_export(
    filepath: str,
    password: Optional[str] = None,
    serial: Optional[str] = None,
    maca: Optional[str] = None,
    output_dir: Optional[str] = None,
    verbose: bool = False,
    decode_secrets: bool = False,
) -> None:
    path = Path(filepath)
    if not path.is_file():
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    # Read file – try UTF-8 first, fall back to latin-1
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="latin-1")

    if verbose:
        print(f"Parsing {filepath} ({len(text)} bytes) ...")

    export = parse_export(text, verbose=verbose)

    # IV
    iv = export.header.password_iv
    has_encrypted = any(s.kind.startswith("CRYPTED") for s in export.sections)
    if not iv and has_encrypted:
        print("Warning: no IV found in Password= header; decryption may fail.",
              file=sys.stderr)
        iv = b"\x00" * 16
    elif not iv:
        iv = b"\x00" * 16  # placeholder — not used for unencrypted exports

    # Derive AES key for encrypted sections (CRYPTEDB64FILE, CRYPTEDBINFILE)
    pw = password if password is not None else DEFAULT_PASSWORD
    aes_key = derive_key(pw)
    if verbose:
        using = "user-supplied" if password is not None else "default"
        print(f"  Using {using} password for section key derivation")
        print(f"  AES key (hex): {aes_key.hex()}")
        print(f"  IV (hex):      {iv.hex()}")

    # Decrypt each section
    encrypted_count = 0
    for sec in export.sections:
        decrypt_section(sec, aes_key, iv, verbose=verbose)
        if sec.kind.startswith("CRYPTED"):
            encrypted_count += 1

    # $$$$-encoded credential decryption
    pw_field = export.header.fields.get("Password", "")
    if (decode_secrets or password or (serial and maca)) and pw_field:
        bootstrap_key = derive_bootstrap_key(
            password=password, serial=serial, maca=maca
        )
        if bootstrap_key is not None:
            if verbose:
                if password:
                    print(f"  Deriving export key from export password...")
                else:
                    print(f"  Deriving export key from serial={serial} maca={maca}...")
                print(f"  Bootstrap key: {bootstrap_key.hex()}")

            export_key = derive_export_key(pw_field, bootstrap_key)
            if export_key is not None:
                export.export_key = export_key
                if verbose:
                    print(f"  ✓ Export key derived: {export_key[:16].hex()}...")

                # Decode all $$$$-values in CFGFILE sections
                total_decoded = 0
                for sec in export.sections:
                    if sec.kind != "CFGFILE" or sec.decrypted is None:
                        continue
                    content = sec.decrypted.decode("utf-8", errors="replace")
                    matches = DOLLAR_RE.findall(content)
                    if not matches:
                        continue
                    decoded_pairs = []
                    for match in matches:
                        plaintext = decrypt_dollar_value(match[4:], export_key)
                        if plaintext is not None:
                            decoded_pairs.append((match, plaintext))
                            total_decoded += 1
                    if decoded_pairs:
                        export.decoded_credentials[sec.path] = decoded_pairs
                print(f"  Decoded {total_decoded} $$$$-encoded credentials across "
                      f"{len(export.decoded_credentials)} section(s)")
            else:
                print("  ✗ Failed to derive export key — wrong password or serial/maca?",
                      file=sys.stderr)
        else:
            if verbose:
                print("  No bootstrap key info provided — skipping $$$$-decryption")

    # CRC check
    if export.crc_expected:
        status = "OK" if export.crc_ok else "MISMATCH"
        if verbose or not export.crc_ok:
            print(f"CRC32: expected={export.crc_expected}, "
                  f"actual={export.crc_actual} [{status}]")
    else:
        if verbose:
            print("CRC32: no checksum found in file")

    # --- Output ---
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for sec in export.sections:
            basename = os.path.basename(sec.path)
            out_path = out / basename
            if sec.decrypted is not None:
                out_path.write_bytes(sec.decrypted)
                print(f"  Extracted: {out_path}")
            elif sec.decode_error:
                print(f"  FAILED ({sec.decode_error}): {sec.path}", file=sys.stderr)
            else:
                # Write raw body as fallback
                out_path.write_text(sec.raw_body, encoding="utf-8")
                print(f"  Extracted (raw): {out_path}")
        print(f"\n{len(export.sections)} section(s) written to {out}/")
    else:
        # Summary mode
        print(f"\nFritz!Box Export: {filepath}")
        print(f"  Header fields: {len(export.header.fields)}")
        for k, v in export.header.fields.items():
            print(f"    {k} = {v}")
        print(f"  Sections: {len(export.sections)}")
        for sec in export.sections:
            size_info = ""
            if sec.decrypted is not None:
                size_info = f" ({len(sec.decrypted)} bytes decrypted)"
            elif sec.decode_error:
                size_info = f" [ERROR: {sec.decode_error}]"
            print(f"    {sec.kind}: {sec.path}{size_info}")

        # Show plaintext CFGFILE contents
        cfg_sections = [s for s in export.sections if s.kind == "CFGFILE"]
        if cfg_sections:
            print(f"\n{'='*60}")
            print("Plaintext CFGFILE contents:")
            print(f"{'='*60}")
            for sec in cfg_sections:
                print(f"\n--- {sec.path} ---")
                if sec.decrypted is not None:
                    try:
                        print(sec.decrypted.decode("utf-8"))
                    except UnicodeDecodeError:
                        print(sec.decrypted.decode("latin-1"))
                else:
                    print(sec.raw_body)

        # Show decrypted encrypted sections
        enc_sections = [s for s in export.sections
                        if s.kind.startswith("CRYPTED") and s.decrypted is not None]
        if enc_sections:
            print(f"\n{'='*60}")
            print("Decrypted encrypted sections:")
            print(f"{'='*60}")
            for sec in enc_sections:
                print(f"\n--- {sec.path} ({sec.kind}) ---")
                try:
                    content = sec.decrypted.decode("utf-8")
                    print(content)
                except UnicodeDecodeError:
                    print(f"  <binary data, {len(sec.decrypted)} bytes>")

        # Show decoded $$$$-credentials
        if export.decoded_credentials:
            print(f"\n{'='*60}")
            print("Decoded $$$$-encoded credentials:")
            print(f"{'='*60}")
            for sec_path, pairs in export.decoded_credentials.items():
                print(f"\n--- {sec_path} ---")
                for encoded, plaintext in pairs:
                    print(f"  {plaintext}")

    if not HAS_CRYPTO and encrypted_count > 0:
        print(
            "\nNote: 'cryptography' package not installed – "
            "encrypted sections could not be decrypted.",
            file=sys.stderr,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fritz!Box .export file parser and decryptor",
    )
    parser.add_argument(
        "export_file",
        help="Path to .export file",
    )
    parser.add_argument(
        "-p", "--password",
        default=None,
        help="Export password (for password-protected exports)",
    )
    parser.add_argument(
        "--serial",
        default=None,
        help="Device serial number (for passwordless exports, from urlader env)",
    )
    parser.add_argument(
        "--maca",
        default=None,
        help="Device MAC address (for passwordless exports, from urlader env)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="OUTPUT_DIR",
        default=None,
        help="Extract sections to directory",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed parsing info",
    )
    parser.add_argument(
        "--decode-secrets",
        action="store_true",
        help="Force $$$$-credential decryption (requires -p or --serial/--maca)",
    )

    args = parser.parse_args()
    process_export(
        filepath=args.export_file,
        password=args.password,
        serial=args.serial,
        maca=args.maca,
        output_dir=args.output,
        verbose=args.verbose,
        decode_secrets=args.decode_secrets,
    )


if __name__ == "__main__":
    main()
