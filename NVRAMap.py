# Tool for mapping relationship between EFI programs and NVRAM Key Values
# Created by : PN-TESTER

import argparse
import os
import re
import struct
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BANNER = r"""
 _______ ___ ___ ______ _______ _______              
|    |  |   |   |   __ \   _   |   |   | _____ _____ 
|       |   |   |      <       |       ||  -  |  _  |
|__|____|\_____/|___|__|___|___|__|_|__||__|__|   __|
                                              |__|   
Created By : PN-TESTER
"""

DEBUG = False   # set to True via --debug flag

# color helpers
try:
    os.system("")
    from colorama import Fore, Style, init as _ci
    _ci(autoreset=True)
    C_HEAD   = Fore.CYAN  + Style.BRIGHT
    C_OK     = Fore.GREEN + Style.BRIGHT
    C_WARN   = Fore.YELLOW
    C_ERR    = Fore.RED   + Style.BRIGHT
    C_RST    = Style.RESET_ALL
    C_GREY   = "\033[90m"
    C_STATUS = Fore.WHITE + Style.BRIGHT
except ImportError:
    C_HEAD = C_OK = C_WARN = C_ERR = C_RST = C_GREY = C_STATUS = ""

# ── grey-phase print helpers ─────────────────────────────────────────────────
# All output after the banner and before "Performing analysis" is rendered in
# grey so the user's eye is drawn to the results table rather than the setup
# chatter.  Call gprint() / gwarn() / gerr() in place of plain print() for
# every informational line in that phase.

def gprint(*args, **kwargs):
    """Print in grey (setup/info phase)."""
    msg = " ".join(str(a) for a in args)
    print(f"{C_GREY}{msg}{C_RST}", **kwargs)

def gwarn(*args, **kwargs):
    """Print a yellow warning that still appears during the grey phase."""
    msg = " ".join(str(a) for a in args)
    print(f"{C_WARN}{msg}{C_RST}", **kwargs)

def gerr(*args, **kwargs):
    """Print a red error during the grey phase (fatal)."""
    msg = " ".join(str(a) for a in args)
    print(f"{C_ERR}{msg}{C_RST}", **kwargs)

# ─────────────────────────────────────────────────────────────────────────────
# data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VarStore:
    guid: str
    var_store_id: int
    attributes: int
    size: int
    name: str

@dataclass
class HiiSetting:
    widget_type: str
    prompt: str
    help_text: str
    question_flags: int
    question_id: int
    var_store_id: int
    var_offset: int
    flags: int
    size: int          # bits
    min_val: int
    max_val: int
    step: int
    var_store: Optional[VarStore] = None
    current_value: Optional[int] = None


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def u8(b: bytes, o: int) -> int:  return b[o]
def u16(b: bytes, o: int) -> int: return struct.unpack_from("<H", b, o)[0]
def u32(b: bytes, o: int) -> int: return struct.unpack_from("<I", b, o)[0]
def u64(b: bytes, o: int) -> int: return struct.unpack_from("<Q", b, o)[0]

def guid_str(b: bytes, o: int) -> str:
    a, bv, c = struct.unpack_from("<IHH", b, o)
    d = b[o+8:o+10].hex().upper()
    e = b[o+10:o+16].hex().upper()
    return f"{a:08X}-{bv:04X}-{c:04X}-{d}-{e}"


# ─────────────────────────────────────────────────────────────────────────────
# UEFI Firmware Volume / FFS extraction
# ─────────────────────────────────────────────────────────────────────────────

# _FVH signature lives at offset +40 inside EFI_FIRMWARE_VOLUME_HEADER
_FV_SIGNATURE = b'_FVH'

# FFS section types
EFI_SECTION_PE32                  = 0x10
EFI_SECTION_TE                    = 0x12
EFI_SECTION_RAW                   = 0x19
EFI_SECTION_USER_INTERFACE        = 0x15
EFI_SECTION_COMPRESSION           = 0x01
EFI_SECTION_GUID_DEFINED          = 0x02
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_DISPOSABLE            = 0x1B
EFI_SECTION_AMD_LZMA              = 0x72

# AMD AGESA CBS section types – contain sequential raw PE32 blobs after a
# platform-specific header; not compressed, not encrypted.
EFI_SECTION_AMD_CBS_E6            = 0xE6
EFI_SECTION_AMD_CBS_F5            = 0xF5

# AMD Pi BIOS-partition section types.  These AMD-specific outer section
# types (0x51, 0x67, 0x77) wrap an LZMA-compressed DXE firmware volume.
# Their EFI-style size field is UNRELIABLE and the LZMA stream may physically
# span across multiple FFS files.  The LZMA data starts 40 bytes into the
# section payload:
#   [0:4]   section header  (type byte in [3], size bytes unreliable)
#   [4:20]  16-byte AMD hash/nonce prefix
#   [20:36] 16-byte AMD BIOS-Store GUID (see _AMD_BIOS_STORE_GUID_RAW)
#   [36:40] 4-byte flags (typically 0x00010018)
#   [40:]   LZMA FORMAT_ALONE stream (may overflow FFS boundary)
EFI_SECTION_AMD_PI_0x51           = 0x51
EFI_SECTION_AMD_PI_0x67           = 0x67
EFI_SECTION_AMD_PI_0x77           = 0x77
_AMD_PI_SECTION_TYPES             = frozenset((0x51, 0x67, 0x77))
_AMD_PI_LZMA_HDR_OFFSET           = 40   # bytes from payload start to LZMA stream
# The raw (on-disk) bytes of AMD BIOS-Store GUID 98584EEE-1439-5942-9D6E-DC7BD79403CF
_AMD_BIOS_STORE_GUID_RAW          = bytes.fromhex("98584eee143959429d6edc7bd79403cf")

# EFI_COMPRESSED_SECTION CompressionType values
EFI_NOT_COMPRESSED       = 0x00
EFI_STANDARD_COMPRESSION = 0x01   # Tiano
EFI_CUSTOMIZED_COMPRESSION = 0x02 # LZMA on many platforms

# GUID-defined section GUIDs that wrap compressed data
_TIANO_COMPRESS_GUID_B = bytes.fromhex("ad80124a9a1b4acab0da83add95859aa")
_LZMA_COMPRESS_GUID_B  = bytes.fromhex("ee4e589839471857" + "8671128f0c0b4132")
_LZMA2_COMPRESS_GUID_B = bytes.fromhex("d1837838ea024cc2" + "8ce2f27fc68c2785")

_COMPRESS_GUIDS = {_TIANO_COMPRESS_GUID_B, _LZMA_COMPRESS_GUID_B, _LZMA2_COMPRESS_GUID_B}

_FFS_SIZE_LARGE = 0xFFFFFF
_MIN_PE_SIZE = 0x1000


def _fv_header_ok(data: bytes, sig_pos: int) -> Tuple[bool, int, int]:
    base = sig_pos - 40
    if base < 0:
        return False, 0, 0
    if base + 56 > len(data):
        return False, 0, 0
    fv_len  = u64(data, base + 32)
    hdr_len = u16(data, base + 48)
    rev     = u8(data,  base + 55)
    if rev < 1 or rev > 2:
        return False, 0, 0
    if fv_len < 0x48 or fv_len > 0x4000000:
        return False, 0, 0
    if hdr_len < 0x48 or hdr_len > min(fv_len, 0x10000):
        return False, 0, 0
    if base + fv_len > len(data):
        fv_len = len(data) - base
    return True, int(fv_len), int(hdr_len)


def _try_lzma(raw: bytes) -> Optional[bytes]:
    import lzma
    strategies = [
        (0,   lzma.FORMAT_AUTO),
        (0,   lzma.FORMAT_ALONE),
        (4,   lzma.FORMAT_ALONE),
        (8,   lzma.FORMAT_ALONE),
        (4,   lzma.FORMAT_AUTO),
        (8,   lzma.FORMAT_AUTO),
        (16,  lzma.FORMAT_ALONE),
        (18,  lzma.FORMAT_ALONE),
    ]
    for skip, fmt in strategies:
        if len(raw) <= skip:
            continue
        try:
            result = lzma.decompress(raw[skip:], format=fmt)
            if len(result) > 0:
                return result
        except Exception:
            pass
    return None


def _try_tiano(raw: bytes) -> Optional[bytes]:
    try:
        from uefi_firmware.efi_compressor import TianoDecompress, EfiDecompress
    except ImportError:
        return None

    for fn in (TianoDecompress, EfiDecompress):
        try:
            result = fn(raw, len(raw))
            if result and len(result) > 0:
                return bytes(result)
        except Exception:
            pass
    return None


def _try_decompress(raw: bytes, comp_type: int = 0xFF) -> Optional[bytes]:
    if comp_type == EFI_STANDARD_COMPRESSION:
        return _try_tiano(raw) or _try_lzma(raw)
    elif comp_type == EFI_CUSTOMIZED_COMPRESSION:
        return _try_lzma(raw) or _try_tiano(raw)
    else:
        return _try_lzma(raw) or _try_tiano(raw)


def _iter_ffs_sections(sec_data: bytes) -> List[Tuple[int, int, int]]:
    results = []
    pos = 0
    n   = len(sec_data)
    itr = 0
    while pos < n - 4 and itr < 8192:
        itr += 1
        sz_b     = sec_data[pos:pos+3]
        sec_size = sz_b[0] | (sz_b[1] << 8) | (sz_b[2] << 16)
        sec_type = sec_data[pos + 3]

        if sec_size == _FFS_SIZE_LARGE:
            if pos + 8 > n:
                break
            sec_size = u32(sec_data, pos + 4)
            hdr_size = 8
        else:
            hdr_size = 4

        if sec_size < hdr_size:
            pos += 4
            continue
        if pos + sec_size > n:
            sec_size = n - pos

        results.append((sec_type, pos + hdr_size, sec_size - hdr_size))
        aligned = (sec_size + 3) & ~3
        pos += max(aligned, hdr_size)

    return results


def _iter_ffs_files(fv_data: bytes, hdr_len: int) -> List[Tuple[bytes, bytes]]:
    results = []
    pos = (hdr_len + 7) & ~7
    n   = len(fv_data)
    itr = 0

    while pos < n - 24 and itr < 65536:
        itr += 1

        if fv_data[pos] == 0xFF:
            skip = pos + 8
            while skip < n and fv_data[skip] == 0xFF:
                skip += 8
            if skip >= n:
                break
            pos = skip
            continue

        raw_size_b = fv_data[pos+20:pos+23]
        raw_size   = raw_size_b[0] | (raw_size_b[1]<<8) | (raw_size_b[2]<<16)
        ffs_attrs  = fv_data[pos+19]
        ffs_type   = fv_data[pos+18]

        large_file = (raw_size == _FFS_SIZE_LARGE) or bool(ffs_attrs & 0x01)

        if large_file:
            if pos + 32 > n:
                break
            raw_size  = u64(fv_data, pos + 24) if pos + 32 <= n else 0
            hdr_bytes = 32
        else:
            hdr_bytes = 24

        if raw_size < hdr_bytes or raw_size > (n - pos):
            pos += 8
            continue

        if ffs_type in (0x00, 0xF0, 0xFF):
            pos += (raw_size + 7) & ~7
            continue

        guid_bytes = fv_data[pos : pos+16]
        payload    = fv_data[pos+hdr_bytes : pos+raw_size]
        results.append((guid_bytes, payload))

        pos += (raw_size + 7) & ~7

    return results


def _process_decompressed(decompressed: bytes, depth: int, label: str) -> List[bytes]:
    blobs: List[bytes] = []

    if len(decompressed) >= _MIN_PE_SIZE and decompressed[:2] in (b'MZ', b'VZ'):
        blobs.append(decompressed)
        if DEBUG:
            print(f"[dbg]{'  '*depth}  → direct PE32/TE blob {len(decompressed):#x} bytes")

    inner = _collect_pe32_blobs_from_sections(decompressed, depth, label)
    blobs.extend(inner)

    return blobs


def _scan_raw_for_pe_blobs(raw: bytes, depth: int = 0,
                            label: str = "") -> List[bytes]:
    """Scan a raw byte region for embedded PE32/TE images by MZ signature.

    Used for AMD CBS sections (0xE6, 0xF5) and similar containers that pack
    multiple PE blobs sequentially without standard EFI section framing.
    Each valid PE found is appended; its contents are also walked recursively
    for nested FVs or section structures.
    """
    # First pass: collect offsets of all valid MZ/PE headers so we can cap sizes.
    mz_offsets: List[int] = []
    n = len(raw)
    scan = 0
    while scan < n - _MIN_PE_SIZE:
        mp = raw.find(b'MZ', scan)
        if mp < 0:
            break
        scan = mp + 1
        if mp + 0x40 > n:
            continue
        e_lfanew = struct.unpack_from("<I", raw, mp + 0x3C)[0]
        if not (0 < e_lfanew < 0x400):
            continue
        pe_hdr = mp + e_lfanew
        if pe_hdr + 4 > n:
            continue
        if raw[pe_hdr: pe_hdr + 2] == b'PE':
            mz_offsets.append(mp)

    blobs: List[bytes] = []
    seen: Set[int] = set()
    for i, mp in enumerate(mz_offsets):
        # Upper bound: start of the next valid MZ or end of region.
        next_mz = mz_offsets[i + 1] if i + 1 < len(mz_offsets) else n
        pe_hdr    = mp + struct.unpack_from("<I", raw, mp + 0x3C)[0]
        opt_hdr_sz = struct.unpack_from("<H", raw, pe_hdr + 20)[0] if pe_hdr + 24 <= n else 0
        img_size   = 0
        if opt_hdr_sz >= 60 and pe_hdr + 24 + opt_hdr_sz <= n:
            img_size = struct.unpack_from("<I", raw, pe_hdr + 24 + 56)[0]
        # Use img_size only when it fits before the next MZ; otherwise span to next MZ.
        if img_size >= _MIN_PE_SIZE and mp + img_size <= next_mz:
            end = mp + img_size
        else:
            end = next_mz
        blob = raw[mp:end]
        if len(blob) < _MIN_PE_SIZE:
            continue
        h = hash(blob)
        if h not in seen:
            seen.add(h)
            blobs.append(blob)
            if DEBUG:
                print(f"[dbg]{'  '*depth}  AMD_CBS PE blob @+{mp:#x}"
                      f" size={len(blob):#x}  [{label}]")
    return blobs


def _collect_pe32_blobs_from_sections(sec_data: bytes, depth: int = 0,
                                       label: str = "") -> List[bytes]:
    if depth > 6:
        return []
    blobs = []

    for sec_type, data_off, data_size in _iter_ffs_sections(sec_data):
        if data_size <= 0:
            continue
        chunk = sec_data[data_off : data_off + data_size]

        if sec_type == EFI_SECTION_PE32 or sec_type == EFI_SECTION_TE:
            if len(chunk) >= _MIN_PE_SIZE:
                blobs.append(chunk)
                if DEBUG:
                    print(f"[dbg]{'  '*depth}  PE32/TE section {len(chunk):#x} bytes  [{label}]")

        elif sec_type == EFI_SECTION_RAW:
            if len(chunk) >= _MIN_PE_SIZE and chunk[:2] == b'MZ':
                blobs.append(chunk)

        elif sec_type == EFI_SECTION_COMPRESSION:
            if len(chunk) < 5:
                continue
            comp_type = chunk[4]
            comp_data = chunk[5:]
            if comp_type == EFI_NOT_COMPRESSED:
                blobs.extend(_collect_pe32_blobs_from_sections(comp_data, depth+1, label))
            else:
                decompressed = _try_decompress(comp_data, comp_type)
                if decompressed:
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  COMPRESSION {len(comp_data):#x}"
                              f" → {len(decompressed):#x}")
                    blobs.extend(_process_decompressed(decompressed, depth+1, label))
                else:
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  COMPRESSION {len(comp_data):#x}"
                              f" decompression failed (type={comp_type:#x})")
                    blobs.extend(_collect_pe32_blobs_from_sections(
                        comp_data, depth+1, label))

        elif sec_type == EFI_SECTION_GUID_DEFINED:
            if len(chunk) < 20:
                continue
            sec_guid  = bytes(chunk[0:16])
            data_off2 = u16(chunk, 16)
            # EFI spec: DataOffset is measured from the very start of the section
            # (i.e. it includes the 4-byte size+type header that precedes `chunk`).
            # Subtract 4 so the offset is relative to the start of `chunk`.
            adj_off = data_off2 - 4
            if adj_off < 0 or adj_off >= len(chunk):
                continue
            raw = chunk[adj_off:]
            if not raw:
                continue

            if sec_guid in _COMPRESS_GUIDS:
                decompressed = _try_decompress(raw)
                if decompressed:
                    if DEBUG:
                        gstr = sec_guid.hex()
                        print(f"[dbg]{'  '*depth}  GUID_DEFINED({gstr[:8]}…)"
                              f" {len(raw):#x} → {len(decompressed):#x}")
                    blobs.extend(_process_decompressed(decompressed, depth+1, label))
                elif DEBUG:
                    print(f"[dbg]{'  '*depth}  GUID_DEFINED({sec_guid.hex()[:8]}…)"
                          f" {len(raw):#x} decompression failed")
            elif sec_guid == _AMD_BIOS_STORE_GUID_RAW:
                # AMD Pi BIOS-Store signed wrapper: the payload is LZMA-compressed
                # (or occasionally plain FFS) after the signing header.
                decompressed = _try_lzma(raw)
                if decompressed:
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  AMD_BIOS_STORE GUID_DEF"
                              f" {len(raw):#x} → {len(decompressed):#x}")
                    blobs.extend(_process_decompressed(decompressed, depth+1, label))
                else:
                    # Might be plain (uncompressed but signed) – walk as sections
                    blobs.extend(_collect_pe32_blobs_from_sections(raw, depth+1, label))
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  AMD_BIOS_STORE GUID_DEF"
                              f" {len(raw):#x} plain/unknown, walked as sections")
            else:
                decompressed = _try_decompress(raw)
                if decompressed:
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  GUID_DEFINED(unknown {sec_guid.hex()[:8]}…)"
                              f" {len(raw):#x} → {len(decompressed):#x}")
                    blobs.extend(_process_decompressed(decompressed, depth+1, label))
                else:
                    blobs.extend(_collect_pe32_blobs_from_sections(raw, depth+1, label))

        elif sec_type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
            if len(chunk) > 56:
                inner_fvs = _find_all_fvs(chunk)
                for fv_base, fv_len, fv_hdr_len in inner_fvs:
                    fv_data   = chunk[fv_base : fv_base + fv_len]
                    ffs_files = _iter_ffs_files(fv_data, fv_hdr_len)
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  nested FV {len(fv_data):#x} bytes,"
                              f" {len(ffs_files)} FFS file(s)")
                    for fg, fp in ffs_files:
                        if len(fp) >= _MIN_PE_SIZE:
                            blobs.append(fp)
                        blobs.extend(_collect_pe32_blobs_from_sections(fp, depth+2, label))

        elif sec_type == EFI_SECTION_DISPOSABLE:
            blobs.extend(_collect_pe32_blobs_from_sections(chunk, depth+1, label))

        elif sec_type == EFI_SECTION_AMD_LZMA:
            if len(chunk) > 32:
                import lzma as _lzma
                try:
                    decompressed = _lzma.decompress(chunk[32:], format=_lzma.FORMAT_ALONE)
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  AMD_LZMA(0x72) {len(chunk):#x}"
                              f" → {len(decompressed):#x}")
                    blobs.extend(_process_decompressed(decompressed, depth+1, label))
                except Exception:
                    if DEBUG:
                        print(f"[dbg]{'  '*depth}  AMD_LZMA(0x72) {len(chunk):#x}"
                              f" decompression failed")

        elif sec_type in (EFI_SECTION_AMD_CBS_E6, EFI_SECTION_AMD_CBS_F5):
            # AMD AGESA CBS sections (0xE6 / 0xF5): raw containers holding one or
            # more sequential PE32 images packed after a platform-specific header.
            # There is no standard sub-section framing – scan for MZ/PE signatures
            # directly, the same way _process_decompressed handles plain blobs.
            if len(chunk) >= _MIN_PE_SIZE:
                if DEBUG:
                    print(f"[dbg]{'  '*depth}  AMD_CBS({sec_type:#04x})"
                          f" {len(chunk):#x} bytes – scanning for PE blobs")
                blobs.extend(_scan_raw_for_pe_blobs(chunk, depth, label))

    return blobs


def _find_all_fvs(data: bytes) -> List[Tuple[int, int, int]]:
    results = []
    seen_bases: Set[int] = set()
    search = 0
    n = len(data)
    while search < n - 4:
        sig_pos = data.find(_FV_SIGNATURE, search)
        if sig_pos < 0:
            break
        search = sig_pos + 1
        ok, fv_len, hdr_len = _fv_header_ok(data, sig_pos)
        if ok:
            fv_base = sig_pos - 40
            if fv_base not in seen_bases:
                seen_bases.add(fv_base)
                results.append((fv_base, fv_len, hdr_len))
    return results


def _iter_ffs_files_with_offsets(fv_data: bytes, hdr_len: int) -> List[int]:
    """Return the FV-relative byte offset of each payload returned by _iter_ffs_files.

    The returned list is parallel to _iter_ffs_files(fv_data, hdr_len): entry i
    is the byte offset *within fv_data* where the i-th FFS file's payload starts.
    This lets callers feed fv_data[offset:] directly to LZMA even when the
    compressed stream spans beyond the FFS file boundary.
    """
    offsets: List[int] = []
    pos = (hdr_len + 7) & ~7
    n   = len(fv_data)
    itr = 0
    while pos < n - 24 and itr < 65536:
        itr += 1
        if fv_data[pos] == 0xFF:
            skip = pos + 8
            while skip < n and fv_data[skip] == 0xFF:
                skip += 8
            if skip >= n:
                break
            pos = skip
            continue
        raw_size_b = fv_data[pos+20:pos+23]
        raw_size   = raw_size_b[0] | (raw_size_b[1] << 8) | (raw_size_b[2] << 16)
        ffs_attrs  = fv_data[pos+19]
        large_file = (raw_size == _FFS_SIZE_LARGE) or bool(ffs_attrs & 0x01)
        if large_file:
            if pos + 32 > n:
                break
            raw_size  = u64(fv_data, pos + 24) if pos + 32 <= n else 0
            hdr_bytes = 32
        else:
            hdr_bytes = 24
        ffs_type = fv_data[pos+18]
        if raw_size < hdr_bytes or raw_size > (n - pos):
            pos += 8
            continue
        if ffs_type not in (0x00, 0xF0, 0xFF):
            offsets.append(pos + hdr_bytes)   # payload starts here in fv_data
        pos += (raw_size + 7) & ~7
    return offsets


def _extract_from_decompressed(decompressed: bytes,
                                parent_label: str) -> List[Tuple[str, bytes]]:
    """Walk a decompressed blob for FVs and PE32 modules; return (label, pe_blob) pairs."""
    results: List[Tuple[str, bytes]] = []
    seen: Set[int] = set()

    def _add(lbl: str, blob: bytes) -> None:
        h = hash(blob)
        if h not in seen and len(blob) >= _MIN_PE_SIZE:
            seen.add(h)
            results.append((lbl, blob))

    inner_fvs = _find_all_fvs(decompressed)
    if inner_fvs:
        for fv_b, fv_l, fv_h in inner_fvs:
            fv_slice = decompressed[fv_b: fv_b + fv_l]
            ffs_list = _iter_ffs_files(fv_slice, fv_h)
            lbl = f"{parent_label}/decomp_FV@{fv_b:#x}"
            if DEBUG:
                print(f"[dbg]    decomp inner FV@{fv_b:#x} len={fv_l:#x}"
                      f" {len(ffs_list)} FFS file(s)")
            for fg, fp in ffs_list:
                g    = guid_str(fg, 0)
                flbl = f"{lbl}/{g}"
                for blob in _collect_pe32_blobs_from_sections(fp, label=flbl):
                    _add(flbl, blob)
    else:
        # No FV structure — try plain PE scan
        for blob in _scan_raw_for_pe_blobs(decompressed, label=parent_label):
            _add(parent_label, blob)
    return results


def extract_efi_blobs_from_firmware(fw_data: bytes) -> List[Tuple[str, bytes]]:
    results: List[Tuple[str, bytes]] = []
    seen_hashes: Set[int] = set()

    fvs = _find_all_fvs(fw_data)
    if DEBUG:
        print(f"[dbg] Found {len(fvs)} firmware volume(s) in image")

    for fv_base, fv_len, hdr_len in fvs:
        fv_data   = fw_data[fv_base : fv_base + fv_len]
        ffs_files = _iter_ffs_files(fv_data, hdr_len)
        if DEBUG:
            print(f"[dbg]   FV@{fv_base:#010x}  len={fv_len:#010x}  "
                  f"hdr={hdr_len:#x}  ffs_files={len(ffs_files)}")

        # Track payload offsets so AMD Pi sections can feed the FV-level stream.
        ffs_payload_offsets = _iter_ffs_files_with_offsets(fv_data, hdr_len)

        for (guid_bytes, payload), payload_fv_offset in zip(ffs_files, ffs_payload_offsets):
            g     = guid_str(guid_bytes, 0)
            lbl   = f"FV@{fv_base:#010x}/{g}"

            # ── AMD Pi BIOS-partition sections (0x51 / 0x67 / 0x77) ──────────
            # These contain an LZMA-compressed DXE firmware volume whose
            # compressed stream may span beyond the current FFS file boundary.
            # Feed the entire FV data from the LZMA start offset so the
            # decompressor can read across FFS boundaries naturally.
            if len(payload) > _AMD_PI_LZMA_HDR_OFFSET:
                sec_type = payload[3]
                if sec_type in _AMD_PI_SECTION_TYPES:
                    # Verify the AMD BIOS-Store GUID is present at [20:36].
                    if payload[20:36] == _AMD_BIOS_STORE_GUID_RAW:
                        lzma_abs = payload_fv_offset + _AMD_PI_LZMA_HDR_OFFSET
                        import lzma as _lzma_mod
                        try:
                            decompressed = _lzma_mod.decompress(
                                fv_data[lzma_abs:], format=_lzma_mod.FORMAT_ALONE)
                            if DEBUG:
                                print(f"[dbg]  AMD_PI({sec_type:#04x})"
                                      f" LZMA FV+{lzma_abs:#x}"
                                      f" → {len(decompressed):#x} bytes")
                            for lbl2, blob in _extract_from_decompressed(
                                    decompressed, lbl):
                                h = hash(blob)
                                if h not in seen_hashes:
                                    seen_hashes.add(h)
                                    results.append((lbl2, blob))
                        except Exception as exc:
                            if DEBUG:
                                print(f"[dbg]  AMD_PI({sec_type:#04x})"
                                      f" LZMA FV+{lzma_abs:#x} failed: {exc}")
                        continue  # don't also walk as plain sections

            blobs = _collect_pe32_blobs_from_sections(payload, label=lbl)
            for blob in blobs:
                h = hash(blob)
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                results.append((lbl, blob))

    return results


def _hii_candidates_from_blobs(blobs: List[Tuple[str, bytes]]) -> List[Tuple[str, bytes, str, str, int]]:
    candidates: List[Tuple[str, bytes, str, str, int]] = []
    seen: Set[int] = set()

    for label, blob in blobs:
        h = hash(blob)
        if h in seen:
            continue
        seen.add(h)

        string_pkgs, form_pkgs = find_packages(blob)
        if not form_pkgs:
            continue

        best_strings: Dict[int, str] = {}
        best_lang = ""
        if string_pkgs:
            en_pkgs = [p for p in string_pkgs if p[3].startswith("en")]
            chosen  = max(en_pkgs if en_pkgs else string_pkgs, key=lambda x: len(x[2]))
            best_strings = chosen[2]
            best_lang    = chosen[3]

        all_lines: List[str] = []
        for off, plen in form_pkgs:
            all_lines.extend(parse_form_package(blob, off, plen, best_strings))

        ifr_text = "\n".join(all_lines)
        if not _RE_SETTING.search(ifr_text):
            continue

        n_settings = len(_RE_SETTING.findall(ifr_text))
        candidates.append((label, blob, ifr_text, best_lang, len(all_lines)))
        if DEBUG:
            print(f"[dbg]   ✓ HII: {label}  "
                  f"forms={len(form_pkgs)}  strings={len(best_strings)}  "
                  f"settings≈{n_settings}  lang={best_lang}")

    def _real_settings(ifr_text: str) -> int:
        return sum(1 for m in _RE_SETTING.finditer(ifr_text)
                   if not m.group(2).startswith('<str#'))

    candidates.sort(key=lambda x: (_real_settings(x[2]), x[4]), reverse=True)
    return candidates


def _find_hii_via_uefi_firmware(fw_data: bytes) -> List[Tuple[str, bytes, str, str, int]]:
    try:
        import uefi_firmware
    except ImportError:
        return []

    import io as _io, os as _os
    try:
        _devnull = open(_os.devnull, 'w')
        _old_stderr = sys.stderr
        sys.stderr = _devnull
        try:
            parser   = uefi_firmware.AutoParser(fw_data)
            firmware = parser.parse()
        finally:
            sys.stderr = _old_stderr
            try: _devnull.close()
            except: pass
        if firmware is None:
            if DEBUG:
                print("[dbg] uefi_firmware: parse() returned None")
            return []
    except Exception as e:
        if DEBUG:
            print(f"[dbg] uefi_firmware parse error: {e}")
        return []

    blobs:    List[Tuple[str, bytes]] = []
    seen:     Set[int]                = set()
    gd_blobs: List[Tuple[str, bytes]] = []

    def _add(path: str, data, max_size: int = 0x800000) -> bool:
        if not data or not isinstance(data, (bytes, bytearray)):
            return False
        d = bytes(data)
        h = hash(d)
        if h in seen or not (_MIN_PE_SIZE <= len(d) <= max_size):
            return False
        seen.add(h)
        blobs.append((path, d))
        return True

    def _walk(obj, path: str, depth: int = 0) -> None:
        if depth > 20:
            return
        ct       = type(obj).__name__
        children = (getattr(obj, 'objects', None) or
                    getattr(obj, 'sections', None) or [])

        if ct == 'FirmwareFile':
            _add(path, getattr(obj, 'data', None))
            for i, child in enumerate(children):
                _walk(child, f"{path}/{type(child).__name__}[{i}]", depth + 1)
            return

        if ct == 'GuidDefinedSection':
            d = getattr(obj, 'data', None)
            if d and isinstance(d, (bytes, bytearray)) and len(d) > 0x1000:
                gd_blobs.append((path, bytes(d)))

        elif 'Section' not in ct and 'Volume' not in ct:
            _add(path, getattr(obj, 'data', None))

        for i, child in enumerate(children):
            _walk(child, f"{path}/{type(child).__name__}[{i}]", depth + 1)

    _walk(firmware, "fw")

    if DEBUG:
        print(f"[dbg] uefi_firmware Layer 1: {len(blobs)} FirmwareFile blob(s)")
        print(f"[dbg] uefi_firmware Layer 2: {len(gd_blobs)} large GuidDefinedSection blob(s)")

    for gd_path, gd_data in gd_blobs:
        inner_blobs = _collect_pe32_blobs_from_sections(gd_data, depth=0,
                                                         label=f"gd:{gd_path[-30:]}")
        for blob in inner_blobs:
            _add(f"gd:{gd_path[-30:]}/sec", blob)

        inner_fvs = _find_all_fvs(gd_data)
        if DEBUG:
            print(f"[dbg]   GuidDef {len(gd_data):#x}: {len(inner_fvs)} inner FV(s)")
        for fv_base, fv_len, hdr_len in inner_fvs:
            fv_slice = gd_data[fv_base : fv_base + fv_len]
            ffs_files = _iter_ffs_files(fv_slice, hdr_len)
            for guid_bytes, payload in ffs_files:
                lbl = f"gd:{gd_path[-30:]}/{guid_str(guid_bytes,0)}"
                _add(lbl, payload)
                for blob in _collect_pe32_blobs_from_sections(payload, label=lbl):
                    _add(f"{lbl}/sec", blob)

    if DEBUG:
        print(f"[dbg] uefi_firmware total blobs after L2: {len(blobs)}")

    return _hii_candidates_from_blobs(blobs)


def find_hii_efi_in_firmware(fw_data: bytes) -> List[Tuple[str, bytes, str, str]]:
    candidates: List[Tuple[str, bytes, str, str, int]] = []
    seen_labels: Set[int] = set()

    def _merge(new_cands):
        for c in new_cands:
            h = hash(c[1])
            if h not in seen_labels:
                seen_labels.add(h)
                candidates.append(c)

    uf_cands = _find_hii_via_uefi_firmware(fw_data)
    if uf_cands:
        _merge(uf_cands)
        if DEBUG:
            print(f"[dbg] uefi_firmware path: {len(uf_cands)} HII candidate(s)")

    manual_blobs = extract_efi_blobs_from_firmware(fw_data)
    if DEBUG:
        print(f"[dbg] Manual FV path: {len(manual_blobs)} PE32 blob(s)")
    manual_cands = _hii_candidates_from_blobs(manual_blobs)
    if manual_cands:
        _merge(manual_cands)
        if DEBUG:
            print(f"[dbg] Manual FV path: {len(manual_cands)} new HII candidate(s)")

    def _real_count(c):
        return sum(1 for m in _RE_SETTING.finditer(c[2])
                   if not m.group(2).startswith('<str#'))

    candidates.sort(key=lambda x: (_real_count(x), x[4]), reverse=True)
    return [(lbl, blob, ifr, lang) for lbl, blob, ifr, lang, _ in candidates]


# ─────────────────────────────────────────────────────────────────────────────
# Firmware diagnostic scan  (--debug-fw)
# ─────────────────────────────────────────────────────────────────────────────

def debug_firmware_scan(fw_data: bytes) -> None:
    print(_hdr("FIRMWARE STRUCTURE SCAN"))

    fvs = _find_all_fvs(fw_data)
    print(f"\n  Found {len(fvs)} Firmware Volume(s):\n")

    import lzma as _lzma

    for fv_idx, (fv_base, fv_len, hdr_len) in enumerate(fvs):
        fv_data   = fw_data[fv_base : fv_base + fv_len]
        ffs_files = _iter_ffs_files(fv_data, hdr_len)
        print(f"  [{fv_idx:2d}] FV  base=0x{fv_base:08X}  "
              f"len=0x{fv_len:08X}  hdrlen=0x{hdr_len:X}  "
              f"ffs_files={len(ffs_files)}")

        sec_counts: Dict[int, int] = {}
        blob_count = 0
        hii_count  = 0
        decomp_ok  = 0
        decomp_fail= 0

        for guid_bytes, payload in ffs_files:
            for sec_type, data_off, data_size in _iter_ffs_sections(payload):
                sec_counts[sec_type] = sec_counts.get(sec_type, 0) + 1
                chunk = payload[data_off : data_off + data_size]

                if sec_type in (EFI_SECTION_PE32, EFI_SECTION_TE):
                    blob_count += 1
                    spkgs, fpkgs = find_packages(chunk)
                    if fpkgs:
                        hii_count += 1

                elif sec_type == EFI_SECTION_COMPRESSION and len(chunk) >= 5:
                    raw = chunk[5:]
                    d   = _try_decompress(raw, chunk[4])
                    if d:
                        decomp_ok += 1
                        inner = _collect_pe32_blobs_from_sections(d)
                        blob_count += len(inner)
                        for b2 in inner:
                            spkgs, fpkgs = find_packages(b2)
                            if fpkgs:
                                hii_count += 1
                    else:
                        decomp_fail += 1

                elif sec_type == EFI_SECTION_GUID_DEFINED and len(chunk) >= 20:
                    doff2 = u16(chunk, 16)
                    # DataOffset is relative to the section start (includes the 4-byte
                    # size+type prefix), so subtract 4 since `chunk` starts after it.
                    adj = doff2 - 4
                    raw   = chunk[adj:] if (0 <= adj < len(chunk)) else b""
                    if raw:
                        d = _try_decompress(raw)
                        if d:
                            decomp_ok += 1
                            inner = _collect_pe32_blobs_from_sections(d)
                            blob_count += len(inner)
                            for b2 in inner:
                                spkgs, fpkgs = find_packages(b2)
                                if fpkgs:
                                    hii_count += 1
                        else:
                            decomp_fail += 1

                elif sec_type in (EFI_SECTION_AMD_CBS_E6, EFI_SECTION_AMD_CBS_F5):
                    inner = _scan_raw_for_pe_blobs(chunk)
                    blob_count += len(inner)
                    for b2 in inner:
                        spkgs, fpkgs = find_packages(b2)
                        if fpkgs:
                            hii_count += 1

        type_names = {
            0x01: "COMPRESS", 0x02: "GUID_DEF", 0x10: "PE32",
            0x12: "TE", 0x15: "UI", 0x17: "FV_IMAGE",
            0x19: "RAW", 0x1B: "DISPOSABLE", 0x72: "AMD_LZMA",
            0xE6: "AMD_CBS_E6", 0xF5: "AMD_CBS_F5",
        }
        sec_summary = "  ".join(
            f"{type_names.get(t, f'0x{t:02X}')}×{c}"
            for t, c in sorted(sec_counts.items())
        )
        print(f"       sections: {sec_summary or '(none)'}")
        print(f"       pe32_blobs={blob_count}  hii_bearing={hii_count}  "
              f"decomp_ok={decomp_ok}  decomp_fail={decomp_fail}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# HII String package parsing
# ─────────────────────────────────────────────────────────────────────────────

SIBT_END             = 0x00
SIBT_STRING_SCSU     = 0x10
SIBT_STRING_SCSU_FONT= 0x11
SIBT_STRINGS_SCSU    = 0x12
SIBT_STRINGS_SCSU_FONT=0x13
SIBT_STRING_UCS2     = 0x14
SIBT_STRING_UCS2_FONT= 0x15
SIBT_STRINGS_UCS2    = 0x16
SIBT_STRINGS_UCS2_FONT=0x17
SIBT_DUPLICATE       = 0x20
SIBT_SKIP2           = 0x21
SIBT_SKIP1           = 0x22
SIBT_EXT1            = 0x30
SIBT_EXT2            = 0x31
SIBT_EXT4            = 0x32


def _read_null_ucs2(data: bytes, pos: int) -> Tuple[str, int]:
    chars = []
    while pos + 1 < len(data):
        cp = u16(data, pos); pos += 2
        if cp == 0: break
        chars.append(chr(cp))
    return "".join(chars), pos


def _read_null_scsu(data: bytes, pos: int) -> Tuple[str, int]:
    chars = []
    while pos < len(data):
        b = data[pos]; pos += 1
        if b == 0: break
        chars.append(chr(b) if b < 0x80 else "?")
    return "".join(chars), pos


def _find_sibt_start(payload: bytes) -> int:
    null_pos = payload.find(0, 42)
    if null_pos < 0:
        return -1
    return null_pos + 1


def _is_valid_string_pkg_hdr(payload: bytes) -> bool:
    if len(payload) < 46:
        return False
    hdr_size = u32(payload, 0)
    if hdr_size < 4 or hdr_size > 0x10000:
        return False
    for k in range(42, min(42 + 64, len(payload))):
        b = payload[k]
        if b == 0:
            return k > 42
        if not (0x20 <= b < 0x7F):
            return False
    return False


def _read_pkg_language(payload: bytes) -> str:
    end = payload.find(0, 42)
    if end < 0:
        return ""
    return payload[42:end].decode("ascii", errors="replace").lower()


def parse_string_package(data: bytes, pkg_offset: int, pkg_len: int) -> Optional[Tuple[Dict[int, str], str]]:
    if pkg_offset + pkg_len > len(data):
        return None
    payload = data[pkg_offset + 4: pkg_offset + pkg_len]
    if not _is_valid_string_pkg_hdr(payload):
        return None
    language  = _read_pkg_language(payload)
    sibt_start = _find_sibt_start(payload)
    if sibt_start < 0:
        return None
    pos = sibt_start
    sid = 1
    string_map: Dict[int, str] = {0: ""}
    itr = 0
    while pos < len(payload) and itr < 0x20000:
        itr += 1
        block_type = payload[pos]; pos += 1
        if block_type == SIBT_END:
            break
        elif block_type == SIBT_STRING_UCS2:
            text, pos = _read_null_ucs2(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_UCS2_FONT:
            pos += 1; text, pos = _read_null_ucs2(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_UCS2:
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_ucs2(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_UCS2_FONT:
            pos += 1
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_ucs2(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_SCSU:
            text, pos = _read_null_scsu(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_SCSU_FONT:
            pos += 1; text, pos = _read_null_scsu(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_SCSU:
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_scsu(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_SCSU_FONT:
            pos += 1
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_scsu(payload, pos); string_map[sid] = text; sid += 1
        elif block_type == SIBT_DUPLICATE:
            sid += 1
        elif block_type == SIBT_SKIP1:
            if pos >= len(payload): break
            sid += payload[pos]; pos += 1
        elif block_type == SIBT_SKIP2:
            if pos + 2 > len(payload): break
            sid += u16(payload, pos); pos += 2
        elif block_type == SIBT_EXT1:
            if pos + 2 > len(payload): break
            pos += 1; blen = payload[pos]; pos += 1; pos += max(0, blen - 3)
        elif block_type == SIBT_EXT2:
            if pos + 3 > len(payload): break
            pos += 1; blen = u16(payload, pos); pos += 2; pos += max(0, blen - 4)
        elif block_type == SIBT_EXT4:
            if pos + 5 > len(payload): break
            pos += 1; blen = u32(payload, pos); pos += 4; pos += max(0, blen - 6)
        else:
            break
    return (string_map, language) if len(string_map) > 1 else None


# ─────────────────────────────────────────────────────────────────────────────
# HII Form package / IFR opcode parsing
# ─────────────────────────────────────────────────────────────────────────────

IFR_OP_FORM        = 0x01
IFR_OP_SUBTITLE    = 0x02
IFR_OP_TEXT        = 0x03
IFR_OP_ONE_OF      = 0x05
IFR_OP_CHECKBOX    = 0x06
IFR_OP_NUMERIC     = 0x07
IFR_OP_PASSWORD    = 0x08
IFR_OP_ONE_OF_OPT  = 0x09
IFR_OP_SUPPRESS_IF = 0x0A
IFR_OP_LOCKED      = 0x0B
IFR_OP_ACTION      = 0x0C
IFR_OP_RESET_BTN   = 0x0D
IFR_OP_FORM_SET    = 0x0E
IFR_OP_REF         = 0x0F
IFR_OP_NO_SUBMIT   = 0x10
IFR_OP_INCONS_IF   = 0x11
IFR_OP_GRAYOUT_IF  = 0x19
IFR_OP_DATE        = 0x1A
IFR_OP_TIME        = 0x1B
IFR_OP_STRING_OP   = 0x1C
IFR_OP_DISABLE_IF  = 0x1E
IFR_OP_ORDERED     = 0x23
IFR_OP_VARSTORE    = 0x24
IFR_OP_VARSTORE_NV = 0x25
IFR_OP_VARSTORE_EFI= 0x26
IFR_OP_VARSTORE_DEV= 0x27
IFR_OP_END         = 0x29
IFR_OP_DEFAULT     = 0x5B
IFR_OP_DEFAULTSTORE= 0x5C
IFR_OP_GUID        = 0x5F
IFR_OP_WARNING_IF  = 0x63

_SIZE_BITS = {0x00: 8, 0x01: 8, 0x02: 16, 0x03: 32, 0x04: 64}


def _parse_min_max_step(opdata: bytes, flags_off: int) -> Tuple[int, int, int, int]:
    if flags_off >= len(opdata):
        return 8, 0, 1, 0
    flags     = opdata[flags_off]
    size_bits = _SIZE_BITS.get(flags & 0x0F, 8)
    base      = flags_off + 1
    if size_bits == 8:
        if base + 3 > len(opdata): return size_bits, 0, 0xFF, 0
        return size_bits, opdata[base], opdata[base+1], opdata[base+2]
    elif size_bits == 16:
        if base + 6 > len(opdata): return size_bits, 0, 0xFFFF, 0
        return size_bits, u16(opdata,base), u16(opdata,base+2), u16(opdata,base+4)
    elif size_bits == 32:
        if base + 12 > len(opdata): return size_bits, 0, 0xFFFFFFFF, 0
        return size_bits, u32(opdata,base), u32(opdata,base+4), u32(opdata,base+8)
    elif size_bits == 64:
        if base + 24 > len(opdata): return size_bits, 0, 0xFFFFFFFFFFFFFFFF, 0
        return size_bits, u64(opdata,base), u64(opdata,base+8), u64(opdata,base+16)
    return size_bits, 0, 0, 0


def _is_valid_form_package(data: bytes, offset: int, pkg_len: int) -> bool:
    payload_start = offset + 4
    if payload_start + 2 > offset + pkg_len:
        return False
    op      = data[payload_start]
    hdr_b   = data[payload_start + 1]
    op_len  = hdr_b & 0x7F
    scope   = bool(hdr_b & 0x80)
    return op == IFR_OP_FORM_SET and op_len >= 24 and scope


def parse_form_package(data: bytes, pkg_offset: int, pkg_len: int,
                       strings: Dict[int, str]) -> List[str]:
    lines: List[str] = []
    scope_depth = 0
    pos = pkg_offset + 4
    end = pkg_offset + pkg_len

    def S(sid: int) -> str:
        return strings.get(sid, f"<str#{sid}>")

    while pos < end - 1:
        op      = data[pos]
        hdr_b   = data[pos + 1]
        op_len  = hdr_b & 0x7F
        scope   = bool(hdr_b & 0x80)

        if op_len < 2 or pos + op_len > end:
            pos += 1
            continue

        opdata = data[pos + 2: pos + op_len]

        if op == IFR_OP_END and scope_depth > 0:
            scope_depth -= 1

        indent = "\t" * scope_depth
        line: Optional[str] = None

        if op == IFR_OP_FORM_SET and len(opdata) >= 20:
            g    = guid_str(opdata, 0)
            tstr = S(u16(opdata, 16))
            hstr = S(u16(opdata, 18))
            line = f'{indent}FormSet Guid: {g}, Title: "{tstr}", Help: "{hstr}"'
        elif op == IFR_OP_FORM and len(opdata) >= 4:
            fid  = u16(opdata, 0)
            tstr = S(u16(opdata, 2))
            line = f'{indent}Form FormId: 0x{fid:X}, Title: "{tstr}"'
        elif op == IFR_OP_SUBTITLE and len(opdata) >= 5:
            pstr = S(u16(opdata, 0)); hstr = S(u16(opdata, 2)); flg = opdata[4]
            line = f'{indent}Subtitle Prompt: "{pstr}", Help: "{hstr}", Flags: 0x{flg:X}'
        elif op == IFR_OP_TEXT and len(opdata) >= 6:
            pstr = S(u16(opdata, 0)); hstr = S(u16(opdata, 2)); tstr = S(u16(opdata, 4))
            line = f'{indent}Text Prompt: "{pstr}", Help: "{hstr}", Text: "{tstr}"'
        elif op == IFR_OP_VARSTORE and len(opdata) >= 20:
            g    = guid_str(opdata, 0)
            vsid = u16(opdata, 16); size = u16(opdata, 18)
            name = opdata[20:].rstrip(b'\x00').decode('ascii', errors='replace')
            line = f'{indent}VarStore Guid: {g}, VarStoreId: 0x{vsid:X}, Size: 0x{size:X}, Name: "{name}"'
        elif op == IFR_OP_VARSTORE_EFI and len(opdata) >= 26:
            vsid  = u16(opdata, 0); g = guid_str(opdata, 2)
            attrs = u32(opdata, 18); size = u16(opdata, 22)
            name  = opdata[24:].rstrip(b'\x00').decode('ascii', errors='replace')
            line  = (f'{indent}VarStoreEfi Guid: {g}, VarStoreId: 0x{vsid:X}, '
                     f'Attributes: 0x{attrs:X}, Size: 0x{size:X}, Name: "{name}"')
        elif op == IFR_OP_ONE_OF and len(opdata) >= 13:
            pstr   = S(u16(opdata, 0)); hstr = S(u16(opdata, 2))
            qid    = u16(opdata, 4); vsid = u16(opdata, 6); vsoff = u16(opdata, 8)
            qflags = u8(opdata, 10)
            sz, mn, mx, st = _parse_min_max_step(opdata, 11)
            line = (f'{indent}OneOf Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{opdata[11]:X}, Size: {sz}, '
                    f'Min: 0x{mn:X}, Max: 0x{mx:X}, Step: 0x{st:X}')
        elif op == IFR_OP_CHECKBOX and len(opdata) >= 12:
            pstr   = S(u16(opdata, 0)); hstr = S(u16(opdata, 2))
            qid    = u16(opdata, 4); vsid = u16(opdata, 6); vsoff = u16(opdata, 8)
            qflags = u8(opdata, 10); cflags = u8(opdata, 11)
            dflt   = "Enabled" if (cflags & 0x01) else "Disabled"
            mfgd   = "Enabled" if (cflags & 0x02) else "Disabled"
            line = (f'{indent}CheckBox Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{cflags:X}, Default: {dflt}, MfgDefault: {mfgd}')
        elif op == IFR_OP_NUMERIC and len(opdata) >= 13:
            pstr   = S(u16(opdata, 0)); hstr = S(u16(opdata, 2))
            qid    = u16(opdata, 4); vsid = u16(opdata, 6); vsoff = u16(opdata, 8)
            qflags = u8(opdata, 10)
            sz, mn, mx, st = _parse_min_max_step(opdata, 11)
            line = (f'{indent}Numeric Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{opdata[11]:X}, Size: {sz}, '
                    f'Min: 0x{mn:X}, Max: 0x{mx:X}, Step: 0x{st:X}')
        elif op == IFR_OP_ONE_OF_OPT and len(opdata) >= 5:
            ostr   = S(u16(opdata, 0)); oflags = opdata[2]; vtype = opdata[3]
            _vsize_map = {0: 1, 1: 1, 2: 2, 3: 4, 4: 8}
            _vfmt_map  = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
            vsize  = _vsize_map.get(vtype, 1)
            raw_val = struct.unpack_from(_vfmt_map[vsize], opdata, 4)[0] if len(opdata) >= 4 + vsize else 0
            dflt   = ", Default"    if (oflags & 0x10) else ""
            mfgd   = ", MfgDefault" if (oflags & 0x20) else ""
            line = f'{indent}OneOfOption Option: "{ostr}", Value: 0x{raw_val:X}{dflt}{mfgd}'
        elif op == IFR_OP_DEFAULTSTORE and len(opdata) >= 4:
            nstr  = S(u16(opdata, 0)); defid = u16(opdata, 2)
            line  = f'{indent}DefaultStore Name: "{nstr}", DefaultId: 0x{defid:X}'
        elif op == IFR_OP_DEFAULT and len(opdata) >= 3:
            defid = u16(opdata, 0); dtype = opdata[2]
            line  = f'{indent}Default DefaultId: 0x{defid:X}, Type: 0x{dtype:X}'
        elif op == IFR_OP_ACTION and len(opdata) >= 11:
            pstr   = S(u16(opdata, 0)); hstr = S(u16(opdata, 2))
            qid    = u16(opdata, 4); vsid = u16(opdata, 6); vsoff = u16(opdata, 8)
            qflags = u8(opdata, 10)
            line = (f'{indent}Action Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}')
        elif op == IFR_OP_REF and len(opdata) >= 11:
            pstr   = S(u16(opdata, 0)); hstr = S(u16(opdata, 2))
            qid    = u16(opdata, 4); vsid = u16(opdata, 6); vsoff = u16(opdata, 8)
            qflags = u8(opdata, 10); fid = u16(opdata, 11) if len(opdata) >= 13 else 0
            line   = (f'{indent}Ref Prompt: "{pstr}", Help: "{hstr}", '
                      f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                      f'FormId: 0x{fid:X}')
        elif op in (IFR_OP_DATE, IFR_OP_TIME, IFR_OP_STRING_OP) and len(opdata) >= 11:
            name_map = {IFR_OP_DATE: "Date", IFR_OP_TIME: "Time", IFR_OP_STRING_OP: "String"}
            pstr   = S(u16(opdata, 0)); hstr = S(u16(opdata, 2))
            qid    = u16(opdata, 4); vsid = u16(opdata, 6); vsoff = u16(opdata, 8)
            qflags = u8(opdata, 10)
            line = (f'{indent}{name_map[op]} Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}')
        elif op == IFR_OP_SUPPRESS_IF: line = f'{indent}SuppressIf'
        elif op == IFR_OP_GRAYOUT_IF:  line = f'{indent}GrayOutIf'
        elif op == IFR_OP_DISABLE_IF:  line = f'{indent}DisableIf'
        elif op == IFR_OP_NO_SUBMIT:   line = f'{indent}NoSubmitIf'
        elif op == IFR_OP_INCONS_IF:   line = f'{indent}InconsistentIf'
        elif op == IFR_OP_END:         line = f'{indent}End'

        if line is not None:
            lines.append(line)
        if scope and op != IFR_OP_END:
            scope_depth += 1
        pos += op_len

    return lines


# ─────────────────────────────────────────────────────────────────────────────
# Top-level HII package scanner
# ─────────────────────────────────────────────────────────────────────────────

PKG_TYPE_FORMS  = 0x02
PKG_TYPE_STRING = 0x04


def find_packages(data: bytes) -> Tuple[List[Tuple[int,int,Dict[int,str],str]], List[Tuple[int,int]]]:
    string_pkgs: List[Tuple[int,int,Dict[int,str],str]] = []
    form_pkgs:   List[Tuple[int,int]]                   = []
    n = len(data)
    i = 0
    while i < n - 4:
        raw   = u32(data, i)
        ptype = (raw >> 24) & 0xFF
        plen  =  raw & 0x00FFFFFF
        if plen >= 4 and i + plen <= n:
            if ptype == PKG_TYPE_STRING and plen >= 50:
                result = parse_string_package(data, i, plen)
                if result is not None:
                    smap, lang = result
                    string_pkgs.append((i, plen, smap, lang))
                    i += plen
                    continue
            elif ptype == PKG_TYPE_FORMS and plen >= 6:
                if _is_valid_form_package(data, i, plen):
                    form_pkgs.append((i, plen))
                    i += plen
                    continue
        i += 1
    return string_pkgs, form_pkgs


def extract_ifr(efi_path: str) -> str:
    data = Path(efi_path).read_bytes()
    gprint(f"[*] Scanning {len(data):,} bytes for HII packages...")
    string_pkgs, form_pkgs = find_packages(data)
    gprint(f"[+] Found {len(string_pkgs)} string package(s), {len(form_pkgs)} form package(s)")
    if not form_pkgs:
        print(f"\n{C_ERR}[!] No form packages found.{C_RST}")
        sys.exit(1)
    if not string_pkgs:
        gwarn(f"[!] No string packages found — settings will show as <str#N>")
    best_strings: Dict[int, str] = {}
    if string_pkgs:
        en_pkgs = [p for p in string_pkgs if p[3].startswith("en")]
        candidates = en_pkgs if en_pkgs else string_pkgs
        best_strings = max(candidates, key=lambda x: len(x[2]))[2]
        gprint(f"[+] Using string package with {len(best_strings)} strings")
    all_lines: List[str] = []
    for idx, (off, plen) in enumerate(form_pkgs):
        lines = parse_form_package(data, off, plen, best_strings)
        all_lines.extend(lines)
        if DEBUG:
            print(f"    Form package {idx}: offset={off:#x}, length={plen:#x}, lines={len(lines)}")
    return "\n".join(all_lines)


# ─────────────────────────────────────────────────────────────────────────────
# VarStore + setting parsing
# ─────────────────────────────────────────────────────────────────────────────

_RE_VARSTORE = re.compile(
    r'VarStore(?:Efi)?\s+Guid:\s*([0-9A-Fa-f\-]{36})'
    r',\s*VarStoreId:\s*0x([0-9A-Fa-f]+)'
    r'(?:,\s*Attributes:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Size:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Name:\s*"([^"]*)")?',
    re.IGNORECASE,
)

_RE_SETTING = re.compile(
    r'(OneOf|CheckBox|Numeric|Action)\s+Prompt:\s*"([^"]*)"'
    r'(?:,\s*Help:\s*"([^"]*)")?'
    r',\s*QuestionFlags:\s*0x([0-9A-Fa-f]+)'
    r',\s*QuestionId:\s*0x([0-9A-Fa-f]+)'
    r',\s*VarStoreId:\s*0x([0-9A-Fa-f]+)'
    r',\s*VarOffset:\s*0x([0-9A-Fa-f]+)'
    r',\s*Flags:\s*0x([0-9A-Fa-f]+)'
    r'(?:,\s*Size:\s*(\d+))?'
    r'(?:,\s*Min:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Max:\s*0x([0-9A-Fa-f]+))?'
    r'(?:,\s*Step:\s*0x([0-9A-Fa-f]+))?',
    re.IGNORECASE,
)


def parse_varstores(ifr_text: str) -> Dict[int, VarStore]:
    stores: Dict[int, VarStore] = {}
    seen_names: Dict[str, int] = {}
    for m in _RE_VARSTORE.finditer(ifr_text):
        guid  = m.group(1).upper()
        vsid  = int(m.group(2), 16)
        attrs = int(m.group(3), 16) if m.group(3) else 0x7
        size  = int(m.group(4), 16) if m.group(4) else 0
        name  = m.group(5) or ""
        if name in seen_names:
            continue
        vs = VarStore(guid=guid, var_store_id=vsid, attributes=attrs, size=size, name=name)
        if vsid not in stores:
            stores[vsid] = vs
            seen_names[name] = vsid
        else:
            synthetic = 0x10000 + len(seen_names)
            while synthetic in stores:
                synthetic += 1
            stores[synthetic] = vs
            seen_names[name] = synthetic
    return stores


def _build_vsid_context(ifr_text: str) -> List[Tuple[int, int, str, str]]:
    result = []
    for m in _RE_VARSTORE.finditer(ifr_text):
        guid = m.group(1).upper()
        vsid = int(m.group(2), 16)
        name = m.group(5) or ""
        result.append((m.start(), vsid, name, guid))
    return result


def _resolve_vsid_at(pos: int, vsid: int,
                     context: List[Tuple[int, int, str, str]],
                     stores: Dict[int, VarStore]) -> Optional[VarStore]:
    best_name = None
    for cpos, cvid, cname, cguid in context:
        if cpos > pos:
            break
        if cvid == vsid:
            best_name = cname
    if best_name is None:
        return stores.get(vsid)
    for vs in stores.values():
        if vs.name == best_name:
            return vs
    return stores.get(vsid)


_RE_ONEOF_HEADER = re.compile(
    r'OneOf\s+Prompt:\s*"[^"]*"'
    r'.*?VarStoreId:\s*0x([0-9A-Fa-f]+)'
    r'.*?VarOffset:\s*0x([0-9A-Fa-f]+)',
    re.IGNORECASE,
)

_RE_ONEOF_OPTION = re.compile(
    r'OneOfOption\s+Option:\s*"([^"]*)"'
    r',\s*Value:\s*0x([0-9A-Fa-f]+)',
    re.IGNORECASE,
)

_SCOPE_OPENERS = (
    "CheckBox ", "Numeric ", "Action ", "Ref ",
    "GrayOutIf", "SuppressIf", "DisableIf", "InconsistentIf",
    "NoSubmitIf", "Form ", "FormSet", "OrderedList",
    "Date ", "Time ", "String ", "OneOf ",
)


def _label_quality(lbl: str) -> int:
    if lbl and not lbl.startswith('<str#'):
        return 2
    if lbl:
        return 1
    return 0


def parse_oneof_options(ifr_text: str,
                        stores: Optional[Dict[int, "VarStore"]] = None,
                        ) -> Dict[Tuple[str, int], Dict[int, str]]:
    _stores  = stores or {}
    _context = _build_vsid_context(ifr_text)

    logical_lines: List[str] = []
    in_string = False
    for raw in ifr_text.splitlines():
        if in_string:
            logical_lines[-1] = logical_lines[-1].rstrip() + " " + raw.strip()
        else:
            logical_lines.append(raw)
        in_string = (raw.count('"') % 2 == 1) != in_string

    line_char_offsets: List[int] = []
    pos = 0
    raw_lines = ifr_text.splitlines(keepends=True)
    raw_idx = 0
    in_str2 = False
    for logical in logical_lines:
        line_char_offsets.append(pos)
        start_pos = pos
        while raw_idx < len(raw_lines):
            raw = raw_lines[raw_idx]
            pos += len(raw)
            raw_idx += 1
            in_str2 = (raw.rstrip('\n\r').count('"') % 2 == 1) != in_str2
            if not in_str2:
                break

    result: Dict[Tuple[str, int], Dict[int, str]] = {}
    i = 0
    while i < len(logical_lines):
        line = logical_lines[i]
        hm = _RE_ONEOF_HEADER.search(line)
        if hm:
            raw_vs_id = int(hm.group(1), 16)
            vs_off    = int(hm.group(2), 16)
            char_pos  = line_char_offsets[i] if i < len(line_char_offsets) else 0
            resolved  = _resolve_vsid_at(char_pos, raw_vs_id, _context, _stores)
            if resolved:
                guid = resolved.name if resolved.name else resolved.guid.upper()
            else:
                guid = f"VSID:{raw_vs_id:#x}"
            key       = (guid, vs_off)

            opts: Dict[int, str] = {}
            depth = 1
            i += 1
            while i < len(logical_lines) and depth > 0:
                l = logical_lines[i]; stripped = l.strip()
                if depth == 1:
                    om = _RE_ONEOF_OPTION.search(l)
                    if om:
                        val = int(om.group(2), 16); opts[val] = om.group(1)
                if stripped.startswith("End"):
                    depth -= 1
                elif not stripped.startswith("OneOfOption") and any(
                    stripped.startswith(kw) for kw in _SCOPE_OPENERS
                ):
                    depth += 1
                i += 1
            if opts:
                if key in result:
                    for val, label in opts.items():
                        existing = result[key].get(val)
                        if existing is None or _label_quality(label) > _label_quality(existing):
                            result[key][val] = label
                else:
                    result[key] = opts
            continue
        i += 1

    return result


_CHECKBOX_OPTIONS: Dict[int, str] = {0: "Disabled", 1: "Enabled"}


def _resolve_opts(widget_type: str,
                  oneof_options: Optional[Dict[Tuple[str, int], Dict[int, str]]],
                  var_store_id: int, var_offset: int,
                  var_store: Optional["VarStore"] = None) -> Optional[Dict[int, str]]:
    if widget_type.lower() == "checkbox":
        return _CHECKBOX_OPTIONS
    if oneof_options:
        if var_store:
            if var_store.name:
                opts = oneof_options.get((var_store.name, var_offset))
                if opts is not None:
                    return opts
            if var_store.guid:
                opts = oneof_options.get((var_store.guid.upper(), var_offset))
                if opts is not None:
                    return opts
    return None


def decode_value(val: Optional[int], options: Optional[Dict[int, str]],
                 widget_type: str = "") -> str:
    if val is None:
        return "unknown"
    if options:
        label = options.get(val, "unknown")
        return label if label != "" else "unknown"
    return "unknown"


def grep_settings(ifr_text: str, terms: List[str],
                  stores: Optional[Dict[int, VarStore]] = None) -> List[HiiSetting]:
    results:    List[HiiSetting]          = []
    key_to_idx: Dict[Tuple[int,int], int] = {}
    _stores  = stores or {}
    _context = _build_vsid_context(ifr_text)

    def _prompt_quality(prompt: str, help_text: str) -> int:
        if prompt.startswith('<str#'):
            return 0
        return 2 if prompt != help_text else 1

    for m in _RE_SETTING.finditer(ifr_text):
        widget    = m.group(1); prompt = m.group(2); help_text = m.group(3) or ""
        q_flags   = int(m.group(4), 16); q_id = int(m.group(5), 16)
        vs_id     = int(m.group(6), 16); vs_off = int(m.group(7), 16)
        flags     = int(m.group(8), 16)
        size      = int(m.group(9))       if m.group(9)  else 8
        min_v     = int(m.group(10), 16)  if m.group(10) else 0
        max_v     = int(m.group(11), 16)  if m.group(11) else 1
        step      = int(m.group(12), 16)  if m.group(12) else 0
        if terms and terms != [""] and not any(t.lower() in (prompt + " " + help_text).lower() for t in terms):
            continue
        resolved_vs = _resolve_vsid_at(m.start(), vs_id, _context, _stores)
        store_key = resolved_vs.var_store_id if resolved_vs else vs_id
        s = HiiSetting(widget_type=widget, prompt=prompt, help_text=help_text,
                       question_flags=q_flags, question_id=q_id,
                       var_store_id=store_key, var_offset=vs_off,
                       flags=flags, size=size, min_val=min_v, max_val=max_v, step=step)
        s.var_store = resolved_vs
        key = (store_key, vs_off)
        if key in key_to_idx:
            existing = results[key_to_idx[key]]
            if _prompt_quality(prompt, help_text) > _prompt_quality(existing.prompt, existing.help_text):
                results[key_to_idx[key]] = s
        else:
            key_to_idx[key] = len(results)
            results.append(s)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# NVRAM parsing
# ─────────────────────────────────────────────────────────────────────────────

def _find_all_nvram_stores(fw: bytes) -> List[Tuple[int, int]]:
    n = len(fw)
    store_candidates = []
    i = 0
    while i < n - 28:
        if fw[i + 20] == 0x5A and fw[i + 21] == 0xFE:
            size = u32(fw, i + 16)
            if 0x400 < size < 0x800000 and i + size <= n:
                aa55_near = fw.find(b'\xaa\x55', i + 28, i + 92)
                if aa55_near >= 0:
                    store_candidates.append((i, size))
        i += 1
    return store_candidates


def _guid_str_to_bytes(gs: str) -> bytes:
    parts = gs.replace("-", "")
    a = int(parts[0:8],  16); b = int(parts[8:12], 16); c = int(parts[12:16],16)
    d = bytes.fromhex(parts[16:20]); e = bytes.fromhex(parts[20:32])
    return struct.pack("<IHH", a, b, c) + d + e


def _probe_var_header(nvram: bytes, guid_pos: int):
    for guid_off_in_hdr, name_off_in_hdr in ((44, 60), (20, 36), (16, 32)):
        hdr = guid_pos - guid_off_in_hdr
        if hdr >= 0 and nvram[hdr] == 0xAA and nvram[hdr + 1] == 0x55:
            return hdr, hdr + name_off_in_hdr
    return None, None


def _search_nvram_region(nvram: bytes, target: bytes, var_offset: int,
                          size_bytes: int, var_name: str, live_result, deleted_result, expected_data_size=None):
    n = len(nvram)
    search_pos = 0
    while search_pos < n - 16:
        guid_pos = nvram.find(target, search_pos)
        if guid_pos < 0: break
        search_pos = guid_pos + 1
        hdr, name_start = _probe_var_header(nvram, guid_pos)
        if hdr is None: continue
        if expected_data_size is not None:
            if guid_pos < 4: continue
            if u32(nvram, guid_pos - 4) != expected_data_size: continue
        state = nvram[hdr + 2]
        pos = name_start; name_chars = []
        while pos + 1 < n:
            lo, hi = nvram[pos], nvram[pos + 1]; pos += 2
            if lo == 0 and hi == 0: break
            name_chars.append(chr(lo) if hi == 0 else "?")
        found_name = "".join(name_chars)
        if var_name and found_name != var_name: continue
        data_off = pos
        if data_off + var_offset + size_bytes > n: continue
        raw = nvram[data_off + var_offset: data_off + var_offset + size_bytes]
        fmt = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(size_bytes, "B")
        try:
            val = struct.unpack(fmt, raw)[0]
        except struct.error:
            continue
        if state == 0x3F: live_result = val
        elif deleted_result is None: deleted_result = val
    return live_result, deleted_result


def find_nvram_value(nvram, guid_str_val: str, var_offset: int, size_bits: int,
                     var_name: str = "", expected_data_size: Optional[int] = None) -> Optional[int]:
    target = _guid_str_to_bytes(guid_str_val)
    size_bytes = max(1, size_bits // 8)
    live_result = deleted_result = None
    for region in (nvram if isinstance(nvram, list) else [nvram]):
        live_result, deleted_result = _search_nvram_region(
            region, target, var_offset, size_bytes, var_name, live_result, deleted_result, expected_data_size)
        if live_result is not None: break
    return live_result if live_result is not None else deleted_result


# ─────────────────────────────────────────────────────────────────────────────
# Reverse lookup
# ─────────────────────────────────────────────────────────────────────────────

def reverse_lookup(ifr_text: str, stores: Dict[int, VarStore],
                   guid: str, key_name: str) -> List[HiiSetting]:
    guid = guid.upper()
    matching_vsids = {vsid for vsid, vs in stores.items()
                      if vs.guid.upper() == guid and vs.name == key_name}
    if not matching_vsids: return []
    results: List[HiiSetting] = []
    off_to_idx: Dict[int, int] = {}
    def _prompt_quality(p, h): return 0 if p == h else 1
    for m in _RE_SETTING.finditer(ifr_text):
        widget    = m.group(1); prompt = m.group(2); help_text = m.group(3) or ""
        q_flags   = int(m.group(4), 16); q_id = int(m.group(5), 16)
        vs_id     = int(m.group(6), 16); vs_off = int(m.group(7), 16)
        flags     = int(m.group(8), 16)
        size      = int(m.group(9))       if m.group(9)  else 8
        min_v     = int(m.group(10), 16)  if m.group(10) else 0
        max_v     = int(m.group(11), 16)  if m.group(11) else 1
        step      = int(m.group(12), 16)  if m.group(12) else 0
        if vs_id not in matching_vsids: continue
        s = HiiSetting(widget_type=widget, prompt=prompt, help_text=help_text,
                       question_flags=q_flags, question_id=q_id,
                       var_store_id=vs_id, var_offset=vs_off,
                       flags=flags, size=size, min_val=min_v, max_val=max_v, step=step)
        s.var_store = stores.get(vs_id)
        if vs_off in off_to_idx:
            existing = results[off_to_idx[vs_off]]
            if _prompt_quality(prompt, help_text) > _prompt_quality(existing.prompt, existing.help_text):
                results[off_to_idx[vs_off]] = s
        else:
            off_to_idx[vs_off] = len(results)
            results.append(s)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Printing
# ─────────────────────────────────────────────────────────────────────────────

def _col_w(rows, headers):
    w = [len(h) for h in headers]
    for row in rows:
        for i, c in enumerate(row):
            if i < len(w): w[i] = max(w[i], len(c))
    return w

def _hdr(text: str) -> str:
    return f"\n{C_HEAD}{text}{C_RST}\n{'─' * len(text)}"

def _box(title: str, lines: List[str]) -> None:
    width = max(len(title) + 4, max((len(l) for l in lines), default=0) + 4)
    bar   = "─" * width
    print(f"\n{C_HEAD}┌{bar}┐")
    print(f"│ {title}{' ' * (width - len(title) - 2)} │")
    print(f"├{bar}┤{C_RST}")
    for l in lines: print(f"  {l}")
    print(f"{C_HEAD}└{bar}┘{C_RST}")

def _mini_box(title: str, lines: List[str], width: int = 60, indent: str = "   ") -> None:
    inner = width - 2; bar = "─" * width
    print(f"\n{indent}{C_HEAD}┌{bar}┐")
    print(f"{indent}│ {title}{' ' * max(inner - len(title) - 1, 0)}  │")
    print(f"{indent}├{bar}┤{C_RST}")
    for l in lines:
        visible = re.sub(r'\x1b\[[0-9;]*m', '', l)
        print(f"{indent}  {l}{' ' * max(inner - len(visible) - 1, 0)}")
    print(f"{indent}{C_HEAD}└{bar}┘{C_RST}")

def print_table(headers, rows, title: str = "") -> None:
    rs  = [[str(c) for c in row] for row in rows]
    w   = _col_w(rs, headers)
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    sep = "  ".join("─" * x for x in w)
    tlines = [fmt.format(*headers), sep] + [fmt.format(*row) for row in rs]
    if title: _box(title, tlines)
    else:
        for l in tlines: print(l)
    print()

def _fmt_value(val: Optional[int], size_bits: int) -> str:
    if val is None: return "NOT FOUND"
    return f"0x{val:0{max(1, size_bits//8)*2}X}"

def print_settings_table(settings, stores, title="SETTINGS", oneof_options=None):
    rows = []
    for i, s in enumerate(settings):
        vs = s.var_store or stores.get(s.var_store_id)
        store_name = vs.name if vs else f"0x{s.var_store_id:X}"
        display = s.prompt if (not s.help_text or len(s.prompt) <= len(s.help_text)) else s.help_text
        setting_name = display if len(display) <= 44 else display[:43] + "…"
        val_str = _fmt_value(s.current_value, s.size)
        opts = _resolve_opts(s.widget_type, oneof_options, s.var_store_id, s.var_offset, s.var_store)
        decoded = decode_value(s.current_value, opts)
        rows.append([str(i + 1), setting_name, store_name, f"0x{s.var_offset:X}", val_str, decoded])
    headers = ["#", "Setting", "Store", "Offset", "Value", "Status"]
    rs = [[str(c) for c in row] for row in rows]
    w  = _col_w(rs, headers)
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    sep = "  ".join("─" * x for x in w)
    tlines = [fmt.format(*headers), sep]
    for row in rs:
        val = row[4]; status = row[5]
        vp = f"{val:<{w[4]}}"; sp = f"{status:<{w[5]}}"
        row[4] = f"{C_WARN}{vp}{C_RST}" if val == "NOT FOUND" else f"{C_OK}{vp}{C_RST}"
        row[5] = f"{C_GREY}{sp}{C_RST}" if status == "unknown" else f"{C_STATUS}{sp}{C_RST}"
        tlines.append("  ".join(f"{row[j]:<{w[j]}}" for j in range(4)) + "  " + row[4] + "  " + row[5])
    _box(title, tlines)
    print()

def print_varstore_map(settings, stores):
    rows = []
    seen: Set[Tuple[str, str]] = set()
    for s in settings:
        vs = s.var_store or stores.get(s.var_store_id)
        if vs:
            key = (vs.name, vs.guid)
            if key in seen:
                continue
            seen.add(key)
            rows.append([vs.name, vs.guid, f"0x{vs.size:X}"])
        else:
            key = (f"0x{s.var_store_id:X}", "?")
            if key in seen:
                continue
            seen.add(key)
            rows.append([f"0x{s.var_store_id:X}", "?", "?"])
    print_table(["Store", "GUID", "Size"], rows, title="VARSTORE  →  GUID")

def print_describe_table(settings, stores, title="SETTING DESCRIPTIONS"):
    """Print help text for each matched setting as Setting/Help label pairs (outside of --modify flag)."""
    lw   = 10   # label column width — pads "Setting:" and "Help:" to same indent
    wrap = 120 # change this if you want narrower/wider description text; it will be wrapped to fit within this width
    pad  = " " * lw

    tlines = []
    for i, s in enumerate(settings):
        if tlines:
            tlines.append("")
        name = s.prompt[:43] + "…" if len(s.prompt) > 44 else s.prompt
        desc = textwrap.wrap(s.help_text or "(no description available)", width=wrap) or [""]
        tlines.append(f"{'Setting:':<{lw}}{name}")
        tlines.append(f"{'Help:':<{lw}}{desc[0]}")
        tlines.extend(f"{pad}{line}" for line in desc[1:])

    _box(title, tlines)
    print()

# ─────────────────────────────────────────────────────────────────────────────
# Extra EFI scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_extra_varstores(paths: List[str]) -> Dict[int, VarStore]:
    combined: Dict[int, VarStore] = {}
    for path in paths:
        if not os.path.isfile(path):
            gwarn(f"[!] Extra EFI not found: {path}"); continue
        data = Path(path).read_bytes()
        _, form_pkgs = find_packages(data)
        if not form_pkgs:
            if DEBUG: gwarn(f"[!] No form packages in: {path}")
            continue
        for off, plen in form_pkgs:
            lines = parse_form_package(data, off, plen, {})
            combined.update(parse_varstores("\n".join(lines)))
    return combined


# ─────────────────────────────────────────────────────────────────────────────
# IFR loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_ifr_and_stores(efi: Optional[str], extra_efi: List[str],
                          dump_ifr: Optional[str],
                          fw_bytes: Optional[bytearray] = None):
    if efi is not None:
        ifr_text = extract_ifr(efi)
        if dump_ifr:
            Path(dump_ifr).write_text(ifr_text, encoding="utf-8")
        stores = parse_varstores(ifr_text)
        if extra_efi:
            extra = scan_extra_varstores(extra_efi)
            stores.update(extra)
        else:
            efi_dir  = os.path.dirname(os.path.abspath(efi))
            efi_name = os.path.basename(efi)
            siblings = [os.path.join(efi_dir, f) for f in os.listdir(efi_dir)
                        if f != efi_name and f.endswith(".efi")
                        and os.path.isfile(os.path.join(efi_dir, f))]
            if siblings:
                extra = scan_extra_varstores(siblings)
                before = len(stores); stores.update(extra)
                if DEBUG and len(stores) > before:
                    gprint(f"[+] Merged {len(stores)-before} VarStore(s) from siblings.")
    else:
        assert fw_bytes is not None
        fw_data = bytes(fw_bytes)
        gprint("[+] Scanning firmware for EFIs...")
        candidates = find_hii_efi_in_firmware(fw_data)
        if not candidates:
            _uf_ok = True
            try:
                import uefi_firmware  # noqa: F401
            except ImportError:
                _uf_ok = False
            try:
                import uefi_firmware as _uf
                _uf_ver = getattr(_uf, "__version__", "?")
                _uf_ok  = True
            except ImportError:
                _uf_ver = None

            if _uf_ok:
                _hint = (f"    uefi_firmware {_uf_ver} is installed but could not find HII\n"
                          "    in this firmware.  Possible causes:\n"
                          "      1. uefi_firmware version < 1.16 (HP archive support)\n"
                          "         Fix: pip install --upgrade uefi-firmware\n"
                          "      2. Firmware uses an unsupported vendor format.\n"
                          "         Fix: extract Setup.efi with UEFITool and re-run with:\n"
                          "              -efi Setup.efi -firmware firmware.bin -terms ...\n"
                          "    Diagnostic: re-run with --debug to see detailed parser output.")
            else:
                _hint = ("    uefi-firmware is NOT installed.  It is required for HP/Dell\n"
                          "    firmware images that use vendor-specific archive formats.\n"
                          "         pip install uefi-firmware\n"
                          "    Then re-run.  Alternatively, extract Setup.efi with UEFITool:\n"
                          "         -efi Setup.efi -firmware firmware.bin -terms ...")
            sys.exit(f"{C_ERR}[!] No HII-bearing EFI modules found in firmware image.\n"
                     f"{_hint}{C_RST}")
        gprint(f"[+] Found {len(candidates)} HII-bearing EFI module(s):")
        for idx, (lbl, _, _, _) in enumerate(candidates):
            marker = " ◄ selected" if idx == 0 else ""
        primary_label, primary_blob, _, _ = candidates[0]
        combined_ifr = "\n".join(ifr for _, _, ifr, _ in candidates)
        if dump_ifr:
            Path(dump_ifr).write_text(combined_ifr, encoding="utf-8")
        def _placeholder_ratio(ifr: str) -> float:
            setting_count = ifr.count('OneOf Prompt:') + ifr.count('CheckBox Prompt:') + ifr.count('Numeric Prompt:')
            if setting_count == 0:
                return 0.0
            placeholder_count = sum(1 for line in ifr.splitlines()
                                    if 'Prompt:' in line and '<str#' in line)
            return placeholder_count / setting_count

        search_ifr_parts = [ifr for _, _, ifr, _ in candidates
                            if _placeholder_ratio(ifr) < 0.5]
        if not search_ifr_parts:
            search_ifr_parts = [candidates[0][2]]
        ifr_text = "\n".join(search_ifr_parts)
        stores = parse_varstores(combined_ifr)
        if extra_efi:
            stores.update(scan_extra_varstores(extra_efi))

    oneof_options = parse_oneof_options(ifr_text, stores=stores)
    if DEBUG:
        total_opts = sum(len(v) for v in oneof_options.values())
        gprint(f"[+] Parsed {len(oneof_options)} OneOf setting(s), {total_opts} total option(s).")
    return ifr_text, stores, oneof_options


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def _load_firmware_nvram(firmware_path: str):
    fw_bytes = bytearray(Path(firmware_path).read_bytes())
    stores_found = _find_all_nvram_stores(bytes(fw_bytes))
    if not stores_found:
        sys.exit(f"{C_ERR}[!] NVRAM variable store not found in firmware image{C_RST}")
    def _count_live(fw, off, sz):
        return sum(1 for i in range(off, off + sz - 4)
                   if fw[i] == 0xAA and fw[i+1] == 0x55 and fw[i+2] == 0x3F)
    nvram_regions = sorted(stores_found,
                           key=lambda t: _count_live(bytes(fw_bytes), t[0], t[1]),
                           reverse=True)
    nvram_bytes = [bytes(fw_bytes[off:off+size]) for off, size in nvram_regions]
    gprint(f"[+] Firmware: {len(fw_bytes):,} bytes")
    gprint(f"[+] Found {len(nvram_regions)} NVRAM store(s) (sorted by live-variable count):")
    for off, size in nvram_regions:
        lv = _count_live(bytes(fw_bytes), off, size)
        gprint(f"    0x{off:X}  size=0x{size:X}  live_vars={lv}")
    return fw_bytes, nvram_bytes, nvram_regions


def main() -> None:
    epilog = """
EXAMPLE USAGE:

  Mode 1 — Map EFI settings to NVRAM variables (search by keyword):
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms VT-d,IOMMU
    nvramap.py -mode 1 -firmware firmware.bin -terms DMA
    nvramap.py -mode 1 -firmware firmware.bin -all

  Mode 2 — Map NVRAM variables to EFI settings (reverse lookup by GUID + key):
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid <GUID> -key <NAME>
    nvramap.py -mode 2 -firmware firmware.bin -guid <GUID> -key <NAME>

  Diagnostics:
    nvramap.py -mode 1 -firmware firmware.bin --list-hii
    nvramap.py -mode 1 -firmware firmware.bin --debug-fw
"""
    ap = argparse.ArgumentParser(
        prog="nvramap.py",
        description=(
            "NVRAMap — UEFI NVRAM Mapper & Editor\n\n"
            "  Automatically discover relationships between settings and NVRAM\n"
            "  Note when only -firmware is provided, NVRAMap will perform discovery\n"
            "  This may take several minutes..\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    req = ap.add_argument_group("required arguments")
    req.add_argument("-mode", required=True, choices=["1", "2"], metavar="MODE",
                    help="Operation mode: 1 = EFI→NVRAM  |  2 = NVRAM→EFI")
    req.add_argument("-efi",  default=None, metavar="FILE",
                    help="EFI module with HII data (optional when -firmware is given)")
    req.add_argument("-nvram", default=None, metavar="FILE",
                    help="Raw NVRAM binary blob (optional when -firmware is given")
    req.add_argument("-firmware", default=None, metavar="FILE",
                    help="Full firmware dump")
    m1 = ap.add_argument_group("mode 1 options")
    m1.add_argument("-terms", "-t", default=None, metavar="TERMS",
                    help="Comma-separated search terms  e.g. VT-d,IOMMU,DMA")
    m1.add_argument("-all", action="store_true",
                    help="Dump every setting (no filter)")
    m2 = ap.add_argument_group("mode 2 options")
    m2.add_argument("-guid", default=None, metavar="GUID", help="GUID of target VarStore")
    m2.add_argument("-key",  default=None, metavar="NAME", help="Name of target NVRAM Key")
    opt = ap.add_argument_group("options")
    opt.add_argument("--modify",    action="store_true", help="Launch interactive editor")
    opt.add_argument("--set", nargs=2, metavar=("INDEX", "VALUE"))
    opt.add_argument("--extra-efi", nargs="+", default=[], metavar="FILE")
    opt.add_argument("--dump-ifr",  default=None, metavar="FILE",help="Save extracted IFR data to file")
    opt.add_argument("--dump-var",  default=None, metavar="GUID")

    opt.add_argument("--setting-info", "-i", action="store_true",
                    help="Print help text for each matched setting")
    opt.add_argument("--list-hii",  action="store_true",
                    help="List all HII-bearing EFI modules found in firmware and exit")
    opt.add_argument("--debug-fw",  action="store_true",
                    help="Print detailed firmware structure scan (FVs, sections, decomp results) and exit")
    opt.add_argument("--debug",     action="store_true",
                    help="Verbose parsing output")
    args = ap.parse_args()

    global DEBUG
    DEBUG = args.debug or args.debug_fw

    print(BANNER)

    # ── inform the user what is being auto-detected ───────────────────────────
    if not args.nvram and not args.firmware:
        ap.error("one of -nvram or -firmware is required")
    if args.nvram and args.firmware:
        ap.error("-nvram and -firmware are mutually exclusive")
    if args.mode == "1" and not args.terms and not args.all and not args.list_hii and not args.debug_fw:
        ap.error("Mode 1 requires -terms, -all, --list-hii, or --debug-fw")
    if args.mode == "2" and (not args.guid or not args.key) and not args.list_hii and not args.debug_fw:
        ap.error("Mode 2 requires both -guid and -key")

    # Grey-phase status messages: tell the user what will be scanned for.
    if args.firmware:
        if not args.efi:
            gprint("[!] EFI not specified, scanning for candidates...")
        # NVRAM is always embedded in the firmware dump; no separate -nvram needed.
        gprint("[!] NVRAM not specified, scanning for candidates...")

    fw_bytes = nvram_bytes = nvram_regions = None

    if args.firmware:
        if not os.path.isfile(args.firmware):
            sys.exit(f"{C_ERR}[!] File not found: -firmware {args.firmware}{C_RST}")
        fw_bytes, nvram_bytes, nvram_regions = _load_firmware_nvram(args.firmware)

        if args.debug_fw:
            debug_firmware_scan(bytes(fw_bytes))
            sys.exit(0)

        if args.list_hii:
            gprint("\n[*] Scanning for HII-bearing EFI modules...\n")
            candidates = find_hii_efi_in_firmware(bytes(fw_bytes))
            if not candidates:
                gwarn("[!] No HII-bearing EFI modules found.\n"
                      "    Tip: run with --debug-fw for a detailed structure scan.")
            else:
                for idx, (lbl, _, ifr, _) in enumerate(candidates):
                    n_s = len(_RE_SETTING.findall(ifr))
                    n_v = len(_RE_VARSTORE.findall(ifr))
                    gprint(f"  [{idx:2d}]  stores={n_v:3d}  settings={n_s:4d}  {lbl}")
            print(); sys.exit(0)

    else:
        if not os.path.isfile(args.nvram):
            sys.exit(f"{C_ERR}[!] File not found: -nvram {args.nvram}{C_RST}")
        if not args.efi:
            gprint("[!] EFI not specified, scanning for candidates...")
        raw_nvram = Path(args.nvram).read_bytes()
        sub_stores = _find_all_nvram_stores(raw_nvram)
        if len(sub_stores) > 1:
            def _clb(data, off, sz):
                return sum(1 for i in range(off, off+sz-4)
                           if data[i]==0xAA and data[i+1]==0x55 and data[i+2]==0x3F)
            sub_stores = sorted(sub_stores, key=lambda t: _clb(raw_nvram,t[0],t[1]), reverse=True)
            nvram_bytes   = [raw_nvram[off:off+sz] for off, sz in sub_stores]
            nvram_regions = sub_stores
            gprint(f"[+] NVRAM blob: {len(raw_nvram):,} bytes, {len(sub_stores)} embedded store(s)")
        else:
            nvram_bytes = raw_nvram; nvram_regions = None
            gprint(f"[+] NVRAM: {len(raw_nvram):,} bytes")
        if args.efi is None:
            ap.error("-efi is required when using -nvram (auto-detection requires -firmware)")

    if args.efi and not os.path.isfile(args.efi):
        sys.exit(f"{C_ERR}[!] File not found: -efi {args.efi}{C_RST}")

    ifr_text, stores, oneof_options = _load_ifr_and_stores(
        args.efi, args.extra_efi, args.dump_ifr, fw_bytes)

    # ── grey phase ends here — "Performing analysis" is the transition line ──
    gprint(f"[+] Performing analysis...\n")

    if args.dump_var:
        _do_dump_var(nvram_bytes, args.dump_var.upper())

    if args.mode == "1":
        if args.all:
            settings = grep_settings(ifr_text, [""], stores)
            title = "MODE 1  —  EFI Settings → NVRAM  (all)"
        else:
            terms = [t.strip() for t in args.terms.split(",") if t.strip()]
            settings = grep_settings(ifr_text, terms, stores)
            title = f"MODE 1  —  EFI Settings → NVRAM  ({args.terms})"
        if not settings:
            sys.exit(f"{C_WARN}[!] No settings found{C_RST}")
        settings = [s for s in settings if s.prompt.strip()]
        for s in settings:
            if s.var_store is None: s.var_store = stores.get(s.var_store_id)
    else:
        settings = reverse_lookup(ifr_text, stores, args.guid, args.key)
        if not settings:
            sys.exit(f"{C_WARN}[!] No settings found for GUID={args.guid}  Key={args.key}{C_RST}")
        settings = [s for s in settings if s.prompt.strip()]
        title = f"MODE 2  —  NVRAM → EFI Settings  |  {args.key}  ({args.guid})"

    for s in settings:
        vs = s.var_store or stores.get(s.var_store_id)
        if vs and vs.guid and vs.guid != "?":
            s.current_value = find_nvram_value(
                nvram_bytes, vs.guid, s.var_offset, s.size, var_name=vs.name)
        if s.current_value is None and vs.size:
            s.current_value = find_nvram_value(
                nvram_bytes, vs.guid, s.var_offset, s.size,
                var_name="", expected_data_size=vs.size)    

    print_varstore_map(settings, stores)
    print_settings_table(settings, stores, title=title, oneof_options=oneof_options)

    if args.setting_info:
        desc_title = f"SETTING DESCRIPTIONS  ({args.terms})" if args.terms else "SETTING DESCRIPTIONS"
        print_describe_table(settings, stores, title=desc_title)

    do_modify = args.modify; set_arg = args.set

    def _parse_val(raw_val):
        raw_val = raw_val.strip()
        return int(raw_val, 16) if raw_val.lower().startswith("0x") else int(raw_val)

    def _apply_change(idx, new_val, patched):
        s = settings[idx]; vs = stores.get(s.var_store_id)
        if not vs:
            print(f"  {C_ERR}No VarStore for setting {idx+1}.{C_RST}"); return False
        target = _guid_str_to_bytes(vs.guid)
        size_bytes = max(1, s.size // 8)
        regions = patched if isinstance(patched, list) else [patched]
        for region in regions:
            n = len(region); live_off = deleted_off = None; search_pos = 0
            while search_pos < n - 16:
                guid_pos = bytes(region).find(target, search_pos)
                if guid_pos < 0: break
                search_pos = guid_pos + 1
                hdr, name_start = _probe_var_header(bytes(region), guid_pos)
                if hdr is None: continue
                state = region[hdr + 2]
                pos = name_start; name_chars = []
                while pos + 1 < n:
                    lo, hi = region[pos], region[pos+1]; pos += 2
                    if lo == 0 and hi == 0: break
                    name_chars.append(chr(lo) if hi == 0 else "?")
                if "".join(name_chars) != vs.name: continue
                write_off = pos + s.var_offset
                if write_off + size_bytes > n: continue
                if state == 0x3F: live_off = write_off
                elif deleted_off is None: deleted_off = write_off
            target_off = live_off if live_off is not None else deleted_off
            if target_off is not None:
                fmt_s = {1:"B",2:"<H",4:"<I",8:"<Q"}.get(size_bytes,"B")
                region[target_off:target_off+size_bytes] = struct.pack(fmt_s, new_val)
                s.current_value = new_val; return True
        print(f"  {C_ERR}Variable not found in NVRAM buffer.{C_RST}"); return False

    patched = [bytearray(r) for r in nvram_bytes] if isinstance(nvram_bytes, list) else bytearray(nvram_bytes)
    changes: List[str] = []

    if set_arg:
        try:
            idx = int(set_arg[0]) - 1; new_val = _parse_val(set_arg[1])
        except (ValueError, IndexError):
            sys.exit(f"{C_ERR}Invalid --set arguments.{C_RST}")
        if not (0 <= idx < len(settings)):
            sys.exit(f"{C_ERR}Index {idx+1} out of range (1–{len(settings)}).{C_RST}")
        if _apply_change(idx, new_val, patched):
            s = settings[idx]
            opts = _resolve_opts(s.widget_type, oneof_options, s.var_store_id, s.var_offset, s.var_store)
            status = decode_value(new_val, opts)
            changes.append(f"[{idx+1}] {s.prompt}  →  {_fmt_value(new_val, s.size)}  ({status})")
            print(f"  Set [{idx+1}] {s.prompt} = {C_OK}{_fmt_value(new_val, s.size)}{C_RST}  ({C_STATUS}{status}{C_RST})")
    elif do_modify:
        print("  Modify mode — select a setting by number, 'done' to save, 'q' to quit.")
        print()
        first_iteration = True
        while True:
            if not first_iteration:
                print_settings_table(settings, stores, title="Current Values", oneof_options=oneof_options)
            first_iteration = False
            try: raw = input("  >> ").strip().lower()
            except (EOFError, KeyboardInterrupt): raw = "q"
            if raw in ("q", "quit"):
                print("  Aborted — no changes written."); return
            if raw in ("done", "d", ""): break
            try: idx = int(raw) - 1
            except ValueError: print("  Enter a number.\n"); continue
            if not (0 <= idx < len(settings)):
                print(f"  Out of range (1–{len(settings)}).\n"); continue
            s = settings[idx]
            cur = _fmt_value(s.current_value, s.size)
            opts = _resolve_opts(s.widget_type, oneof_options, s.var_store_id, s.var_offset, s.var_store)
            display = s.prompt if (not s.help_text or len(s.prompt) <= len(s.help_text)) else s.help_text
            help_to_show = s.help_text if (not s.help_text or len(s.prompt) <= len(s.help_text)) else s.prompt
            _mini_box(f"[{idx+1}] {display}", [
                f"Current  : {C_OK}{cur}{C_RST}  ({C_STATUS}{decode_value(s.current_value, opts)}{C_RST})",
                f"Range    : 0x{s.min_val:X} – 0x{s.max_val:X}",
            ])
            if help_to_show:
                _mini_box("Help", textwrap.wrap(help_to_show, width=56) or [help_to_show])
            if opts:
                _mini_box("Valid Options", [f"{C_OK}0x{ov:02X}{C_RST}  →  {ol}"
                                            for ov, ol in sorted(opts.items())])
            print()
            try:
                raw_val = input("\n  Enter New Value\n\n  >> ").strip()
                if not raw_val: print("  Skipped.\n"); continue
                new_val = _parse_val(raw_val)
            except (ValueError, EOFError, KeyboardInterrupt):
                print("  Cancelled.\n"); continue
            if not (s.min_val <= new_val <= s.max_val):
                print(f"  {C_WARN}Warning: outside valid range.{C_RST}")
            if _apply_change(idx, new_val, patched):
                status = decode_value(new_val, opts)
                changes.append(f"[{idx+1}] {s.prompt}  →  {_fmt_value(new_val, s.size)}  ({status})")
                print(f"\n  New Value: {C_OK}{_fmt_value(new_val, s.size)}{C_RST}  ({C_STATUS}{status}{C_RST})\n")

    if changes:
        if args.firmware:
            src_p = Path(args.firmware)
            out_path = src_p.parent / (src_p.stem + "_patched" + src_p.suffix)
            for (off, size), region in zip(nvram_regions, patched):
                fw_bytes[off:off + size] = region
            out_path.write_bytes(bytes(fw_bytes))
        else:
            src_p = Path(args.nvram)
            out_path = src_p.parent / (src_p.stem + "_patched" + src_p.suffix)
            if isinstance(nvram_regions, list):
                buf = bytearray(Path(args.nvram).read_bytes())
                for (off, size), region in zip(nvram_regions, patched):
                    buf[off:off + size] = region
                out_path.write_bytes(bytes(buf))
            else:
                out_path.write_bytes(bytes(patched))
        print(f"\n{C_OK}  Saved → {out_path}{C_RST}")
        #for c in changes: print(f"    {c}")
        print()


def _do_dump_var(nvram, dump_guid: str) -> None:
    try: target = _guid_str_to_bytes(dump_guid)
    except Exception:
        print(f"{C_ERR}Invalid GUID: {dump_guid}{C_RST}"); return
    regions = nvram if isinstance(nvram, list) else [nvram]
    print(_hdr(f"NVRAM VAR DUMP  {dump_guid}"))
    match_n = 0
    for region in regions:
        n = len(region); search = 0
        while search < n - 16:
            gi = region.find(target, search)
            if gi < 0: break
            search = gi + 1; match_n += 1
            hdr = gi
            while hdr > max(0, gi - 256):
                if region[hdr] == 0xAA and region[hdr+1] == 0x55: break
                hdr -= 1
            print(f"\n  Match {match_n}:  GUID@{gi:#x}  AA55@{hdr:#x}")
            chunk = region[hdr:hdr+80]
            for row in range(0, len(chunk), 16):
                hp = " ".join(f"{chunk[row+k]:02X}" for k in range(16) if row+k < len(chunk))
                print(f"    {hdr+row:08X}:  {hp}")
            p = gi + 16; name_chars = []
            while p + 1 < n:
                lo, hi = region[p], region[p+1]; p += 2
                if lo == 0 and hi == 0: break
                name_chars.append(chr(lo) if hi == 0 else "?")
            name = "".join(name_chars)
            print(f"\n  Key: '{name}'   data @ {p:#x}")
            next_hdr = n
            for np in range(p+2, min(p+0x10000, n-1)):
                if region[np] == 0xAA and region[np+1] == 0x55:
                    next_hdr = np; break
            db = region[p:next_hdr]
            print(f"  Data ({len(db):#x} bytes):")
            print("  off:  " + "  ".join(f"{k:02X}" for k in range(16)))
            print("  ----  " + "  ".join("--" for _ in range(16)))
            for row in range(0, min(len(db), 64), 16):
                vs = "  ".join(f"{db[row+k]:02X}" for k in range(16) if row+k < len(db))
                print(f"  {row:04X}:  {vs}")
    if match_n == 0: print("  GUID not found.")
    print()


if __name__ == "__main__":
    main()
