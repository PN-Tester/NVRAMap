#!/usr/bin/env python3
# Tool for mapping relationship between EFI programs and NVRAM Key Values
# Created by : PN-TESTER

import argparse
import os
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BANNER = r"""
 _______ ___ ___ ______ _______ _______              
|    |  |   |   |   __ \   _   |   |   | _____ _____ 
|       |   |   |      <       |       ||  _  |  _  |
|__|____|\_____/|___|__|___|___|__|_|__||__|__|   __|
                                              |__|   
Created By : PN-TESTER
"""

DEBUG = False   # set to True via --debug flag

#color helpers

try:
    from colorama import Fore, Style, init as _ci
    _ci(autoreset=True)
    C_HEAD = Fore.CYAN  + Style.BRIGHT
    C_OK   = Fore.GREEN + Style.BRIGHT
    C_WARN = Fore.YELLOW
    C_ERR  = Fore.RED   + Style.BRIGHT
    C_RST  = Style.RESET_ALL
except ImportError:
    C_HEAD = C_OK = C_WARN = C_ERR = C_RST = ""


# data structures

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


# helpers

def u8(b: bytes, o: int) -> int:  return b[o]
def u16(b: bytes, o: int) -> int: return struct.unpack_from("<H", b, o)[0]
def u32(b: bytes, o: int) -> int: return struct.unpack_from("<I", b, o)[0]
def u64(b: bytes, o: int) -> int: return struct.unpack_from("<Q", b, o)[0]

def guid_str(b: bytes, o: int) -> str:
    a, bv, c = struct.unpack_from("<IHH", b, o)
    d = b[o+8:o+10].hex().upper()
    e = b[o+10:o+16].hex().upper()
    return f"{a:08X}-{bv:04X}-{c:04X}-{d}-{e}"


# HII String package parsing
#
# EFI_HII_PACKAGE_HEADER  (4 bytes, little-endian u32):
#   bits[23:0]  = Length  (includes this header)
#   bits[31:24] = Type
#
# EFI_HII_STRING_PACKAGE_HDR (after the 4-byte pkg header):
#   HdrSize          u32   @ +0
#   StringInfoOffset u32   @ +4
#   LanguageWindow   u16[16] @ +8  (32 bytes)
#   LanguageName     u16   @ +40
#   Language         null-terminated ASCII @ +42
#
# After header: SIBT blocks (block_type u8, then type-specific data)

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
    """
    Find where SIBT blocks actually start in a string package payload
    (data after the 4-byte EFI_HII_PACKAGE_HEADER).

    EFI_HII_STRING_PACKAGE_HDR layout:
      HdrSize          u32  @ 0
      StringInfoOffset u32  @ 4   (unreliable in some firmware - equals HdrSize
                                    but points into the middle of the first block)
      LanguageWindow   u16[16] @ 8  (32 bytes)
      LanguageName     u16  @ 40
      Language         null-terminated ASCII @ 42

    SIBT blocks start immediately after the null terminator of the Language
    string.  We compute that directly rather than trusting StringInfoOffset.
    """
    null_pos = payload.find(0, 42)
    if null_pos < 0:
        return -1
    return null_pos + 1   # byte right after the \0


def _is_valid_string_pkg_hdr(payload: bytes) -> bool:
    """
    Quick validity check: language tag at offset 42 must be printable ASCII
    with a null terminator, and HdrSize must be sane.
    """
    if len(payload) < 46:
        return False
    hdr_size = u32(payload, 0)
    if hdr_size < 4 or hdr_size > 0x10000:
        return False
    # Language tag at offset 42 must be printable ASCII, null-terminated
    for k in range(42, min(42 + 64, len(payload))):
        b = payload[k]
        if b == 0:
            return k > 42   # at least 1 char before null
        if not (0x20 <= b < 0x7F):
            return False
    return False


def parse_string_package(data: bytes, pkg_offset: int, pkg_len: int) -> Optional[Dict[int, str]]:
    """Parse one string package at data[pkg_offset:pkg_offset+pkg_len]."""
    if pkg_offset + pkg_len > len(data):
        return None
    payload = data[pkg_offset + 4: pkg_offset + pkg_len]

    if not _is_valid_string_pkg_hdr(payload):
        return None

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
            text, pos = _read_null_ucs2(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_UCS2_FONT:
            pos += 1
            text, pos = _read_null_ucs2(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_UCS2:
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_ucs2(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_UCS2_FONT:
            pos += 1
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_ucs2(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_SCSU:
            text, pos = _read_null_scsu(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRING_SCSU_FONT:
            pos += 1
            text, pos = _read_null_scsu(payload, pos)
            string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_SCSU:
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_scsu(payload, pos)
                string_map[sid] = text; sid += 1
        elif block_type == SIBT_STRINGS_SCSU_FONT:
            pos += 1
            if pos + 2 > len(payload): break
            count = u16(payload, pos); pos += 2
            for _ in range(count):
                text, pos = _read_null_scsu(payload, pos)
                string_map[sid] = text; sid += 1
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
            pos += 1   # sub-type
            blen = payload[pos]; pos += 1
            pos += max(0, blen - 3)
        elif block_type == SIBT_EXT2:
            if pos + 3 > len(payload): break
            pos += 1
            blen = u16(payload, pos); pos += 2
            pos += max(0, blen - 4)
        elif block_type == SIBT_EXT4:
            if pos + 5 > len(payload): break
            pos += 1
            blen = u32(payload, pos); pos += 4
            pos += max(0, blen - 6)
        else:
            break  # unknown block, can't determine length

    return string_map if len(string_map) > 1 else None



# HII Form package / IFR opcode parsing
#
# EFI_IFR_OP_HEADER (2 bytes):
#   OpCode  u8        @ byte 0
#   LenScope u8       @ byte 1: bits[6:0]=length (includes 2-byte header), bit[7]=scope


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
    """Return (size_bits, min, max, step) from OneOf/Numeric flags+data."""
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
    """
    The form package's first opcode must be FormSet (0x0E) with scope bit set
    and length >= 24.  Mirrors IFRExtractor-RS hii_form_package_candidate.
    """
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
    """Walk IFR opcodes and emit text lines matching IFRExtractor-RS output."""
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

        # Dedent before End opcode
        if op == IFR_OP_END and scope_depth > 0:
            scope_depth -= 1

        indent = "\t" * scope_depth
        line: Optional[str] = None

        # FormSet
        if op == IFR_OP_FORM_SET and len(opdata) >= 20:
            g    = guid_str(opdata, 0)
            tstr = S(u16(opdata, 16))
            hstr = S(u16(opdata, 18))
            line = f'{indent}FormSet Guid: {g}, Title: "{tstr}", Help: "{hstr}"'

        # Form
        elif op == IFR_OP_FORM and len(opdata) >= 4:
            fid  = u16(opdata, 0)
            tstr = S(u16(opdata, 2))
            line = f'{indent}Form FormId: 0x{fid:X}, Title: "{tstr}"'

        # Subtitle
        elif op == IFR_OP_SUBTITLE and len(opdata) >= 5:
            pstr = S(u16(opdata, 0))
            hstr = S(u16(opdata, 2))
            flg  = opdata[4]
            line = f'{indent}Subtitle Prompt: "{pstr}", Help: "{hstr}", Flags: 0x{flg:X}'

        # Text
        elif op == IFR_OP_TEXT and len(opdata) >= 6:
            pstr = S(u16(opdata, 0))
            hstr = S(u16(opdata, 2))
            tstr = S(u16(opdata, 4))
            line = f'{indent}Text Prompt: "{pstr}", Help: "{hstr}", Text: "{tstr}"'

        # VarStore
        elif op == IFR_OP_VARSTORE and len(opdata) >= 20:
            g    = guid_str(opdata, 0)
            vsid = u16(opdata, 16)
            size = u16(opdata, 18)
            name = opdata[20:].rstrip(b'\x00').decode('ascii', errors='replace')
            line = f'{indent}VarStore Guid: {g}, VarStoreId: 0x{vsid:X}, Size: 0x{size:X}, Name: "{name}"'

        # VarStoreEfi
        elif op == IFR_OP_VARSTORE_EFI and len(opdata) >= 26:
            # EFI_IFR_VARSTORE_EFI layout (UEFI spec):
            #   VarStoreId u16  @ opdata[0]
            #   Guid      (16)  @ opdata[2]
            #   Attributes u32  @ opdata[18]
            #   Size       u16  @ opdata[22]
            #   Name      (var) @ opdata[24]
            vsid  = u16(opdata, 0)
            g     = guid_str(opdata, 2)
            attrs = u32(opdata, 18)
            size  = u16(opdata, 22)
            name  = opdata[24:].rstrip(b'\x00').decode('ascii', errors='replace')
            line  = (f'{indent}VarStoreEfi Guid: {g}, VarStoreId: 0x{vsid:X}, '
                     f'Attributes: 0x{attrs:X}, Size: 0x{size:X}, Name: "{name}"')

        # OneOf
        elif op == IFR_OP_ONE_OF and len(opdata) >= 13:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            sz, mn, mx, st = _parse_min_max_step(opdata, 11)
            line = (f'{indent}OneOf Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{opdata[11]:X}, Size: {sz}, '
                    f'Min: 0x{mn:X}, Max: 0x{mx:X}, Step: 0x{st:X}')

        # CheckBox
        elif op == IFR_OP_CHECKBOX and len(opdata) >= 12:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            cflags = u8(opdata, 11)
            dflt   = "Enabled" if (cflags & 0x01) else "Disabled"
            mfgd   = "Enabled" if (cflags & 0x02) else "Disabled"
            line = (f'{indent}CheckBox Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{cflags:X}, Default: {dflt}, MfgDefault: {mfgd}')

        # Numeric
        elif op == IFR_OP_NUMERIC and len(opdata) >= 13:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            sz, mn, mx, st = _parse_min_max_step(opdata, 11)
            line = (f'{indent}Numeric Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}, '
                    f'Flags: 0x{opdata[11]:X}, Size: {sz}, '
                    f'Min: 0x{mn:X}, Max: 0x{mx:X}, Step: 0x{st:X}')

        # OneOfOption
        elif op == IFR_OP_ONE_OF_OPT and len(opdata) >= 7:
            ostr   = S(u16(opdata, 0))
            oflags = opdata[2]
            val_hex = opdata[4:12].hex().upper()
            dflt   = ", Default"    if (oflags & 0x10) else ""
            mfgd   = ", MfgDefault" if (oflags & 0x20) else ""
            line = f'{indent}OneOfOption Option: "{ostr}", Value: 0x{val_hex}{dflt}{mfgd}'

        # DefaultStore
        elif op == IFR_OP_DEFAULTSTORE and len(opdata) >= 4:
            nstr  = S(u16(opdata, 0))
            defid = u16(opdata, 2)
            line  = f'{indent}DefaultStore Name: "{nstr}", DefaultId: 0x{defid:X}'

        # Default
        elif op == IFR_OP_DEFAULT and len(opdata) >= 3:
            defid = u16(opdata, 0)
            dtype = opdata[2]
            line  = f'{indent}Default DefaultId: 0x{defid:X}, Type: 0x{dtype:X}'

        # Action
        elif op == IFR_OP_ACTION and len(opdata) >= 11:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            line = (f'{indent}Action Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}')

        # Ref
        elif op == IFR_OP_REF and len(opdata) >= 11:
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            # FormId is in extended ref (opdata[11..12]) if present
            fid    = u16(opdata, 11) if len(opdata) >= 13 else 0
            line   = (f'{indent}Ref Prompt: "{pstr}", Help: "{hstr}", '
                      f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                      f'FormId: 0x{fid:X}')

        # Date - Time - String
        elif op in (IFR_OP_DATE, IFR_OP_TIME, IFR_OP_STRING_OP) and len(opdata) >= 11:
            name_map = {IFR_OP_DATE: "Date", IFR_OP_TIME: "Time", IFR_OP_STRING_OP: "String"}
            pstr   = S(u16(opdata, 0))
            hstr   = S(u16(opdata, 2))
            qid    = u16(opdata, 4)
            vsid   = u16(opdata, 6)
            vsoff  = u16(opdata, 8)
            qflags = u8(opdata, 10)
            line = (f'{indent}{name_map[op]} Prompt: "{pstr}", Help: "{hstr}", '
                    f'QuestionFlags: 0x{qflags:X}, QuestionId: 0x{qid:X}, '
                    f'VarStoreId: 0x{vsid:X}, VarOffset: 0x{vsoff:X}')

        # opcodes
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



# Top-level scanner
#
# KEY INSIGHT from IFRExtractor-RS source (main.rs):
#   It does NOT look for EFI_HII_PACKAGE_LIST_HEADER.
#   It walks byte-by-byte calling hii_string_package_candidate and
#   hii_form_package_candidate at every position, validating structural
#   properties directly.  No package list wrapper required.


PKG_TYPE_FORMS  = 0x02
PKG_TYPE_STRING = 0x04


def find_packages(data: bytes) -> Tuple[List[Tuple[int,int,Dict[int,str]]], List[Tuple[int,int]]]:
    """
    Byte-by-byte scan for HII string and form packages.
    Returns:
        string_pkgs: [(offset, length, string_map), ...]
        form_pkgs:   [(offset, length), ...]
    """
    string_pkgs: List[Tuple[int,int,Dict[int,str]]] = []
    form_pkgs:   List[Tuple[int,int]]               = []
    n = len(data)
    i = 0
    while i < n - 4:
        raw   = u32(data, i)
        ptype = (raw >> 24) & 0xFF
        plen  =  raw & 0x00FFFFFF

        if plen >= 4 and i + plen <= n:
            if ptype == PKG_TYPE_STRING and plen >= 50:
                smap = parse_string_package(data, i, plen)
                if smap is not None:
                    string_pkgs.append((i, plen, smap))
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
    print(f"[*] Scanning {len(data):,} bytes for HII packages...")

    string_pkgs, form_pkgs = find_packages(data)
    print(f"[+] Found {len(string_pkgs)} string package(s), {len(form_pkgs)} form package(s)")

    if not form_pkgs:
        print(f"\n{C_ERR}[!] No form packages found.{C_RST}")
        print("    Try extracting the Setup module from the firmware with UEFITool first.")
        sys.exit(1)

    if not string_pkgs:
        print(f"{C_WARN}[!] No string packages found — settings will show as <str#N>{C_RST}")

    best_strings: Dict[int, str] = {}
    if string_pkgs:
        best_strings = max(string_pkgs, key=lambda x: len(x[2]))[2]
        print(f"[+] Using string package with {len(best_strings)} strings")

    all_lines: List[str] = []
    for idx, (off, plen) in enumerate(form_pkgs):
        lines = parse_form_package(data, off, plen, best_strings)
        all_lines.extend(lines)
        if DEBUG:
            print(f"    Form package {idx}: offset={off:#x}, length={plen:#x}, lines={len(lines)}")

    return "\n".join(all_lines)



# VarStore + setting parsing


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
    for m in _RE_VARSTORE.finditer(ifr_text):
        guid  = m.group(1).upper()
        vsid  = int(m.group(2), 16)
        attrs = int(m.group(3), 16) if m.group(3) else 0x7
        size  = int(m.group(4), 16) if m.group(4) else 0
        name  = m.group(5) or ""
        stores[vsid] = VarStore(guid=guid, var_store_id=vsid,
                                attributes=attrs, size=size, name=name)
    return stores


def grep_settings(ifr_text: str, terms: List[str]) -> List[HiiSetting]:
    results: List[HiiSetting] = []
    seen: Set[Tuple] = set()
    for m in _RE_SETTING.finditer(ifr_text):
        widget    = m.group(1)
        prompt    = m.group(2)
        help_text = m.group(3) or ""
        q_flags   = int(m.group(4), 16)
        q_id      = int(m.group(5), 16)
        vs_id     = int(m.group(6), 16)
        vs_off    = int(m.group(7), 16)
        flags     = int(m.group(8), 16)
        size      = int(m.group(9))       if m.group(9)  else 8
        min_v     = int(m.group(10), 16)  if m.group(10) else 0
        max_v     = int(m.group(11), 16)  if m.group(11) else 1
        step      = int(m.group(12), 16)  if m.group(12) else 0

        if terms and terms != [""] and not any(t.lower() in (prompt + " " + help_text).lower() for t in terms):
            continue
        key = (q_id, vs_id, vs_off)
        if key in seen:
            continue
        seen.add(key)
        results.append(HiiSetting(
            widget_type=widget, prompt=prompt, help_text=help_text,
            question_flags=q_flags, question_id=q_id,
            var_store_id=vs_id, var_offset=vs_off,
            flags=flags, size=size, min_val=min_v, max_val=max_v, step=step,
        ))
    return results


# NVRAM parsing  (VSS variable store)

VAR_HDR_MAGIC = 0x55AA


def _guid_str_to_bytes(gs: str) -> bytes:
    parts = gs.replace("-", "")
    a = int(parts[0:8],  16)
    b = int(parts[8:12], 16)
    c = int(parts[12:16],16)
    d = bytes.fromhex(parts[16:20])
    e = bytes.fromhex(parts[20:32])
    return struct.pack("<IHH", a, b, c) + d + e


def find_nvram_value(nvram: bytes, guid_str_val: str, var_offset: int, size_bits: int,
                     var_name: str = "") -> Optional[int]:
    """
    Scan NVRAM for a variable matching guid_str_val AND var_name.
    For each GUID hit: read the UTF-16LE name that follows, compare to var_name,
    and only read data from the matching entry.
    """
    target     = _guid_str_to_bytes(guid_str_val)
    size_bytes = max(1, size_bits // 8)
    n          = len(nvram)

    search_pos = 0
    while search_pos < n - 16:
        guid_pos = nvram.find(target, search_pos)
        if guid_pos < 0:
            break
        search_pos = guid_pos + 1

        # Read the UTF-16LE name that follows the GUID
        pos = guid_pos + 16
        name_chars = []
        while pos + 1 < n:
            lo, hi = nvram[pos], nvram[pos + 1]
            pos += 2
            if lo == 0 and hi == 0:
                break
            name_chars.append(chr(lo) if hi == 0 else "?")
        found_name = "".join(name_chars)

        # If a var_name was supplied, skip entries that don't match
        if var_name and found_name != var_name:
            continue

        # pos now points at the first data byte
        data_off = pos
        if data_off + var_offset + size_bytes > n:
            continue

        raw = nvram[data_off + var_offset: data_off + var_offset + size_bytes]
        fmt = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(size_bytes, "B")
        try:
            return struct.unpack(fmt, raw)[0]
        except struct.error:
            continue

    return None


def write_nvram_value(nvram_path: str, guid_str_val: str, var_name: str,
                      var_offset: int, size_bits: int, new_value: int) -> bool:
    """
    Write new_value at var_offset inside the named NVRAM variable.
    Modifies the file in-place.
    """
    nvram = Path(nvram_path).read_bytes()
    target = _guid_str_to_bytes(guid_str_val)
    size_bytes = max(1, size_bits // 8)
    n = len(nvram)

    search_pos = 0
    while search_pos < n - 16:
        guid_pos = nvram.find(target, search_pos)
        if guid_pos < 0:
            break
        search_pos = guid_pos + 1

        pos = guid_pos + 16
        name_chars = []
        while pos + 1 < n:
            lo, hi = nvram[pos], nvram[pos + 1]
            pos += 2
            if lo == 0 and hi == 0:
                break
            name_chars.append(chr(lo) if hi == 0 else "?")
        found_name = "".join(name_chars)

        if found_name != var_name:
            continue

        data_off = pos
        write_off = data_off + var_offset
        if write_off + size_bytes > n:
            return False

        fmt = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(size_bytes, "B")
        packed = struct.pack(fmt, new_value)
        buf = bytearray(nvram)
        buf[write_off: write_off + size_bytes] = packed
        Path(nvram_path).write_bytes(bytes(buf))
        return True

    return False



# Reverse lookup , find all settings that map to a given GUID + key name

def reverse_lookup(ifr_text: str, stores: Dict[int, VarStore],
                   guid: str, key_name: str) -> List[HiiSetting]:
    """Return all HiiSettings whose VarStore matches guid+key_name."""
    guid = guid.upper()
    # Find the VarStoreId(s) that correspond to this guid+name
    matching_vsids = {
        vsid for vsid, vs in stores.items()
        if vs.guid.upper() == guid and vs.name == key_name
    }
    if not matching_vsids:
        return []
    # Get all settings for those VarStoreIds (no term filter)
    results: List[HiiSetting] = []
    seen: Set[Tuple] = set()
    for m in _RE_SETTING.finditer(ifr_text):
        widget    = m.group(1)
        prompt    = m.group(2)
        help_text = m.group(3) or ""
        q_flags   = int(m.group(4), 16)
        q_id      = int(m.group(5), 16)
        vs_id     = int(m.group(6), 16)
        vs_off    = int(m.group(7), 16)
        flags     = int(m.group(8), 16)
        size      = int(m.group(9))       if m.group(9)  else 8
        min_v     = int(m.group(10), 16)  if m.group(10) else 0
        max_v     = int(m.group(11), 16)  if m.group(11) else 1
        step      = int(m.group(12), 16)  if m.group(12) else 0
        if vs_id not in matching_vsids:
            continue
        key = (q_id, vs_id, vs_off)
        if key in seen:
            continue
        seen.add(key)
        s = HiiSetting(widget_type=widget, prompt=prompt, help_text=help_text,
                       question_flags=q_flags, question_id=q_id,
                       var_store_id=vs_id, var_offset=vs_off,
                       flags=flags, size=size, min_val=min_v, max_val=max_v, step=step)
        s.var_store = stores.get(vs_id)
        results.append(s)
    return results


# printing tables

def _col_w(rows: List[List[str]], headers: List[str]) -> List[int]:
    w = [len(h) for h in headers]
    for row in rows:
        for i, c in enumerate(row):
            if i < len(w):
                w[i] = max(w[i], len(c))
    return w

def _hdr(text: str) -> str:
    """Simple section header — used by _do_dump_var and legacy callers."""
    return f"\n{C_HEAD}{text}{C_RST}\n{'─' * len(text)}"

def _box(title: str, lines: List[str]) -> None:
    """Print a titled box around a block of lines."""
    width = max(len(title) + 4, max((len(l) for l in lines), default=0) + 4)
    bar   = "─" * width
    print(f"\n{C_HEAD}┌{bar}┐")
    pad   = width - len(title) - 2
    print(f"│ {title}{' ' * pad} │")
    print(f"├{bar}┤{C_RST}")
    for l in lines:
        pad = width - len(l) - 2
        print(f"  {l}")
    print(f"{C_HEAD}└{bar}┘{C_RST}")

def print_table(headers: List[str], rows: List[List], title: str = "") -> None:
    rs  = [[str(c) for c in row] for row in rows]
    w   = _col_w(rs, headers)
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    sep = "  ".join("─" * x for x in w)
    table_lines = [fmt.format(*headers), sep] + [fmt.format(*row) for row in rs]
    if title:
        _box(title, table_lines)
    else:
        for l in table_lines:
            print(l)
    print()

def _fmt_value(val: Optional[int], size_bits: int) -> str:
    """Format a value with the correct hex width for its size."""
    if val is None:
        return "NOT FOUND"
    size_bytes = max(1, size_bits // 8)
    hex_digits = size_bytes * 2
    return f"0x{val:0{hex_digits}X}"


def print_settings_table(settings: List[HiiSetting], stores: Dict[int, VarStore],
                          title: str = "SETTINGS") -> None:
    rows = []
    for i, s in enumerate(settings):
        vs = stores.get(s.var_store_id)
        store_name = vs.name if vs else f"0x{s.var_store_id:X}"
        setting_name = s.prompt if len(s.prompt) <= 44 else s.prompt[:43] + "\u2026"
        val_str = _fmt_value(s.current_value, s.size)
        rows.append([str(i + 1), setting_name, store_name,
                     f"0x{s.var_offset:X}", val_str])
    headers = ["#", "Setting", "Store", "Offset", "Value"]
    rs = [[str(c) for c in row] for row in rows]
    w  = _col_w(rs, headers)
    fmt = "  ".join(f"{{:<{x}}}" for x in w)
    sep = "  ".join("─" * x for x in w)
    table_lines = [fmt.format(*headers), sep]
    for row in rs:
        line = fmt.format(*row)
        val = row[4]
        if val == "NOT FOUND":
            line = line.replace(val, f"{C_WARN}{val}{C_RST}", 1)
        else:
            line = line.replace(val, f"{C_OK}{val}{C_RST}", 1)
        table_lines.append(line)
    _box(title, table_lines)
    print()


def print_varstore_map(settings: List[HiiSetting], stores: Dict[int, VarStore]) -> None:
    rows = []
    seen: Set[int] = set()
    for s in settings:
        if s.var_store_id in seen:
            continue
        seen.add(s.var_store_id)
        vs = stores.get(s.var_store_id)
        if vs:
            rows.append([vs.name, vs.guid, f"0x{vs.size:X}"])
        else:
            rows.append([f"0x{s.var_store_id:X}", "?", "?"])
    print_table(["Store", "GUID", "Size"], rows, title="VARSTORE  →  GUID")


# Extra EFI scanner, for complex relationships that involve multiple EFI programs

def scan_extra_varstores(paths: List[str]) -> Dict[int, VarStore]:
    """
    Scan one or more extra EFI files for VarStore / VarStoreEfi opcode definitions.
    These are returned as a VarStore dict that can be merged with the main one.
    Strings are not needed — we only care about the opcode field values.
    """
    empty_strings: Dict[int, str] = {}
    combined: Dict[int, VarStore] = {}

    for path in paths:
        if not os.path.isfile(path):
            print(f"{C_WARN}[!] Extra EFI not found, skipping: {path}{C_RST}")
            continue
        data = Path(path).read_bytes()
        _, form_pkgs = find_packages(data)
        if not form_pkgs:
            if DEBUG: print(f"{C_WARN}[!] No form packages in: {path}{C_RST}")
            continue
        for off, plen in form_pkgs:
            lines = parse_form_package(data, off, plen, empty_strings)
            ifr_chunk = "\n".join(lines)
            stores = parse_varstores(ifr_chunk)
            combined.update(stores)
        if DEBUG:
            print(f"[+] Extra EFI {os.path.basename(path)}: {len(form_pkgs)} form pkg(s), {len(combined)} VarStore(s) so far")

    return combined


# --------------- MAIN -------------------

def _load_ifr_and_stores(efi: str, extra_efi: List[str], dump_ifr: Optional[str]):
    """Shared setup: extract IFR, build VarStore map."""
    ifr_text = extract_ifr(efi)
    if dump_ifr:
        Path(dump_ifr).write_text(ifr_text, encoding="utf-8")
        if DEBUG:
            print(f"[+] IFR text saved to: {dump_ifr}")

    stores = parse_varstores(ifr_text)

    if extra_efi:
        extra = scan_extra_varstores(extra_efi)
        before = len(stores)
        stores.update(extra)
        if DEBUG:
            print(f"[+] {before} VarStore(s) in EFI + {len(extra)} from extras = {len(stores)} total.")
    else:
        efi_dir  = os.path.dirname(os.path.abspath(efi))
        efi_name = os.path.basename(efi)
        siblings = [os.path.join(efi_dir, f) for f in os.listdir(efi_dir)
                    if f != efi_name and f.endswith(".efi")
                    and os.path.isfile(os.path.join(efi_dir, f))]
        if siblings:
            extra = scan_extra_varstores(siblings)
            before = len(stores)
            stores.update(extra)
            if DEBUG and len(stores) > before:
                print(f"[+] Merged {len(stores)-before} additional VarStore(s) from siblings.")

    return ifr_text, stores


def main() -> None:
    epilog = """
EXAMPLE USAGE:\n
  Mode 1 — Map EFI settings to NVRAM variables (search by keyword):
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms VT-d,IOMMU
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms DMA --modify
    nvramap.py -mode 1 -efi Setup.efi -nvram NVRAM.bin -terms DMA --set 2 0x1

  Mode 2 — Map NVRAM variables to EFI settings (reverse lookup by GUID + key):
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid FB3B9ECE-4ABA-4933-B49D-B4D67D892351 -key HpDmarOptions
    nvramap.py -mode 2 -efi Setup.efi -nvram NVRAM.bin -guid <GUID> -key <KeyName> --modify
"""
    ap = argparse.ArgumentParser(
        prog="nvramap.py",
        description=(
            "NVRAMap — UEFI NVRAM Mapper & Editor\n"
            "\n"
            "  Parses HII form data from any UEFI EFI module and maps firmware\n"
            "  settings to their NVRAM variable store locations. Supports reading\n"
            "  and writing live values in raw NVRAM binary blobs.\n"
            "\n"
            "  Mode 1: Map EFI Settings  →  NVRAM Variables  (search by keyword)\n"
            "  Mode 2: Map NVRAM Variables  →  EFI Settings  (reverse, by GUID+key)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    req = ap.add_argument_group("required arguments")
    req.add_argument("-mode", required=True, choices=["1", "2"],
                    metavar="MODE",
                    help="Operation mode: 1 = EFI→NVRAM  |  2 = NVRAM→EFI")
    req.add_argument("-efi",  required=True, metavar="FILE",
                    help="Path to EFI module containing HII form data")
    req.add_argument("-nvram", required=True, metavar="FILE",
                    help="Path to raw NVRAM binary blob")

    m1 = ap.add_argument_group("mode 1 options")
    m1.add_argument("-terms", "-t", default=None, metavar="TERMS",
                    help="Comma-separated search terms  e.g. VT-d,IOMMU,DMA")
    m1.add_argument("-all", action="store_true",
                    help="Dump every setting in the EFI (no search filter)")

    m2 = ap.add_argument_group("mode 2 options")
    m2.add_argument("-guid", default=None, metavar="GUID",
                    help="VarStore GUID  e.g. FB3B9ECE-4ABA-4933-B49D-B4D67D892351")
    m2.add_argument("-key",  default=None, metavar="NAME",
                    help="NVRAM variable name  e.g. HpDmarOptions")

    opt = ap.add_argument_group("options")
    opt.add_argument("--modify", action="store_true",
                    help="Interactive edit mode — select and modify values after display")
    opt.add_argument("--set", nargs=2, metavar=("INDEX", "VALUE"),
                    help="Non-interactive write: set setting [INDEX] to VALUE (0x.. or decimal)")
    opt.add_argument("--extra-efi", nargs="+", default=[], metavar="FILE",
                    help="Additional EFI files to scan for VarStore GUID definitions")
    opt.add_argument("--dump-ifr", default=None, metavar="FILE",
                    help="Save full extracted IFR text to FILE")
    opt.add_argument("--dump-var", default=None, metavar="GUID",
                    help="Debug: dump all raw NVRAM entries for a given GUID")
    opt.add_argument("--debug", action="store_true",
                    help="Verbose parsing output")

    args = ap.parse_args()

    global DEBUG
    DEBUG = args.debug

    print(BANNER)

    # Mode specific args
    if args.mode == "1" and not args.terms and not getattr(args, 'all', False):
        ap.error("Mode 1 requires either -terms KEYWORD or -all")
    if args.mode == "2" and (not args.guid or not args.key):
        ap.error("Mode 2 requires both -guid and -key")

    for path, label in [(args.efi, "-efi"), (args.nvram, "-nvram")]:
        if not os.path.isfile(path):
            sys.exit(f"{C_ERR}[!] File not found: {label} {path}{C_RST}")

    # Load IFR
    ifr_text, stores = _load_ifr_and_stores(args.efi, args.extra_efi, args.dump_ifr)

    # Load NVRAM
    nvram_bytes = Path(args.nvram).read_bytes()
    print(f"[+] NVRAM: {len(nvram_bytes):,} bytes")
    print("[+] Performing analysis...\n")

    # dump var
    if args.dump_var:
        _do_dump_var(nvram_bytes, args.dump_var.upper())

    # get settings
    if args.mode == "1":
        if getattr(args, 'all', False):
            settings = grep_settings(ifr_text, [""])   # empty string matches everything
            title = "MODE 1  —  EFI Settings → NVRAM  (all)"
        else:
            terms = [t.strip() for t in args.terms.split(",") if t.strip()]
            settings = grep_settings(ifr_text, terms)
            title = f"MODE 1  —  EFI Settings → NVRAM  ({args.terms})"
        if not settings:
            sys.exit(f"{C_WARN}[!] No settings found{C_RST}")
        for s in settings:
            s.var_store = stores.get(s.var_store_id)

    else:  # mode 2
        settings = reverse_lookup(ifr_text, stores, args.guid, args.key)
        if not settings:
            sys.exit(f"{C_WARN}[!] No settings found for GUID={args.guid}  Key={args.key}{C_RST}")
        title = f"MODE 2  —  NVRAM → EFI Settings  |  {args.key}  ({args.guid})"

    # read NVRAM values
    for s in settings:
        vs = stores.get(s.var_store_id)
        if vs and vs.guid and vs.guid != "?":
            s.current_value = find_nvram_value(
                nvram_bytes, vs.guid, s.var_offset, s.size, var_name=vs.name)

    print_varstore_map(settings, stores)
    print_settings_table(settings, stores, title=title)


    # Modification logic
    do_modify = args.modify
    set_arg   = args.set

    def _parse_val(raw_val: str) -> int:
        raw_val = raw_val.strip()
        if raw_val.lower().startswith("0x"):
            return int(raw_val, 16)
        return int(raw_val)

    def _apply_change(idx: int, new_val: int, patched: bytearray) -> bool:
        """Write new_val into patched buffer at the correct offset for settings[idx]."""
        s  = settings[idx]
        vs = stores.get(s.var_store_id)
        if not vs:
            print(f"  {C_ERR}No VarStore for setting {idx+1}.{C_RST}")
            return False
        target = _guid_str_to_bytes(vs.guid)
        size_bytes = max(1, s.size // 8)
        n = len(patched)
        search_pos = 0
        while search_pos < n - 16:
            guid_pos = bytes(patched).find(target, search_pos)
            if guid_pos < 0:
                break
            search_pos = guid_pos + 1
            pos = guid_pos + 16
            name_chars = []
            while pos + 1 < n:
                lo, hi = patched[pos], patched[pos+1]; pos += 2
                if lo == 0 and hi == 0: break
                name_chars.append(chr(lo) if hi == 0 else "?")
            if "".join(name_chars) != vs.name:
                continue
            write_off = pos + s.var_offset
            if write_off + size_bytes > n:
                print(f"  {C_ERR}Offset out of bounds.{C_RST}")
                return False
            fmt_s = {1:"B", 2:"<H", 4:"<I", 8:"<Q"}.get(size_bytes, "B")
            packed = struct.pack(fmt_s, new_val)
            patched[write_off: write_off + size_bytes] = packed
            s.current_value = new_val
            return True
        print(f"  {C_ERR}Variable not found in NVRAM buffer.{C_RST}")
        return False

    # Work on an in-memory buffer; only write file at the end
    patched = bytearray(nvram_bytes)
    changes: List[str] = []

    if set_arg:
        try:
            idx     = int(set_arg[0]) - 1
            new_val = _parse_val(set_arg[1])
        except (ValueError, IndexError):
            sys.exit(f"{C_ERR}Invalid --set arguments.{C_RST}")
        if not (0 <= idx < len(settings)):
            sys.exit(f"{C_ERR}Index {idx+1} out of range (1–{len(settings)}).{C_RST}")
        if _apply_change(idx, new_val, patched):
            s = settings[idx]
            changes.append(f"[{idx+1}] {s.prompt}  →  {_fmt_value(new_val, s.size)}")
            print(f"  {C_OK}Set [{idx+1}] {s.prompt} = {_fmt_value(new_val, s.size)}{C_RST}")

    elif do_modify:
        print("  Modify mode — select a setting by number, 'done' to save, 'q' to quit without saving.")
        print()
        while True:
            # Reprint table with current values
            print_settings_table(settings, stores, title="Current Values")
            try:
                raw = input("  >> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                raw = "q"

            if raw in ("q", "quit"):
                print("  Aborted — no changes written.")
                return
            if raw in ("done", "d", ""):
                break

            try:
                idx = int(raw) - 1
            except ValueError:
                print("  Enter a number.\n"); continue
            if not (0 <= idx < len(settings)):
                print(f"  Out of range (1–{len(settings)}).\\n"); continue

            s  = settings[idx]
            vs = stores.get(s.var_store_id)
            cur = _fmt_value(s.current_value, s.size)
            print(f"\n  [{idx+1}] {s.prompt}")
            print(f"       Current : {cur}")
            print(f"       Range   : 0x{s.min_val:X} – 0x{s.max_val:X}")
            try:
                raw_val = input("  New value (hex 0x.. or decimal, blank to skip): ").strip()
                if not raw_val:
                    print("  Skipped.\n"); continue
                new_val = _parse_val(raw_val)
            except (ValueError, EOFError, KeyboardInterrupt):
                print("  Cancelled.\n"); continue
            if not (s.min_val <= new_val <= s.max_val):
                print(f"  {C_WARN}Warning: outside valid range.{C_RST}")
            if _apply_change(idx, new_val, patched):
                changes.append(f"[{idx+1}] {s.prompt}  →  {_fmt_value(new_val, s.size)}")
                print(f"  {C_OK}New Value: {_fmt_value(new_val, s.size)}{C_RST}\n")

    # Save patched nvram file
    if changes:
        nvram_p   = Path(args.nvram)
        out_path  = nvram_p.parent / (nvram_p.stem + "_patched" + nvram_p.suffix)
        out_path.write_bytes(bytes(patched))
        print(f"\n{C_OK}  Saved patched NVRAM → {out_path}{C_RST}")
        print(f"  Changes applied:")
        for c in changes:
            print(f"    {c}")
        print()


def _do_dump_var(nvram: bytes, dump_guid: str) -> None:
    try:
        target = _guid_str_to_bytes(dump_guid)
    except Exception:
        print(f"{C_ERR}Invalid GUID: {dump_guid}{C_RST}")
        return

    print(_hdr(f"NVRAM VAR DUMP  {dump_guid}"))
    search, match_n = 0, 0
    n = len(nvram)
    while search < n - 16:
        gi = nvram.find(target, search)
        if gi < 0: break
        search = gi + 1
        match_n += 1

        hdr = gi
        while hdr > max(0, gi - 256):
            if nvram[hdr] == 0xAA and nvram[hdr+1] == 0x55: break
            hdr -= 1

        print(f"\n  Match {match_n}:  GUID@{gi:#x}  AA55@{hdr:#x}")
        chunk = nvram[hdr:hdr+80]
        for row in range(0, len(chunk), 16):
            hp = " ".join(f"{chunk[row+k]:02X}" for k in range(16) if row+k < len(chunk))
            print(f"    {hdr+row:08X}:  {hp}")

        p = gi + 16
        name_chars = []
        while p + 1 < n:
            lo, hi = nvram[p], nvram[p+1]; p += 2
            if lo == 0 and hi == 0: break
            name_chars.append(chr(lo) if hi == 0 else "?")
        name = "".join(name_chars)
        print(f"\n  Key: '{name}'   data @ {p:#x}")

        next_hdr = n
        for np in range(p+2, min(p+0x10000, n-1)):
            if nvram[np] == 0xAA and nvram[np+1] == 0x55:
                next_hdr = np; break
        db = nvram[p:next_hdr]
        print(f"  Data ({len(db):#x} bytes):")
        print("  off:  " + "  ".join(f"{k:02X}" for k in range(16)))
        print("  ----  " + "  ".join("--" for _ in range(16)))
        for row in range(0, min(len(db), 64), 16):
            vs = "  ".join(f"{db[row+k]:02X}" for k in range(16) if row+k < len(db))
            print(f"  {row:04X}:  {vs}")

    if match_n == 0:
        print("  GUID not found.")
    print()


if __name__ == "__main__":
    main()
