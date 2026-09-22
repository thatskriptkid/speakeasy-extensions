#!/usr/bin/env python3
"""Static PE classification for fast EXE/DLL/SYS triage. No emulation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


IMAGE_FILE_DLL = 0x2000
IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 64
MAX_IMPORTS_PER_DLL = 32
MAX_EXPORTS = 128
ORDINAL_FLAG32 = 0x80000000
ORDINAL_FLAG64 = 0x8000000000000000

MACHINES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
SUBSYSTEMS = {
    0: "unknown",
    IMAGE_SUBSYSTEM_NATIVE: "native",
    IMAGE_SUBSYSTEM_WINDOWS_GUI: "windows_gui",
    IMAGE_SUBSYSTEM_WINDOWS_CUI: "windows_cui",
    9: "efi_application",
    10: "efi_boot",
    16: "efi_runtime",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 8], "little")


def _cstr(data: bytes, offset: int | None, limit: int = 260) -> str:
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    raw = data[offset:end]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return ""
    if not text or any(ord(ch) < 32 or ord(ch) > 126 for ch in text):
        return ""
    return text


def rva_to_offset(sections: list[dict[str, int]], rva: int, size: int = 1) -> int | None:
    if rva < 0 or size < 1:
        return None
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if span <= 0 or not (start <= rva < start + span):
            continue
        delta = rva - start
        raw_ptr = section["raw_ptr"]
        raw_size = section["raw_size"]
        if raw_ptr <= 0 or delta + size > raw_size:
            return None
        return raw_ptr + delta
    return None


def _read_sections(data: bytes, table: int, count: int) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for index in range(min(count, MAX_SECTIONS)):
        off = table + index * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = _u32(data, off + 8) or 0
        virtual_address = _u32(data, off + 12) or 0
        raw_size = _u32(data, off + 16) or 0
        raw_ptr = _u32(data, off + 20) or 0
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
            }
        )
    return sections


def _imports(data: bytes, sections: list[dict[str, int]], rva: int, size: int, pe32plus: bool) -> list[dict[str, Any]]:
    if rva <= 0 or size < 20:
        return []
    off = rva_to_offset(sections, rva, 20)
    if off is None:
        return []
    dlls: list[dict[str, Any]] = []
    ptr = 8 if pe32plus else 4
    ordinal_flag = ORDINAL_FLAG64 if pe32plus else ORDINAL_FLAG32
    for _ in range(MAX_IMPORT_DLLS):
        if off + 20 > len(data):
            break
        original = _u32(data, off) or 0
        name_rva = _u32(data, off + 12) or 0
        first_thunk = _u32(data, off + 16) or 0
        if original == 0 and name_rva == 0 and first_thunk == 0:
            break
        name_off = rva_to_offset(sections, name_rva, 1)
        dll_name = _cstr(data, name_off)
        thunk_rva = original or first_thunk
        names: list[str] = []
        thunk_off = rva_to_offset(sections, thunk_rva, ptr) if thunk_rva else None
        if thunk_off is not None:
            for slot in range(MAX_IMPORTS_PER_DLL):
                entry_off = thunk_off + slot * ptr
                entry = _u64(data, entry_off) if pe32plus else _u32(data, entry_off)
                if not entry:
                    break
                if entry & ordinal_flag:
                    names.append(f"#{entry & 0xFFFF}")
                    continue
                hint_off = rva_to_offset(sections, entry & 0xFFFFFFFF, 3)
                names.append(_cstr(data, None if hint_off is None else hint_off + 2) or f"rva_{entry & 0xFFFFFFFF:x}")
        dlls.append({"dll": dll_name or f"rva_{name_rva:x}", "imports": names})
        off += 20
    return dlls


def _exports(data: bytes, sections: list[dict[str, int]], rva: int, size: int) -> tuple[list[str], bool]:
    if rva <= 0 or size < 40:
        return [], False
    off = rva_to_offset(sections, rva, 40)
    if off is None:
        return [], False
    count = _u32(data, off + 24) or 0
    names_rva = _u32(data, off + 32) or 0
    names_off = rva_to_offset(sections, names_rva, 4) if names_rva else None
    if names_off is None or count <= 0:
        return [], False
    found: list[str] = []
    for index in range(min(count, MAX_EXPORTS)):
        name_rva = _u32(data, names_off + index * 4)
        if not name_rva:
            continue
        name = _cstr(data, rva_to_offset(sections, name_rva, 1))
        if name:
            found.append(name)
    return found, count > MAX_EXPORTS


def parse_pe(data: bytes, filename: str = "") -> dict[str, Any] | None:
    """Return static facts for an EXE, DLL, or SYS image, or None when data is not a PE."""

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew is None or e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    machine = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    optional_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    if None in (machine, section_count, timestamp, optional_size, characteristics):
        return None
    optional = coff + 20
    if optional_size < 96 or optional + optional_size > len(data):
        return None
    magic = _u16(data, optional)
    if magic == 0x20B:
        pe32plus = True
        image_base = _u64(data, optional + 24)
        dir_count_off = optional + 108
        dir_off = optional + 112
    elif magic == 0x10B:
        pe32plus = False
        image_base = _u32(data, optional + 28)
        dir_count_off = optional + 92
        dir_off = optional + 96
    else:
        return None
    entry_rva = _u32(data, optional + 16) or 0
    subsystem = _u16(data, optional + 68) or 0
    if image_base is None:
        return None
    sections = _read_sections(data, optional + optional_size, section_count or 0)
    section_rows = [
        {
            "name": item["name"],
            "virtual_address": item["virtual_address"],
            "virtual_size": item["virtual_size"],
            "raw_size": item["raw_size"],
        }
        for item in sections
    ]
    directories = _data_directories(data, dir_off, _u32(data, dir_count_off) or 0)
    export_rva, export_size = directories.get(0, (0, 0))
    import_rva, import_size = directories.get(1, (0, 0))
    com_rva, com_size = directories.get(14, (0, 0))
    suffix = Path(filename).suffix.lower()
    is_dll = bool(characteristics & IMAGE_FILE_DLL)
    is_native = subsystem == IMAGE_SUBSYSTEM_NATIVE
    if suffix == ".sys" or (is_native and not is_dll):
        kind = "sys"
    elif is_dll:
        kind = "dll"
    else:
        kind = "exe"
    export_names, export_truncated = _exports(data, sections, export_rva, export_size)
    return {
        "kind": kind,
        "arch": MACHINES.get(machine, hex(machine)),
        "machine": machine,
        "magic": "pe32+" if pe32plus else "pe32",
        "subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
        "subsystem_id": subsystem,
        "characteristics": characteristics,
        "dll": is_dll,
        "image_base": image_base,
        "entry_rva": entry_rva,
        "timestamp": timestamp,
        "section_count": len(sections),
        "sections": section_rows,
        "imports": _imports(data, sections, import_rva, import_size, pe32plus),
        "exports": export_names,
        "dotnet": bool(com_rva and com_size),
        "export_count_truncated": export_truncated,
    }


def _data_directories(data: bytes, offset: int, count: int) -> dict[int, tuple[int, int]]:
    found: dict[int, tuple[int, int]] = {}
    for index in range(min(count, 16)):
        rva = _u32(data, offset + index * 8)
        size = _u32(data, offset + index * 8 + 4)
        if rva is None or size is None:
            break
        found[index] = (rva, size)
    return found


def entry_mode(kind: str, *, raw: bool = False, all_exports: bool = False) -> str:
    if raw or kind == "shellcode":
        return "shellcode"
    if kind == "dll":
        return "all_exports" if all_exports else "DllMain"
    if kind == "sys":
        return "DriverEntry+exports" if all_exports else "DriverEntry"
    if all_exports:
        return "entry_point+exports"
    return "entry_point"
