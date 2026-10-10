"""
ELF64 Parser tailored for FreeBSD and Prospero OS binaries.
Detects segment permissions, XOM (Execute-Only Memory) enforcement, and program headers.
"""

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple


# Program header types
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_SCE_DYNLIBDATA = 0x61000000  # Sony Proprietary
PT_SCE_PROGLST = 0x61000001
PT_SCE_RELA = 0x61000010
PT_SCE_COMMENT = 0x6FFFFF00
PT_SCE_LIBVERSION = 0x6FFFFF01

# Segment permission flags
PF_X = 0x1  # Execute
PF_W = 0x2  # Write
PF_R = 0x4  # Read


@dataclass
class ProgramHeader:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    @property
    def is_executable(self) -> bool:
        return bool(self.p_flags & PF_X)

    @property
    def is_readable(self) -> bool:
        return bool(self.p_flags & PF_R)

    @property
    def is_writable(self) -> bool:
        return bool(self.p_flags & PF_W)

    @property
    def is_xom(self) -> bool:
        """True if the segment is executable but NOT readable (eXecute-Only Memory)."""
        return self.is_executable and not self.is_readable

    @property
    def permission_str(self) -> str:
        r = "R" if self.is_readable else "-"
        w = "W" if self.is_writable else "-"
        x = "X" if self.is_executable else "-"
        return f"{r}{w}{x}"


class ELF64Parser:
    """
    Parses 64-bit ELF binaries and extracts execution segments and memory permissions.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.headers: List[ProgramHeader] = []
        self._parse()

    def _parse(self):
        if len(self.data) < 64:
            raise ValueError("File is too small to be a valid ELF64 binary.")

        # Check Magic \x7fELF
        if self.data[:4] != b"\x7fELF":
            raise ValueError("Invalid ELF magic header.")

        ei_class = self.data[4]
        if ei_class != 2:
            raise ValueError("Only 64-bit ELF binaries are supported.")

        ei_data = self.data[5]  # 1 = little endian, 2 = big endian
        endian = "<" if ei_data == 1 else ">"

        # Unpack ELF64 header fields
        # e_phoff is at offset 32 (8 bytes)
        e_phoff = struct.unpack_from(f"{endian}Q", self.data, 32)[0]
        # e_phentsize is at offset 54 (2 bytes)
        e_phentsize = struct.unpack_from(f"{endian}H", self.data, 54)[0]
        # e_phnum is at offset 56 (2 bytes)
        e_phnum = struct.unpack_from(f"{endian}H", self.data, 56)[0]

        # Unpack each Program Header
        for i in range(e_phnum):
            ph_offset = e_phoff + (i * e_phentsize)
            if ph_offset + 56 > len(self.data):
                break

            p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                f"{endian}IIQQQQQQ", self.data, ph_offset
            )

            ph = ProgramHeader(
                p_type=p_type,
                p_flags=p_flags,
                p_offset=p_off,
                p_vaddr=p_vaddr,
                p_paddr=p_paddr,
                p_filesz=p_filesz,
                p_memsz=p_memsz,
                p_align=p_align,
            )
            self.headers.append(ph)

    def get_executable_segments(self) -> List[Tuple[ProgramHeader, bytes]]:
        """
        Returns a list of tuples (header, segment_data) for all executable segments.
        """
        results = []
        for ph in self.headers:
            if ph.is_executable and ph.p_filesz > 0:
                end = ph.p_offset + ph.p_filesz
                seg_bytes = self.data[ph.p_offset:end]
                results.append((ph, seg_bytes))
        return results

    def check_xom_enforcement(self) -> bool:
        """
        Checks whether any segment in the binary has XOM (PF_X without PF_R) set.
        """
        return any(ph.is_xom for ph in self.headers)
