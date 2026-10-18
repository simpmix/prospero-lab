"""
Sony Signed ELF (SELF / SPRX) Format Parser.
Extracts container metadata, segment descriptors, compression/encryption flags,
and embedded ELF headers from PlayStation executables.
"""

import struct
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

SELF_MAGIC_SCE = b"\x53\x43\x45\x00"  # 'SCE\0'
SELF_MAGIC_OSELF = b"\x4f\x53\x45\x4c\x46"  # 'OSELF'


@dataclass
class SELFSegment:
    index: int
    flags: int
    offset: int
    file_size: int
    memory_size: int
    is_encrypted: bool
    is_compressed: bool
    is_signed: bool

    @property
    def status_summary(self) -> str:
        status = []
        if self.is_encrypted:
            status.append("ENCRYPTED")
        if self.is_compressed:
            status.append("COMPRESSED")
        if self.is_signed:
            status.append("SIGNED")
        return ", ".join(status) if status else "PLAIN"


@dataclass
class SELFHeader:
    magic: bytes
    version: int
    mode: int
    endianness: str
    attributes: int
    key_type: int
    header_size: int
    meta_size: int
    file_size: int
    num_segments: int


class SELFParser:
    """
    Parses Sony Signed ELF (SELF) containers commonly used for PS4/PS5
    binaries (.bin, .prx, .sprx).
    """

    def __init__(self, data: bytes):
        self.data = data
        self.header: Optional[SELFHeader] = None
        self.segments: List[SELFSegment] = []
        self._parse()

    def _parse(self):
        if len(self.data) < 32:
            raise ValueError("Data is too small for a SELF container header.")

        magic = self.data[:4]
        if magic != SELF_MAGIC_SCE and self.data[:5] != SELF_MAGIC_OSELF:
            raise ValueError(f"Invalid SELF magic header: {magic!r}")

        endian = "<"
        if magic == SELF_MAGIC_SCE:
            (
                version,
                mode,
                endian_flag,
                attributes,
                key_type,
                header_size,
                meta_size,
                file_size,
                num_segments,
                flags,
            ) = struct.unpack_from(f"{endian}IHHIIIIQHH", self.data, 4)

            self.header = SELFHeader(
                magic=magic,
                version=version,
                mode=mode,
                endianness="little" if endian_flag == 1 else "big",
                attributes=attributes,
                key_type=key_type,
                header_size=header_size,
                meta_size=meta_size,
                file_size=file_size,
                num_segments=num_segments,
            )

            # Parse Segment Descriptors
            # Each segment entry is 32 bytes (offset 40 onwards)
            curr_offset = 40
            for i in range(num_segments):
                if curr_offset + 32 > len(self.data):
                    break

                props, seg_offset, seg_filesz, seg_memsz = struct.unpack_from(
                    f"{endian}QQQQ", self.data, curr_offset
                )

                # Flag breakdown:
                # Bit 1 (0x2): Encrypted (SAMU / Crypto engine)
                # Bit 3 (0x8): Compressed (zlib / deflate)
                # Bit 0 (0x1): Signed
                is_encrypted = bool(props & 0x02)
                is_compressed = bool(props & 0x08)
                is_signed = bool(props & 0x01)

                self.segments.append(
                    SELFSegment(
                        index=i,
                        flags=props,
                        offset=seg_offset,
                        file_size=seg_filesz,
                        memory_size=seg_memsz,
                        is_encrypted=is_encrypted,
                        is_compressed=is_compressed,
                        is_signed=is_signed,
                    )
                )
                curr_offset += 32

    def is_fully_decrypted(self) -> bool:
        """Checks if all payload segments are decrypted."""
        return not any(s.is_encrypted for s in self.segments)

    def get_summary(self) -> Dict[str, Any]:
        """Provides a structured dictionary summary of the SELF binary."""
        if not self.header:
            return {}
        return {
            "magic": self.header.magic.decode("latin1", errors="replace"),
            "version": self.header.version,
            "endianness": self.header.endianness,
            "header_size": self.header.header_size,
            "total_file_size": self.header.file_size,
            "num_segments": len(self.segments),
            "fully_decrypted": self.is_fully_decrypted(),
            "segments": [
                {
                    "index": s.index,
                    "offset": f"0x{s.offset:x}",
                    "file_size": f"0x{s.file_size:x}",
                    "memory_size": f"0x{s.memory_size:x}",
                    "encrypted": s.is_encrypted,
                    "compressed": s.is_compressed,
                    "status": s.status_summary,
                }
                for s in self.segments
            ],
        }
