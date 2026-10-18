"""
Sony Signed ELF (SELF / SPRX) Format Parser.
Extracts container metadata, segment descriptors, compression/encryption flags,
Control Info blocks (NPDRM, Auth ID, Capabilities), and embedded ELF headers.
"""

import json
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from prospero_lab.exceptions import SELFParseError

SELF_MAGIC_SCE = b"\x53\x43\x45\x00"  # 'SCE\0'
SELF_MAGIC_OSELF = b"\x4f\x53\x45\x4c\x46"  # 'OSELF'

# Control Info Types
CONTROL_TYPE_DIGEST = 1
CONTROL_TYPE_NPDRM = 2
CONTROL_TYPE_BOOT_PARAM = 3
CONTROL_TYPE_CAPABILITIES = 4
CONTROL_TYPE_AUTH_ID = 5


@dataclass
class ControlInfoBlock:
    type_id: int
    type_name: str
    size: int
    raw_data: bytes
    details: Dict[str, Any] = field(default_factory=dict)


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
        self.control_blocks: List[ControlInfoBlock] = []
        self._parse()

    def _parse(self):
        if len(self.data) < 40:
            raise SELFParseError("Data is too small for a SELF container header.")

        magic = self.data[:4]
        if magic != SELF_MAGIC_SCE and self.data[:5] != SELF_MAGIC_OSELF:
            raise SELFParseError(f"Invalid SELF magic header: {magic!r}")

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

            # Parse Segment Descriptors (32 bytes each)
            curr_offset = 40
            for i in range(num_segments):
                if curr_offset + 32 > len(self.data):
                    break

                props, seg_offset, seg_filesz, seg_memsz = struct.unpack_from(
                    f"{endian}QQQQ", self.data, curr_offset
                )

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

            # Parse Control Info Metadata Blocks if present
            if meta_size > 0 and curr_offset + meta_size <= len(self.data):
                self._parse_control_info(curr_offset, meta_size)

    def _parse_control_info(self, start_offset: int, total_size: int):
        end = start_offset + total_size
        offset = start_offset

        type_names = {
            CONTROL_TYPE_DIGEST: "CONTROL_DIGEST",
            CONTROL_TYPE_NPDRM: "NPDRM_INFO",
            CONTROL_TYPE_BOOT_PARAM: "BOOT_PARAM",
            CONTROL_TYPE_CAPABILITIES: "CAPABILITIES",
            CONTROL_TYPE_AUTH_ID: "PROGRAM_AUTH_ID",
        }

        while offset + 8 <= end:
            type_id, block_size = struct.unpack_from("<II", self.data, offset)
            if block_size == 0 or offset + block_size > end:
                break

            block_data = self.data[offset + 8 : offset + block_size]
            t_name = type_names.get(type_id, f"UNKNOWN_0x{type_id:X}")
            details: Dict[str, Any] = {}

            # Parse known payload types
            if type_id == CONTROL_TYPE_AUTH_ID and len(block_data) >= 8:
                auth_id = struct.unpack_from("<Q", block_data, 0)[0]
                details["auth_id"] = f"0x{auth_id:016X}"

            elif type_id == CONTROL_TYPE_NPDRM and len(block_data) >= 48:
                content_id = block_data[:36].decode("latin1", errors="replace").strip("\x00")
                details["content_id"] = content_id

            self.control_blocks.append(
                ControlInfoBlock(
                    type_id=type_id,
                    type_name=t_name,
                    size=block_size,
                    raw_data=block_data,
                    details=details,
                )
            )
            offset += block_size

    def extract_embedded_elf(self) -> Optional[bytes]:
        """
        Attempts to extract the decrypted ELF binary payload from segment 0 if present.
        """
        if not self.segments:
            return None

        seg0 = self.segments[0]
        if seg0.is_encrypted:
            return None  # Cannot extract encrypted payload without hardware keys

        start = seg0.offset
        end = start + seg0.file_size
        if end <= len(self.data):
            candidate = self.data[start:end]
            if candidate.startswith(b"\x7fELF"):
                return candidate
        return None

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
            "meta_size": self.header.meta_size,
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
            "control_info_blocks": [
                {
                    "type": b.type_name,
                    "size": b.size,
                    "details": b.details,
                }
                for b in self.control_blocks
            ],
        }

    def export_json(self, indent: int = 2) -> str:
        """Serializes container metadata to JSON."""
        return json.dumps(self.get_summary(), indent=indent)
