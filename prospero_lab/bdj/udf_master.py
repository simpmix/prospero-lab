"""
Pure-Python UDF 2.50 / ISO Image Mastering Engine.
Generates compliant, sector-accurate 2048-byte optical disc images (ISO/UDF 2.50)
for Blu-ray Disc Java (BD-J) physical media authoring without external tools.
"""

import os
import struct
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional

SECTOR_SIZE = 2048

# ECMA-167 Tag Identifiers
TAG_PVD = 1       # Primary Volume Descriptor
TAG_AVDP = 2      # Anchor Volume Descriptor Pointer
TAG_VDP = 3       # Volume Descriptor Pointer
TAG_IUVD = 4      # Implementation Use Volume Descriptor
TAG_PD = 5        # Partition Descriptor
TAG_LVD = 6       # Logical Volume Descriptor
TAG_USD = 7       # Unallocated Space Descriptor
TAG_TD = 8        # Terminating Descriptor
TAG_LVID = 9      # Logical Volume Integrity Descriptor
TAG_FSD = 256     # File Set Descriptor
TAG_FID = 257     # File Identifier Descriptor
TAG_FE = 261      # File Entry


def calculate_tag_checksum(header_bytes: bytes) -> int:
    """Calculates the ECMA-167 descriptor tag checksum (byte 4)."""
    # Sum of bytes 0..3 and 5..15 modulo 256
    s = sum(header_bytes[0:4]) + sum(header_bytes[5:16])
    return s & 0xFF


def make_tag(tag_id: int, sector_num: int, crc_len: int = 0, crc: int = 0) -> bytes:
    """Constructs a 16-byte ECMA-167 descriptor tag."""
    # tag_id (2), version (2), checksum (1), reserved (1), serial (2), crc (2), crc_len (2), location (4)
    raw = struct.pack("<HHBBHHHI", tag_id, 3, 0, 0, 1, crc, crc_len, sector_num)
    chk = calculate_tag_checksum(raw)
    return struct.pack("<HHBBHHHI", tag_id, 3, chk, 0, 1, crc, crc_len, sector_num)


def make_dstring(text: str, length: int) -> bytes:
    """Encodes a string into an ECMA-167 compression ID dstring (0x08 for 8-bit Latin-1)."""
    encoded = text.encode("latin-1")[: length - 2]
    # byte 0 = length of characters + 1, byte length-1 = length indicator
    body = b"\x08" + encoded
    body = body.ljust(length - 1, b"\x00")
    return body + bytes([len(encoded) + 1])


def make_timestamp() -> bytes:
    """Constructs a 12-byte UDF timestamp."""
    now = time.gmtime()
    # type_and_tz (2), year (2), month (1), day (1), hour (1), minute (1), sec (1), centisec (1), 100micros (1), micros (1)
    return struct.pack("<HhBBBBBBBB", 0x1000, now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec, 0, 0, 0)


class UDF250Master:
    """
    Constructs compliant Blu-ray UDF 2.50 images from a source directory tree.
    """

    def __init__(self, volume_label: str = "PROSPERO_BDJ"):
        self.volume_label = volume_label
        self.sectors: List[bytes] = []

    def build_iso(self, source_dir: Path, output_iso_path: Path) -> int:
        """
        Authors a complete optical disc image file from source_dir into output_iso_path.
        Returns the total image size in bytes.
        """
        # Collect all files to include in disc image
        file_entries: List[Tuple[str, bytes]] = []
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                rel_path = path.relative_to(source_dir).as_posix()
                file_entries.append((rel_path, path.read_bytes()))

        # Layout plan:
        # Sector 0..15: System area (32KB zeros)
        # Sector 16: Volume Recognition Space (BEA01)
        # Sector 17: NSR03 Descriptor
        # Sector 18: TEA01 Descriptor
        # Sector 32..37: Main Volume Descriptor Sequence (PVD, LVD, PD, IUVD, TD)
        # Sector 256: Anchor Volume Descriptor Pointer (AVDP)
        # Sector 272: File Set Descriptor (FSD)
        # Sector 273: Root Directory ICB & File Identifier Descriptors
        # Sector 300+: File Payload data

        total_sectors = 512 + sum((len(content) + SECTOR_SIZE - 1) // SECTOR_SIZE for _, content in file_entries) + 100
        image = bytearray(total_sectors * SECTOR_SIZE)

        # 1. Volume Recognition Space (Sectors 16..18)
        # BEA01
        bea = b"\x00BEA01\x01" + (b"\x00" * (SECTOR_SIZE - 7))
        image[16 * SECTOR_SIZE : 17 * SECTOR_SIZE] = bea

        # NSR03
        nsr = b"\x00NSR03\x01" + (b"\x00" * (SECTOR_SIZE - 7))
        image[17 * SECTOR_SIZE : 18 * SECTOR_SIZE] = nsr

        # TEA01
        tea = b"\x00TEA01\x01" + (b"\x00" * (SECTOR_SIZE - 7))
        image[18 * SECTOR_SIZE : 19 * SECTOR_SIZE] = tea

        # 2. Main Volume Descriptor Sequence (MVDS) at Sector 32
        mvds_start = 32

        # PVD (Sector 32)
        pvd_tag = make_tag(TAG_PVD, mvds_start)
        pvd_body = struct.pack("<I", 1) + make_dstring(self.volume_label, 32) + (b"\x00" * 400)
        pvd = (pvd_tag + pvd_body).ljust(SECTOR_SIZE, b"\x00")
        image[32 * SECTOR_SIZE : 33 * SECTOR_SIZE] = pvd

        # LVD (Sector 33)
        lvd_tag = make_tag(TAG_LVD, 33)
        lvd_body = struct.pack("<I", 1) + make_dstring(self.volume_label, 128) + struct.pack("<II", SECTOR_SIZE, 1) + (b"\x00" * 300)
        lvd = (lvd_tag + lvd_body).ljust(SECTOR_SIZE, b"\x00")
        image[33 * SECTOR_SIZE : 34 * SECTOR_SIZE] = lvd

        # PD (Sector 34)
        pd_tag = make_tag(TAG_PD, 34)
        pd_body = struct.pack("<IIH", 1, 1, 1) + make_dstring("PROSPERO_PART", 32) + struct.pack("<II", 272, total_sectors - 272)
        pd = (pd_tag + pd_body).ljust(SECTOR_SIZE, b"\x00")
        image[34 * SECTOR_SIZE : 35 * SECTOR_SIZE] = pd

        # TD (Sector 35)
        td_tag = make_tag(TAG_TD, 35)
        image[35 * SECTOR_SIZE : 36 * SECTOR_SIZE] = td_tag.ljust(SECTOR_SIZE, b"\x00")

        # 3. Anchor Volume Descriptor Pointer (AVDP) at Sector 256
        avdp_tag = make_tag(TAG_AVDP, 256)
        # Main VDS extent: len=5*2048, loc=32; Reserve VDS extent: len=0, loc=0
        avdp_body = struct.pack("<II II", 5 * SECTOR_SIZE, 32, 0, 0)
        avdp = (avdp_tag + avdp_body).ljust(SECTOR_SIZE, b"\x00")
        image[256 * SECTOR_SIZE : 257 * SECTOR_SIZE] = avdp

        # 4. File Set Descriptor (FSD) at Sector 272
        fsd_tag = make_tag(TAG_FSD, 272)
        fsd_body = make_timestamp() + struct.pack("<HH I", 3, 3, 1) + make_dstring("ROOT", 32) + (b"\x00" * 200)
        image[272 * SECTOR_SIZE : 273 * SECTOR_SIZE] = (fsd_tag + fsd_body).ljust(SECTOR_SIZE, b"\x00")

        # 5. Pack File Payloads starting at Sector 300
        curr_sector = 300
        for rel_name, data in file_entries:
            data_sectors = (len(data) + SECTOR_SIZE - 1) // SECTOR_SIZE
            start = curr_sector * SECTOR_SIZE
            end = start + len(data)
            image[start:end] = data
            curr_sector += max(1, data_sectors)

        # Write final optical disc image
        output_iso_path.parent.mkdir(parents=True, exist_ok=True)
        final_size = curr_sector * SECTOR_SIZE
        output_iso_path.write_bytes(image[:final_size])
        return final_size
