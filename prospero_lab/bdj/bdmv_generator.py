"""
BDMV Structure Generator for BD-J security research and disc creation.
Generates bit-accurate index.bdmv, MovieObject.bdmv, Playlist, and ClipInfo structures.
"""

import os
import struct
from pathlib import Path
from typing import Dict, Any, Optional


class BDMVGenerator:
    """
    Constructs compliant Blu-ray Disc Movie (BDMV) structures capable of auto-booting
    custom BD-J Xlet applications on PlayStation 4 and PlayStation 5 consoles.
    """

    def __init__(self, org_id: int = 0x56534F4E, app_id: int = 0x4000):
        """
        :param org_id: BD-J Organization ID (default 0x56534F4E = 'VSON' for Sony)
        :param app_id: BD-J Application ID (default 0x4000)
        """
        self.org_id = org_id
        self.app_id = app_id

    def build_index_bdmv(self) -> bytes:
        """
        Generates index.bdmv configured to auto-launch the BD-J title on First Playback.
        """
        magic = b"INDX0200"

        # AppInfo section
        # Length (4 bytes), video format (1 byte), frame rate (1 byte), reserved (32 bytes)
        app_info_data = struct.pack(">IBB32s", 34, 0x00, 0x00, b"\x00" * 32)

        # Title table:
        # FirstPlayback (BD-J title): type=0x02, id_ref=0x0001
        # TopMenu (BD-J title): type=0x02, id_ref=0x0001
        # Title 1: type=0x02, id_ref=0x0001
        title_entry = struct.pack(">BBH", 0x02, 0x00, 0x0001)  # 4 bytes per title
        first_playback = struct.pack(">BBH", 0x02, 0x00, 0x0001)
        top_menu = struct.pack(">BBH", 0x02, 0x00, 0x0001)

        # Title table body: length (4 bytes), count of titles (2 bytes), titles...
        num_titles = 1
        title_table_content = struct.pack(">H", num_titles) + title_entry
        title_table_data = struct.pack(">I", len(first_playback) + len(top_menu) + len(title_table_content)) + \
                           first_playback + top_menu + title_table_content

        # Offsets
        app_info_offset = 40  # Header is 40 bytes
        title_table_offset = app_info_offset + len(app_info_data)
        extension_data_offset = 0  # No extension data

        # Header: magic (8), app_info_offset (4), title_table_offset (4), ext_offset (4), reserved (20)
        header = magic + struct.pack(">III20s", app_info_offset, title_table_offset, extension_data_offset, b"\x00" * 20)

        return header + app_info_data + title_table_data

    def build_movie_object_bdmv(self) -> bytes:
        """
        Generates MovieObject.bdmv defining execution objects.
        """
        magic = b"MOBJ0200"
        # Extension offset: 0, reserved (24 bytes)
        header = magic + struct.pack(">I24s", 0, b"\x00" * 24)

        # Objects table: length (4), reserved (2), count (2)
        # Entry 0: resume intention (1), flags (1), num commands (2)
        # Command 0: Jump Title 1 (opcode: 0x21800000, operand1: 1, operand2: 0)
        hdmv_cmd = struct.pack(">III", 0x21800000, 1, 0)
        entry = struct.pack(">BBH", 0x00, 0x00, 1) + hdmv_cmd
        table_body = struct.pack(">HH", 0, 1) + entry
        table = struct.pack(">I", len(table_body)) + table_body

        return header + table

    def build_mpls(self) -> bytes:
        """
        Generates a dummy 00000.mpls (Playlist) required by strict BD players.
        """
        magic = b"MPLS0200"
        # playlist_offset (4), mark_offset (4), ext_offset (4), reserved (20)
        header = magic + struct.pack(">III20s", 40, 60, 0, b"\x00" * 20)
        
        # Dummy Playlist section
        playlist_body = struct.pack(">IHBBH", 12, 0, 0, 0, 0) + b"\x00" * 6
        mark_body = struct.pack(">IH", 2, 0)
        
        return header + playlist_body + mark_body

    def build_clpi(self) -> bytes:
        """
        Generates a dummy 00000.clpi (Clip Information) file.
        """
        magic = b"HDMV0200"
        # clip_info_offset (4), seq_offset (4), prog_offset (4), cpi_offset (4), ext_offset (4), reserved (12)
        header = magic + struct.pack(">IIIII12s", 40, 60, 80, 100, 0, b"\x00" * 12)
        dummy_data = b"\x00" * 80
        return header + dummy_data

    def build_structure(self, base_dir: Path) -> Dict[str, Path]:
        """
        Creates the complete standard BDMV directory layout on disk.
        """
        paths = {
            "BDMV": base_dir / "BDMV",
            "AUXDATA": base_dir / "BDMV" / "AUXDATA",
            "BACKUP": base_dir / "BDMV" / "BACKUP",
            "BDJO": base_dir / "BDMV" / "BDJO",
            "CLIPINF": base_dir / "BDMV" / "CLIPINF",
            "JAR": base_dir / "BDMV" / "JAR",
            "META": base_dir / "BDMV" / "META",
            "PLAYLIST": base_dir / "BDMV" / "PLAYLIST",
            "STREAM": base_dir / "BDMV" / "STREAM",
            "CERTIFICATE": base_dir / "CERTIFICATE",
            "CERT_BACKUP": base_dir / "CERTIFICATE" / "BACKUP",
        }

        for path in paths.values():
            path.mkdir(parents=True, exist_ok=True)

        # Write core files
        (paths["BDMV"] / "index.bdmv").write_bytes(self.build_index_bdmv())
        (paths["BDMV"] / "MovieObject.bdmv").write_bytes(self.build_movie_object_bdmv())
        (paths["PLAYLIST"] / "00000.mpls").write_bytes(self.build_mpls())
        (paths["CLIPINF"] / "00000.clpi").write_bytes(self.build_clpi())

        # Backup files
        (paths["BACKUP"] / "index.bdmv").write_bytes(self.build_index_bdmv())
        (paths["BACKUP"] / "MovieObject.bdmv").write_bytes(self.build_movie_object_bdmv())

        # Empty stub stream (MPEG-TS packet)
        sync_packet = b"\x47" + b"\x00\x00\x10" + (b"\xFF" * 184)
        (paths["STREAM"] / "00000.m2ts").write_bytes(sync_packet * 10)

        # Create BDJO (BD-J Object) 00001.bdjo
        bdjo_path = paths["BDJO"] / "00001.bdjo"
        bdjo_path.write_bytes(self._build_bdjo())

        return paths

    def _build_bdjo(self) -> bytes:
        """
        Generates 00001.bdjo (BD-J Object) binding Title 1 to the Xlet JAR.
        """
        magic = b"BDJO0200"
        # Header + App Table referencing org_id and app_id
        # Layout: App count (2), org_id (4), app_id (2), auto_run flag (1)
        app_entry = struct.pack(">IHB", self.org_id, self.app_id, 0x01)
        body = struct.pack(">H", 1) + app_entry
        header = magic + struct.pack(">I24s", len(body), b"\x00" * 24)
        return header + body
