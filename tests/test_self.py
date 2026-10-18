import unittest
import struct
from prospero_lab.formats.self_parser import SELFParser, SELF_MAGIC_SCE


def create_minimal_self(is_encrypted: bool = False) -> bytes:
    """
    Creates a minimal synthetic Sony Signed ELF container.
    """
    magic = SELF_MAGIC_SCE
    version = 2
    mode = 1
    endian_flag = 1  # little endian
    attributes = 0
    key_type = 0
    header_size = 40 + 32  # header + 1 segment entry
    meta_size = 0
    file_size = header_size + 64
    num_segments = 1
    flags = 0

    header = magic + struct.pack(
        "<IHHIIIIQHH",
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
    )

    # Segment descriptor: props, offset, filesz, memsz
    # props bit 1 (0x2) is encrypted
    props = 0x2 if is_encrypted else 0x1
    seg_offset = header_size
    seg_filesz = 64
    seg_memsz = 64

    segment = struct.pack("<QQQQ", props, seg_offset, seg_filesz, seg_memsz)
    payload = b"\x90" * 64

    return header + segment + payload


class TestSELFParser(unittest.TestCase):
    def test_plain_self_parsing(self):
        data = create_minimal_self(is_encrypted=False)
        parser = SELFParser(data)
        summary = parser.get_summary()

        self.assertEqual(summary["version"], 2)
        self.assertEqual(summary["endianness"], "little")
        self.assertEqual(summary["num_segments"], 1)
        self.assertTrue(summary["fully_decrypted"])
        self.assertFalse(summary["segments"][0]["encrypted"])

    def test_encrypted_self_parsing(self):
        data = create_minimal_self(is_encrypted=True)
        parser = SELFParser(data)
        summary = parser.get_summary()

        self.assertFalse(summary["fully_decrypted"])
        self.assertTrue(summary["segments"][0]["encrypted"])
        self.assertIn("ENCRYPTED", summary["segments"][0]["status"])


if __name__ == "__main__":
    unittest.main()
