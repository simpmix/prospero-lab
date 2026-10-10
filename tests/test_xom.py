import unittest
import struct
from prospero_lab.xom.elf_parser import ELF64Parser, PF_X, PF_R, PF_W, PT_LOAD
from prospero_lab.xom.gadget_analyzer import GadgetAnalyzer
from prospero_lab.xom.blind_rop import ROPChainBuilder


def create_minimal_elf64(xom: bool = False, payload: bytes = b"") -> bytes:
    """
    Synthesizes a minimal 64-bit ELF binary with 1 PT_LOAD segment.
    """
    endian = "<"
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 9, 0]) + (b"\x00" * 7)  # EI_OSABI = 9 (FreeBSD)
    e_type = 2  # ET_EXEC
    e_machine = 62  # EM_X86_64
    e_version = 1
    e_entry = 0x400000
    e_phoff = 64  # Follows immediately after 64-byte ELF header
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 0
    e_shnum = 0
    e_shstrndx = 0

    header = e_ident + struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )

    # Program header
    p_type = PT_LOAD
    p_flags = PF_X if xom else (PF_R | PF_X)
    p_offset = 64 + 56
    p_vaddr = 0x400000
    p_paddr = 0x400000
    p_filesz = len(payload)
    p_memsz = len(payload)
    p_align = 0x1000

    ph = struct.pack(
        f"{endian}IIQQQQQQ",
        p_type,
        p_flags,
        p_offset,
        p_vaddr,
        p_paddr,
        p_filesz,
        p_memsz,
        p_align,
    )

    return header + ph + payload


class TestXOM(unittest.TestCase):
    def test_elf_parser_and_xom_detection(self):
        # Non-XOM ELF
        elf_normal = create_minimal_elf64(xom=False, payload=b"\x90\x90\xc3")
        parser1 = ELF64Parser(elf_normal)
        self.assertFalse(parser1.check_xom_enforcement())
        self.assertEqual(len(parser1.get_executable_segments()), 1)

        # XOM ELF
        elf_xom = create_minimal_elf64(xom=True, payload=b"\x90\x90\xc3")
        parser2 = ELF64Parser(elf_xom)
        self.assertTrue(parser2.check_xom_enforcement())

    def test_gadget_analyzer(self):
        # Gadget payload containing: pop rdi; ret (0x5f 0xc3) and syscall; ret (0x0f 0x05 0xc3)
        code = b"\x90\x90\x5f\xc3\x90\x0f\x05\xc3"
        analyzer = GadgetAnalyzer(base_address=0x1000)
        gadgets = analyzer.scan_segment(code, segment_vaddr=0x1000)

        self.assertGreaterEqual(len(gadgets), 2)
        roles = [g.role for g in gadgets]
        self.assertIn("arg1_setup", roles)
        self.assertIn("syscall_invoke", roles)

    def test_rop_chain_builder(self):
        gadget_map = {
            "pop_rdi": 0x1111,
            "pop_rsi": 0x2222,
            "pop_rdx": 0x3333,
            "pop_rax": 0x4444,
            "syscall": 0x5555,
        }
        builder = ROPChainBuilder(gadget_map)
        builder.build_syscall(sys_num=74, arg1=0x1000, arg2=0x2000, arg3=0x7)
        raw = builder.serialize()

        # Each element is 8 bytes: pop_rdi (1), arg1 (1), pop_rsi (1), arg2 (1),
        # pop_rdx (1), arg3 (1), pop_rax (1), sys_num (1), syscall (1) = 9 entries = 72 bytes
        self.assertEqual(len(raw), 9 * 8)
        unpacked = [struct.unpack("<Q", raw[i:i+8])[0] for i in range(0, len(raw), 8)]
        self.assertEqual(unpacked[0], 0x1111)
        self.assertEqual(unpacked[1], 0x1000)
        self.assertEqual(unpacked[8], 0x5555)


if __name__ == "__main__":
    unittest.main()
