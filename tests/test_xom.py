import unittest
import struct
import json
from prospero_lab.xom.elf_parser import ELF64Parser, PF_X, PF_R, PF_W, PT_LOAD
from prospero_lab.xom.gadget_analyzer import GadgetAnalyzer
from prospero_lab.xom.blind_rop import ROPChainBuilder


def create_minimal_elf64(xom: bool = False, payload: bytes = b"") -> bytes:
    """
    Synthesizes a minimal 64-bit ELF binary with 1 PT_LOAD segment.
    """
    endian = "<"
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 9, 0]) + (b"\x00" * 7)  # EI_OSABI = 9 (FreeBSD)
    e_type = 2
    e_machine = 62
    e_version = 1
    e_entry = 0x400000
    e_phoff = 64
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
        elf_normal = create_minimal_elf64(xom=False, payload=b"\x90\x90\xc3")
        parser1 = ELF64Parser(elf_normal)
        self.assertFalse(parser1.check_xom_enforcement())
        self.assertEqual(len(parser1.get_executable_segments()), 1)

        elf_xom = create_minimal_elf64(xom=True, payload=b"\x90\x90\xc3")
        parser2 = ELF64Parser(elf_xom)
        self.assertTrue(parser2.check_xom_enforcement())

    def test_malformed_elf_error(self):
        from prospero_lab.exceptions import ELFParseError
        with self.assertRaises(ELFParseError):
            ELF64Parser(b"\x00" * 30)

        with self.assertRaises(ELFParseError):
            ELF64Parser(b"INVALID_MAGIC" + (b"\x00" * 60))

    def test_gadget_analyzer_and_jop(self):
        # Code containing:
        # pop rdi; ret (0x5f 0xc3)
        # syscall; ret (0x0f 0x05 0xc3)
        # pop r10; ret (0x41 0x5a 0xc3)
        # jmp rax (0xff 0xe0)
        code = b"\x5f\xc3\x0f\x05\xc3\x41\x5a\xc3\xff\xe0"
        analyzer = GadgetAnalyzer(base_address=0x1000)
        gadgets = analyzer.scan_segment(code, segment_vaddr=0x1000)

        self.assertGreaterEqual(len(gadgets), 4)
        roles = [g.role for g in gadgets]
        categories = [g.category for g in gadgets]

        self.assertIn("arg1_setup", roles)
        self.assertIn("syscall_invoke", roles)
        self.assertIn("arg4_syscall_setup", roles)
        self.assertIn("JOP_DISPATCHER", categories)

        # Test JSON export
        json_str = analyzer.export_json(gadgets)
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed), len(gadgets))

    def test_rop_chain_builder_full_syscall(self):
        gadget_map = {
            "pop_rdi": 0x1111,
            "pop_rsi": 0x2222,
            "pop_rdx": 0x3333,
            "pop_r10": 0x4444,
            "pop_r8": 0x5555,
            "pop_r9": 0x6666,
            "pop_rax": 0x7777,
            "syscall": 0x8888,
            "stack_pivot_pop": 0x9999,
            "write64_primitive": 0xAAAA,
        }
        builder = ROPChainBuilder(gadget_map)
        builder.build_syscall(
            sys_num=54,
            arg1=3,
            arg2=0xC0184B01,
            arg3=0x100000,
            arg4=0x200000,
            arg5=0x300000,
            arg6=0x400000,
        )
        raw = builder.serialize()
        self.assertGreater(len(raw), 0)

        # Test write64 helper
        builder2 = ROPChainBuilder(gadget_map)
        builder2.write64(0x200000, 0x1337)
        raw2 = builder2.serialize()
        self.assertEqual(len(raw2), 5 * 8)


if __name__ == "__main__":
    unittest.main()
