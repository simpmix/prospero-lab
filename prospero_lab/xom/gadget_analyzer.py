"""
XOM-Aware Gadget Analyzer & ROP/JOP Classifier.
Scans binary segments for control-flow primitives, evaluates XOM suitability,
and extracts multi-instruction gadgets and indirect jump dispatchers.
"""

import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any

# Standard 64-bit GPR names for opcodes 0x58-0x5F
GPR_BASE_MAP = {
    0x58: "rax",
    0x59: "rcx",
    0x5A: "rdx",
    0x5B: "rbx",
    0x5C: "rsp",
    0x5D: "rbp",
    0x5E: "rsi",
    0x5F: "rdi",
}

# REX.B (0x41) extended registers 0x58-0x5F
GPR_EXT_MAP = {
    0x58: "r8",
    0x59: "r9",
    0x5A: "r10",
    0x5B: "r11",
    0x5C: "r12",
    0x5D: "r13",
    0x5E: "r14",
    0x5F: "r15",
}


@dataclass
class Gadget:
    address: int
    offset: int
    instruction_bytes: bytes
    disassembly: str
    role: str
    category: str  # 'PIVOT', 'SYSCALL', 'REGISTER_LOAD', 'MEMORY_WRITE', 'MEMORY_READ', 'JOP_DISPATCHER'
    xom_score: int  # 1 to 10

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": f"0x{self.address:016X}",
            "offset": f"0x{self.offset:08X}",
            "hex_bytes": self.instruction_bytes.hex(),
            "disassembly": self.disassembly,
            "role": self.role,
            "category": self.category,
            "xom_score": self.xom_score,
        }


# Well-known static ROP / JOP signatures
EXTENDED_SIGNATURES: List[Tuple[bytes, str, str, str, int]] = [
    # (bytes, disasm, role, category, score)
    # Stack Pivots
    (b"\x5c\xc3", "pop rsp; ret", "stack_pivot_pop", "PIVOT", 10),
    (b"\x48\x89\xe0\xc3", "mov rax, rsp; ret", "stack_read", "PIVOT", 8),
    (b"\x48\x89\xfc\xc3", "mov rsp, rdi; ret", "stack_pivot_mov", "PIVOT", 10),
    (b"\x48\x87\xe7\xc3", "xchg rsp, rdi; ret", "stack_pivot_xchg", "PIVOT", 10),
    (b"\x48\x87\xf4\xc3", "xchg rsi, rsp; ret", "stack_pivot_xchg", "PIVOT", 10),
    (b"\x48\x83\xc4\x08\xc3", "add rsp, 8; ret", "stack_adjust", "PIVOT", 7),
    (b"\x48\x83\xc4\x10\xc3", "add rsp, 0x10; ret", "stack_adjust", "PIVOT", 7),
    (b"\x48\x83\xc4\x20\xc3", "add rsp, 0x20; ret", "stack_adjust", "PIVOT", 7),

    # Syscall Invocation
    (b"\x0f\x05\xc3", "syscall; ret", "syscall_invoke", "SYSCALL", 10),
    (b"\x0f\x05", "syscall", "syscall_raw", "SYSCALL", 9),

    # Memory Write Primitives
    (b"\x48\x89\x37\xc3", "mov [rdi], rsi; ret", "write64_primitive", "MEMORY_WRITE", 9),
    (b"\x48\x89\x07\xc3", "mov [rdi], rax; ret", "write64_primitive", "MEMORY_WRITE", 9),
    (b"\x89\x37\xc3", "mov [rdi], esi; ret", "write32_primitive", "MEMORY_WRITE", 8),
    (b"\x89\x07\xc3", "mov [rdi], eax; ret", "write32_primitive", "MEMORY_WRITE", 8),

    # Memory Read Primitives
    (b"\x48\x8b\x07\xc3", "mov rax, [rdi]; ret", "read64_primitive", "MEMORY_READ", 9),
    (b"\x48\x8b\x37\xc3", "mov rsi, [rdi]; ret", "read64_primitive", "MEMORY_READ", 9),
    (b"\x8b\x07\xc3", "mov eax, [rdi]; ret", "read32_primitive", "MEMORY_READ", 8),

    # Arithmetic & Logic
    (b"\x48\x01\xf7\xc3", "add rdi, rsi; ret", "math_add", "ARITHMETIC_LOGIC", 6),
    (b"\x48\x31\xc0\xc3", "xor rax, rax; ret", "zero_rax", "ARITHMETIC_LOGIC", 7),
    (b"\x48\x31\xff\xc3", "xor rdi, rdi; ret", "zero_rdi", "ARITHMETIC_LOGIC", 7),

    # JOP (Jump-Oriented Programming) Dispatchers
    (b"\xff\xe0", "jmp rax", "jop_jmp_rax", "JOP_DISPATCHER", 8),
    (b"\xff\x20", "jmp [rax]", "jop_indirect_rax", "JOP_DISPATCHER", 8),
    (b"\xff\xe7", "jmp rdi", "jop_jmp_rdi", "JOP_DISPATCHER", 8),
    (b"\xff\x27", "jmp [rdi]", "jop_indirect_rdi", "JOP_DISPATCHER", 8),
    (b"\x41\xff\xe0", "jmp r8", "jop_jmp_r8", "JOP_DISPATCHER", 8),
]


class GadgetAnalyzer:
    """
    Advanced Control-Flow Primitive Scanner.
    Extracts ROP, JOP, and stack manipulation gadgets with automated classification
    and XOM vulnerability scoring.
    """

    def __init__(self, base_address: int = 0x0):
        self.base_address = base_address

    def scan_segment(self, data: bytes, segment_vaddr: int = 0x0) -> List[Gadget]:
        """
        Scans a binary segment for static signatures and dynamic x86-64 register pop patterns.
        """
        found_gadgets: List[Gadget] = []
        seen_offsets = set()

        # 1. Scan Static Extended Signatures
        for sig, disasm, role, category, score in EXTENDED_SIGNATURES:
            start = 0
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break

                gadget_vaddr = segment_vaddr + idx
                seen_offsets.add(idx)
                found_gadgets.append(
                    Gadget(
                        address=gadget_vaddr,
                        offset=idx,
                        instruction_bytes=sig,
                        disassembly=disasm,
                        role=role,
                        category=category,
                        xom_score=score,
                    )
                )
                start = idx + 1

        # 2. Dynamic Register Pop Scanner: Single Pops (0x58..0x5F + 0xC3)
        for op, reg in GPR_BASE_MAP.items():
            pattern = bytes([op, 0xC3])
            role_name = f"arg1_setup" if reg == "rdi" else (
                f"arg2_setup" if reg == "rsi" else (
                    f"arg3_setup" if reg == "rdx" else (
                        f"rax_setup" if reg == "rax" else f"pop_{reg}"
                    )
                )
            )
            score = 10 if reg == "rsp" else (9 if reg in ["rdi", "rsi", "rdx", "rax"] else 7)
            start = 0
            while True:
                idx = data.find(pattern, start)
                if idx == -1:
                    break
                if idx not in seen_offsets:
                    seen_offsets.add(idx)
                    found_gadgets.append(
                        Gadget(
                            address=segment_vaddr + idx,
                            offset=idx,
                            instruction_bytes=pattern,
                            disassembly=f"pop {reg}; ret",
                            role=role_name,
                            category="PIVOT" if reg == "rsp" else "REGISTER_LOAD",
                            xom_score=score,
                        )
                    )
                start = idx + 1

        # 3. Dynamic Register Pop Scanner: Extended R8..R15 (0x41 + 0x58..0x5F + 0xC3)
        for op, reg in GPR_EXT_MAP.items():
            pattern = bytes([0x41, op, 0xC3])
            role_name = f"arg4_syscall_setup" if reg == "r10" else f"pop_{reg}"
            score = 9 if reg == "r10" else 8
            start = 0
            while True:
                idx = data.find(pattern, start)
                if idx == -1:
                    break
                if idx not in seen_offsets:
                    seen_offsets.add(idx)
                    found_gadgets.append(
                        Gadget(
                            address=segment_vaddr + idx,
                            offset=idx,
                            instruction_bytes=pattern,
                            disassembly=f"pop {reg}; ret",
                            role=role_name,
                            category="REGISTER_LOAD",
                            xom_score=score,
                        )
                    )
                start = idx + 1

        # Sort gadgets by xom_score descending, then offset ascending
        found_gadgets.sort(key=lambda g: (-g.xom_score, g.offset))
        return found_gadgets

    def analyze_coverage(self, gadgets: List[Gadget]) -> Dict[str, Any]:
        """
        Calculates exploitation completeness and classifies available primitives.
        """
        roles_present = set(g.role for g in gadgets)
        categories_present = set(g.category for g in gadgets)

        has_pivot = "PIVOT" in categories_present
        has_syscall = "SYSCALL" in categories_present
        has_args = all(r in roles_present for r in ["arg1_setup", "arg2_setup", "arg3_setup"])
        has_write = "MEMORY_WRITE" in categories_present
        has_jop = "JOP_DISPATCHER" in categories_present

        can_execute_syscalls = has_syscall and has_args

        # Categorical counts
        category_counts: Dict[str, int] = {}
        for g in gadgets:
            category_counts[g.category] = category_counts.get(g.category, 0) + 1

        score = (
            (25 if has_pivot else 0)
            + (25 if has_syscall else 0)
            + (25 if has_args else 0)
            + (25 if has_write else 0)
        )

        return {
            "total_gadgets": len(gadgets),
            "category_breakdown": category_counts,
            "has_stack_pivot": has_pivot,
            "has_syscall": has_syscall,
            "has_core_args (rdi, rsi, rdx)": has_args,
            "has_write_primitive": has_write,
            "has_jop_dispatchers": has_jop,
            "can_execute_syscalls": can_execute_syscalls,
            "rop_viability_score": score,
        }

    def export_json(self, gadgets: List[Gadget], indent: int = 2) -> str:
        """Serializes discovered gadgets to JSON for Ghidra / IDA Pro consumption."""
        return json.dumps([g.to_dict() for g in gadgets], indent=indent)
