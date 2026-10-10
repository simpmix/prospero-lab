"""
XOM-Aware Gadget Analyzer.
Scans binary segments for ROP/JOP gadgets and evaluates their suitability for
exploits under eXecute-Only Memory and CFI (Control Flow Integrity) constraints.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any


@dataclass
class Gadget:
    address: int
    offset: int
    instruction_bytes: bytes
    disassembly: str
    role: str
    xom_score: int  # 1 (low) to 10 (essential primitive like stack pivot or syscall)


# Well-known byte signatures for essential 64-bit ROP primitives
SIGNATURE_PATTERNS = [
    # Stack pivots
    (b"\x5c\xc3", "pop rsp; ret", "stack_pivot", 10),
    (b"\x48\x89\xe0\xc3", "mov rax, rsp; ret", "stack_read", 8),
    (b"\x48\x89\xfc\xc3", "mov rsp, rdi; ret", "stack_pivot", 10),
    (b"\x48\x87\xe7\xc3", "xchg rsp, rdi; ret", "stack_pivot", 10),
    (b"\x48\x87\xf4\xc3", "xchg rsi, rsp; ret", "stack_pivot", 10),

    # Syscall invocation
    (b"\x0f\x05\xc3", "syscall; ret", "syscall_invoke", 10),
    (b"\x0f\x05", "syscall", "syscall_raw", 9),

    # Argument setup (SysV ABI registers)
    (b"\x5f\xc3", "pop rdi; ret", "arg1_setup", 9),
    (b"\x5e\xc3", "pop rsi; ret", "arg2_setup", 9),
    (b"\x5a\xc3", "pop rdx; ret", "arg3_setup", 9),
    (b"\x59\xc3", "pop rcx; ret", "arg4_setup", 8),
    (b"\x41\x5a\xc3", "pop r10; ret", "arg4_syscall_setup", 9),
    (b"\x41\x58\xc3", "pop r8; ret", "arg5_setup", 8),
    (b"\x41\x59\xc3", "pop r9; ret", "arg6_setup", 8),
    (b"\x58\xc3", "pop rax; ret", "rax_setup", 9),

    # Memory write/read primitives
    (b"\x48\x89\x37\xc3", "mov [rdi], rsi; ret", "write64_primitive", 9),
    (b"\x89\x37\xc3", "mov [rdi], esi; ret", "write32_primitive", 8),
    (b"\x48\x8b\x07\xc3", "mov rax, [rdi]; ret", "read64_primitive", 9),
    (b"\x8b\x07\xc3", "mov eax, [rdi]; ret", "read32_primitive", 8),

    # Arithmetic / Logic
    (b"\x48\x01\xf7\xc3", "add rdi, rsi; ret", "math_add", 6),
    (b"\x48\x31\xc0\xc3", "xor rax, rax; ret", "zero_rax", 7),
    (b"\x48\x31\xff\xc3", "xor rdi, rdi; ret", "zero_rdi", 7),
]


class GadgetAnalyzer:
    """
    Identifies control-flow primitives inside binary segments, rating them
    for XOM resistance and ROP chain synthesis.
    """

    def __init__(self, base_address: int = 0x0):
        self.base_address = base_address

    def scan_segment(self, data: bytes, segment_vaddr: int = 0x0) -> List[Gadget]:
        """
        Scans binary segment data for known ROP gadget sequences.
        """
        found_gadgets: List[Gadget] = []

        for sig, disasm, role, score in SIGNATURE_PATTERNS:
            start = 0
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break

                gadget_vaddr = segment_vaddr + idx
                found_gadgets.append(
                    Gadget(
                        address=gadget_vaddr,
                        offset=idx,
                        instruction_bytes=sig,
                        disassembly=disasm,
                        role=role,
                        xom_score=score,
                    )
                )
                start = idx + 1

        # Sort by score descending, then offset ascending
        found_gadgets.sort(key=lambda g: (-g.xom_score, g.offset))
        return found_gadgets

    def analyze_coverage(self, gadgets: List[Gadget]) -> Dict[str, Any]:
        """
        Calculates whether the found gadgets form a complete exploitation primitive
        (Stack Pivot + Arg Setup + Syscall + Read/Write).
        """
        roles_present = set(g.role for g in gadgets)
        has_pivot = any("pivot" in r for r in roles_present)
        has_syscall = "syscall_invoke" in roles_present or "syscall_raw" in roles_present
        has_args = all(r in roles_present for r in ["arg1_setup", "arg2_setup", "arg3_setup"])
        has_write = "write64_primitive" in roles_present or "write32_primitive" in roles_present

        can_execute_syscalls = has_syscall and has_args
        turing_complete = has_pivot and can_execute_syscalls and has_write

        return {
            "total_gadgets": len(gadgets),
            "has_stack_pivot": has_pivot,
            "has_syscall": has_syscall,
            "has_core_args (rdi, rsi, rdx)": has_args,
            "has_write_primitive": has_write,
            "can_execute_syscalls": can_execute_syscalls,
            "rop_viability_score": (
                (25 if has_pivot else 0)
                + (25 if has_syscall else 0)
                + (25 if has_args else 0)
                + (25 if has_write else 0)
            ),
        }
