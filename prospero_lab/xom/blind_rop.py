"""
ROP Chain Builder for Prospero (PS5) exploitation research.
Synthesizes 64-bit payload buffers with register setups, stack pivots,
and FreeBSD/Prospero system call frames.
"""

import struct
from typing import List, Dict, Optional, Tuple


class ROPChainBuilder:
    """
    Constructs little-endian 64-bit ROP payloads given a set of known gadget addresses.
    """

    def __init__(self, gadgets_map: Optional[Dict[str, int]] = None):
        """
        :param gadgets_map: Map of role -> virtual address (e.g. 'pop_rdi': 0x7fff00010)
        """
        self.gadgets: Dict[str, int] = gadgets_map or {}
        self.stack: List[int] = []

    def set_gadget(self, role: str, address: int):
        self.gadgets[role] = address

    def push(self, value: int):
        """Push an arbitrary 64-bit integer or address onto the fake stack."""
        self.stack.append(value)

    def pop_rdi(self, val: int):
        if "arg1_setup" not in self.gadgets and "pop_rdi" not in self.gadgets:
            raise KeyError("Missing pop rdi gadget")
        addr = self.gadgets.get("arg1_setup") or self.gadgets.get("pop_rdi")
        self.push(addr)
        self.push(val)

    def pop_rsi(self, val: int):
        if "arg2_setup" not in self.gadgets and "pop_rsi" not in self.gadgets:
            raise KeyError("Missing pop rsi gadget")
        addr = self.gadgets.get("arg2_setup") or self.gadgets.get("pop_rsi")
        self.push(addr)
        self.push(val)

    def pop_rdx(self, val: int):
        if "arg3_setup" not in self.gadgets and "pop_rdx" not in self.gadgets:
            raise KeyError("Missing pop rdx gadget")
        addr = self.gadgets.get("arg3_setup") or self.gadgets.get("pop_rdx")
        self.push(addr)
        self.push(val)

    def pop_rax(self, val: int):
        if "rax_setup" not in self.gadgets and "pop_rax" not in self.gadgets:
            raise KeyError("Missing pop rax gadget")
        addr = self.gadgets.get("rax_setup") or self.gadgets.get("pop_rax")
        self.push(addr)
        self.push(val)

    def syscall(self):
        if "syscall_invoke" not in self.gadgets and "syscall" not in self.gadgets:
            raise KeyError("Missing syscall gadget")
        addr = self.gadgets.get("syscall_invoke") or self.gadgets.get("syscall")
        self.push(addr)

    def build_syscall(self, sys_num: int, arg1: int = 0, arg2: int = 0, arg3: int = 0):
        """
        Assembles a complete 3-argument FreeBSD/Prospero syscall chain:
        rdi = arg1, rsi = arg2, rdx = arg3, rax = sys_num -> syscall
        """
        self.pop_rdi(arg1)
        self.pop_rsi(arg2)
        self.pop_rdx(arg3)
        self.pop_rax(sys_num)
        self.syscall()

    def serialize(self) -> bytes:
        """
        Serializes the ROP stack into raw little-endian 64-bit words.
        """
        return b"".join(struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF) for val in self.stack)

    def hex_dump(self) -> str:
        """
        Produces a formatted memory dump of the ROP chain with annotated offsets.
        """
        lines = []
        for i, val in enumerate(self.stack):
            offset = i * 8
            lines.append(f"[+0x{offset:04x}] 0x{val:016x}")
        return "\n".join(lines)
