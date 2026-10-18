"""
ROP Chain Builder for Prospero (PS5) exploitation research.
Synthesizes 64-bit payload buffers with register setups, stack pivots,
memory write primitives, and full 6-argument FreeBSD/Prospero system call frames.
"""

import struct
from typing import List, Dict, Optional, Tuple


class ROPChainBuilder:
    """
    Constructs little-endian 64-bit ROP payloads given a set of known gadget addresses.
    Supports complete SysV AMD64 system call dispatch (up to 6 arguments).
    """

    def __init__(self, gadgets_map: Optional[Dict[str, int]] = None):
        """
        :param gadgets_map: Map of role -> virtual address (e.g. 'pop_rdi': 0x7fff00010)
        """
        self.gadgets: Dict[str, int] = dict(gadgets_map) if gadgets_map else {}
        self.stack: List[int] = []

    def set_gadget(self, role: str, address: int):
        """Registers or updates a gadget virtual address by role."""
        self.gadgets[role] = address

    def push(self, value: int):
        """Pushes an arbitrary 64-bit integer or address onto the fake stack."""
        self.stack.append(value & 0xFFFFFFFFFFFFFFFF)

    def _get_gadget(self, *roles: str) -> int:
        for r in roles:
            if r in self.gadgets:
                return self.gadgets[r]
        raise KeyError(f"Missing required gadget for any of: {roles}")

    def pop_rdi(self, val: int):
        addr = self._get_gadget("arg1_setup", "pop_rdi")
        self.push(addr)
        self.push(val)

    def pop_rsi(self, val: int):
        addr = self._get_gadget("arg2_setup", "pop_rsi")
        self.push(addr)
        self.push(val)

    def pop_rdx(self, val: int):
        addr = self._get_gadget("arg3_setup", "pop_rdx")
        self.push(addr)
        self.push(val)

    def pop_r10(self, val: int):
        """In SysV AMD64 kernel syscalls, Arg 4 is passed in R10 (not RCX)."""
        addr = self._get_gadget("arg4_syscall_setup", "pop_r10")
        self.push(addr)
        self.push(val)

    def pop_r8(self, val: int):
        addr = self._get_gadget("arg5_setup", "pop_r8")
        self.push(addr)
        self.push(val)

    def pop_r9(self, val: int):
        addr = self._get_gadget("arg6_setup", "pop_r9")
        self.push(addr)
        self.push(val)

    def pop_rax(self, val: int):
        addr = self._get_gadget("rax_setup", "pop_rax")
        self.push(addr)
        self.push(val)

    def syscall(self):
        addr = self._get_gadget("syscall_invoke", "syscall_raw", "syscall")
        self.push(addr)

    def pivot_stack(self, new_rsp: int):
        """Appends a stack pivot sequence redirecting RSP to new_rsp."""
        addr = self._get_gadget("stack_pivot_pop", "pop_rsp")
        self.push(addr)
        self.push(new_rsp)

    def write64(self, target_vaddr: int, val: int):
        """
        Uses write primitive: mov [rdi], rsi; ret
        Sets rdi = target_vaddr, rsi = val, then writes.
        """
        self.pop_rdi(target_vaddr)
        self.pop_rsi(val)
        write_gadget = self._get_gadget("write64_primitive", "mov_[rdi]_rsi")
        self.push(write_gadget)

    def build_syscall(
        self,
        sys_num: int,
        arg1: int = 0,
        arg2: int = 0,
        arg3: int = 0,
        arg4: Optional[int] = None,
        arg5: Optional[int] = None,
        arg6: Optional[int] = None,
    ):
        """
        Assembles a complete 1-to-6 argument FreeBSD/Prospero syscall chain.
        """
        self.pop_rdi(arg1)
        self.pop_rsi(arg2)
        self.pop_rdx(arg3)

        if arg4 is not None:
            self.pop_r10(arg4)
        if arg5 is not None:
            self.pop_r8(arg5)
        if arg6 is not None:
            self.pop_r9(arg6)

        self.pop_rax(sys_num)
        self.syscall()

    def serialize(self) -> bytes:
        """Serializes the ROP stack into raw little-endian 64-bit words."""
        return b"".join(struct.pack("<Q", val) for val in self.stack)

    def hex_dump(self) -> str:
        """Produces a formatted memory dump of the ROP chain with annotated offsets."""
        lines = []
        for i, val in enumerate(self.stack):
            offset = i * 8
            lines.append(f"[+0x{offset:04x}] 0x{val:016x}")
        return "\n".join(lines)
