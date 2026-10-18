"""
Mock Execution Runtime & ROP Chain Verifier.
Simulates an AMD64 CPU state, memory pages with W^X and XOM permissions,
and validates whether a ROP chain dispatches system calls cleanly.
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from prospero_lab.exceptions import XOMViolationError, WXPViolationError, SimulationError
from prospero_lab.xom.gadget_analyzer import Gadget

# Memory protection flags
PROT_NONE = 0x0
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4


@dataclass
class MemoryRegion:
    start_vaddr: int
    size: int
    prot: int
    name: str = ""

    def contains(self, vaddr: int) -> bool:
        return self.start_vaddr <= vaddr < (self.start_vaddr + self.size)

    @property
    def is_xom(self) -> bool:
        """Execute-Only Memory: executable but not readable."""
        return bool(self.prot & PROT_EXEC) and not bool(self.prot & PROT_READ)

    @property
    def is_writable_and_executable(self) -> bool:
        """Violates W^X (Write XOR Execute) security mitigation."""
        return bool(self.prot & PROT_WRITE) and bool(self.prot & PROT_EXEC)


@dataclass
class CPUState:
    rax: int = 0
    rdi: int = 0
    rsi: int = 0
    rdx: int = 0
    rcx: int = 0
    r10: int = 0
    r8: int = 0
    r9: int = 0
    rsp: int = 0
    rip: int = 0

    def dump(self) -> str:
        return (
            f"RAX: 0x{self.rax:016x} | RDI: 0x{self.rdi:016x} | RSI: 0x{self.rsi:016x}\n"
            f"RDX: 0x{self.rdx:016x} | R10: 0x{self.r10:016x} | RSP: 0x{self.rsp:016x}\n"
            f"RIP: 0x{self.rip:016x}"
        )


@dataclass
class ExecutionTrace:
    step_num: int
    rip: int
    disassembly: str
    cpu_before: Dict[str, int]
    cpu_after: Dict[str, int]
    syscall_dispatched: Optional[Dict[str, Any]] = None


class MockRuntime:
    """
    Virtual execution engine for verifying 64-bit ROP payloads and syscall sequences
    under FreeBSD / Prospero security constraints.
    """

    def __init__(self, enforce_wx: bool = True):
        self.cpu = CPUState()
        self.memory_regions: List[MemoryRegion] = []
        self.memory: Dict[int, int] = {}  # 64-bit aligned virtual address -> 64-bit integer
        self.gadget_handlers: Dict[int, Tuple[str, Any]] = {}
        self.syscall_log: List[Dict[str, Any]] = []
        self.traces: List[ExecutionTrace] = []
        self.enforce_wx = enforce_wx

        # Simulated kernel state
        self.active_event_flags: Dict[int, int] = {}
        self.named_objects: Dict[str, int] = {}
        self.next_handle_id: int = 100

    def map_region(self, vaddr: int, size: int, prot: int, name: str = "") -> MemoryRegion:
        region = MemoryRegion(start_vaddr=vaddr, size=size, prot=prot, name=name)
        self.memory_regions.append(region)
        return region

    def find_region(self, vaddr: int) -> Optional[MemoryRegion]:
        for reg in self.memory_regions:
            if reg.contains(vaddr):
                return reg
        return None

    def register_gadget(self, vaddr: int, disasm: str, handler):
        self.gadget_handlers[vaddr] = (disasm, handler)

    def load_gadgets_from_analyzer(self, gadgets: List[Gadget]):
        """
        Automatically registers CPU manipulation handlers for gadgets identified
        by GadgetAnalyzer.
        """
        for g in gadgets:
            disasm = g.disassembly.strip()
            vaddr = g.address

            if disasm.startswith("pop ") and disasm.endswith("; ret"):
                reg_name = disasm[4:-5].strip()
                if hasattr(self.cpu, reg_name):
                    def make_pop(rn):
                        return lambda rt: (
                            setattr(rt.cpu, rn, rt.read_qword(rt.cpu.rsp, allow_xom=True)),
                            setattr(rt.cpu, "rsp", rt.cpu.rsp + 8),
                        )
                    self.register_gadget(vaddr, disasm, make_pop(reg_name))

            elif disasm == "syscall; ret" or disasm == "syscall":
                self.register_gadget(vaddr, disasm, lambda rt: None)

            elif disasm == "mov [rdi], rsi; ret":
                self.register_gadget(
                    vaddr, disasm,
                    lambda rt: rt.write_qword(rt.cpu.rdi, rt.cpu.rsi)
                )

            elif disasm == "mov rax, [rdi]; ret":
                self.register_gadget(
                    vaddr, disasm,
                    lambda rt: setattr(rt.cpu, "rax", rt.read_qword(rt.cpu.rdi))
                )

    def write_qword(self, vaddr: int, value: int):
        reg = self.find_region(vaddr)
        if reg and not (reg.prot & PROT_WRITE):
            raise PermissionError(f"[WRITE FAULT] Illegal write at non-writable vaddr 0x{vaddr:x}")
        self.memory[vaddr & ~0x7] = value & 0xFFFFFFFFFFFFFFFF

    def read_qword(self, vaddr: int, allow_xom: bool = False) -> int:
        reg = self.find_region(vaddr)
        if reg and reg.is_xom and not allow_xom:
            raise XOMViolationError(f"[XOM VIOLATION] Attempted read on Execute-Only page at 0x{vaddr:x}")
        return self.memory.get(vaddr & ~0x7, 0)

    def load_rop_chain(self, stack_base: int, payload_bytes: bytes):
        """Loads a serialized ROP chain buffer into memory at stack_base."""
        num_qwords = len(payload_bytes) // 8
        self.map_region(
            vaddr=stack_base,
            size=len(payload_bytes) + 0x1000,
            prot=PROT_READ | PROT_WRITE,
            name="fake_stack",
        )
        for i in range(num_qwords):
            val = struct.unpack_from("<Q", payload_bytes, i * 8)[0]
            self.write_qword(stack_base + (i * 8), val)
        self.cpu.rsp = stack_base

    def run_rop(self, max_steps: int = 100) -> List[ExecutionTrace]:
        """
        Executes the loaded ROP chain step-by-step by popping gadget addresses from the stack.
        """
        step = 0
        while step < max_steps:
            if self.cpu.rsp not in self.memory:
                break

            gadget_addr = self.read_qword(self.cpu.rsp, allow_xom=True)
            self.cpu.rsp += 8
            self.cpu.rip = gadget_addr

            if gadget_addr == 0:
                break

            # Check W^X enforcement
            reg = self.find_region(gadget_addr)
            if self.enforce_wx and reg and reg.is_writable_and_executable:
                raise WXPViolationError(
                    f"[W^X VIOLATION] Execution attempted in W+X page at 0x{gadget_addr:x} (Region: {reg.name})"
                )

            if gadget_addr not in self.gadget_handlers:
                raise SimulationError(f"Segmentation Fault: Unknown gadget address 0x{gadget_addr:x} at step {step}")

            disasm, handler = self.gadget_handlers[gadget_addr]
            cpu_before = dict(self.cpu.__dict__)

            syscall_info = None
            if "syscall" in disasm:
                syscall_info = self._handle_syscall()
            else:
                handler(self)

            cpu_after = dict(self.cpu.__dict__)
            trace = ExecutionTrace(
                step_num=step,
                rip=gadget_addr,
                disassembly=disasm,
                cpu_before=cpu_before,
                cpu_after=cpu_after,
                syscall_dispatched=syscall_info,
            )
            self.traces.append(trace)
            step += 1

        return self.traces

    def _handle_syscall(self) -> Dict[str, Any]:
        """Dispatches and audits simulated system calls."""
        sys_num = self.cpu.rax
        info = {
            "syscall_number": sys_num,
            "arg1_rdi": self.cpu.rdi,
            "arg2_rsi": self.cpu.rsi,
            "arg3_rdx": self.cpu.rdx,
            "arg4_r10": self.cpu.r10,
            "arg5_r8": self.cpu.r8,
            "arg6_r9": self.cpu.r9,
            "success": True,
        }

        # 74: sys_mprotect
        if sys_num == 74:
            target_addr = self.cpu.rdi
            target_size = self.cpu.rsi
            new_prot = self.cpu.rdx
            reg = self.find_region(target_addr)
            if reg:
                reg.prot = new_prot
                info["effect"] = f"Updated region '{reg.name}' protection to 0x{new_prot:x}"
            else:
                self.map_region(target_addr, target_size, new_prot, name="mprotected_page")
                info["effect"] = f"Mapped new page at 0x{target_addr:x} with prot 0x{new_prot:x}"
            self.cpu.rax = 0

        # 4: sys_write
        elif sys_num == 4:
            fd = self.cpu.rdi
            buf_addr = self.cpu.rsi
            count = self.cpu.rdx
            info["effect"] = f"Wrote {count} bytes to fd {fd} from 0x{buf_addr:x}"
            self.cpu.rax = count

        # 454: _umtx_op
        elif sys_num == 454:
            op = self.cpu.rsi
            info["effect"] = f"Simulated _umtx_op (op={op}) on mutex 0x{self.cpu.rdi:x}"
            self.cpu.rax = 0

        # 608: sys_evf_create
        elif sys_num == 608:
            evf_id = self.next_handle_id
            self.next_handle_id += 1
            self.active_event_flags[evf_id] = self.cpu.rdx
            info["effect"] = f"Created Event Flag #{evf_id} (initial=0x{self.cpu.rdx:x})"
            self.cpu.rax = evf_id

        # 585: sys_namedobj_create
        elif sys_num == 585:
            obj_id = self.next_handle_id
            self.next_handle_id += 1
            info["effect"] = f"Created Named Object #{obj_id}"
            self.cpu.rax = obj_id

        # 594: sys_dynlib_get_info
        elif sys_num == 594:
            info["effect"] = f"Reported dynlib info for handle {self.cpu.rdi}"
            self.cpu.rax = 0

        # Default fallback
        else:
            info["effect"] = f"Dispatched generic syscall #{sys_num}"
            self.cpu.rax = 0

        self.syscall_log.append(info)
        return info
