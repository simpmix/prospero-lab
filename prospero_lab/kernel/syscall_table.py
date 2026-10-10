"""
Syscall Table Database: Upstream FreeBSD 12 vs. Sony Prospero/Orbis Proprietary Extensions.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SyscallEntry:
    number: int
    name: str
    origin: str  # 'freebsd' or 'sony_prospero'
    subsystem: str  # 'ipc', 'memory', 'filesystem', 'threading', 'networking', 'security'
    historical_vuln_class: Optional[str] = None
    audit_notes: str = ""


# Baseline FreeBSD 12 system calls of high interest
FREEBSD_SYSCALLS: Dict[int, SyscallEntry] = {
    1: SyscallEntry(1, "sys_exit", "freebsd", "process"),
    2: SyscallEntry(2, "fork", "freebsd", "process"),
    3: SyscallEntry(3, "read", "freebsd", "filesystem"),
    4: SyscallEntry(4, "write", "freebsd", "filesystem"),
    5: SyscallEntry(5, "open", "freebsd", "filesystem"),
    6: SyscallEntry(6, "close", "freebsd", "filesystem"),
    54: SyscallEntry(54, "ioctl", "freebsd", "device", "type confusion / buffer overflow", "Crucial driver gateway"),
    73: SyscallEntry(73, "munmap", "freebsd", "memory"),
    74: SyscallEntry(74, "mprotect", "freebsd", "memory", "permission bypass", "Enforces XOM and W^X"),
    97: SyscallEntry(97, "socket", "freebsd", "networking"),
    98: SyscallEntry(98, "connect", "freebsd", "networking"),
    105: SyscallEntry(105, "setsockopt", "freebsd", "networking", "use-after-free / double-free", "IPv6 option handling bugs"),
    118: SyscallEntry(118, "getsockopt", "freebsd", "networking", "infoleak"),
    454: SyscallEntry(454, "_umtx_op", "freebsd", "threading", "race condition / UAF", "UMTX lock operations (Andy Nguyen / TheFlow)"),
    477: SyscallEntry(477, "mmap", "freebsd", "memory", "integer overflow / unaligned mapping"),
    532: SyscallEntry(532, "pipe2", "freebsd", "ipc"),
    546: SyscallEntry(546, "kqueue", "freebsd", "event", "race condition / UAF"),
    547: SyscallEntry(547, "kevent", "freebsd", "event", "race condition / UAF", "knote allocation races"),
}

# Sony Prospero / Orbis proprietary extensions
PROSPERO_SYSCALLS: Dict[int, SyscallEntry] = {
    585: SyscallEntry(585, "sys_namedobj_create", "sony_prospero", "ipc", "race condition", "Inter-process named kernel object creation"),
    586: SyscallEntry(586, "sys_namedobj_delete", "sony_prospero", "ipc", "double free", "Named object lifecycle management"),
    590: SyscallEntry(590, "sys_budget_get_ptype", "sony_prospero", "process", "infoleak"),
    591: SyscallEntry(591, "sys_budget_get_budget_type", "sony_prospero", "process"),
    593: SyscallEntry(593, "sys_dynlib_get_list", "sony_prospero", "loader", "infoleak", "Enumerates loaded PRX/SPRX dynamic libraries"),
    594: SyscallEntry(594, "sys_dynlib_get_info", "sony_prospero", "loader", "infoleak", "Provides module base addresses (ASLR bypass)"),
    595: SyscallEntry(595, "sys_dynlib_load_prx", "sony_prospero", "loader", "privilege escalation", "Loads system PRX"),
    596: SyscallEntry(596, "sys_dynlib_unload_prx", "sony_prospero", "loader", "UAF"),
    597: SyscallEntry(597, "sys_dynlib_dlsym", "sony_prospero", "loader", "infoleak"),
    598: SyscallEntry(598, "sys_dynlib_get_list2", "sony_prospero", "loader", "infoleak"),
    608: SyscallEntry(608, "sys_evf_create", "sony_prospero", "ipc", "resource exhaustion", "Event flag creation for real-time synchronization"),
    609: SyscallEntry(609, "sys_evf_delete", "sony_prospero", "ipc", "race condition / UAF"),
    610: SyscallEntry(610, "sys_evf_open", "sony_prospero", "ipc"),
    611: SyscallEntry(611, "sys_evf_close", "sony_prospero", "ipc"),
    612: SyscallEntry(612, "sys_evf_wait", "sony_prospero", "ipc", "race condition"),
    613: SyscallEntry(613, "sys_evf_trywait", "sony_prospero", "ipc"),
    614: SyscallEntry(614, "sys_evf_set", "sony_prospero", "ipc"),
    615: SyscallEntry(615, "sys_evf_clear", "sony_prospero", "ipc"),
    616: SyscallEntry(616, "sys_evf_cancel", "sony_prospero", "ipc"),
    654: SyscallEntry(654, "sys_ipmimgr_call", "sony_prospero", "hardware", "command injection / buffer overflow", "IPMI management bridge"),
    657: SyscallEntry(657, "sys_blockpool_open", "sony_prospero", "memory", "out-of-bounds mapping", "Shared hardware block pool allocator"),
    658: SyscallEntry(658, "sys_blockpool_map", "sony_prospero", "memory", "page table corruption"),
    668: SyscallEntry(668, "sys_dnm_create", "sony_prospero", "ipc", "kernel memory corruption", "Direct Node Manager interface"),
}


def get_all_syscalls() -> Dict[int, SyscallEntry]:
    combined = dict(FREEBSD_SYSCALLS)
    combined.update(PROSPERO_SYSCALLS)
    return combined
