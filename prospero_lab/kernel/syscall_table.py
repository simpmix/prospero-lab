"""
Comprehensive Syscall Table Database: Upstream FreeBSD 12 vs. Sony Prospero/Orbis Extensions.
Includes detailed subsystem classification, calling parameters, and security risk auditing.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SyscallEntry:
    number: int
    name: str
    origin: str  # 'freebsd' or 'sony_prospero'
    subsystem: str  # 'ipc', 'memory', 'filesystem', 'threading', 'networking', 'hardware', 'loader'
    parameters: List[str] = field(default_factory=list)
    historical_vuln_class: Optional[str] = None
    audit_notes: str = ""
    risk_level: str = "low"  # 'critical', 'high', 'medium', 'low', 'info'


# Baseline FreeBSD 12 System Calls with Security Relevance
FREEBSD_SYSCALLS: Dict[int, SyscallEntry] = {
    1: SyscallEntry(1, "sys_exit", "freebsd", "process", ["int status"], risk_level="info"),
    2: SyscallEntry(2, "fork", "freebsd", "process", [], risk_level="medium"),
    3: SyscallEntry(3, "read", "freebsd", "filesystem", ["int fd", "void *buf", "size_t nbytes"], risk_level="low"),
    4: SyscallEntry(4, "write", "freebsd", "filesystem", ["int fd", "const void *buf", "size_t nbytes"], risk_level="low"),
    5: SyscallEntry(5, "open", "freebsd", "filesystem", ["const char *path", "int flags", "mode_t mode"], risk_level="medium"),
    6: SyscallEntry(6, "close", "freebsd", "filesystem", ["int fd"], risk_level="low"),
    54: SyscallEntry(
        54, "ioctl", "freebsd", "hardware",
        ["int fd", "unsigned long req", "void *argp"],
        historical_vuln_class="type confusion / buffer overflow / uninitialized copyout",
        audit_notes="Primary entrypoint into proprietary hardware drivers (/dev/kmd, /dev/dnm).",
        risk_level="critical",
    ),
    73: SyscallEntry(73, "munmap", "freebsd", "memory", ["void *addr", "size_t len"], risk_level="low"),
    74: SyscallEntry(
        74, "mprotect", "freebsd", "memory",
        ["void *addr", "size_t len", "int prot"],
        historical_vuln_class="permission bypass",
        audit_notes="Enforces W^X and XOM; hypervisor blocks transitioning executable pages to writable.",
        risk_level="high",
    ),
    97: SyscallEntry(97, "socket", "freebsd", "networking", ["int domain", "int type", "int protocol"], risk_level="low"),
    98: SyscallEntry(98, "connect", "freebsd", "networking", ["int s", "const struct sockaddr *name", "socklen_t namelen"], risk_level="low"),
    105: SyscallEntry(
        105, "setsockopt", "freebsd", "networking",
        ["int s", "int level", "int optname", "const void *optval", "socklen_t optlen"],
        historical_vuln_class="use-after-free / double-free",
        audit_notes="Historically vulnerable to IPv6 extension header UAFs (TheFlow, SpecterDev).",
        risk_level="critical",
    ),
    118: SyscallEntry(
        118, "getsockopt", "freebsd", "networking",
        ["int s", "int level", "int optname", "void *optval", "socklen_t *optlen"],
        historical_vuln_class="kernel infoleak",
        audit_notes="Potential disclosure of uninitialized kernel stack or heap memory.",
        risk_level="high",
    ),
    454: SyscallEntry(
        454, "_umtx_op", "freebsd", "threading",
        ["void *obj", "int op", "u_long val", "void *uaddr1", "void *uaddr2"],
        historical_vuln_class="race condition / use-after-free",
        audit_notes="FreeBSD userspace mutex subsystem. Target of critical PS4/PS5 jailbreaks.",
        risk_level="critical",
    ),
    477: SyscallEntry(
        477, "mmap", "freebsd", "memory",
        ["void *addr", "size_t len", "int prot", "int flags", "int fd", "off_t pos"],
        historical_vuln_class="integer overflow / invalid mapping",
        audit_notes="Subject to strict sandbox limits (MAP_SHARED / MAP_ANON).",
        risk_level="medium",
    ),
    499: SyscallEntry(
        499, "shm_open", "freebsd", "ipc",
        ["const char *path", "int flags", "mode_t mode"],
        audit_notes="POSIX shared memory object descriptor.",
        risk_level="medium",
    ),
    532: SyscallEntry(532, "pipe2", "freebsd", "ipc", ["int *fildes", "int flags"], risk_level="low"),
    546: SyscallEntry(
        546, "kqueue", "freebsd", "ipc", [],
        historical_vuln_class="kernel heap exhaustion",
        risk_level="medium",
    ),
    547: SyscallEntry(
        547, "kevent", "freebsd", "ipc",
        ["int kq", "const struct kevent *changelist", "int nchanges", "struct kevent *eventlist", "int nevents", "const struct timespec *timeout"],
        historical_vuln_class="race condition / UAF",
        audit_notes="Multi-threaded knote manipulation races.",
        risk_level="high",
    ),
}

# Sony Prospero / Orbis Custom System Calls
PROSPERO_SYSCALLS: Dict[int, SyscallEntry] = {
    # Named Objects
    585: SyscallEntry(
        585, "sys_namedobj_create", "sony_prospero", "ipc",
        ["const char *name", "uint32_t flags", "uint32_t mode"],
        historical_vuln_class="race condition / name collision",
        audit_notes="Allows cross-process object lookup by symbolic name.",
        risk_level="high",
    ),
    586: SyscallEntry(
        586, "sys_namedobj_delete", "sony_prospero", "ipc",
        ["int obj_id", "uint32_t flags"],
        historical_vuln_class="double free / dangling pointer",
        audit_notes="Destroys named object reference.",
        risk_level="high",
    ),

    # Budget & Sandboxing
    590: SyscallEntry(
        590, "sys_budget_get_ptype", "sony_prospero", "process",
        ["pid_t pid", "int *ptype"],
        historical_vuln_class="kernel infoleak",
        audit_notes="Exposes process execution category (Game, Shell, App).",
        risk_level="medium",
    ),
    591: SyscallEntry(591, "sys_budget_get_budget_type", "sony_prospero", "process", ["int *budget"], risk_level="low"),

    # Dynamic Library Subsystem (PRX / SPRX)
    593: SyscallEntry(
        593, "sys_dynlib_get_list", "sony_prospero", "loader",
        ["int *handles", "size_t max_entries", "size_t *count"],
        historical_vuln_class="ASLR bypass / address disclosure",
        audit_notes="Enumerates handles of all loaded modules in current process.",
        risk_level="high",
    ),
    594: SyscallEntry(
        594, "sys_dynlib_get_info", "sony_prospero", "loader",
        ["int handle", "struct dynlib_info *info"],
        historical_vuln_class="ASLR bypass / base address disclosure",
        audit_notes="Returns module load address, segment sizes, and text/data offsets.",
        risk_level="critical",
    ),
    595: SyscallEntry(
        595, "sys_dynlib_load_prx", "sony_prospero", "loader",
        ["const char *path", "uint32_t flags", "int *handle"],
        historical_vuln_class="privilege escalation / code execution",
        audit_notes="Loads system PRX modules. Enforces cryptographic signatures in kernel.",
        risk_level="critical",
    ),
    596: SyscallEntry(
        596, "sys_dynlib_unload_prx", "sony_prospero", "loader",
        ["int handle", "uint32_t flags"],
        historical_vuln_class="use-after-free",
        audit_notes="Unmaps module segments. Risk of dangling pointers in threads.",
        risk_level="high",
    ),
    597: SyscallEntry(
        597, "sys_dynlib_dlsym", "sony_prospero", "loader",
        ["int handle", "const char *symbol_name", "void **addr"],
        historical_vuln_class="symbol resolution / infoleak",
        risk_level="medium",
    ),
    598: SyscallEntry(
        598, "sys_dynlib_get_list2", "sony_prospero", "loader",
        ["int *handles", "size_t max_entries", "size_t *count", "uint32_t flags"],
        historical_vuln_class="ASLR bypass",
        risk_level="high",
    ),
    599: SyscallEntry(
        599, "sys_dynlib_get_info2", "sony_prospero", "loader",
        ["int handle", "uint32_t flags", "struct dynlib_info2 *info"],
        historical_vuln_class="ASLR bypass",
        risk_level="high",
    ),

    # Event Flags (Custom Multi-threaded IPC)
    608: SyscallEntry(
        608, "sys_evf_create", "sony_prospero", "ipc",
        ["const char *name", "uint32_t flags", "uint64_t init_val"],
        historical_vuln_class="kernel heap exhaustion",
        audit_notes="Creates a 64-bit synchronized event flag bitmask.",
        risk_level="high",
    ),
    609: SyscallEntry(
        609, "sys_evf_delete", "sony_prospero", "ipc",
        ["int evf_id"],
        historical_vuln_class="race condition / UAF",
        audit_notes="Destroys an active event flag while threads may be waiting.",
        risk_level="critical",
    ),
    610: SyscallEntry(610, "sys_evf_open", "sony_prospero", "ipc", ["const char *name", "int *id"], risk_level="medium"),
    611: SyscallEntry(611, "sys_evf_close", "sony_prospero", "ipc", ["int evf_id"], risk_level="low"),
    612: SyscallEntry(
        612, "sys_evf_wait", "sony_prospero", "ipc",
        ["int evf_id", "uint64_t pattern", "uint32_t mode", "uint64_t *result", "struct timespec *timeout"],
        historical_vuln_class="race condition / deadlocks",
        audit_notes="Multi-threaded wait primitive; prone to TOCTOU race conditions.",
        risk_level="high",
    ),
    613: SyscallEntry(613, "sys_evf_trywait", "sony_prospero", "ipc", ["int evf_id", "uint64_t pattern", "uint32_t mode", "uint64_t *result"], risk_level="medium"),
    614: SyscallEntry(614, "sys_evf_set", "sony_prospero", "ipc", ["int evf_id", "uint64_t bits"], risk_level="medium"),
    615: SyscallEntry(615, "sys_evf_clear", "sony_prospero", "ipc", ["int evf_id", "uint64_t bits"], risk_level="medium"),
    616: SyscallEntry(616, "sys_evf_cancel", "sony_prospero", "ipc", ["int evf_id", "uint64_t pattern"], risk_level="medium"),

    # Semaphores
    617: SyscallEntry(617, "sys_semaphore_create", "sony_prospero", "threading", ["const char *name", "uint32_t flags", "int init_count", "int max_count"], risk_level="medium"),
    618: SyscallEntry(618, "sys_semaphore_destroy", "sony_prospero", "threading", ["int sem_id"], risk_level="medium"),
    619: SyscallEntry(619, "sys_semaphore_wait", "sony_prospero", "threading", ["int sem_id", "int count", "struct timespec *timeout"], risk_level="medium"),
    620: SyscallEntry(620, "sys_semaphore_signal", "sony_prospero", "threading", ["int sem_id", "int count"], risk_level="low"),

    # Hardware IPMI & Secure Subsystem
    654: SyscallEntry(
        654, "sys_ipmimgr_call", "sony_prospero", "hardware",
        ["uint32_t cmd", "void *in_buf", "size_t in_size", "void *out_buf", "size_t out_size"],
        historical_vuln_class="buffer overflow / privileged command injection",
        audit_notes="Direct management bridge to the Southbridge and Secure Processor (SAMU/PSP).",
        risk_level="critical",
    ),

    # Blockpool (Hardware Accelerated Shared Memory)
    657: SyscallEntry(
        657, "sys_blockpool_open", "sony_prospero", "memory",
        ["const char *name", "size_t size", "uint32_t flags", "int *pool_fd"],
        historical_vuln_class="out-of-bounds mapping",
        audit_notes="Allocates contiguous memory blocks for GPU and media engines.",
        risk_level="high",
    ),
    658: SyscallEntry(
        658, "sys_blockpool_map", "sony_prospero", "memory",
        ["int pool_fd", "void *vaddr", "size_t size", "int prot"],
        historical_vuln_class="page table corruption / remap vulnerability",
        audit_notes="Maps blockpool memory with specified hardware page attributes.",
        risk_level="critical",
    ),
    659: SyscallEntry(659, "sys_blockpool_unmap", "sony_prospero", "memory", ["void *vaddr", "size_t size"], risk_level="medium"),

    # Direct Node Manager (DNM - Custom Kernel Interconnect)
    668: SyscallEntry(
        668, "sys_dnm_create", "sony_prospero", "ipc",
        ["const char *name", "uint32_t flags", "int *dnm_fd"],
        historical_vuln_class="kernel memory corruption / UAF",
        audit_notes="Direct Node Manager driver gateway.",
        risk_level="critical",
    ),
    669: SyscallEntry(669, "sys_dnm_control", "sony_prospero", "ipc", ["int dnm_fd", "uint32_t op", "void *arg"], risk_level="high"),

    # JIT & Execute-Only Memory Extensions
    676: SyscallEntry(
        676, "sys_mprotect_xom", "sony_prospero", "memory",
        ["void *addr", "size_t len", "int xom_flags"],
        historical_vuln_class="hypervisor memory protection bypass",
        audit_notes="Specialized Sony system call enforcing Execute-Only Memory without read permissions.",
        risk_level="critical",
    ),
    677: SyscallEntry(
        677, "sys_jit_reserve_range", "sony_prospero", "memory",
        ["size_t len", "void **vaddr_out"],
        audit_notes="Allocates dedicated paired dual-mapped JIT memory ranges.",
        risk_level="high",
    ),
}


def get_all_syscalls() -> Dict[int, SyscallEntry]:
    """Returns merged dictionary of FreeBSD baseline and Prospero custom system calls."""
    combined = dict(FREEBSD_SYSCALLS)
    combined.update(PROSPERO_SYSCALLS)
    return combined
