"""
FreeBSD 12 vs. Prospero OS Kernel Attack Surface Audit Tools.
"""

from .syscall_table import PROSPERO_SYSCALLS, FREEBSD_SYSCALLS, SyscallEntry, get_all_syscalls
from .ioctl_table import PROSPERO_IOCTL_COMMANDS, IOCTLEntry, get_all_ioctls
from .surface_auditor import KernelSurfaceAuditor

__all__ = [
    "PROSPERO_SYSCALLS",
    "FREEBSD_SYSCALLS",
    "SyscallEntry",
    "get_all_syscalls",
    "PROSPERO_IOCTL_COMMANDS",
    "IOCTLEntry",
    "get_all_ioctls",
    "KernelSurfaceAuditor",
]
