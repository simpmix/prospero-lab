"""
FreeBSD 12 vs. Prospero OS Kernel Attack Surface Audit Tools.
"""

from .syscall_table import PROSPERO_SYSCALLS, FREEBSD_SYSCALLS, SyscallEntry
from .surface_auditor import KernelSurfaceAuditor

__all__ = ["PROSPERO_SYSCALLS", "FREEBSD_SYSCALLS", "SyscallEntry", "KernelSurfaceAuditor"]
