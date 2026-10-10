"""
Kernel Surface Auditor for Prospero OS.
Audits the divergence between upstream FreeBSD and Sony's customized kernel,
identifying high-value attack surfaces, race-condition candidates, and ASLR infoleak vectors.
"""

from typing import Dict, List, Any
from .syscall_table import get_all_syscalls, SyscallEntry, PROSPERO_SYSCALLS, FREEBSD_SYSCALLS


class KernelSurfaceAuditor:
    """
    Evaluates the vulnerability potential of the Prospero kernel boundary.
    """

    def __init__(self):
        self.syscalls = get_all_syscalls()

    def audit_attack_surface(self) -> Dict[str, Any]:
        """
        Generates a comprehensive risk profile of the kernel boundary.
        """
        high_risk_entries: List[SyscallEntry] = []
        infoleak_entries: List[SyscallEntry] = []
        custom_sony_entries: List[SyscallEntry] = []

        for entry in self.syscalls.values():
            if entry.origin == "sony_prospero":
                custom_sony_entries.append(entry)

            if entry.historical_vuln_class:
                if "infoleak" in entry.historical_vuln_class.lower():
                    infoleak_entries.append(entry)
                if any(k in entry.historical_vuln_class.lower() for k in ["race", "uaf", "corruption", "overflow", "type confusion"]):
                    high_risk_entries.append(entry)

        return {
            "total_monitored_syscalls": len(self.syscalls),
            "freebsd_baseline_syscalls": len(FREEBSD_SYSCALLS),
            "prospero_proprietary_syscalls": len(PROSPERO_SYSCALLS),
            "critical_race_uaf_targets": [
                {
                    "num": e.number,
                    "name": e.name,
                    "subsystem": e.subsystem,
                    "vuln_class": e.historical_vuln_class,
                    "notes": e.audit_notes,
                }
                for e in high_risk_entries
            ],
            "aslr_bypass_targets": [
                {
                    "num": e.number,
                    "name": e.name,
                    "subsystem": e.subsystem,
                    "notes": e.audit_notes,
                }
                for e in infoleak_entries
            ],
            "fuzzing_priority_score": {
                "umtx_subsystem": 9.5,  # Highest historical yield (Andy Nguyen / TheFlow)
                "event_flags_evf": 8.5,  # Proprietary Sony multi-threaded primitives
                "named_objects": 8.0,
                "dynamic_library_loader": 7.5,
                "ipmi_and_blockpool": 8.0,
            },
        }

    def generate_syzkaller_descriptions(self) -> str:
        """
        Generates Syzkaller-compatible syscall definitions for fuzzing
        Prospero-specific syscalls.
        """
        output = [
            "# Auto-generated Syzkaller descriptions for Prospero Kernel Fuzzing",
            "# Source: prospero-lab KernelSurfaceAuditor",
            "",
            "include <sys/types.h>",
            "",
            "# Named Objects",
            "sys_namedobj_create(name ptr[in, string], flags flags[namedobj_flags], mode int32) int32",
            "sys_namedobj_delete(id int32, flags flags[namedobj_flags]) int32",
            "",
            "# Event Flags",
            "sys_evf_create(name ptr[in, string], flags flags[evf_flags], initial_val int64) int32",
            "sys_evf_delete(evf_id int32) int32",
            "sys_evf_wait(evf_id int32, pattern int64, mode int32, result ptr[out, int64], timeout ptr[in, timespec]) int32",
            "sys_evf_set(evf_id int32, bits int64) int32",
            "sys_evf_clear(evf_id int32, bits int64) int32",
            "",
            "# Dynamic Library Subsystem",
            "sys_dynlib_get_list(list_out ptr[out, array[int32, 128]], max_entries int32, count_out ptr[out, int32]) int32",
            "sys_dynlib_get_info(handle int32, info_out ptr[out, dynlib_info]) int32",
            "",
            "# UMTX Locking Primitives",
            "_umtx_op(obj ptr[inout, int32], op flags[umtx_ops], val int64, uaddr1 ptr[in, int64], uaddr2 ptr[in, int64]) int32",
        ]
        return "\n".join(output)
