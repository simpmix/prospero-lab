"""
Kernel Surface Auditor for Prospero OS.
Audits the divergence between upstream FreeBSD and Sony's customized kernel,
evaluating syscalls, character device IOCTL entry points, race-condition candidates,
and ASLR infoleak vectors.
"""

import json
from typing import Dict, List, Any, Optional
from .syscall_table import get_all_syscalls, SyscallEntry, PROSPERO_SYSCALLS, FREEBSD_SYSCALLS
from .ioctl_table import get_all_ioctls, IOCTLEntry


class KernelSurfaceAuditor:
    """
    Evaluates the attack surface and vulnerability potential of the Prospero kernel boundary.
    """

    def __init__(self):
        self.syscalls = get_all_syscalls()
        self.ioctls = get_all_ioctls()

    def audit_attack_surface(self) -> Dict[str, Any]:
        """
        Generates a comprehensive risk profile of the kernel boundary including
        system calls and character device drivers.
        """
        critical_targets: List[SyscallEntry] = []
        high_risk_entries: List[SyscallEntry] = []
        infoleak_entries: List[SyscallEntry] = []
        custom_sony_entries: List[SyscallEntry] = []

        for entry in self.syscalls.values():
            if entry.origin == "sony_prospero":
                custom_sony_entries.append(entry)

            if entry.risk_level == "critical":
                critical_targets.append(entry)
            elif entry.risk_level == "high":
                high_risk_entries.append(entry)

            if entry.historical_vuln_class and "infoleak" in entry.historical_vuln_class.lower():
                infoleak_entries.append(entry)

        # Critical / High IOCTL commands
        high_risk_ioctls = [i for i in self.ioctls if i.risk_level in ["critical", "high"]]

        return {
            "total_monitored_syscalls": len(self.syscalls),
            "freebsd_baseline_syscalls": len(FREEBSD_SYSCALLS),
            "prospero_proprietary_syscalls": len(PROSPERO_SYSCALLS),
            "total_monitored_ioctls": len(self.ioctls),
            "critical_race_uaf_targets": [
                {
                    "num": e.number,
                    "name": e.name,
                    "subsystem": e.subsystem,
                    "vuln_class": e.historical_vuln_class,
                    "risk_level": e.risk_level,
                    "notes": e.audit_notes,
                }
                for e in (critical_targets + high_risk_entries)
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
            "hardware_ioctl_surface": [
                {
                    "code": f"0x{i.code:08X}",
                    "name": i.name,
                    "device": i.device_node,
                    "direction": i.direction,
                    "size": i.data_size,
                    "risk_level": i.risk_level,
                    "notes": i.audit_notes,
                }
                for i in high_risk_ioctls
            ],
            "fuzzing_priority_score": {
                "umtx_subsystem": 9.5,
                "gpu_kmd_ioctl": 9.2,
                "event_flags_evf": 8.5,
                "named_objects": 8.0,
                "ipmi_and_blockpool": 8.0,
                "dynamic_library_loader": 7.5,
            },
        }

    def export_json(self, indent: int = 2) -> str:
        """Serializes the attack surface audit into clean JSON format."""
        return json.dumps(self.audit_attack_surface(), indent=indent)

    def generate_syzkaller_descriptions(self) -> str:
        """
        Generates Syzkaller-compatible syscall and IOCTL definitions for fuzzing
        Prospero-specific attack surfaces.
        """
        output = [
            "# Auto-generated Syzkaller descriptions for Prospero Kernel Fuzzing",
            "# Source: prospero-lab KernelSurfaceAuditor",
            "",
            "include <sys/types.h>",
            "",
            "# Named Objects Subsystem",
            "sys_namedobj_create(name ptr[in, string], flags flags[namedobj_flags], mode int32) int32",
            "sys_namedobj_delete(id int32, flags flags[namedobj_flags]) int32",
            "",
            "# Event Flags Subsystem",
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
            "",
            "# Proprietary Character Device IOCTLs",
            "ioctl$KMD_SUBMIT(fd fd_kmd, cmd const[0xC0184B01], arg ptr[inout, kmd_submit_args]) int32",
            "ioctl$ICC_SYSCON(fd fd_icc, cmd const[0x80204901], arg ptr[inout, icc_syscon_args]) int32",
            "ioctl$DNM_ALLOC_CHANNEL(fd fd_dnm, cmd const[0xC0204E01], arg ptr[inout, dnm_channel_args]) int32",
        ]
        return "\n".join(output)
