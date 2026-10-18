"""
Proprietary IOCTL Device Driver Attack Surface Database.
Documents Sony Prospero character devices, major IOCTL control codes,
structure layouts, and hardware interaction boundaries.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class IOCTLEntry:
    code: int
    name: str
    device_node: str
    direction: str  # 'in', 'out', 'inout', 'void'
    data_size: int
    struct_description: str
    audit_notes: str
    risk_level: str = "medium"  # 'critical', 'high', 'medium', 'low'


# Character device nodes and proprietary IOCTL commands
PROSPERO_IOCTL_COMMANDS: List[IOCTLEntry] = [
    # Kernel Mode Driver (GPU / APU Command Ring)
    IOCTLEntry(
        code=0xC0184B01,
        name="KMD_IOCTL_SUBMIT_COMMAND_BUFFER",
        device_node="/dev/kmd",
        direction="inout",
        data_size=24,
        struct_description="struct { uint64_t ring_addr; uint32_t ring_size; uint32_t flags; uint64_t fence_val; }",
        audit_notes="Submits raw GPU command packets to the RDNA 2 command processor. Critical target for GPU shader escape.",
        risk_level="critical",
    ),
    IOCTLEntry(
        code=0xC0104B02,
        name="KMD_IOCTL_ALLOCATE_PAGETABLE",
        device_node="/dev/kmd",
        direction="inout",
        data_size=16,
        struct_description="struct { uint64_t vaddr; uint64_t page_count; }",
        audit_notes="Configures GPU virtual address space mapping and page table entries.",
        risk_level="critical",
    ),

    # Inter-Chip Communication (Syscon / Southbridge)
    IOCTLEntry(
        code=0x80204901,
        name="ICC_IOCTL_SYSCON_CMD",
        device_node="/dev/icc",
        direction="inout",
        data_size=32,
        struct_description="struct { uint16_t cmd; uint16_t length; uint8_t data[28]; }",
        audit_notes="Sends raw serial commands to the Syscon microcontroller controlling power, fans, and hardware state.",
        risk_level="high",
    ),
    IOCTLEntry(
        code=0x40044902,
        name="ICC_IOCTL_GET_THERMAL_STATUS",
        device_node="/dev/icc",
        direction="out",
        data_size=4,
        struct_description="struct { uint32_t temp_celsius; }",
        audit_notes="Reads APU thermal sensor diodes.",
        risk_level="low",
    ),

    # Serial Flash (SPI Flash / Secure NVRAM)
    IOCTLEntry(
        code=0x80105301,
        name="SFLASH_IOCTL_READ_BLOCK",
        device_node="/dev/sflash",
        direction="inout",
        data_size=16,
        struct_description="struct { uint32_t offset; uint32_t length; uint64_t user_buf; }",
        audit_notes="Reads non-volatile system firmware partitions. Protected by kernel access control lists.",
        risk_level="high",
    ),

    # DIP Switch & Diagnostic Control
    IOCTLEntry(
        code=0x40044401,
        name="DIPSW_IOCTL_GET_FLAGS",
        device_node="/dev/dipsw",
        direction="out",
        data_size=4,
        struct_description="struct { uint32_t flags; }",
        audit_notes="Reads diagnostic hardware mode flags (Retail vs Development/TestKit mode).",
        risk_level="medium",
    ),

    # Direct Node Manager
    IOCTLEntry(
        code=0xC0204E01,
        name="DNM_IOCTL_ALLOCATE_CHANNEL",
        device_node="/dev/dnm",
        direction="inout",
        data_size=32,
        struct_description="struct { uint32_t node_id; uint32_t priority; uint64_t shm_handle; uint64_t result; }",
        audit_notes="Direct Node Manager IPC channel configuration; prone to unaligned pointer dereference.",
        risk_level="critical",
    ),
]


def get_all_ioctls() -> List[IOCTLEntry]:
    """Returns the full catalog of documented character device IOCTL entry points."""
    return list(PROSPERO_IOCTL_COMMANDS)
