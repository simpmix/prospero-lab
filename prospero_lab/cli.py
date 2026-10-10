"""
ProsperoLab Unified Command Line Interface.
Tools for BD-J disc generation, XOM/ROP mitigation auditing, and Prospero kernel analysis.
"""

import argparse
import sys
import os
from pathlib import Path

from prospero_lab.bdj.bdmv_generator import BDMVGenerator
from prospero_lab.bdj.xlet_bundler import XletBundler
from prospero_lab.bdj.iso_builder import DiscImageBuilder
from prospero_lab.xom.elf_parser import ELF64Parser
from prospero_lab.xom.gadget_analyzer import GadgetAnalyzer
from prospero_lab.xom.blind_rop import ROPChainBuilder
from prospero_lab.kernel.surface_auditor import KernelSurfaceAuditor


def cmd_bdj_create(args):
    out_dir = Path(args.output)
    print(f"[*] Initializing BDMV generator for target: {out_dir}")
    generator = BDMVGenerator()
    paths = generator.build_structure(out_dir)

    print(f"[*] Packaging BD-J Xlet bundle for class: {args.xlet_class}")
    bundler = XletBundler(xlet_class_name=args.xlet_class)
    jar_path = bundler.write_jar_to_bdmv(paths["JAR"], "00000.jar")

    print(f"[+] Successfully wrote BD-J JAR to: {jar_path}")

    # Validate compliance
    builder = DiscImageBuilder(out_dir)
    compliance = builder.validate_compliance()
    if compliance["compliant"]:
        print("[+] BD-J structure passed all Blu-ray compliance checks!")
    else:
        print("[!] Warning: Some compliance checks failed:")
        for check, passed in compliance["details"].items():
            print(f"    {'[OK]' if passed else '[FAIL]'} {check}")

    if args.burn_instructions:
        print("\n" + builder.export_burn_instructions())


def cmd_xom_scan(args):
    target = Path(args.file)
    if not target.is_file():
        print(f"[-] Error: Target file {target} does not exist.")
        sys.exit(1)

    raw_data = target.read_bytes()
    print(f"[*] Reading {len(raw_data)} bytes from {target.name}...")

    # Check if ELF
    is_elf = raw_data[:4] == b"\x7fELF"
    analyzer = GadgetAnalyzer(base_address=args.base)

    if is_elf:
        try:
            parser = ELF64Parser(raw_data)
            has_xom = parser.check_xom_enforcement()
            print(f"[+] Detected valid ELF64 binary.")
            print(f"    - Total Program Headers: {len(parser.headers)}")
            print(f"    - XOM Enforced (Execute-Only): {'YES [ALERT: Reads will fault]' if has_xom else 'NO [Readable]'}")

            exec_segments = parser.get_executable_segments()
            print(f"    - Executable segments found: {len(exec_segments)}")

            all_gadgets = []
            for ph, seg_bytes in exec_segments:
                print(f"    - Scanning segment at vaddr 0x{ph.p_vaddr:x} (size: {len(seg_bytes)} bytes)...")
                gadgets = analyzer.scan_segment(seg_bytes, ph.p_vaddr)
                all_gadgets.extend(gadgets)

        except Exception as e:
            print(f"[-] Failed to parse ELF structures: {e}. Falling back to raw scan.")
            all_gadgets = analyzer.scan_segment(raw_data, args.base)
    else:
        print("[*] Treating target as raw memory dump or code payload.")
        all_gadgets = analyzer.scan_segment(raw_data, args.base)

    coverage = analyzer.analyze_coverage(all_gadgets)
    print("\n=== GADGET & MITIGATION COVERAGE REPORT ===")
    print(f"  Total Gadgets Identified: {coverage['total_gadgets']}")
    print(f"  Stack Pivot Available:     {'YES' if coverage['has_stack_pivot'] else 'NO'}")
    print(f"  Syscall Invoker:          {'YES' if coverage['has_syscall'] else 'NO'}")
    print(f"  Core Arg Setters (RDI..): {'YES' if coverage['has_core_args (rdi, rsi, rdx)'] else 'NO'}")
    print(f"  Memory Write Primitive:   {'YES' if coverage['has_write_primitive'] else 'NO'}")
    print(f"  ROP Viability Score:      {coverage['rop_viability_score']} / 100")

    print("\nTop Primitives Discovered:")
    for g in all_gadgets[:15]:
        print(f"  [0x{g.address:012x}] ({g.role:<20}) {g.disassembly} (Score: {g.xom_score})")


def cmd_kernel_audit(args):
    print("[*] Performing Prospero Kernel Attack Surface Audit...")
    auditor = KernelSurfaceAuditor()
    report = auditor.audit_attack_surface()

    print(f"\n=== PROSPERO KERNEL ATTACK SURFACE ===")
    print(f"  Total Monitored Syscalls:     {report['total_monitored_syscalls']}")
    print(f"  Base FreeBSD 12 Syscalls:     {report['freebsd_baseline_syscalls']}")
    print(f"  Sony Custom Syscalls:         {report['prospero_proprietary_syscalls']}")

    print("\n[!] Top High-Risk Primitives (Race Conditions & UAF):")
    for t in report["critical_race_uaf_targets"]:
        print(f"  - Syscall #{t['num']:<3} {t['name']:<25} [{t['subsystem'].upper()}] - {t['vuln_class']}")
        if t["notes"]:
            print(f"      Note: {t['notes']}")

    print("\n[*] ASLR Infoleak Vectors:")
    for t in report["aslr_bypass_targets"]:
        print(f"  - Syscall #{t['num']:<3} {t['name']:<25} [{t['subsystem'].upper()}] - {t['notes']}")

    print("\n[*] Recommended Fuzzing Priorities (1-10):")
    for sub, prio in report["fuzzing_priority_score"].items():
        print(f"  - {sub:<28}: {prio}")

    if args.syzkaller:
        print("\n=== GENERATED SYZKALLER DEFINITIONS ===")
        print(auditor.generate_syzkaller_descriptions())


def cmd_build_chain(args):
    print("[*] Generating Sample 64-bit Syscall ROP Chain (e.g. sys_mprotect)...")
    # Mock gadget table representing standard Prospero addresses
    gadget_map = {
        "pop_rdi": 0x7FFF00010000,
        "pop_rsi": 0x7FFF00010050,
        "pop_rdx": 0x7FFF000100A0,
        "pop_rax": 0x7FFF000100F0,
        "syscall": 0x7FFF00010120,
    }

    builder = ROPChainBuilder(gadget_map)
    # mprotect(addr=0x100000, len=0x4000, prot=0x7 [RWX])
    # Syscall #74 is mprotect
    builder.build_syscall(sys_num=74, arg1=0x100000, arg2=0x4000, arg3=0x7)

    raw_chain = builder.serialize()
    print(f"[+] Chain size: {len(raw_chain)} bytes ({len(raw_chain)//8} QWORDS)")
    print("\nSerialized ROP Stack Layout:")
    print(builder.hex_dump())


def main():
    parser = argparse.ArgumentParser(
        prog="prospero-lab",
        description="PlayStation 5 (Prospero OS) Security Research & Exploration Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: bdj-create
    p_bdj = subparsers.add_parser("bdj-create", help="Create a complete, compliant BD-J research disc structure")
    p_bdj.add_argument("-o", "--output", default="prospero_bdj_disc", help="Output directory for BDMV tree")
    p_bdj.add_argument("--xlet-class", default="prospero.research.ProbeXlet", help="Target Java Xlet entry class")
    p_bdj.add_argument("--burn-instructions", action="store_true", help="Print ISO authoring & burning instructions")
    p_bdj.set_defaults(func=cmd_bdj_create)

    # Command: xom-scan
    p_xom = subparsers.add_parser("xom-scan", help="Scan binary/ELF for XOM constraints and ROP primitives")
    p_xom.add_argument("file", help="Path to ELF binary or memory dump")
    p_xom.add_argument("--base", type=lambda x: int(x, 0), default=0x0, help="Base address offset (e.g. 0x7fff00000)")
    p_xom.set_defaults(func=cmd_xom_scan)

    # Command: kernel-audit
    p_kernel = subparsers.add_parser("kernel-audit", help="Audit Prospero vs. FreeBSD 12 kernel attack surface")
    p_kernel.add_argument("--syzkaller", action="store_true", help="Output Syzkaller definitions for kernel fuzzers")
    p_kernel.set_defaults(func=cmd_kernel_audit)

    # Command: build-chain
    p_chain = subparsers.add_parser("build-chain", help="Synthesize and inspect a 64-bit ROP syscall chain")
    p_chain.set_defaults(func=cmd_build_chain)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
