"""
ProsperoLab Unified Command Line Interface.
Tools for BD-J disc generation, XOM/ROP mitigation auditing, SELF parsing,
simulation, and Prospero kernel attack surface analysis.
"""

import argparse
import sys
import os
import json
from pathlib import Path

from prospero_lab.bdj.bdmv_generator import BDMVGenerator
from prospero_lab.bdj.xlet_bundler import XletBundler, PERMISSION_PROFILES
from prospero_lab.bdj.iso_builder import DiscImageBuilder
from prospero_lab.xom.elf_parser import ELF64Parser
from prospero_lab.xom.gadget_analyzer import GadgetAnalyzer, Gadget
from prospero_lab.xom.blind_rop import ROPChainBuilder
from prospero_lab.kernel.surface_auditor import KernelSurfaceAuditor
from prospero_lab.formats.self_parser import SELFParser
from prospero_lab.simulator.mock_runtime import MockRuntime
from prospero_lab.reporting.dashboard import DashboardGenerator
from prospero_lab.logging import logger


def cmd_bdj_create(args):
    out_dir = Path(args.output)
    logger.info(f"Initializing BDMV generator for target: {out_dir}")
    generator = BDMVGenerator()
    paths = generator.build_structure(out_dir)

    logger.info(f"Packaging BD-J Xlet bundle for class: {args.xlet_class} (Profile: {args.profile})")
    bundler = XletBundler(xlet_class_name=args.xlet_class, permission_profile=args.profile)
    jar_path = bundler.write_jar_to_bdmv(paths["JAR"], "00000.jar")

    logger.info(f"Successfully wrote BD-J JAR to: {jar_path}")

    # Validate compliance
    builder = DiscImageBuilder(out_dir)
    compliance = builder.validate_compliance()
    if compliance["compliant"]:
        logger.info("BD-J structure passed all Blu-ray compliance checks!")
    else:
        logger.warning("Some compliance checks failed:")
        for check, passed in compliance["details"].items():
            print(f"    {'[OK]' if passed else '[FAIL]'} {check}")

    if args.burn_instructions:
        print("\n" + builder.export_burn_instructions())


def cmd_xom_scan(args):
    target = Path(args.file)
    if not target.is_file():
        logger.error(f"Target file {target} does not exist.")
        sys.exit(1)

    raw_data = target.read_bytes()
    is_elf = raw_data[:4] == b"\x7fELF"
    analyzer = GadgetAnalyzer(base_address=args.base)

    all_gadgets = []
    has_xom = False

    if is_elf:
        try:
            parser = ELF64Parser(raw_data)
            has_xom = parser.check_xom_enforcement()
            exec_segments = parser.get_executable_segments()
            for ph, seg_bytes in exec_segments:
                gadgets = analyzer.scan_segment(seg_bytes, ph.p_vaddr)
                all_gadgets.extend(gadgets)
        except Exception as e:
            logger.warning(f"Failed to parse ELF structures: {e}. Falling back to raw scan.")
            all_gadgets = analyzer.scan_segment(raw_data, args.base)
    else:
        all_gadgets = analyzer.scan_segment(raw_data, args.base)

    coverage = analyzer.analyze_coverage(all_gadgets)

    if args.json:
        result = {
            "file": str(target),
            "is_elf": is_elf,
            "xom_enforced": has_xom,
            "coverage": coverage,
            "gadgets": [g.to_dict() for g in all_gadgets],
        }
        print(json.dumps(result, indent=2))
        return

    logger.info(f"Reading {len(raw_data)} bytes from {target.name}...")
    if is_elf:
        print(f"[+] Detected valid ELF64 binary.")
        print(f"    - XOM Enforced (Execute-Only): {'YES [ALERT: Reads will fault]' if has_xom else 'NO [Readable]'}")

    print("\n=== GADGET & MITIGATION COVERAGE REPORT ===")
    print(f"  Total Gadgets Identified: {coverage['total_gadgets']}")
    print(f"  Stack Pivot Available:     {'YES' if coverage['has_stack_pivot'] else 'NO'}")
    print(f"  Syscall Invoker:          {'YES' if coverage['has_syscall'] else 'NO'}")
    print(f"  Core Arg Setters (RDI..): {'YES' if coverage['has_core_args (rdi, rsi, rdx)'] else 'NO'}")
    print(f"  Memory Write Primitive:   {'YES' if coverage['has_write_primitive'] else 'NO'}")
    print(f"  JOP Dispatchers:          {'YES' if coverage['has_jop_dispatchers'] else 'NO'}")
    print(f"  ROP Viability Score:      {coverage['rop_viability_score']} / 100")

    print("\nTop Primitives Discovered:")
    for g in all_gadgets[:15]:
        print(f"  [0x{g.address:012x}] ({g.category:<16}) {g.disassembly:<25} (Score: {g.xom_score})")


def cmd_kernel_audit(args):
    auditor = KernelSurfaceAuditor()
    if args.json:
        print(auditor.export_json())
        return

    logger.info("Performing Prospero Kernel Attack Surface Audit...")
    report = auditor.audit_attack_surface()

    print(f"\n=== PROSPERO KERNEL ATTACK SURFACE ===")
    print(f"  Total Monitored Syscalls:     {report['total_monitored_syscalls']}")
    print(f"  Base FreeBSD 12 Syscalls:     {report['freebsd_baseline_syscalls']}")
    print(f"  Sony Custom Syscalls:         {report['prospero_proprietary_syscalls']}")
    print(f"  Monitored IOCTL Commands:     {report.get('total_monitored_ioctls', 0)}")

    print("\n[!] Top High-Risk Primitives (Race Conditions & Memory Corruption):")
    for t in report["critical_race_uaf_targets"]:
        vuln_str = t.get("vuln_class") or "Attack Surface"
        print(f"  - Syscall #{t['num']:<3} {t['name']:<25} [{t['subsystem'].upper()}] - {vuln_str}")
        if t["notes"]:
            print(f"      Note: {t['notes']}")

    print("\n[*] High-Risk Character Device IOCTLs:")
    for i in report.get("hardware_ioctl_surface", []):
        print(f"  - {i['device']:<12} {i['name']:<30} [{i['direction']}] - {i['notes']}")

    print("\n[*] Recommended Fuzzing Priorities (1-10):")
    for sub, prio in report["fuzzing_priority_score"].items():
        print(f"  - {sub:<28}: {prio}")

    if args.syzkaller:
        print("\n=== GENERATED SYZKALLER DEFINITIONS ===")
        print(auditor.generate_syzkaller_descriptions())


def cmd_build_chain(args):
    logger.info("Generating Sample 64-bit Syscall ROP Chain (e.g. sys_mprotect)...")
    gadget_map = {
        "pop_rdi": 0x7FFF00010000,
        "pop_rsi": 0x7FFF00010050,
        "pop_rdx": 0x7FFF000100A0,
        "pop_rax": 0x7FFF000100F0,
        "syscall": 0x7FFF00010120,
    }

    builder = ROPChainBuilder(gadget_map)
    # mprotect(addr=0x100000, len=0x4000, prot=0x7 [RWX])
    builder.build_syscall(sys_num=74, arg1=0x100000, arg2=0x4000, arg3=0x7)

    raw_chain = builder.serialize()
    print(f"[+] Chain size: {len(raw_chain)} bytes ({len(raw_chain)//8} QWORDS)")
    print("\nSerialized ROP Stack Layout:")
    print(builder.hex_dump())


def cmd_simulate_chain(args):
    logger.info("Setting up Mock Virtual Execution Runtime (AMD64)...")
    vm = MockRuntime()

    addr_pop_rdi = 0x7FFF00010000
    addr_pop_rsi = 0x7FFF00010050
    addr_pop_rdx = 0x7FFF000100A0
    addr_pop_rax = 0x7FFF000100F0
    addr_syscall = 0x7FFF00010120

    # Auto register standard test gadgets
    test_gadgets = [
        Gadget(addr_pop_rdi, 0, b"\x5f\xc3", "pop rdi; ret", "arg1_setup", "REGISTER_LOAD", 9),
        Gadget(addr_pop_rsi, 0, b"\x5e\xc3", "pop rsi; ret", "arg2_setup", "REGISTER_LOAD", 9),
        Gadget(addr_pop_rdx, 0, b"\x5a\xc3", "pop rdx; ret", "arg3_setup", "REGISTER_LOAD", 9),
        Gadget(addr_pop_rax, 0, b"\x58\xc3", "pop rax; ret", "rax_setup", "REGISTER_LOAD", 9),
        Gadget(addr_syscall, 0, b"\x0f\x05\xc3", "syscall; ret", "syscall_invoke", "SYSCALL", 10),
    ]
    vm.load_gadgets_from_analyzer(test_gadgets)

    # Build ROP chain for sys_mprotect(0x100000, 0x4000, 0x7)
    builder = ROPChainBuilder({
        "pop_rdi": addr_pop_rdi,
        "pop_rsi": addr_pop_rsi,
        "pop_rdx": addr_pop_rdx,
        "pop_rax": addr_pop_rax,
        "syscall": addr_syscall,
    })
    builder.build_syscall(sys_num=74, arg1=0x100000, arg2=0x4000, arg3=0x7)

    payload = builder.serialize()
    fake_stack = 0x7FFFFFFFE000
    vm.load_rop_chain(fake_stack, payload)

    logger.info(f"Running ROP payload simulation from stack: 0x{fake_stack:x}...")
    traces = vm.run_rop()

    print(f"[+] Simulation completed successfully ({len(traces)} gadget steps executed)!\n")
    for tr in traces:
        print(f"Step {tr.step_num:02d} | RIP: 0x{tr.rip:012x} | {tr.disassembly:<15}")
        if tr.syscall_dispatched:
            sc = tr.syscall_dispatched
            print(f"    --> [SYSCALL #{sc['syscall_number']}] RDI=0x{sc['arg1_rdi']:x}, RSI=0x{sc['arg2_rsi']:x}, RDX=0x{sc['arg3_rdx']:x}")
            print(f"        Result: {sc['effect']}")

    print("\nFinal CPU State:")
    print(vm.cpu.dump())


def cmd_parse_self(args):
    target = Path(args.file)
    if not target.is_file():
        logger.error(f"File {target} does not exist.")
        sys.exit(1)

    data = target.read_bytes()
    try:
        parser = SELFParser(data)
        if args.json:
            print(parser.export_json())
            return

        logger.info(f"Parsing SELF binary: {target.name} ({len(data)} bytes)...")
        summary = parser.get_summary()

        print("\n=== SONY SIGNED ELF (SELF) HEADER ===")
        print(f"  Magic:           {summary['magic']!r}")
        print(f"  Format Version:  {summary['version']}")
        print(f"  Endianness:      {summary['endianness']}")
        print(f"  Total File Size: {summary['total_file_size']} bytes")
        print(f"  Total Segments:  {summary['num_segments']}")
        print(f"  Fully Decrypted: {'YES' if summary['fully_decrypted'] else 'NO (Contains SAMU encrypted segments)'}")

        if summary.get("control_info_blocks"):
            print("\nControl Info Blocks:")
            for b in summary["control_info_blocks"]:
                print(f"  - [{b['type']}] Size: {b['size']} bytes {b['details']}")

        print("\nSegment Descriptors:")
        for seg in summary["segments"]:
            print(f"  Segment #{seg['index']:<2} Offset: {seg['offset']:<10} FileSize: {seg['file_size']:<10} MemSize: {seg['memory_size']:<10} [{seg['status']}]")

    except Exception as e:
        logger.error(f"Failed to parse SELF container: {e}")


def cmd_generate_dashboard(args):
    out_file = Path(args.output)
    logger.info(f"Generating offline security audit dashboard to: {out_file}...")
    dash = DashboardGenerator()
    dash.write_report(out_file)
    logger.info(f"Dashboard generated successfully! Open file:///{out_file.resolve()} in your browser.")


def main():
    parser = argparse.ArgumentParser(
        prog="prospero-lab",
        description="PlayStation 5 (Prospero OS) Systems Security & Exploration Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: bdj-create
    p_bdj = subparsers.add_parser("bdj-create", help="Create a complete, compliant BD-J research disc structure")
    p_bdj.add_argument("-o", "--output", default="prospero_bdj_disc", help="Output directory for BDMV tree")
    p_bdj.add_argument("--xlet-class", default="prospero.research.ProbeXlet", help="Target Java Xlet entry class")
    p_bdj.add_argument("--profile", choices=list(PERMISSION_PROFILES.keys()), default="unrestricted", help="Permission preset")
    p_bdj.add_argument("--burn-instructions", action="store_true", help="Print ISO authoring & burning instructions")
    p_bdj.set_defaults(func=cmd_bdj_create)

    # Command: xom-scan
    p_xom = subparsers.add_parser("xom-scan", help="Scan binary/ELF for XOM constraints and ROP primitives")
    p_xom.add_argument("file", help="Path to ELF binary or memory dump")
    p_xom.add_argument("--base", type=lambda x: int(x, 0), default=0x0, help="Base address offset (e.g. 0x7fff00000)")
    p_xom.add_argument("--json", action="store_true", help="Output findings in JSON format")
    p_xom.set_defaults(func=cmd_xom_scan)

    # Command: kernel-audit
    p_kernel = subparsers.add_parser("kernel-audit", help="Audit Prospero vs. FreeBSD 12 kernel attack surface")
    p_kernel.add_argument("--syzkaller", action="store_true", help="Output Syzkaller definitions for kernel fuzzers")
    p_kernel.add_argument("--json", action="store_true", help="Output findings in JSON format")
    p_kernel.set_defaults(func=cmd_kernel_audit)

    # Command: build-chain
    p_chain = subparsers.add_parser("build-chain", help="Synthesize and inspect a 64-bit ROP syscall chain")
    p_chain.set_defaults(func=cmd_build_chain)

    # Command: simulate-chain
    p_sim = subparsers.add_parser("simulate-chain", help="Simulate 64-bit ROP execution in a mock AMD64 environment")
    p_sim.set_defaults(func=cmd_simulate_chain)

    # Command: parse-self
    p_self = subparsers.add_parser("parse-self", help="Parse Sony Signed ELF (SELF/SPRX) container headers")
    p_self.add_argument("file", help="Path to SELF / SPRX binary")
    p_self.add_argument("--json", action="store_true", help="Output container metadata in JSON format")
    p_self.set_defaults(func=cmd_parse_self)

    # Command: dashboard
    p_dash = subparsers.add_parser("dashboard", help="Generate an interactive single-file HTML audit report")
    p_dash.add_argument("-o", "--output", default="prospero_audit_dashboard.html", help="Output HTML file path")
    p_dash.set_defaults(func=cmd_generate_dashboard)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
