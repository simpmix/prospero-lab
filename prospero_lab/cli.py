"""
ProsperoLab Unified Command Line Interface.
Tools for BD-J disc generation, XOM/ROP mitigation auditing, SELF parsing,
simulation, and Prospero kernel attack surface analysis.
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
from prospero_lab.formats.self_parser import SELFParser
from prospero_lab.simulator.mock_runtime import MockRuntime
from prospero_lab.reporting.dashboard import DashboardGenerator


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
    print("[*] Setting up Mock Virtual Execution Runtime (AMD64)...")
    vm = MockRuntime()

    # Define gadget virtual addresses
    addr_pop_rdi = 0x7FFF00010000
    addr_pop_rsi = 0x7FFF00010050
    addr_pop_rdx = 0x7FFF000100A0
    addr_pop_rax = 0x7FFF000100F0
    addr_syscall = 0x7FFF00010120

    # Register gadget handlers
    vm.register_gadget(addr_pop_rdi, "pop rdi; ret", lambda rt: setattr(rt.cpu, "rdi", rt.read_qword(rt.cpu.rsp, allow_xom=True)) or setattr(rt.cpu, "rsp", rt.cpu.rsp + 8))
    vm.register_gadget(addr_pop_rsi, "pop rsi; ret", lambda rt: setattr(rt.cpu, "rsi", rt.read_qword(rt.cpu.rsp, allow_xom=True)) or setattr(rt.cpu, "rsp", rt.cpu.rsp + 8))
    vm.register_gadget(addr_pop_rdx, "pop rdx; ret", lambda rt: setattr(rt.cpu, "rdx", rt.read_qword(rt.cpu.rsp, allow_xom=True)) or setattr(rt.cpu, "rsp", rt.cpu.rsp + 8))
    vm.register_gadget(addr_pop_rax, "pop rax; ret", lambda rt: setattr(rt.cpu, "rax", rt.read_qword(rt.cpu.rsp, allow_xom=True)) or setattr(rt.cpu, "rsp", rt.cpu.rsp + 8))
    vm.register_gadget(addr_syscall, "syscall; ret", lambda rt: None)

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

    print(f"[*] Running ROP payload simulation from stack: 0x{fake_stack:x}...")
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
        print(f"[-] Error: File {target} does not exist.")
        sys.exit(1)

    data = target.read_bytes()
    print(f"[*] Parsing SELF binary: {target.name} ({len(data)} bytes)...")
    try:
        parser = SELFParser(data)
        summary = parser.get_summary()

        print("\n=== SONY SIGNED ELF (SELF) HEADER ===")
        print(f"  Magic:           {summary['magic']!r}")
        print(f"  Format Version:  {summary['version']}")
        print(f"  Endianness:      {summary['endianness']}")
        print(f"  Total File Size: {summary['total_file_size']} bytes")
        print(f"  Total Segments:  {summary['num_segments']}")
        print(f"  Fully Decrypted: {'YES' if summary['fully_decrypted'] else 'NO (Contains SAMU encrypted segments)'}")

        print("\nSegment Descriptors:")
        for seg in summary["segments"]:
            print(f"  Segment #{seg['index']:<2} Offset: {seg['offset']:<10} FileSize: {seg['file_size']:<10} MemSize: {seg['memory_size']:<10} [{seg['status']}]")

    except Exception as e:
        print(f"[-] Failed to parse SELF container: {e}")


def cmd_generate_dashboard(args):
    out_file = Path(args.output)
    print(f"[*] Generating offline security audit dashboard to: {out_file}...")
    dash = DashboardGenerator()
    dash.write_report(out_file)
    print(f"[+] Dashboard generated successfully! Open file:///{out_file.resolve()} in your browser.")


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

    # Command: simulate-chain
    p_sim = subparsers.add_parser("simulate-chain", help="Simulate 64-bit ROP execution in a mock AMD64 environment")
    p_sim.set_defaults(func=cmd_simulate_chain)

    # Command: parse-self
    p_self = subparsers.add_parser("parse-self", help="Parse Sony Signed ELF (SELF/SPRX) container headers")
    p_self.add_argument("file", help="Path to SELF / SPRX binary")
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
