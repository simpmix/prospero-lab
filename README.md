# ProsperoLab

> **A Systems Security & Exploration Framework for PlayStation 5 (Prospero OS)**

`prospero-lab` is a modular, zero-dependency Python research framework built to address real bottlenecks in PlayStation 5 systems security and homebrew research. Rather than rehashing ephemeral webkit payloads, it provides tooling for:

1. **BD-J (Blu-ray Disc Java) Automation & Synthesis**: Programmatically generates bit-accurate, compliant Blu-ray Movie (`BDMV 2.0`) disc structures (`index.bdmv`, `MovieObject.bdmv`, playlists, BDJO) and packages Xlet JARs with synthetic bytecode (no JDK required).
2. **XOM (eXecute-Only Memory) & ROP Analysis**: Evaluates binary segments under modern hypervisor memory protections (`PF_X` without `PF_R`), locating viable control-flow primitives (stack pivots, SysV ABI register setup, system call invocations).
3. **Execution Simulator & ROP Verifier**: Emulates AMD64 CPU execution and virtual memory permissions (W^X and XOM) to verify ROP payload dispatch safely without hardware panics.
4. **Kernel Surface Auditing & Differential Mapping**: Compares baseline FreeBSD 12 against Sony's proprietary Prospero kernel extensions (UMTX, Event Flags, Named Objects, Dynamic Loader) and generates Syzkaller descriptions for automated kernel fuzzers.
5. **SELF / SPRX Binary Format Parser**: Inspects Sony Signed ELF containers, metadata blocks, and segment encryption status (SAMU flags).
6. **Interactive HTML Security Dashboard**: Generates self-contained, offline HTML visual audit reports.

---

## Architecture Overview

```
prospero_lab/
├── bdj/
│   ├── bdmv_generator.py   # Bit-accurate BDMV 2.0 file structures (index, MovieObject, MPLS, CLPI)
│   ├── xlet_bundler.py     # JAR packager & pure-Python Java .class bytecode synthesizer
│   └── iso_builder.py      # Blu-ray compliance validator & UDF 2.50 burning instructions
├── xom/
│   ├── elf_parser.py       # ELF64 header & program segment parser with XOM detection
│   ├── gadget_analyzer.py  # Control-flow primitive scanner with XOM suitability scoring
│   └── blind_rop.py        # 64-bit ROP syscall chain assembler and stack layout visualizer
├── simulator/
│   └── mock_runtime.py     # AMD64 virtual execution engine, W^X / XOM enforcement & syscall auditor
├── formats/
│   └── self_parser.py      # Sony Signed ELF (SELF/SPRX) container parser & SAMU flag inspector
├── kernel/
│   ├── syscall_table.py    # Database of FreeBSD 12 vs. Prospero proprietary syscalls
│   └── surface_auditor.py  # Attack surface auditor & Syzkaller fuzzer definition generator
├── reporting/
│   └── dashboard.py        # Offline single-file HTML audit report & security dashboard generator
├── templates/
│   └── ProbeXlet.java      # Reference Java source for BD-J environment introspection
└── cli.py                  # Unified CLI interface
```

---

## Quick Start

### 1. Requirements
* Python 3.9+ (Zero external dependencies; uses Python standard library).

### 2. Running the Tool
Run directly as a Python module:
```bash
python -m prospero_lab.cli --help
```

---

## Core Capabilities

### 1. Authoring BD-J Research Discs (`bdj-create`)
Physical Blu-ray discs provide an offline attack surface that cannot be remotely patched by WebKit updates. `prospero-lab` constructs the entire BDMV tree, generates compliant `index.bdmv` and `MovieObject.bdmv` files, synthesizes valid Java 5 Xlet bytecode, and injects sandbox-escape permission requests:

```bash
python -m prospero_lab.cli bdj-create --output my_disc --burn-instructions
```

### 2. Simulating ROP Execution in a Mock AMD64 Runtime (`simulate-chain`)
Safely verify that a synthesized 64-bit ROP chain sets up registers correctly and dispatches system calls without memory faults:

```bash
python -m prospero_lab.cli simulate-chain
```

Output:
```
[*] Setting up Mock Virtual Execution Runtime (AMD64)...
[*] Running ROP payload simulation from stack: 0x7fffffffe000...
[+] Simulation completed successfully (5 gadget steps executed)!

Step 00 | RIP: 0x7fff00010000 | pop rdi; ret   
Step 01 | RIP: 0x7fff00010050 | pop rsi; ret   
Step 02 | RIP: 0x7fff000100a0 | pop rdx; ret   
Step 03 | RIP: 0x7fff000100f0 | pop rax; ret   
Step 04 | RIP: 0x7fff00010120 | syscall; ret   
    --> [SYSCALL #74] RDI=0x100000, RSI=0x4000, RDX=0x7
        Result: Mapped new page at 0x100000 with prot 0x7
```

### 3. Auditing the Prospero Kernel Attack Surface (`kernel-audit`)
Compares FreeBSD 12 system calls with Sony's proprietary extensions, highlighting historical vulnerability classes (race conditions, UAFs, ASLR infoleaks) and generating fuzzing targets:

```bash
python -m prospero_lab.cli kernel-audit --syzkaller
```

### 4. Generating Offline HTML Security Dashboards (`dashboard`)
Creates a visual report summarizing monitored syscalls, high-risk race conditions, and Syzkaller fuzzer definitions:

```bash
python -m prospero_lab.cli dashboard --output prospero_audit_dashboard.html
```

### 5. Inspecting Sony Signed ELF Containers (`parse-self`)
Inspects PlayStation `.prx`, `.sprx`, or `.bin` files to identify segment encryption flags and container metadata:

```bash
python -m prospero_lab.cli parse-self /path/to/binary.sprx
```

### 6. Scanning Binaries for XOM Mitigations & ROP Gadgets (`xom-scan`)
The PS5 Hypervisor enforces eXecute-Only Memory (XOM). `xom-scan` checks segment permissions and extracts essential execution primitives:

```bash
python -m prospero_lab.cli xom-scan /path/to/binary_or_dump.elf --base 0x7fff00000
```

---

## Running the Test Suite

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## Ethical & Security Disclaimer

This project is created strictly for **authorized security research, vulnerability analysis, systems engineering, and academic study**. If you discover security vulnerabilities, report them responsibly via the [PlayStation Bug Bounty program on HackerOne](https://hackerone.com/playstation).
