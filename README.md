# ProsperoLab

[![ProsperoLab CI](https://github.com/simpmix/prospero-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/simpmix/prospero-lab/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **A Systems Security & Exploration Framework for PlayStation 5 (Prospero OS)**

`prospero-lab` is a modular, zero-dependency Python research framework built to address real bottlenecks in PlayStation 5 systems security and homebrew research. Rather than rehashing ephemeral webkit payloads, it provides tooling for:

1. **BD-J (Blu-ray Disc Java) Automation & Synthesis**: Programmatically generates bit-accurate, compliant Blu-ray Movie (`BDMV 2.0`) disc structures (`index.bdmv`, `MovieObject.bdmv`, playlists, BDJO) and packages Xlet JARs with synthetic bytecode (no JDK required) and configurable permission profiles (`unrestricted`, `network`, `storage`, `minimal`).
2. **XOM (eXecute-Only Memory) & ROP Analysis**: Evaluates binary segments under modern hypervisor memory protections (`PF_X` without `PF_R`), locating viable control-flow primitives (stack pivots, SysV ABI register setup, JOP dispatchers, and system call invocations).
3. **Execution Simulator & ROP Verifier**: Emulates AMD64 CPU execution and virtual memory permissions (W^X and XOM) to verify ROP payload dispatch safely without hardware panics.
4. **Kernel Surface Auditing & Differential Mapping**: Compares baseline FreeBSD 12 against Sony's proprietary Prospero kernel extensions (UMTX, Event Flags, Named Objects, Dynamic Loader, and `/dev/` character device IOCTL interfaces) with automated Syzkaller grammar generation.
5. **SELF / SPRX Binary Format Parser**: Inspects Sony Signed ELF containers, metadata blocks, and segment encryption status (SAMU flags).
6. **Interactive HTML Security Dashboard**: Generates self-contained, offline HTML visual audit reports with tabbed navigation and real-time live search.

---

## Architecture Overview

```
prospero_lab/
├── bdj/
│   ├── bdmv_generator.py   # Bit-accurate BDMV 2.0 file structures (index, MovieObject, MPLS, CLPI)
│   ├── xlet_bundler.py     # JAR packager with permission profiles & pure-Python Java .class synthesizer
│   └── iso_builder.py      # Blu-ray compliance validator & UDF 2.50 burning instructions
├── xom/
│   ├── elf_parser.py       # ELF64 header & program segment parser with XOM detection
│   ├── gadget_analyzer.py  # Control-flow primitive scanner with dynamic GPR pops & JOP dispatchers
│   └── blind_rop.py        # 64-bit SysV AMD64 syscall chain assembler, pivots & write64 primitives
├── simulator/
│   └── mock_runtime.py     # AMD64 virtual execution engine, W^X / XOM enforcement & syscall auditor
├── formats/
│   └── self_parser.py      # Sony Signed ELF container parser, Control Info blocks & SAMU flags
├── kernel/
│   ├── syscall_table.py    # Database of FreeBSD 12 vs. Prospero proprietary syscalls
│   ├── ioctl_table.py      # Proprietary character device drivers (/dev/kmd, /dev/dnm, /dev/icc)
│   └── surface_auditor.py  # Attack surface auditor & Syzkaller fuzzer definition generator
├── reporting/
│   └── dashboard.py        # Multi-tab offline single-file HTML audit report with live search
├── templates/
│   └── ProbeXlet.java      # Reference Java source for BD-J environment introspection
├── exceptions.py           # Domain-specific exception hierarchy
├── logging.py              # Structured logging with ANSI styling
└── cli.py                  # Unified CLI interface
```

---

## Quick Start

### 1. Requirements
* Python 3.9+ (Zero external third-party dependencies; uses only standard Python libraries).

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
# Generate with unrestricted security research permissions
python -m prospero_lab.cli bdj-create --output my_disc --burn-instructions

# Generate with targeted permission profiles (unrestricted, network, storage, minimal)
python -m prospero_lab.cli bdj-create --profile network --output my_net_disc
```

### 2. Simulating ROP Execution in a Mock AMD64 Runtime (`simulate-chain`)
Safely verify that a synthesized 64-bit ROP chain sets up registers correctly and dispatches system calls without memory faults:

```bash
python -m prospero_lab.cli simulate-chain
```

Output:
```
[INFO] Setting up Mock Virtual Execution Runtime (AMD64)...
[INFO] Running ROP payload simulation from stack: 0x7fffffffe000...
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
Compares FreeBSD 12 system calls and character devices (`/dev/kmd`, `/dev/dnm`, `/dev/icc`, `/dev/sflash`) with Sony's proprietary extensions, highlighting historical vulnerability classes (race conditions, UAFs, ASLR infoleaks) and generating fuzzing targets:

```bash
python -m prospero_lab.cli kernel-audit

# Output in JSON format for automated pipelines
python -m prospero_lab.cli kernel-audit --json

# Generate Syzkaller definitions for kernel fuzzers
python -m prospero_lab.cli kernel-audit --syzkaller
```

### 4. Generating Offline HTML Security Dashboards (`dashboard`)
Creates an interactive visual report with tabbed views, KPI cards, and live client-side search:

```bash
python -m prospero_lab.cli dashboard --output prospero_audit_dashboard.html
```

### 5. Inspecting Sony Signed ELF Containers (`parse-self`)
Inspects PlayStation `.prx`, `.sprx`, or `.bin` files to identify segment encryption flags (SAMU) and Control Info metadata blocks:

```bash
python -m prospero_lab.cli parse-self /path/to/binary.sprx
python -m prospero_lab.cli parse-self /path/to/binary.sprx --json
```

### 6. Scanning Binaries for XOM Mitigations & ROP Gadgets (`xom-scan`)
The PS5 Hypervisor enforces eXecute-Only Memory (XOM). `xom-scan` checks segment permissions, extracts register pops, stack pivots, and indirect JOP dispatchers:

```bash
python -m prospero_lab.cli xom-scan /path/to/binary_or_dump.elf --base 0x7fff00000
python -m prospero_lab.cli xom-scan /path/to/binary_or_dump.elf --json
```

---

## Running the Test Suite

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Ethical & Security Disclaimer

This project is created strictly for **authorized security research, vulnerability analysis, systems engineering, and academic study**. If you discover security vulnerabilities, report them responsibly via the [PlayStation Bug Bounty program on HackerOne](https://hackerone.com/playstation).
