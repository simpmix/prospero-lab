# ProsperoLab

> **A Systems Security & Exploration Framework for PlayStation 5 (Prospero OS)**

`prospero-lab` is a modular, zero-dependency Python research framework built to address real bottlenecks in PlayStation 5 systems security and homebrew research. Rather than rehashing ephemeral webkit payloads, it provides tooling for:

1. **BD-J (Blu-ray Disc Java) Automation & Synthesis**: Programmatically generates bit-accurate, compliant Blu-ray Movie (`BDMV 2.0`) disc structures (`index.bdmv`, `MovieObject.bdmv`, playlists, BDJO) and packages Xlet JARs with synthetic bytecode (no JDK required).
2. **XOM (eXecute-Only Memory) & ROP Analysis**: Evaluates binary segments under modern hypervisor memory protections (`PF_X` without `PF_R`), locating viable control-flow primitives (stack pivots, SysV ABI register setup, system call invocations).
3. **Kernel Surface Auditing & Differential Mapping**: Compares baseline FreeBSD 12 against Sony's proprietary Prospero kernel extensions (UMTX, Event Flags, Named Objects, Dynamic Loader) and generates Syzkaller descriptions for automated kernel fuzzers.

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
├── kernel/
│   ├── syscall_table.py    # Database of FreeBSD 12 vs. Prospero proprietary syscalls
│   └── surface_auditor.py  # Attack surface auditor & Syzkaller fuzzer definition generator
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

Output:
```
[*] Initializing BDMV generator for target: my_disc
[*] Packaging BD-J Xlet bundle for class: prospero.research.ProbeXlet
[+] Successfully wrote BD-J JAR to: my_disc/BDMV/JAR/00000.jar
[+] BD-J structure passed all Blu-ray compliance checks!

=== BLU-RAY UDF 2.50 AUTHORING INSTRUCTIONS ===
The PS5 requires discs formatted with Universal Disk Format (UDF) 2.50.
...
```

### 2. Auditing the Prospero Kernel Attack Surface (`kernel-audit`)
Compares FreeBSD 12 system calls with Sony's proprietary extensions, highlighting historical vulnerability classes (race conditions, UAFs, ASLR infoleaks) and generating fuzzing targets:

```bash
python -m prospero_lab.cli kernel-audit
```

To output Syzkaller descriptions for integration with automated kernel fuzzers:
```bash
python -m prospero_lab.cli kernel-audit --syzkaller
```

### 3. Scanning Binaries for XOM Mitigations & ROP Gadgets (`xom-scan`)
The PS5 Hypervisor enforces eXecute-Only Memory (XOM), causing memory reads against code segments to fault. `xom-scan` checks segment permissions and extracts essential execution primitives:

```bash
python -m prospero_lab.cli xom-scan /path/to/binary_or_dump.elf --base 0x7fff00000
```

### 4. Synthesizing 64-bit ROP Syscall Chains (`build-chain`)
Generates annotated 64-bit stack layouts configured for SysV AMD64 system call dispatch:

```bash
python -m prospero_lab.cli build-chain
```

---

## Running the Test Suite

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## Ethical & Security Disclaimer

This project is created strictly for **authorized security research, vulnerability analysis, systems engineering, and academic study**. If you discover security vulnerabilities, report them responsibly via the [PlayStation Bug Bounty program on HackerOne](https://hackerone.com/playstation).
