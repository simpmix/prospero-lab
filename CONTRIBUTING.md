# Contributing to ProsperoLab

Thank you for your interest in contributing to `prospero-lab`! We welcome contributions from systems engineers, security researchers, and console homebrew developers.

---

## Code of Conduct & Scope

1. **Defensive & Research Focus**: All contributions must focus on static binary analysis, architecture reverse engineering, firmware diffing, hardware analysis tooling, emulation, and educational frameworks.
2. **Responsible Disclosure**: Do not submit weaponized zero-day exploit payloads. Vulnerabilities discovered using this tooling should be reported responsibly to Sony via the [PlayStation Bug Bounty Program on HackerOne](https://hackerone.com/playstation).

---

## Development Setup

`prospero-lab` is intentionally designed with zero external third-party dependencies, running entirely on the standard Python 3.9+ runtime.

### Running Tests
Before submitting any pull request, ensure all unit tests pass:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Coding Standards

- **Type Hints**: All new functions and methods should include Python type hints (`typing`).
- **Docstrings**: Provide Google-style or standard Sphinx docstrings explaining parameters and security implications.
- **Exceptions**: Use domain-specific exceptions from `prospero_lab.exceptions` (`ELFParseError`, `SELFParseError`, `XOMViolationError`) rather than bare `Exception`.
- **Cross-Platform**: Test file path handling and binary packing across both Windows and POSIX environments.
