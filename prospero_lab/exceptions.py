"""
ProsperoLab Exception Hierarchy.
Provides domain-specific exceptions for binary parsing, mitigation auditing,
simulation, and disc generation.
"""


class ProsperoLabError(Exception):
    """Base exception for all ProsperoLab errors."""
    pass


class FormatError(ProsperoLabError):
    """Raised when parsing or validating an executable container fails."""
    pass


class ELFParseError(FormatError):
    """Raised when an ELF binary header or segment is malformed."""
    pass


class SELFParseError(FormatError):
    """Raised when a Sony Signed ELF (SELF) header or segment fails to parse."""
    pass


class BDMVError(ProsperoLabError):
    """Raised when constructing or validating Blu-ray disc structures fails."""
    pass


class MitigationViolationError(ProsperoLabError):
    """Base class for memory mitigation and sandbox violations."""
    pass


class XOMViolationError(MitigationViolationError):
    """Raised when an illegal memory read is attempted on an Execute-Only Memory page."""
    pass


class WXPViolationError(MitigationViolationError):
    """Raised when execution is attempted in a writable page (W^X violation)."""
    pass


class SimulationError(ProsperoLabError):
    """Raised during mock execution runtime faults."""
    pass
