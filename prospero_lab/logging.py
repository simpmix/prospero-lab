"""
Structured Logging Subsystem for ProsperoLab.
Supports configurable logging levels, optional ANSI terminal styling,
and machine-readable formatting.
"""

import logging
import sys
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """ANSI color-coded formatter for clean terminal output."""

    COLORS = {
        logging.DEBUG: "\033[36m",    # Cyan
        logging.INFO: "\033[32m",     # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",    # Red
        logging.CRITICAL: "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        prefix = f"{color}[{record.levelname[0]}]{self.RESET}"
        return f"{prefix} {record.getMessage()}"


def setup_logger(
    name: str = "prospero-lab",
    level: int = logging.INFO,
    colored: bool = True,
    stream: Optional[sys.stdout.__class__] = None,
) -> logging.Logger:
    """Configures and returns the central logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.setLevel(level)
        if colored and hasattr(handler.stream, "isatty") and handler.stream.isatty():
            handler.setFormatter(ColoredFormatter())
        else:
            handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)

    return logger


logger = setup_logger()
