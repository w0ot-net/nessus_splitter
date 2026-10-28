"""Split Nessus XML exports into smaller, independently valid files."""

from .splitter import NessusSplitError, PartResult, split_nessus

__all__ = ["NessusSplitError", "PartResult", "split_nessus"]
__version__ = "0.1.0"
