"""
hash_identifier
~~~~~~~~~~~~~~~~

A small, dependency-light toolkit for guessing what kind of hash a
string is, based on its prefix, length, and character set.

Public API:
    scan(sample: str) -> ScanReport
"""

from .engine import scan
from .models import Confidence, Finding, ScanReport

__all__ = ["scan", "Confidence", "Finding", "ScanReport"]
__version__ = "0.1.0"
