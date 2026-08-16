"""
The scan() entry point — runs every registered rule against a sample
and folds the results into a single ScanReport.
"""

from __future__ import annotations

from .models import ScanReport
from .rules import RULES


def scan(sample: str) -> ScanReport:
    """
    Run every registered detection rule against `sample` and return
    a ScanReport with all findings, sorted by confidence.

    Never raises on malformed input — an unrecognized string simply
    produces an empty report.
    """
    report = ScanReport(sample=sample)
    cleaned = sample.strip()

    for detector in RULES:
        for finding in detector(cleaned):
            report.add(finding)

    return report
