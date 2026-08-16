"""
Command-line interface for hash-identifier.

Two ways to use it:
    hashid <sample>        one-shot scan, prints a report, exits
    hashid                 no argument -> interactive prompt loop

UI is deliberately panel-based (rich.Panel + rich.Table nested inside)
rather than a single flat table, so a scan reads like a small report
card: sample header, then ranked candidates, then a footer hint.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import version as _pkg_version

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .engine import scan
from .models import ScanReport

console = Console()
BANNER = r"""
[bold cyan] _               _         _     _            _   _  __ _
| |__   __ _ ___| |__     (_) __| | ___ _ __ | |_(_)/ _(_) ___ _ __
| '_ \ / _` / __| '_ \    | |/ _` |/ _ \ '_ \| __| | |_| |/ _ \ '__|
| | | | (_| \__ \ | | |   | | (_| |  __/ | | | |_| |  _| |  __/ |
|_| |_|\__,_|___/_| |_|   |_|\__,_|\___|_| |_|\__|_|_| |_|\___|_|[/bold cyan]
"""


def _report_panel(report: ScanReport) -> Panel:
    header = Text.assemble(("sample  ", "dim"), (report.sample, "bold white"))

    if report.is_empty:
        body = Text("no candidates matched — unrecognized format", style="italic red")
        return Panel(Group(header, "", body), title="scan report", border_style="red")

    table = Table(show_header=True, header_style="bold cyan", expand=True, box=None)
    table.add_column("#", width=3, justify="right")
    table.add_column("algorithm", style="bold")
    table.add_column("confidence", width=10)
    table.add_column("reason")

    for i, finding in enumerate(report.findings, start=1):
        marker = "✕ not a hash" if not finding.is_hash else ""
        name = finding.algorithm if not marker else f"{finding.algorithm}  [dim]{marker}[/dim]"
        table.add_row(
            str(i),
            name,
            f"[{finding.confidence.style()}]{finding.confidence.label()}[/{finding.confidence.style()}]",
            finding.reason,
        )

    border = "green" if report.best and report.best.confidence.name == "HIGH" else "yellow"
    return Panel(Group(header, "", table), title="scan report", border_style=border)


def _print_report(report: ScanReport, as_json: bool) -> None:
    if as_json:
        payload = {
            "sample": report.sample,
            "findings": [
                {
                    "algorithm": f.algorithm,
                    "confidence": f.confidence.label(),
                    "reason": f.reason,
                    "is_hash": f.is_hash,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    console.print(_report_panel(report))


def _interactive() -> int:
    console.print(BANNER)
    console.print("[dim]interactive mode — paste a hash, or type 'quit' to exit[/dim]\n")
    try:
        while True:
            sample = console.input("[bold cyan]hashid>[/bold cyan] ").strip()
            if sample.lower() in {"quit", "exit", "q"}:
                break
            if not sample:
                continue
            _print_report(scan(sample), as_json=False)
            console.print()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]bye[/dim]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashid",
        description="Guess a hash's algorithm from its prefix, length, and character set.",
    )
    parser.add_argument(
        "sample",
        nargs="?",
        help="the hash string to identify (omit to enter interactive mode)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of the rich report panel",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"hash-identifier {_pkg_version('hash-identifier')}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.sample is None:
        if args.json:
            parser.error("--json requires a sample; interactive mode is for humans")
        return _interactive()

    report = scan(args.sample)
    _print_report(report, as_json=args.json)
    return 0 if not report.is_empty else 1


if __name__ == "__main__":
    sys.exit(main())
