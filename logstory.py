#!/usr/bin/env python3
"""
LogStory - turn raw Windows / Sysmon logs into an attack story.

    python3 logstory.py sample_attack.jsonl -o report.html --json findings.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from engine import analyze
from logparser import load_events
from report import render

COLORS = {"low": "\033[32m", "medium": "\033[33m", "high": "\033[38;5;208m", "critical": "\033[1;31m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def print_story(analysis, color: bool) -> None:
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)
    print(c(BOLD, f"\n  LogStory | {len(analysis.events)} events -> "
                  f"{len(analysis.detections)} detections -> {len(analysis.incidents)} incident(s)\n"))
    for inc in analysis.incidents:
        print(c(BOLD, f"  Incident #{inc.id} on {inc.computer} [{inc.severity.upper()}]"))
        print(c(DIM, f"  {inc.headline()}\n"))
        for d in inc.detections:
            sev = c(COLORS[d.severity], f"{d.severity.upper():8}")
            ts = d.timestamp.strftime("%H:%M:%S")
            print(f"  {ts}  {sev} {d.rule.technique:<10} {d.rule.title}")
            print(c(DIM, f"            {d.story.replace('`', '')}"))
        print()
    if not analysis.incidents:
        print(c(COLORS["low"], "  No suspicious activity found.\n"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Reconstruct an attack timeline from Windows/Sysmon logs.")
    p.add_argument("logfile", type=Path, help=".jsonl / .json / .xml / .evtx")
    p.add_argument("-o", "--output", type=Path, default=Path("logstory_report.html"),
                   help="HTML report path (default: logstory_report.html)")
    p.add_argument("--json", type=Path, help="Also write findings as JSON")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    if not args.logfile.exists():
        print(f"[!] File not found: {args.logfile}", file=sys.stderr)
        return 2

    events = load_events(args.logfile)
    analysis = analyze(events)
    print_story(analysis, color=sys.stdout.isatty() and not args.no_color)

    args.output.write_text(render(analysis, args.logfile.name), encoding="utf-8")
    print(f"  [+] HTML report: {args.output}")
    if args.json:
        args.json.write_text(json.dumps(analysis.to_dict(), indent=2, default=str), encoding="utf-8")
        print(f"  [+] JSON findings: {args.json}")
    return 1 if analysis.detections else 0


if __name__ == "__main__":
    sys.exit(main())
