"""Command-line entry point for standalone PCAP investigation."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.analysis.pcap_analyzer import analyze_pcap, write_html_report
from src.analysis.pcap_json_report import write_json_report
from src.ingestion.pcap_reader import PcapReadError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Investigate a PCAP/PCAPNG capture and save a JSON report.",
        epilog="Run from the repository root: python -m src.analysis.pcap_cli capture.pcap",
    )
    parser.add_argument("capture", help="Input capture file (.pcap, .pcapng, or .cap)")
    parser.add_argument(
        "--output", "-o",
        help="JSON report output path (default: <capture>_analysis.json beside the input)",
    )
    parser.add_argument("--html", help="Optional standalone HTML report output path")
    parser.add_argument("--window", type=float, default=1.0, help="Time-series window size in seconds (default: 1)")
    parser.add_argument("--top", type=int, default=10, help="Maximum IPs, ports, and communications per ranking")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    capture_path = Path(args.capture)
    json_path = Path(args.output) if args.output else capture_path.with_name(f"{capture_path.stem}_analysis.json")

    try:
        investigation = analyze_pcap(args.capture, window_seconds=args.window, top_n=args.top)
        write_json_report(investigation, json_path)
        if args.html:
            write_html_report(investigation, args.html)
    except (PcapReadError, ValueError, OSError) as exc:
        parser.error(str(exc))

    print(f"Wrote {json_path}")
    if args.html:
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
