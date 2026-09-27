"""Standalone statistics and JSON/HTML reporting for PCAP/PCAPNG files."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.capture.packet_schema import ParsedPacket
from src.ingestion.pcap_reader import PcapReadError, iter_pcap
from src.analysis.pcap_json_report import write_json_report

SERVICE_PORTS = (22, 53, 80, 443, 445, 3389, 8080)
PROTOCOLS = ("TCP", "UDP", "ICMP", "OTHER")


def _iso_time(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _top(counter: Counter, limit: int) -> list[dict[str, Any]]:
    return [{"value": key, "packets": count} for key, count in counter.most_common(limit)]


def _packet_timestamp(packet: ParsedPacket) -> float | None:
    """Return a finite, datetime-representable timestamp or skip the record."""
    value = getattr(packet, "timestamp", None)
    if value is None or isinstance(value, bool):
        return None
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(timestamp) or _iso_time(timestamp) is None:
        return None
    return timestamp


def analyze_packets(
    packets: Iterable[ParsedPacket],
    window_seconds: float = 1.0,
    top_n: int = 10,
    *,
    capture_name: str = "<packets>",
    file_size: int = 0,
) -> dict[str, Any]:
    """Analyze normalized packets and return a JSON-serializable report.

    Time windows are fixed-width buckets relative to the first parsed packet.
    Packet size comes from each shared ParsedPacket. Records with missing,
    non-finite, nonnumeric, or unrepresentable timestamps are skipped.
    """
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite number greater than zero")
    if top_n < 0:
        raise ValueError("top_n cannot be negative")

    protocol_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    source_ports: Counter[int] = Counter()
    destination_ports: Counter[int] = Counter()
    pair_stats: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    flag_counts: Counter[str] = Counter()
    window_stats: dict[int, dict[str, Any]] = {}
    source_ips: set[str] = set()
    destination_ips: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    first_time: float | None = None
    last_time: float | None = None
    total_packets = 0
    total_bytes = 0
    min_size: int | None = None
    max_size = 0

    for packet in packets:
        timestamp = _packet_timestamp(packet)
        if timestamp is None:
            continue
        if first_time is None:
            first_time = timestamp
        last_time = timestamp
        total_packets += 1
        size = packet.packet_length
        total_bytes += size
        min_size = size if min_size is None else min(min_size, size)
        max_size = max(max_size, size)
        protocol_counts[packet.protocol if packet.protocol in PROTOCOLS else "OTHER"] += 1
        source_counts[packet.src_ip] += 1
        destination_counts[packet.dst_ip] += 1
        source_ips.add(packet.src_ip)
        destination_ips.add(packet.dst_ip)
        pair = (packet.src_ip, packet.dst_ip)
        pairs.add(pair)
        pair_stats[pair][0] += 1
        pair_stats[pair][1] += size

        if packet.protocol in {"TCP", "UDP"}:
            if packet.src_port is not None:
                source_ports[packet.src_port] += 1
            if packet.dst_port is not None:
                destination_ports[packet.dst_port] += 1
        if packet.protocol == "TCP" and packet.tcp_flags:
            flags = set(packet.tcp_flags)
            for flag, label in (("A", "ACK"), ("F", "FIN"), ("R", "RST"), ("P", "PSH"), ("U", "URG"), ("E", "ECE"), ("C", "CWR")):
                if flag in flags:
                    flag_counts[label] += 1
            if "S" in flags and "A" in flags:
                flag_counts["SYN-ACK"] += 1
            elif "S" in flags:
                flag_counts["SYN"] += 1

        window_index = int((timestamp - first_time) // window_seconds)
        bucket = window_stats.setdefault(window_index, {
            "window_start": first_time + window_index * window_seconds,
            "window_end": first_time + (window_index + 1) * window_seconds,
            "packet_count": 0,
            "byte_count": 0,
            "source_ips": set(),
            "destination_ips": set(),
            "protocols": Counter(),
        })
        bucket["packet_count"] += 1
        bucket["byte_count"] += size
        bucket["source_ips"].add(packet.src_ip)
        bucket["destination_ips"].add(packet.dst_ip)
        bucket["protocols"][packet.protocol if packet.protocol in PROTOCOLS else "OTHER"] += 1

    duration = max(0.0, last_time - first_time) if total_packets else 0.0
    protocol_distribution = {
        protocol: round(protocol_counts[protocol] * 100 / total_packets, 2) if total_packets else 0.0
        for protocol in PROTOCOLS
    }
    time_series = []
    for index in sorted(window_stats):
        bucket = window_stats[index]
        time_series.append({
            "window_start": bucket["window_start"],
            "window_start_iso": _iso_time(bucket["window_start"]),
            "window_end": bucket["window_end"],
            "packet_count": bucket["packet_count"],
            "byte_count": bucket["byte_count"],
            "unique_source_ips": len(bucket["source_ips"]),
            "unique_destination_ips": len(bucket["destination_ips"]),
            "tcp_count": bucket["protocols"]["TCP"],
            "udp_count": bucket["protocols"]["UDP"],
            "icmp_count": bucket["protocols"]["ICMP"],
            "other_count": bucket["protocols"]["OTHER"],
        })

    communications = [
        {"src_ip": src, "dst_ip": dst, "packet_count": stats[0], "byte_count": stats[1]}
        for (src, dst), stats in sorted(pair_stats.items(), key=lambda entry: (-entry[1][0], entry[0]))[:top_n]
    ]
    used_service_ports = {
        str(port): {"source_packets": source_ports[port], "destination_packets": destination_ports[port]}
        for port in SERVICE_PORTS if source_ports[port] or destination_ports[port]
    }
    observations: list[str] = []
    if total_packets == 0:
        observations.append("No supported IPv4 packets were available for analysis.")
    else:
        peak_packets_per_second = max(
            bucket["packet_count"] / window_seconds for bucket in window_stats.values()
        )
        peak_bytes_per_second = max(
            bucket["byte_count"] / window_seconds for bucket in window_stats.values()
        )
        peak_window_destinations = max(
            len(bucket["destination_ips"]) for bucket in window_stats.values()
        )
        if peak_packets_per_second >= 1000:
            observations.append("A time window reached at least 1,000 packets per second.")
        if peak_bytes_per_second >= 10_000_000:
            observations.append("A time window carried at least 10,000,000 bytes per second.")
        if peak_window_destinations >= 50:
            observations.append("A time window included at least 50 unique destination IP addresses.")

    return {
        "file": {"name": capture_name, "size_bytes": file_size},
        "capture": {
            "start_time": first_time,
            "start_time_iso": _iso_time(first_time),
            "end_time": last_time,
            "end_time_iso": _iso_time(last_time),
            "duration_seconds": duration,
            "time_series_window_seconds": window_seconds,
            "total_packets": total_packets,
        },
        "protocols": {
            "counts": {protocol: protocol_counts[protocol] for protocol in PROTOCOLS},
            "distribution_percent": protocol_distribution,
        },
        "ips": {
            "unique_source_ips": len(source_ips),
            "unique_destination_ips": len(destination_ips),
            "unique_communicating_pairs": len(pairs),
            "top_sources": _top(source_counts, top_n),
            "top_destinations": _top(destination_counts, top_n),
        },
        "ports": {
            "top_sources": _top(source_ports, top_n),
            "top_destinations": _top(destination_ports, top_n),
            "common_service_ports": used_service_ports,
        },
        "traffic": {
            "total_bytes": total_bytes,
            "average_packet_size_bytes": round(total_bytes / total_packets, 2) if total_packets else 0.0,
            "minimum_packet_size_bytes": min_size,
            "maximum_packet_size_bytes": max_size if total_packets else None,
            "average_packets_per_second": round(total_packets / duration, 4) if duration > 0 else 0.0,
            "average_bytes_per_second": round(total_bytes / duration, 4) if duration > 0 else 0.0,
        },
        "tcp_flags": {name: flag_counts[name] for name in ("SYN", "SYN-ACK", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR")},
        "top_communications": communications,
        "time_series": time_series,
        "observations": observations,
    }


def analyze_pcap(path: str | Path, window_seconds: float = 1.0, top_n: int = 10) -> dict[str, Any]:
    """Read a capture through Scapy and analyze its normalized packets."""
    capture_path = Path(path)
    try:
        file_size = capture_path.stat().st_size
    except OSError as exc:
        raise PcapReadError(f"Cannot stat capture {capture_path}: {exc}") from exc
    return analyze_packets(
        iter_pcap(capture_path),
        window_seconds=window_seconds,
        top_n=top_n,
        capture_name=capture_path.name,
        file_size=file_size,
    )


def write_html_report(report: dict[str, Any], path: str | Path) -> None:
    """Write a lightweight, self-contained HTML summary with a packet-rate chart."""
    import html

    series = report["time_series"]
    values = [item["packet_count"] / report["capture"]["time_series_window_seconds"] for item in series]
    labels = [item["window_start_iso"] for item in series]
    table_rows = "".join(f"<tr><td>{html.escape(str(label))}</td><td>{value}</td></tr>" for label, value in zip(labels, values))
    def ranked_rows(items):
        return "".join(
            f"<tr><td>{html.escape(str(item['value']))}</td><td>{item['packets']}</td></tr>"
            for item in items
        )

    protocol = report["protocols"]["distribution_percent"]
    title = html.escape(report["file"]["name"])
    document = f"""<!doctype html><html><head><meta charset="utf-8"><title>PCAP analysis: {title}</title>
<style>body{{font:15px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#182230}}.cards{{display:flex;gap:1rem;flex-wrap:wrap}}.card{{background:#f1f5f9;padding:1rem;border-radius:8px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:.45rem;border-bottom:1px solid #ddd;text-align:left}}canvas{{max-width:100%;height:260px}}</style></head><body>
<h1>PCAP investigation: {title}</h1><div class="cards"><div class="card">Packets: {report['capture']['total_packets']}</div><div class="card">Duration: {report['capture']['duration_seconds']:.3f}s</div><div class="card">Bytes: {report['traffic']['total_bytes']}</div><div class="card">Average packets/s: {report['traffic']['average_packets_per_second']}</div></div>
<h2>Protocol distribution</h2><table><tr><th>Protocol</th><th>Percent</th></tr>{''.join(f'<tr><td>{k}</td><td>{v}%</td></tr>' for k,v in protocol.items())}</table>
<h2>Top source IPs</h2><table><tr><th>IP</th><th>Packets</th></tr>{ranked_rows(report['ips']['top_sources'])}</table>
<h2>Top destination IPs</h2><table><tr><th>IP</th><th>Packets</th></tr>{ranked_rows(report['ips']['top_destinations'])}</table>
<h2>Top source ports</h2><table><tr><th>Port</th><th>Packets</th></tr>{ranked_rows(report['ports']['top_sources'])}</table>
<h2>Top destination ports</h2><table><tr><th>Port</th><th>Packets</th></tr>{ranked_rows(report['ports']['top_destinations'])}</table>
<h2>Traffic over time</h2><canvas id="chart" width="950" height="260"></canvas><table><tr><th>Window start (UTC)</th><th>Packets per second</th></tr>{table_rows}</table>
<script>const values={json.dumps(values, allow_nan=False)};const c=document.getElementById('chart'),x=c.getContext('2d'),m=Math.max(1,...values),w=c.width,h=c.height;x.beginPath();x.strokeStyle='#2563eb';values.forEach((v,i)=>{{const px=20+i*(w-40)/Math.max(1,values.length-1),py=h-20-v/m*(h-40);i?x.lineTo(px,py):x.moveTo(px,py)}});x.stroke();</script></body></html>"""
    Path(path).write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze PCAP/PCAPNG traffic and write a JSON report")
    parser.add_argument("path", help="Path to a .pcap or .pcapng file")
    parser.add_argument("--output", "-o", help="JSON report path (default: <capture>_analysis.json)")
    parser.add_argument("--html", help="Optional HTML report path")
    parser.add_argument("--window", type=float, default=1.0, help="Time-series window in seconds (default: 1)")
    parser.add_argument("--top", type=int, default=10, help="Number of top IPs, ports, and pairs to include")
    args = parser.parse_args()
    output = Path(args.output) if args.output else Path(args.path).with_name(f"{Path(args.path).stem}_analysis.json")
    try:
        report = analyze_pcap(args.path, window_seconds=args.window, top_n=args.top)
        write_json_report(report, output)
        if args.html:
            write_html_report(report, args.html)
    except (PcapReadError, ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"Wrote {output}")
    if args.html:
        print(f"Wrote {args.html}")


if __name__ == "__main__":
    main()
