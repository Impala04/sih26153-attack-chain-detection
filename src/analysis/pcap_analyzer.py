"""Standalone statistics and JSON/HTML reporting for PCAP/PCAPNG files."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.capture.packet_schema import ParsedPacket
from src.ingestion.pcap_reader import PcapReadError, iter_pcap

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
    """Write a readable, self-contained HTML investigation report."""
    import html

    def escape(value: Any) -> str:
        return "—" if value is None else html.escape(str(value), quote=True)

    def table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> str:
        heading = "".join(f"<th scope=\"col\">{escape(label)}</th>" for label in headers)
        if rows:
            body = "".join(
                "<tr>" + "".join(f"<td>{escape(value)}</td>" for value in row) + "</tr>"
                for row in rows
            )
        else:
            body = f'<tr><td class="empty" colspan="{len(headers)}">No data available.</td></tr>'
        return f"<div class=\"table-wrap\"><table><thead><tr>{heading}</tr></thead><tbody>{body}</tbody></table></div>"

    capture = report["capture"]
    traffic = report["traffic"]
    protocols = report["protocols"]
    ips = report["ips"]
    ports = report["ports"]
    title = escape(report["file"]["name"])
    cards = (
        ("Packet count", capture["total_packets"]),
        ("Duration", f"{capture['duration_seconds']:.3f} s"),
        ("Total bytes", traffic["total_bytes"]),
        ("Average packets / second", traffic["average_packets_per_second"]),
        ("Average bytes / second", traffic["average_bytes_per_second"]),
    )
    summary_cards = "".join(
        f"<div class=\"card\"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>"
        for label, value in cards
    )

    protocol_rows = [
        (protocol, protocols["counts"].get(protocol, 0), f"{protocols['distribution_percent'].get(protocol, 0)}%")
        for protocol in PROTOCOLS
    ]
    ip_summary_rows = [
        ("Unique source IPs", ips["unique_source_ips"]),
        ("Unique destination IPs", ips["unique_destination_ips"]),
        ("Unique communicating pairs", ips["unique_communicating_pairs"]),
    ]
    ip_rows = table(("Statistic", "Count"), ip_summary_rows)
    source_ip_rows = table(
        ("Source IP", "Packets"),
        [(item["value"], item["packets"]) for item in ips["top_sources"]],
    )
    destination_ip_rows = table(
        ("Destination IP", "Packets"),
        [(item["value"], item["packets"]) for item in ips["top_destinations"]],
    )
    source_port_rows = table(
        ("Source port", "Packets"),
        [(item["value"], item["packets"]) for item in ports["top_sources"]],
    )
    destination_port_rows = table(
        ("Destination port", "Packets"),
        [(item["value"], item["packets"]) for item in ports["top_destinations"]],
    )
    service_port_rows = table(
        ("Service port", "Source packets", "Destination packets"),
        [
            (port, values["source_packets"], values["destination_packets"])
            for port, values in ports["common_service_ports"].items()
        ],
    )
    flag_rows = table(("TCP flag", "Packets"), list(report["tcp_flags"].items()))
    communication_rows = table(
        ("Source IP", "Destination IP", "Packets", "Bytes"),
        [
            (item["src_ip"], item["dst_ip"], item["packet_count"], item["byte_count"])
            for item in report["top_communications"]
        ],
    )
    window_seconds = capture["time_series_window_seconds"]
    window_rows = table(
        (
            "Window start (UTC)", "Packets", "Bytes", "Packets / second", "Bytes / second",
            "Unique sources", "Unique destinations", "TCP", "UDP", "ICMP", "Other",
        ),
        [
            (
                item["window_start_iso"], item["packet_count"], item["byte_count"],
                round(item["packet_count"] / window_seconds, 4),
                round(item["byte_count"] / window_seconds, 4),
                item["unique_source_ips"], item["unique_destination_ips"],
                item["tcp_count"], item["udp_count"], item["icmp_count"], item["other_count"],
            )
            for item in report["time_series"]
        ],
    )

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PCAP investigation: {title}</title>
<style>
:root{{color-scheme:light;--ink:#182230;--muted:#5c6878;--line:#d8e0e8;--panel:#f3f6f9;--accent:#245a83}}
*{{box-sizing:border-box}}body{{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;max-width:1180px;margin:2rem auto;padding:0 1rem;color:var(--ink)}}
h1{{font-size:1.75rem;margin:0 0 .3rem}}h2{{font-size:1.2rem;margin:1.7rem 0 .65rem}}h3{{font-size:1rem;margin:1rem 0 .5rem}}.subtitle{{color:var(--muted);margin:0 0 1.4rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.7rem}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.85rem;display:flex;flex-direction:column;gap:.2rem}}.card span{{color:var(--muted);font-size:.8rem}}.card strong{{font-size:1.15rem;font-variant-numeric:tabular-nums}}
.split{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:1rem}}.table-wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:7px;margin:.45rem 0 1rem}}table{{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}}th,td{{padding:.5rem .65rem;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}}th{{background:var(--panel);font-size:.78rem;color:#334155}}tbody tr:last-child td{{border-bottom:0}}.empty{{color:var(--muted);text-align:center}}@media print{{body{{margin:0;max-width:none}}}}
</style></head><body>
<h1>PCAP investigation report</h1><p class="subtitle">{title}</p>
<div class="cards">{summary_cards}</div>
<h2>Protocol statistics</h2>{table(("Protocol", "Packets", "Share"), protocol_rows)}
<h2>IP statistics</h2>{ip_rows}<div class="split"><section><h3>Top source IPs</h3>{source_ip_rows}</section><section><h3>Top destination IPs</h3>{destination_ip_rows}</section></div>
<h2>Port statistics</h2><div class="split"><section><h3>Top source ports</h3>{source_port_rows}</section><section><h3>Top destination ports</h3>{destination_port_rows}</section></div><h3>Common service ports</h3>{service_port_rows}
<h2>TCP flag statistics</h2>{flag_rows}
<h2>Communication pairs</h2>{communication_rows}
<h2>Time-window statistics</h2>{window_rows}
</body></html>
"""
    Path(path).write_text(document, encoding="utf-8")
