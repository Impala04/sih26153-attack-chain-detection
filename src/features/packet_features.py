"""Deterministic packet-level statistics over normalized ParsedPacket records."""

from collections import defaultdict
from math import isfinite, log
from statistics import fmean, pvariance
from typing import Any, Iterable


def _number(packet: Any, name: str, *, integer: bool = False) -> float | None:
    value = getattr(packet, name, None)
    if isinstance(packet, dict):
        value = packet.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not isfinite(number) or (integer and not number.is_integer()):
        return None
    return number


def _stats(values: list[float], prefix: str) -> dict[str, float | int | None]:
    return {
        f"{prefix}_mean": fmean(values) if values else None,
        f"{prefix}_variance": pvariance(values) if values else None,
        f"{prefix}_min": min(values) if values else None,
        f"{prefix}_max": max(values) if values else None,
        f"{prefix}_sample_count": len(values),
    }


def packet_features(packets: Iterable[Any]) -> dict[str, Any]:
    """Return JSON-safe packet features under the stable ``packet`` key.

    IAT uses all finite timestamps sorted ascending (ties are retained); negative
    intervals are therefore impossible. Variances are population variances.
    TTL is IPv4's 1..255 TTL field. Payload is transport payload bytes from the
    parser. Retransmissions mean repeated TCP data sequence ranges in one
    directional 4-tuple; this cannot distinguish retransmission from duplicated
    capture records. Port pattern scores are descriptive signals, not detectors.
    """
    records = list(packets)
    ttls: list[float] = []
    windows: list[float] = []
    payloads: list[float] = []
    timestamps: list[float] = []
    fragmented_count = 0
    fragment_known = 0
    tcp_count = tcp_seq_known = 0
    ranges: set[tuple[Any, ...]] = set()
    retransmissions = 0
    ports_by_target: dict[tuple[Any, Any], list[int]] = defaultdict(list)
    valid_ports = 0
    malformed_count = 0

    for packet in records:
        if not isinstance(packet, dict) and not hasattr(packet, "__dict__"):
            malformed_count += 1
            continue
        for field_name, destination in (("ttl", ttls), ("tcp_window", windows), ("payload_size", payloads), ("timestamp", timestamps)):
            value = _number(packet, field_name, integer=field_name != "timestamp")
            if value is not None and (field_name not in {"ttl", "tcp_window", "payload_size"} or value >= 0):
                if field_name == "ttl" and not 1 <= value <= 255:
                    continue
                destination.append(value)

        fragmented = packet.get("fragmented") if isinstance(packet, dict) else getattr(packet, "fragmented", None)
        if isinstance(fragmented, bool):
            fragment_known += 1
            fragmented_count += int(fragmented)

        get = packet.get if isinstance(packet, dict) else lambda key, default=None: getattr(packet, key, default)
        protocol = str(get("protocol", "")).upper()
        if protocol == "TCP":
            tcp_count += 1
            seq = _number(packet, "tcp_seq", integer=True)
            payload = _number(packet, "payload_size", integer=True)
            src, dst = get("src_ip"), get("dst_ip")
            sport, dport = get("src_port"), get("dst_port")
            flags = str(get("tcp_flags", "") or "").upper()
            if seq is not None and payload is not None:
                tcp_seq_known += 1
                if payload > 0 and all(x is not None for x in (src, dst, sport, dport)):
                    start = int(seq) + int("S" in flags)
                    signature = (src, dst, sport, dport, start, start + int(payload))
                    if signature in ranges:
                        retransmissions += 1
                    else:
                        ranges.add(signature)

        dport = get("dst_port")
        src, dst = get("src_ip"), get("dst_ip")
        if protocol in {"TCP", "UDP"} and isinstance(dport, int) and not isinstance(dport, bool) and 0 <= dport <= 65535:
            ports_by_target[(src, dst)].append(dport)
            valid_ports += 1

    intervals = [later - earlier for earlier, later in zip(sorted(timestamps), sorted(timestamps)[1:])]
    sequential_steps = 0
    port_steps = 0
    entropy_sum = 0.0
    unique_ports: set[int] = set()
    for ports in ports_by_target.values():
        unique_ports.update(ports)
        # Ignore repeat observations; only distinct adjacent probes characterize order.
        distinct_order = list(dict.fromkeys(ports))
        for left, right in zip(distinct_order, distinct_order[1:]):
            port_steps += 1
            sequential_steps += int(abs(right - left) == 1)
    if unique_ports:
        from collections import Counter
        counts = Counter(port for ports in ports_by_target.values() for port in ports)
        total = sum(counts.values())
        entropy = -sum((n / total) * log(n / total) for n in counts.values())
        entropy_sum = entropy / log(len(counts)) if len(counts) > 1 else 0.0
    sequential_score = sequential_steps / port_steps if port_steps else 0.0

    features: dict[str, Any] = {}
    features.update(_stats(ttls, "ttl"))
    features.update(_stats(windows, "tcp_window"))
    features.update(_stats(payloads, "payload_size"))
    features.update(_stats(intervals, "iat"))
    features["fragmented_packet_count"] = fragmented_count
    features["fragment_ratio"] = fragmented_count / fragment_known if fragment_known else None
    features["fragment_sample_count"] = fragment_known
    features["retransmission_count"] = retransmissions
    features["retransmission_status"] = (
        "available" if tcp_seq_known == tcp_count and tcp_count else
        "partial" if tcp_seq_known else "unavailable"
    )
    features["retransmission_sample_count"] = tcp_seq_known
    features["port_diversity"] = len(unique_ports) / valid_ports if valid_ports else None
    features["unique_destination_ports"] = len(unique_ports)
    features["sequential_port_score"] = sequential_score if port_steps else None
    features["port_randomness_score"] = entropy_sum * (1.0 - sequential_score) if unique_ports else None
    features["port_sample_count"] = valid_ports
    features["malformed_packet_count"] = malformed_count
    return {"packet": features}
