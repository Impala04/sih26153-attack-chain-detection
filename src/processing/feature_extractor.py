"""Extract Phase 1-compatible features and live traffic diagnostics."""

from statistics import mean, stdev
from typing import Dict, Iterable, List, Set, Tuple

from .flow_tracker import FlowStats
from .window_manager import TrafficWindow


# Keep this order and these names aligned with src/model/train.py.
PHASE1_FEATURE_COLUMNS = [
    "connection_count",
    "unique_destinations",
    "unique_ports",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_bytes_fwd",
    "total_bytes_bwd",
    "avg_flow_duration",
    "max_flow_duration",
    "std_flow_duration",
    "max_bytes_total",
    "std_bytes_total",
    "max_packets_total",
    "bytes_per_connection",
    "flows_per_second",
    "lateral_move_flag",
]


def _sample_std(values: List[float]) -> float:
    """Match pandas' sample standard deviation; use zero for fewer than 2 values."""
    return stdev(values) if len(values) > 1 else 0.0


class FeatureExtractor:
    """Convert completed traffic windows into deterministic feature rows."""

    def __init__(self, lateral_move_threshold: int = 5) -> None:
        if lateral_move_threshold < 0:
            raise ValueError("lateral_move_threshold cannot be negative")
        self.lateral_move_threshold = lateral_move_threshold

    def extract(
        self,
        windows: Iterable[TrafficWindow],
    ) -> List[Dict[str, object]]:
        """Return one feature row per (source, destination, window).

        Pass all ready windows for a source and time window together so
        unique_destinations matches Phase 1's source-window calculation.
        """
        window_list = list(windows)

        destinations_by_source_window: Dict[
            Tuple[str, object], Set[str]
        ] = {}
        for window in window_list:
            key = (window.src_ip, window.window_start)
            destinations_by_source_window.setdefault(key, set()).add(window.dst_ip)

        rows: List[Dict[str, object]] = []

        ordered_windows = sorted(
            window_list,
            key=lambda w: (w.window_start, w.src_ip, w.dst_ip),
        )

        for window in ordered_windows:
            flows = window.flows
            connection_count = len(flows)
            durations = [flow.duration_seconds for flow in flows]
            byte_counts = [float(flow.total_bytes) for flow in flows]
            packet_counts = [float(flow.packet_count) for flow in flows]

            packet_sizes = [
                float(size)
                for flow in flows
                for size in flow.packet_sizes
            ]

            unique_destinations = len(
                destinations_by_source_window[
                    (window.src_ip, window.window_start)
                ]
            )
            unique_dst_ports = {
                flow.key[3] for flow in flows if flow.key[3] is not None
            }
            unique_src_ports = {
                flow.key[2] for flow in flows if flow.key[2] is not None
            }

            total_packets = sum(flow.packet_count for flow in flows)
            total_bytes = sum(flow.total_bytes for flow in flows)
            syn_count = sum(flow.syn_count for flow in flows)
            ack_count = sum(flow.ack_count for flow in flows)
            rst_count = sum(flow.rst_count for flow in flows)
            fin_count = sum(flow.fin_count for flow in flows)

            seconds = float(window.window_seconds)
            phase1_features: Dict[str, object] = {
                "connection_count": connection_count,
                "unique_destinations": unique_destinations,
                "unique_ports": len(unique_dst_ports),
                "total_fwd_packets": total_packets,
                # The current tracker uses directional flow keys, so reverse
                # packets are tracked in their own directional flow/window.
                "total_bwd_packets": 0,
                "total_bytes_fwd": total_bytes,
                "total_bytes_bwd": 0,
                "avg_flow_duration": mean(durations) if durations else 0.0,
                "max_flow_duration": max(durations, default=0.0),
                "std_flow_duration": _sample_std(durations),
                "max_bytes_total": max(byte_counts, default=0.0),
                "std_bytes_total": _sample_std(byte_counts),
                "max_packets_total": max(packet_counts, default=0.0),
                "bytes_per_connection": (
                    total_bytes / connection_count if connection_count else 0.0
                ),
                "flows_per_second": connection_count / seconds,
                "lateral_move_flag": int(
                    unique_destinations > self.lateral_move_threshold
                ),
            }

            # Diagnostics for explainable behavioral rules. These remain
            # separate from PHASE1_FEATURE_COLUMNS.
            packet_size_count = len(packet_sizes)
            diagnostics: Dict[str, object] = {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "packets_per_second": total_packets / seconds,
                "bytes_per_second": total_bytes / seconds,
                "flow_count": connection_count,
                "unique_dst_ips": unique_destinations,
                "unique_dst_ports": len(unique_dst_ports),
                "unique_src_ports": len(unique_src_ports),
                "connection_attempt_rate": syn_count / seconds,
                "avg_packet_size": mean(packet_sizes) if packet_sizes else 0.0,
                "std_packet_size": _sample_std(packet_sizes),
                "min_packet_size": min(packet_sizes, default=0.0),
                "max_packet_size": max(packet_sizes, default=0.0),
                "syn_count": syn_count,
                "ack_count": ack_count,
                "rst_count": rst_count,
                "fin_count": fin_count,
                "syn_ratio": syn_count / total_packets if total_packets else 0.0,
                "rst_ratio": rst_count / total_packets if total_packets else 0.0,
            }

            row: Dict[str, object] = {
                "src_ip": window.src_ip,
                "dst_ip": window.dst_ip,
                "window_start": window.window_start,
                "window_end": window.window_end,
            }
            for column in PHASE1_FEATURE_COLUMNS:
                row[column] = phase1_features[column]
            row.update(diagnostics)
            rows.append(row)

        return rows