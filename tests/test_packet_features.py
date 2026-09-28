from src.capture.packet_schema import ParsedPacket
from src.features.packet_features import packet_features


def packet(ts=1.0, **kwargs):
    values = dict(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP", packet_length=60,
                  src_port=50000, dst_port=80, tcp_flags="PA", ttl=64, tcp_window=4096,
                  fragmented=False, payload_size=10, tcp_seq=100)
    values.update(kwargs)
    return ParsedPacket(timestamp=ts, **values)


def test_empty_and_missing_values_are_explicit():
    empty = packet_features([])["packet"]
    assert empty["ttl_mean"] is None and empty["iat_mean"] is None
    assert empty["fragment_ratio"] is None
    assert empty["retransmission_status"] == "unavailable"
    malformed = packet_features([object()])["packet"]
    assert malformed["malformed_packet_count"] == 1
    constant = packet_features([packet(ttl=64)])["packet"]
    assert constant["ttl_mean"] == 64 and constant["ttl_variance"] == 0
    assert constant["iat_mean"] is None
    missing = packet_features([packet(ttl=None, tcp_window=None, fragmented=None, payload_size=None)])['packet']
    assert missing["ttl_sample_count"] == 0
    assert missing["tcp_window_mean"] is None
    assert missing["fragment_ratio"] is None
    assert missing["payload_size_mean"] is None


def test_ttl_window_fragment_payload_and_iat_statistics():
    result = packet_features([
        packet(3, ttl=60, tcp_window=100, fragmented=False, payload_size=4),
        packet(1, ttl=64, tcp_window=200, fragmented=True, payload_size=8),
        packet(1, ttl=68, tcp_window=300, fragmented=False, payload_size=0),
    ])["packet"]
    assert result["ttl_mean"] == 64
    assert result["ttl_variance"] == 32 / 3
    assert result["tcp_window_min"] == 100 and result["tcp_window_max"] == 300
    assert result["fragmented_packet_count"] == 1 and result["fragment_ratio"] == 1 / 3
    udp = packet_features([packet(protocol="UDP", tcp_window=None, tcp_seq=None, tcp_flags=None)])["packet"]
    assert udp["tcp_window_sample_count"] == 0 and udp["fragment_ratio"] == 0
    assert result["payload_size_min"] == 0 and result["payload_size_max"] == 8
    assert result["iat_mean"] == 1 and result["iat_variance"] == 1
    assert result["iat_max"] == 2


def test_retransmission_requires_same_tcp_direction_and_sequence_range():
    packets = [packet(tcp_seq=100), packet(tcp_seq=100), packet(src_ip="10.0.0.3", tcp_seq=100)]
    result = packet_features(packets)["packet"]
    assert result["retransmission_count"] == 1
    assert result["retransmission_status"] == "available"
    repeated = packet_features([packet(tcp_seq=9), packet(tcp_seq=9), packet(tcp_seq=9)])["packet"]
    assert repeated["retransmission_count"] == 2


def test_port_signals_distinguish_sequential_from_diverse_ports():
    sequential = [packet(dst_port=p, tcp_seq=100 + p) for p in (80, 81, 82, 83, 84)]
    randomish = [packet(dst_port=p, tcp_seq=100 + p) for p in (22, 443, 3389, 8080, 53)]
    seq_features = packet_features(sequential)["packet"]
    random_features = packet_features(randomish)["packet"]
    assert seq_features["sequential_port_score"] == 1
    assert seq_features["port_randomness_score"] == 0
    assert random_features["sequential_port_score"] == 0
    assert random_features["port_randomness_score"] > 0
    assert random_features["unique_destination_ports"] == 5
