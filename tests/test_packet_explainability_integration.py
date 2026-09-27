from scapy.all import IP, TCP, Raw

from src.capture.packet_parser import parse_packet
from src.explainability import explain_prediction
from src.features.packet_features import packet_features


class SimpleAnomalyModel:
    def decision_function(self, rows):
        return [100.0 - float(row[0]) for row in rows]


def test_parsed_packet_to_features_to_structured_explanation():
    raw = IP(src="192.0.2.1", dst="198.51.100.8", ttl=42) / TCP(sport=12345, dport=443, seq=99, window=2048) / Raw(load=b"hello")
    raw.time = 12.0
    parsed = parse_packet(raw)
    assert parsed.ttl == 42 and parsed.tcp_window == 2048 and parsed.payload_size == 5
    result = packet_features([parsed])["packet"]
    assert result["ttl_mean"] == 42
    explanation = explain_prediction(
        SimpleAnomalyModel(), {"payload_size_mean": result["payload_size_mean"]},
        baseline={"payload_size_mean": 0}, top_k=1,
    )
    assert explanation["status"] == "available"
    assert explanation["top_features"][0]["feature"] == "payload_size_mean"
    assert explanation["top_features"][0]["contribution"] == 5
