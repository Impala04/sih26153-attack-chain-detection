"""Regenerate the small deterministic PCAP fixtures used by the tests."""

from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap

DATA = Path(__file__).parent / "data"
DATA.mkdir(exist_ok=True)


def packet(layer, timestamp):
    result = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layer
    result.time = timestamp
    return result


fixtures = {
    "tcp_test.pcap": [
        packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=41000, dport=443, flags="S"), 1700000000),
        packet(IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=41000, flags="SA"), 1700000000.1),
    ],
    "udp_test.pcap": [
        packet(IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=53000, dport=53), 1700000001),
    ],
    "icmp_test.pcap": [
        packet(IP(src="10.0.0.4", dst="10.0.0.1") / ICMP(), 1700000002),
    ],
    "mixed_test.pcap": [
        packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=42000, dport=80, flags="S"), 1700000100),
        packet(IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=42001, dport=53), 1700000100.25),
        packet(IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(), 1700000101),
    ],
    "burst_test.pcap": [
        packet(IP(src=f"10.0.0.{1 + index % 3}", dst="10.0.1.1") / UDP(sport=43000 + index, dport=8080), 1700000200 + index * 0.01)
        for index in range(20)
    ],
}

for name, packets in fixtures.items():
    wrpcap(str(DATA / name), packets)
