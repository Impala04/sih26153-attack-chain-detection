"""Regenerate the small deterministic PCAP/PCAPNG fixtures used by tests."""

from pathlib import Path

from scapy.all import ARP, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap
from scapy.utils import PcapNgWriter

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
    # Shared integration fixture: protocol mix, repeated bidirectional communication,
    # varied ports/flags/timestamps, unknown IPv4 protocol, IPv6, and ARP.
    "investigation_fixture.pcap": [
        packet(IP(src="10.10.0.1", dst="10.10.0.2") / TCP(sport=51514, dport=443, flags="S"), 1700000300.0),
        packet(IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=443, dport=51514, flags="SA"), 1700000300.25),
        packet(IP(src="10.10.0.1", dst="10.10.0.2") / TCP(sport=51514, dport=443, flags="A"), 1700000300.5),
        packet(IP(src="10.10.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53), 1700000300.75),
        packet(IP(src="10.10.0.3", dst="8.8.8.8") / UDP(sport=40000, dport=53), 1700000301.0),
        packet(IP(src="10.10.0.2", dst="10.10.0.3") / ICMP(), 1700000301.5),
        packet(IP(src="10.10.0.9", dst="10.10.0.10", proto=99) / Raw(load=b"unknown-ip-protocol"), 1700000302.0),
        packet(IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1234, dport=53), 1700000302.25),
        packet(ARP(psrc="10.10.0.11", pdst="10.10.0.12"), 1700000302.5),
    ],
    "investigation_fixture.pcapng": [
        packet(IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=50100, dport=443, flags="S"), 1700000400.0),
        packet(IP(src="192.0.2.20", dst="192.0.2.10") / TCP(sport=443, dport=50100, flags="SA"), 1700000400.5),
        packet(IP(src="192.0.2.10", dst="198.51.100.53") / UDP(sport=53000, dport=53), 1700000401.0),
        packet(IP(src="192.0.2.30", dst="192.0.2.10") / ICMP(), 1700000402.0),
    ],
}

for name, packets in fixtures.items():
    if name.endswith(".pcapng"):
        writer = PcapNgWriter(str(DATA / name))
        try:
            for item in packets:
                writer.write(item)
        finally:
            writer.close()
    else:
        wrpcap(str(DATA / name), packets)

# An invalid capture container is kept as bytes because it cannot be written by Scapy.
(DATA / "malformed_capture.pcap").write_bytes(b"not a pcap: malformed synthetic fixture\n")
