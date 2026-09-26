# PCAP ingestion

This module streams `.pcap` and `.pcapng` captures through Scapy and the
existing `src.capture.packet_parser.parse_packet` function. It yields the
existing `src.capture.packet_schema.ParsedPacket`; it does not define a second
packet contract and it contains no detection or flow logic.

## Install and use

From the repository root, install Scapy (and pytest for tests):

```bash
pip install -r requirements-pcap.txt
pip install -r requirements-test.txt
```

Then use the reader:

```python
from src.ingestion.pcap_reader import iter_pcap

for parsed_packet in iter_pcap("capture.pcapng"):
    common_pipeline.ingest(parsed_packet)
```

`read_pcap(path)` is an alias that also returns a streaming iterator. A quick
inspection CLI is available with `python -m src.ingestion.pcap_reader file.pcap`;
it prints each normalized packet dictionary.

## Parsing behavior

IPv4 TCP, UDP, ICMP, and other IPv4 protocols use the shared parser. TCP flags
are the Scapy string form (for example `S`, `SA`, or `PA`). UDP and ICMP have
`tcp_flags=None`; ICMP ports are `None`. ARP, IPv6, and non-IP packets are
skipped with a debug message. Packet normalization exceptions are logged and
that packet is skipped. PCAP timestamps are preserved as Unix epoch seconds
(float), and equal timestamps keep their capture order.

Packets are streamed in file order. The reader checks that timestamps do not
move backwards and raises `PcapReadError` if they do; arbitrary timestamp
sorting would require buffering or externally sorting the capture. Empty
captures yield no packets. Missing/unreadable files, malformed capture files,
and unsupported extensions raise `PcapReadError` with context.

`packet_length` is `len(raw_scapy_packet)`, measured in captured bytes as
Scapy exposes the record. The capture file size and packet length are distinct.
