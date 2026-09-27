# PCAP investigation and reporting

The analyzer consumes the standalone ingestion iterator and the shared
`ParsedPacket` contract. It has no dependency on the flow tracker, detector,
or frontend. It makes descriptive statistics only; ports and TCP flag counts
are not attack verdicts.

The reusable `analyze_packets(iterable, window_seconds=1.0, top_n=10)` function
accepts normalized `ParsedPacket` records directly and returns investigation
statistics. `analyze_pcap(path, ...)` reads a capture through Scapy and
delegates to the same packet analyzer. `pcap_json_report` builds and writes the
JSON report separately from packet reading and analysis; output object keys
are sorted, non-finite numbers are rejected, and `packet_count` is included at
the report's top level.

## Run

Install dependencies with `pip install -r requirements-pcap.txt`, then from the
repository root:

```bash
python -m src.analysis.pcap_analyzer capture.pcap --output reports/capture.json
python -m src.analysis.pcap_analyzer capture.pcapng --output reports/capture.json --html reports/capture.html --window 5
```

`--window` sets fixed-width time-series buckets in seconds (default 1), and
`--top` sets the number of top IPs, ports, and communications (default 10).
Without `--output`, JSON is written beside the input as
`<capture>_analysis.json`.

## JSON report schema

- `file`: input basename and file size in bytes.
- `capture`: first/last parsed packet timestamps (epoch seconds and UTC ISO
  strings), duration, time-series window width, and parsed packet count.
- `protocols`: counts and percentage distribution for TCP, UDP, ICMP, OTHER.
- `ips`: unique source/destination/pair counts and top source/destination IPs.
- `ports`: top TCP/UDP source and destination ports, plus observed counts for
  common service ports 22, 53, 80, 443, 445, 3389, and 8080.
- `traffic`: total bytes, average/minimum/maximum packet size in bytes, and
  average packets/bytes per second. Duration is last timestamp minus first;
  a zero-duration capture has a rate of zero.
- `tcp_flags`: packet counts containing SYN, SYN-ACK, ACK, FIN, RST, PSH,
  URG, ECE, and CWR flags. SYN is exclusive of SYN-ACK.
- `top_communications`: directional source/destination IP pairs with counts
  and summed bytes.
- `time_series`: chronological fixed-width buckets relative to the first
  parsed packet, with packet/byte totals, unique endpoint counts, and per-
  protocol counts.
- `observations`: deterministic descriptive indicators, including a window at
  or above 1,000 packets/s, 10,000,000 bytes/s, or 50 unique destinations.
  Empty supported captures receive a no-supported-packets observation. These
  are statistical notes and do not make attack determinations.

Packet bytes use `len(raw_scapy_packet)`. Protocol percentages are based on
parsed IPv4 packets (including IPv4 OTHER). Unsupported/non-IP packets are
skipped by ingestion and therefore excluded from packet counts. Start/end
times are null and numeric totals are zero for an empty capture.
Packets with missing, nonnumeric, non-finite, or unrepresentable timestamps are
skipped. The CLI serializes JSON with
non-finite values disallowed and reports invalid input/output paths as a
concise command error with a non-zero exit status.
