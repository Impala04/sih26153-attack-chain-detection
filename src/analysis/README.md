# PCAP investigation and reporting

The analyzer consumes the standalone ingestion iterator and the shared
`ParsedPacket` contract. It has no dependency on the flow tracker, detector,
or frontend. It makes descriptive statistics only; ports and TCP flag counts
are not attack verdicts.

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
- `observations`: currently empty; the report makes no attack determinations.

Packet bytes use `len(raw_scapy_packet)`. Protocol percentages are based on
parsed IPv4 packets (including IPv4 OTHER). Unsupported/non-IP packets are
skipped by ingestion and therefore excluded from packet counts. Start/end
times are null and numeric totals are zero for an empty capture.
