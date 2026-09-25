\# Capture Layer (feature/live-capture)



Converts raw network packets (live or, later, PCAP) into a normalized

`ParsedPacket` object for downstream flow tracking / feature extraction /

detection. This layer does no detection, windowing, or scoring.



\## Architecture



```

Network Interface -> Scapy sniff() -> parse\_packet() -> ParsedPacket -> your callback

```



\## ParsedPacket schema



```python

ParsedPacket(

&#x20;   timestamp: float,        # unix epoch seconds

&#x20;   src\_ip: str,

&#x20;   dst\_ip: str,

&#x20;   protocol: str,            # "TCP" | "UDP" | "ICMP" | "OTHER"

&#x20;   packet\_length: int,

&#x20;   src\_port: Optional\[int],  # None for ICMP

&#x20;   dst\_port: Optional\[int],  # None for ICMP

&#x20;   tcp\_flags: Optional\[str], # None for UDP/ICMP

)

```

Call `.to\_dict()` for a plain dict if needed.



\## Consuming it (for Aaron's pipeline)



```python

from src.capture.live\_sniffer import LiveSniffer



def handle\_packet(pkt):

&#x20;   flow\_tracker.ingest(pkt)  # your pipeline's entry point



sniffer = LiveSniffer(callback=handle\_packet, iface=None, bpf\_filter=None)

sniffer.start()   # runs in a background thread

...

sniffer.stop()

```



\- `iface=None` uses Scapy's default interface; pass a name (e.g. `"eth0"`, `"Wi-Fi"`) to select one.

\- `bpf\_filter` is an optional BPF string (`"tcp"`, `"udp"`, `"port 443"`, `"tcp or udp"`). Leave `None` to capture everything.



\## Platform requirements



\- \*\*Windows\*\*: install \[Npcap](https://npcap.com/) first (Scapy needs it for raw capture).

\- \*\*Linux/Mac\*\*: run with `sudo`, or grant `CAP\_NET\_RAW` to your Python interpreter.



\## Testing without real traffic



`src/capture/mock\_packets.py` builds synthetic TCP/UDP/ICMP/non-IP Scapy

packets. `tests/test\_packet\_parser.py` covers the parser fully offline:



```bash

pytest tests/test\_packet\_parser.py -v

```



Aaron can also import `mock\_packets.py` directly to feed fake `ParsedPacket`

sequences into the flow tracker while this branch is developed independently.



\## PCAP compatibility (future)



`parse\_packet()` takes a raw Scapy packet regardless of source, so a PCAP

reader (`scapy.rdpcap`) can reuse it unchanged:



```python

from scapy.all import rdpcap

from src.capture.packet\_parser import parse\_packet



for raw\_pkt in rdpcap("capture.pcap"):

&#x20;   parsed = parse\_packet(raw\_pkt)

&#x20;   if parsed:

&#x20;       flow\_tracker.ingest(parsed)

```

