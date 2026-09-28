from src.capture.live_sniffer import LiveSniffer
import time

def handle(pkt):
    print(pkt.to_dict())

sniffer = LiveSniffer(callback=handle, iface=None, bpf_filter=None)
sniffer.start()
time.sleep(15)
sniffer.stop()
print('done')