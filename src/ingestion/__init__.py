"""Offline PCAP ingestion helpers, imported lazily to keep module CLIs clean."""

__all__ = ["PcapReadError", "iter_pcap", "read_pcap"]


def __getattr__(name):
    if name in __all__:
        from src.ingestion import pcap_reader

        return getattr(pcap_reader, name)
    raise AttributeError(name)
