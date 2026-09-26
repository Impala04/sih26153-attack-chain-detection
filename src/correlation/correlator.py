"""Correlation of processing detection events into attack chains."""

from typing import List, Optional
from uuid import NAMESPACE_URL, uuid5

from src.processing.events import DetectionEvent

from .attack_chain import AttackChain
from .stage_mapper import FallbackStageMapper, StageMapper


class AttackChainCorrelator:
    """Group nearby detection events that share a source or destination host."""

    def __init__(
        self,
        max_event_gap_seconds: float = 300.0,
        chain_timeout_seconds: float = 1800.0,
        stage_mapper: Optional[StageMapper] = None,
    ) -> None:
        if max_event_gap_seconds < 0:
            raise ValueError("max_event_gap_seconds must be non-negative")
        if chain_timeout_seconds < 0:
            raise ValueError("chain_timeout_seconds must be non-negative")

        self.max_event_gap_seconds = max_event_gap_seconds
        self.chain_timeout_seconds = chain_timeout_seconds
        self.stage_mapper = stage_mapper or FallbackStageMapper()
        self.chains: List[AttackChain] = []
        self._event_ids = set()

    def add_event(self, event: DetectionEvent) -> AttackChain:
        """Add an event to a matching active chain or create a new chain."""
        if event.event_id in self._event_ids:
            return self._chain_containing(event.event_id)

        self.expire_chains(event.timestamp)
        chain = self._find_matching_chain(event)
        if chain is None:
            chain = AttackChain(
                # The first event is deterministic after correlate() sorts its input.
                chain_id=str(uuid5(NAMESPACE_URL, event.event_id)),
                source_hosts={event.src_ip},
                destination_hosts={event.dst_ip} if event.dst_ip else set(),
                start_time=event.timestamp,
                last_seen=event.timestamp,
            )
            self.chains.append(chain)
        else:
            chain.source_hosts.add(event.src_ip)
            if event.dst_ip:
                chain.destination_hosts.add(event.dst_ip)
            chain.last_seen = max(chain.last_seen, event.timestamp)

        chain.events.append(event)
        stage = self.stage_mapper.map_event(event)
        if stage not in chain.stages:
            chain.stages.append(stage)
        chain.current_stage = stage
        chain.confidence = self._confidence(chain)
        self._event_ids.add(event.event_id)
        return chain

    def correlate(self, events: List[DetectionEvent]) -> List[AttackChain]:
        """Correlate events deterministically, independent of input ordering."""
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            self.add_event(event)
        return list(self.chains)

    def expire_chains(self, now: float) -> None:
        """Mark timed-out chains inactive while retaining them as history."""
        for chain in self.chains:
            if chain.is_active and now - chain.last_seen > self.chain_timeout_seconds:
                chain.is_active = False

    def _find_matching_chain(self, event: DetectionEvent) -> Optional[AttackChain]:
        matches = [
            chain for chain in self.chains
            if chain.is_active
            and event.timestamp >= chain.last_seen
            and event.timestamp - chain.last_seen <= self.max_event_gap_seconds
            and self._hosts_overlap(chain, event)
        ]
        if not matches:
            return None
        return max(matches, key=lambda chain: (chain.last_seen, chain.start_time, chain.chain_id))

    @staticmethod
    def _hosts_overlap(chain: AttackChain, event: DetectionEvent) -> bool:
        event_hosts = {event.src_ip}
        if event.dst_ip:
            event_hosts.add(event.dst_ip)
        return bool(event_hosts & (chain.source_hosts | chain.destination_hosts))

    def _chain_containing(self, event_id: str) -> AttackChain:
        for chain in self.chains:
            if any(event.event_id == event_id for event in chain.events):
                return chain
        raise RuntimeError("known event id is not present in a chain")

    @staticmethod
    def _confidence(chain: AttackChain) -> float:
        """Compute: 0.30 base + 0.10/event (max 0.30), +0.15 for repeated
        sources, +0.10 per stage beyond first (max 0.25), clamped to 1.0.
        """
        event_bonus = min(0.30, 0.10 * len(chain.events))
        repeated_source_bonus = 0.15 if len(chain.source_hosts) < len(chain.events) else 0.0
        progression_bonus = min(0.25, 0.10 * max(0, len(chain.stages) - 1))
        return round(min(1.0, 0.30 + event_bonus + repeated_source_bonus + progression_bonus), 3)
