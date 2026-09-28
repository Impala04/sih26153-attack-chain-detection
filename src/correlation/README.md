# Attack-chain correlation

`AttackChainCorrelator` groups nearby `DetectionEvent` instances when they share a source or destination host. It retains inactive chains as history.

The default `FallbackStageMapper` is deliberately temporary. It maps only the current detector values: `potential_network_scan` to `Discovery`, `potential_flood` to `Impact`, and `suspicious_traffic` to `Lateral Movement`. A future MITRE mapper can implement `StageMapper` and be passed to the correlator constructor.

Events are matched to active chains only when their timestamp is within the configured event gap and they overlap on at least one source/destination host. Batches are sorted by `(timestamp, event_id)` before processing.

Note: add\_event() assumes timestamps are non-decreasing across successive calls, since it uses the current event's timestamp to expire stale chains and match against each chain's last\_seen. Always use correlate() for batches of events, which sorts by (timestamp, event\_id) first. If calling add\_event() directly with individual events, ensure they are pre-sorted by timestamp.
