"""Host-domain readers & Windows offline analysis.

The `LiveHostSource`/`DiskImageSource` themselves live in `sorb.source` (L4, the
Source subsystem). This L3 package holds the host-domain logic layered on top:
container sub-target discovery, `/proc` runtime observation, offline Windows
registry-hive/service analysis, and fleet aggregation. The orchestration that
drives these against the `ProgressBus` lives in `sorb.core.host_augment` (L2), so
this package never imports upward into `sorb.core`.
"""
