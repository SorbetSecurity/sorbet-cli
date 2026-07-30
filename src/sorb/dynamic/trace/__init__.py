"""Runtime observation.

``sorb trace -- <cmd>`` records what a process actually loads. Two mechanisms,
combined:

- **interpreter hooks** (no privileges): a Python ``sitecustomize`` import
  hook maps every imported module back to its installed distribution, and a
  Node ``--require`` probe records resolved module paths. These are shipped as
  data and injected via the child's environment.
- **process-tree file tracing**: platform backends record every file open that
  lands inside a known package store — Linux eBPF (→ fanotify → strace), macOS
  EndpointSecurity/dtrace, Windows ETW. The privileged backends run only where
  available; the fallback chain and the hooks cover the unprivileged case.

Every observation carries the observing technique and maps, via the mapper,
to an installed-state finding as an ``OBSERVED_IN`` edge at the top trust tier.
"""

from sorb.dynamic.trace.model import Observation, TraceResult
from sorb.dynamic.trace.runner import available_backends, run_trace

__all__ = [
    "Observation",
    "TraceResult",
    "available_backends",
    "run_trace",
]
