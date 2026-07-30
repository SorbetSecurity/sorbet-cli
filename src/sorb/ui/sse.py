"""Progress-bus → SSE bridge.

The scan pipeline emits typed events onto a `ProgressBus`. The bus's
sinks run on whatever thread the scan runs on; the SSE endpoint consumes them on
the event loop. `EventStream` is the thread-safe seam between the two: a bus sink
pushes each event onto a per-subscriber `asyncio.Queue` via
`loop.call_soon_threadsafe`, and a late subscriber replays a bounded ring buffer
so a browser that connects mid-scan still sees what already happened.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import asdict
from typing import Any

from sorb.core.events import Event, ProgressBus


def event_to_sse(event: Event) -> str:
    name = type(event).__name__
    payload = {"event": name, **asdict(event)}
    return f"event: {name}\ndata: {json.dumps(payload, sort_keys=True)}\n\n"


class EventStream:
    """Fan-out from one `ProgressBus` to many SSE subscribers, loop-safe.

    `loop` must be the loop the SSE endpoints run on; a background scan thread
    publishes via `loop.call_soon_threadsafe`. It defaults to the running loop,
    so construct this from within the serving loop (e.g. a startup handler).
    """

    def __init__(
        self, bus: ProgressBus, *, loop: asyncio.AbstractEventLoop | None = None, replay: int = 256
    ) -> None:
        self._loop = loop or asyncio.get_event_loop()
        self._subscribers: set[asyncio.Queue[Event | None]] = set()
        self._history: deque[Event] = deque(maxlen=replay)
        self._done = False
        bus.subscribe(self._on_event)

    # -- producer side (may run on a scan thread) -------------------------------

    def _on_event(self, event: Event) -> None:
        self._loop.call_soon_threadsafe(self._deliver, event)

    def _deliver(self, event: Event) -> None:
        self._history.append(event)
        for q in self._subscribers:
            q.put_nowait(event)

    def close(self) -> None:
        """Signal end-of-stream to every subscriber (scan finished)."""
        self._done = True
        for q in self._subscribers:
            self._loop.call_soon_threadsafe(q.put_nowait, None)

    # -- consumer side (the SSE endpoint) ---------------------------------------

    async def subscribe(self, *, replay: bool = True) -> Any:
        """Async generator of SSE-framed strings for one HTTP connection."""
        q: asyncio.Queue[Event | None] = asyncio.Queue()
        self._subscribers.add(q)
        try:
            if replay:
                for past in list(self._history):
                    yield event_to_sse(past)
            yield ": connected\n\n"  # SSE comment: flush headers, open the stream
            while True:
                item: Event | None
                try:
                    async with asyncio.timeout(15.0):
                        item = await q.get()
                except TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if item is None:
                    yield "event: done\ndata: {}\n\n"
                    return
                yield event_to_sse(item)
        finally:
            self._subscribers.discard(q)
