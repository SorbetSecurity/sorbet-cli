"""SSE progress-bus bridge: replay + live delivery + end sentinel."""

from __future__ import annotations

import asyncio

from sorb.core.events import ProgressBus, ScanStarted, StageCompleted, StageProgress
from sorb.ui.sse import EventStream, event_to_sse


def test_event_to_sse_frames_type_and_json() -> None:
    frame = event_to_sse(StageProgress(stage="walk", detail="walking", count=3))
    assert frame.startswith("event: StageProgress\n")
    assert '"stage": "walk"' in frame
    assert frame.endswith("\n\n")


def test_stream_replays_then_delivers_live_then_done() -> None:
    async def scenario() -> str:
        bus = ProgressBus()
        stream = EventStream(bus)
        bus.emit(ScanStarted(target="proj", subject="proj"))  # before subscribe → replay

        received: list[str] = []

        async def consume() -> None:
            async for chunk in stream.subscribe():
                received.append(chunk)
                if "event: done" in chunk:
                    return

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.02)
        bus.emit(StageProgress(stage="detect", detail="detecting", count=7))  # live
        bus.emit(StageCompleted(stage="detect", duration_s=0.1))
        await asyncio.sleep(0.02)
        stream.close()
        await asyncio.wait_for(task, timeout=2.0)
        return "".join(received)

    joined = asyncio.run(scenario())
    assert "ScanStarted" in joined  # replayed
    assert "StageProgress" in joined  # live
    assert "StageCompleted" in joined
    assert "event: done" in joined  # end sentinel on scan finish
