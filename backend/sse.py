"""
SentinelSOC - Server-Sent Events helper.

Provides an async queue-backed channel that the pipeline pushes into from a
worker thread, and a FastAPI-compatible async generator that yields properly
formatted text/event-stream lines.

Design: the pipeline is synchronous (CPU-bound ML, blocking LLM calls).  It
runs in a background thread and pushes dicts into an asyncio.Queue via
call_soon_threadsafe.  The SSE generator awaits that queue and yields to the
HTTP response as each event lands.  The sentinel value None closes the stream.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator


class SSEChannel:
    """Thread-safe bridge between a synchronous pipeline and an async SSE stream."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._queue: asyncio.Queue[dict | None] = asyncio.Queue()

    # -- called from the worker thread (synchronous) -------------------------

    def send(self, event: str, data: Any) -> None:
        """Push a typed event.  Thread-safe."""
        self._loop.call_soon_threadsafe(
            self._queue.put_nowait, {"event": event, "data": data}
        )

    def close(self) -> None:
        """Signal end-of-stream."""
        self._loop.call_soon_threadsafe(self._queue.put_nowait, None)

    # -- called from the async response (coroutine) --------------------------

    async def __aiter__(self) -> AsyncGenerator[dict, None]:
        while True:
            item = await self._queue.get()
            if item is None:
                break
            yield item


async def event_stream(channel: SSEChannel) -> AsyncGenerator[str, None]:
    """
    Yields lines in the text/event-stream format.

    Each message is:
        event: <type>\n
        data: <json>\n
        \n

    Clients receive them via EventSource or fetch with ReadableStream.
    """
    async for msg in channel:
        event_type = msg["event"]
        payload = json.dumps(msg["data"], default=str)
        yield f"event: {event_type}\ndata: {payload}\n\n"
