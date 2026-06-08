from __future__ import annotations

import json
import logging
from typing import AsyncGenerator

log = logging.getLogger(__name__)


_LINES_TTL = 86400  # 24 h


def channel_name(job_id: str) -> str:
    return f"job:{job_id}:output"


def lines_key(job_id: str) -> str:
    return f"job:{job_id}:lines"


async def publish_line(redis_client, job_id: str, data: dict) -> None:
    payload = json.dumps(data)
    await redis_client.publish(channel_name(job_id), payload)


async def store_and_publish_line(redis_client, job_id: str, data: dict) -> None:
    """Publish to pub/sub AND persist to a Redis list for late-subscriber replay."""
    payload = json.dumps(data)
    key = lines_key(job_id)
    await redis_client.publish(channel_name(job_id), payload)
    await redis_client.rpush(key, payload)
    await redis_client.expire(key, _LINES_TTL)


async def get_stored_lines(redis_client, job_id: str) -> list[dict]:
    """Return all stored lines for a job (for replay after the fact)."""
    key = lines_key(job_id)
    raw_list = await redis_client.lrange(key, 0, -1)
    result = []
    for raw in raw_list:
        try:
            result.append(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            pass
    return result


async def subscribe_lines(redis_client, job_id: str) -> AsyncGenerator[dict, None]:
    """Yield parsed line dicts from Redis pub/sub for a job. Stops on 'done' message."""
    channel = channel_name(job_id)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                log.warning("Invalid JSON on job channel: %r", message["data"])
                continue
            yield data
            if data.get("done") or data.get("error"):
                break
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
