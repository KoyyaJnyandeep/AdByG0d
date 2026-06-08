import json
import pytest
from unittest.mock import AsyncMock
from adbygod_api.core.streaming import channel_name, publish_line


def test_channel_name_format():
    result = channel_name("abc-123")
    assert result == "job:abc-123:output"


@pytest.mark.asyncio
async def test_publish_line_calls_redis_publish():
    mock_redis = AsyncMock()
    line_data = {"stream": "stdout", "line": "Kerberoasting...", "ts": "2026-04-28T00:00:00"}
    await publish_line(mock_redis, "job-id-1", line_data)
    mock_redis.publish.assert_called_once_with(
        "job:job-id-1:output",
        json.dumps(line_data)
    )
