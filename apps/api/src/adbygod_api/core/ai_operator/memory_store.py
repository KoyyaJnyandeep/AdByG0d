from __future__ import annotations
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class MemoryStore:
    def __init__(self, base_dir: str | None = None):
        self._base = Path(base_dir or os.path.expanduser("~/.adbygod/memory"))
        self._base.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    def _path(self, assessment_id: str) -> Path:
        return self._base / f"{assessment_id}.json"

    async def _load_unlocked(self, assessment_id: str) -> dict:
        """Load without acquiring lock — caller must hold lock."""
        path = self._path(assessment_id)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    async def load(self, assessment_id: str) -> dict:
        async with self._lock:
            return await self._load_unlocked(assessment_id)

    async def _save_unlocked(self, assessment_id: str, data: dict) -> None:
        """Save without acquiring lock — caller must hold lock."""
        path = self._path(assessment_id)
        data["last_updated"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        path.write_text(json.dumps(data, indent=2, default=str))

    async def append(self, assessment_id: str, key: str, value) -> None:
        async with self._lock:
            data = await self._load_unlocked(assessment_id)
            existing = data.get(key, [])
            if not isinstance(existing, list):
                existing = [existing]
            if value not in existing:
                existing.append(value)
            data[key] = existing
            await self._save_unlocked(assessment_id, data)

    async def set(self, assessment_id: str, key: str, value) -> None:
        async with self._lock:
            data = await self._load_unlocked(assessment_id)
            data[key] = value
            await self._save_unlocked(assessment_id, data)

    async def set_report_section(self, assessment_id: str, section: str, content: str) -> None:
        async with self._lock:
            data = await self._load_unlocked(assessment_id)
            sections = data.get("report_sections", {})
            sections[section] = {"content": content, "updated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}
            data["report_sections"] = sections
            await self._save_unlocked(assessment_id, data)

    async def get_report_sections(self, assessment_id: str) -> dict:
        data = await self.load(assessment_id)
        return data.get("report_sections", {})


_store = MemoryStore()


def get_memory_store() -> MemoryStore:
    return _store
