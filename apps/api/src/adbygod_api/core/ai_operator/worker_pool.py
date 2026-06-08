from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger(__name__)


class WorkerStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


@dataclass
class Worker:
    worker_id: int
    status: WorkerStatus = WorkerStatus.IDLE
    current_technique_id: str | None = None


@dataclass
class WorkerPoolState:
    session_id: uuid.UUID
    running: bool = False
    max_workers: int = 3
    workers: list[Worker] = field(default_factory=list)
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    tasks_completed: int = 0
    tasks_queued: int = 0


_ACTIVE_POOLS: dict[str, WorkerPoolState] = {}


def get_pool(session_id: uuid.UUID) -> WorkerPoolState | None:
    return _ACTIVE_POOLS.get(str(session_id))


def create_pool(session_id: uuid.UUID, max_workers: int = 3) -> WorkerPoolState:
    pool = WorkerPoolState(session_id=session_id, max_workers=max_workers)
    pool.workers = [Worker(worker_id=i) for i in range(max_workers)]
    _ACTIVE_POOLS[str(session_id)] = pool
    return pool


def stop_pool(session_id: uuid.UUID) -> bool:
    pool = _ACTIVE_POOLS.get(str(session_id))
    if pool:
        pool.stop_event.set()
        pool.running = False
        return True
    return False


def get_pool_status(session_id: uuid.UUID) -> dict:
    pool = _ACTIVE_POOLS.get(str(session_id))
    if not pool:
        return {
            "running": False,
            "session_id": str(session_id),
            "max_workers": 0,
            "active_workers": 0,
            "tasks_queued": 0,
            "tasks_completed": 0,
            "stop_requested": False,
        }
    return {
        "running": pool.running,
        "session_id": str(pool.session_id),
        "max_workers": pool.max_workers,
        "active_workers": sum(1 for w in pool.workers if w.status == WorkerStatus.RUNNING),
        "tasks_queued": pool.tasks_queued,
        "tasks_completed": pool.tasks_completed,
        "stop_requested": pool.stop_event.is_set(),
    }
