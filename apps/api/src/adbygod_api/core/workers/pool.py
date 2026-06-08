from __future__ import annotations

import asyncio
import logging
from typing import Callable, Awaitable

from adbygod_api.core.workers.base import ExecutorWorker

log = logging.getLogger(__name__)


class WorkerPool:
    def __init__(self, max_workers: int = 10):
        self._sem = asyncio.Semaphore(max_workers)
        self._tasks: dict[str, asyncio.Task] = {}

    async def submit(
        self,
        job_id: str,
        worker: ExecutorWorker,
        params: dict,
        emit: Callable[[dict], Awaitable[None]],
    ) -> None:
        task = asyncio.create_task(self._run(job_id, worker, params, emit))
        self._tasks[job_id] = task

    async def _run(
        self,
        job_id: str,
        worker: ExecutorWorker,
        params: dict,
        emit: Callable[[dict], Awaitable[None]],
    ) -> None:
        async with self._sem:
            try:
                exit_code = await worker.execute(job_id, params, emit)
                await emit({"done": True, "exit_code": exit_code})
            except asyncio.CancelledError:
                await emit({"done": True, "exit_code": -1, "killed": True})
            except Exception as exc:
                log.exception("Worker error for job %s", job_id)
                await emit({"error": str(exc), "done": True, "exit_code": 1})
            finally:
                self._tasks.pop(job_id, None)

    async def kill(self, job_id: str) -> bool:
        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def is_running(self, job_id: str) -> bool:
        task = self._tasks.get(job_id)
        return task is not None and not task.done()


_pool: WorkerPool | None = None


def get_pool() -> WorkerPool:
    global _pool
    if _pool is None:
        _pool = WorkerPool(max_workers=10)
    return _pool


def init_pool(max_workers: int = 10) -> WorkerPool:
    global _pool
    _pool = WorkerPool(max_workers=max_workers)
    return _pool
