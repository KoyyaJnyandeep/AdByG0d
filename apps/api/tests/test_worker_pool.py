import asyncio
import pytest
from adbygod_api.core.workers.pool import WorkerPool
from adbygod_api.core.workers.base import ExecutorWorker


class DummyWorker(ExecutorWorker):
    async def execute(self, job_id: str, params: dict, emit) -> int:
        await emit({"stream": "stdout", "line": "done"})
        return 0


def test_executor_worker_is_abstract():
    import inspect
    assert inspect.isabstract(ExecutorWorker)


@pytest.mark.asyncio
async def test_pool_submit_runs_worker():
    pool = WorkerPool(max_workers=2)
    results = []

    async def fake_emit(data):
        results.append(data)

    worker = DummyWorker()
    await pool.submit("job-1", worker, {}, fake_emit)
    await asyncio.sleep(0.05)
    assert results[0] == {"stream": "stdout", "line": "done"}
    assert results[1] == {"done": True, "exit_code": 0}
