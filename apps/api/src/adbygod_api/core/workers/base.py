from __future__ import annotations

import abc
from typing import Callable, Awaitable


class ExecutorWorker(abc.ABC):
    @abc.abstractmethod
    async def execute(
        self,
        job_id: str,
        params: dict,
        emit: Callable[[dict], Awaitable[None]],
    ) -> int:
        """Execute the technique. Call emit() for each output line. Return exit code."""
        ...
