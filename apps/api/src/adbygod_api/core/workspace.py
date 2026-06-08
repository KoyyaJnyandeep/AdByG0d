"""
Per-job isolated workspace for offensive subprocess execution.

Every job that emits file artifacts (PFX, ccache, hash files) gets its own
directory under JOB_WORKSPACE_BASE. This prevents cross-job artifact
contamination, enables safe cleanup, and gives subprocesses a predictable cwd.

Usage (async context manager):

    async with job_workspace(job_id) as ws:
        # ws.path — absolute path to the job directory
        # ws.artifact("foo.pfx") — absolute path within the workspace
        # ws.list_artifacts("*.ccache") — glob within the workspace
        rc = await worker._stream_subprocess(cmd, emit, cwd=ws.path)
        loot = ws.list_artifacts("*.pfx")
        # workspace is cleaned up on exit unless retained for debugging
"""

from __future__ import annotations

import glob
import logging
import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from typing import AsyncGenerator

log = logging.getLogger(__name__)


class JobWorkspace:
    """Isolated temp directory for a single job's subprocess artifacts."""

    def __init__(self, job_id: str, base: str, retain_on_failure: bool = False):
        self.job_id = job_id
        self.base = base
        self.retain_on_failure = retain_on_failure
        self.path: str = ""
        self._failed: bool = False

    def create(self) -> str:
        os.makedirs(self.base, mode=0o700, exist_ok=True)
        self.path = tempfile.mkdtemp(
            prefix=f"adbygod_{self.job_id[:8]}_",
            dir=self.base,
        )
        os.chmod(self.path, 0o700)
        log.debug("Job workspace created: %s", self.path)
        return self.path

    def artifact(self, filename: str) -> str:
        """Return absolute path for a filename inside this workspace."""
        return os.path.join(self.path, os.path.basename(filename))

    def list_artifacts(self, pattern: str = "*") -> list[str]:
        """Return files matching glob pattern within the workspace."""
        return sorted(glob.glob(os.path.join(self.path, pattern)))

    def mark_failed(self) -> None:
        self._failed = True

    def cleanup(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        if self.retain_on_failure and self._failed:
            log.info("Retaining failed job workspace for debugging: %s", self.path)
            return
        try:
            shutil.rmtree(self.path, ignore_errors=True)
            log.debug("Job workspace removed: %s", self.path)
        except Exception:
            log.warning("Failed to remove workspace %s", self.path, exc_info=True)


@asynccontextmanager
async def job_workspace(
    job_id: str,
    base: str | None = None,
    retain_on_failure: bool | None = None,
) -> AsyncGenerator[JobWorkspace, None]:
    """Async context manager providing an isolated per-job workspace.

    Yields a JobWorkspace.  Cleans up on exit unless the job failed AND
    JOB_WORKSPACE_RETAIN_ON_FAILURE is enabled.
    """
    from adbygod_api.config import settings

    effective_base = base if base is not None else settings.JOB_WORKSPACE_BASE
    effective_retain = (
        retain_on_failure
        if retain_on_failure is not None
        else settings.JOB_WORKSPACE_RETAIN_ON_FAILURE
    )

    ws = JobWorkspace(job_id, effective_base, effective_retain)
    ws.create()
    try:
        yield ws
    except Exception:
        ws.mark_failed()
        raise
    finally:
        ws.cleanup()
