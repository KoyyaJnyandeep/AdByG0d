"""Tests for per-job isolated workspace abstraction."""

from __future__ import annotations

import os
import pytest

from adbygod_api.core.workspace import JobWorkspace, job_workspace


class TestJobWorkspace:
    def test_create_makes_directory(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path))
        path = ws.create()
        assert os.path.isdir(path)
        assert path.startswith(str(tmp_path))

    def test_artifact_returns_path_inside_workspace(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path))
        ws.create()
        art = ws.artifact("output.pfx")
        assert art.startswith(ws.path)
        assert art.endswith("output.pfx")

    def test_artifact_strips_directory_traversal(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path))
        ws.create()
        # basename of ../../etc/passwd is "passwd" — stays inside workspace
        art = ws.artifact("../../etc/passwd")
        assert "etc" not in art
        assert art.startswith(ws.path)

    def test_list_artifacts_returns_matching_files(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path))
        ws.create()
        for name in ("a.pfx", "b.pfx", "c.ccache"):
            open(os.path.join(ws.path, name), "w").close()
        pfx = ws.list_artifacts("*.pfx")
        assert len(pfx) == 2
        assert all(f.endswith(".pfx") for f in pfx)

    def test_cleanup_removes_directory(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path))
        ws.create()
        assert os.path.isdir(ws.path)
        ws.cleanup()
        assert not os.path.exists(ws.path)

    def test_cleanup_retains_on_failure_when_configured(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path), retain_on_failure=True)
        ws.create()
        ws.mark_failed()
        ws.cleanup()
        # Should still exist because retain_on_failure=True and job failed.
        assert os.path.isdir(ws.path)
        # Manual cleanup for test isolation
        import shutil
        shutil.rmtree(ws.path, ignore_errors=True)

    def test_cleanup_removes_on_success_even_with_retain_flag(self, tmp_path):
        ws = JobWorkspace("test-job-id-1234", str(tmp_path), retain_on_failure=True)
        ws.create()
        # No mark_failed() call — simulate success.
        ws.cleanup()
        assert not os.path.exists(ws.path)


@pytest.mark.asyncio
async def test_context_manager_creates_and_cleans_up(tmp_path):
    captured_path = None
    async with job_workspace("job-abc-123", base=str(tmp_path)) as ws:
        captured_path = ws.path
        assert os.path.isdir(captured_path)
    # Workspace must be gone after context exits.
    assert not os.path.exists(captured_path)


@pytest.mark.asyncio
async def test_context_manager_cleans_up_on_exception(tmp_path):
    captured_path = None
    with pytest.raises(RuntimeError):
        async with job_workspace("job-abc-123", base=str(tmp_path)) as ws:
            captured_path = ws.path
            raise RuntimeError("simulated failure")
    assert not os.path.exists(captured_path)


@pytest.mark.asyncio
async def test_context_manager_retains_on_failure_when_configured(tmp_path):
    captured_path = None
    with pytest.raises(RuntimeError):
        async with job_workspace("job-abc-123", base=str(tmp_path), retain_on_failure=True) as ws:
            captured_path = ws.path
            ws.mark_failed()
            raise RuntimeError("simulated failure")
    assert os.path.isdir(captured_path)
    import shutil
    shutil.rmtree(captured_path, ignore_errors=True)


@pytest.mark.asyncio
async def test_artifacts_scoped_to_job_workspace(tmp_path):
    """No artifact from job A should be visible to job B."""
    async with job_workspace("job-aaa", base=str(tmp_path)) as ws_a:
        open(ws_a.artifact("secret.pfx"), "w").close()
        async with job_workspace("job-bbb", base=str(tmp_path)) as ws_b:
            pfx_in_b = ws_b.list_artifacts("*.pfx")
            assert pfx_in_b == [], "Job B must not see Job A's artifacts"
