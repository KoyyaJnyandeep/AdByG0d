"""Entrypoint for the Celery worker EXE (Windows-compatible)."""
from __future__ import annotations
import os
import sys

def main() -> None:
    if sys.platform == "win32":
        # Required for multiprocessing spawn on Windows
        import multiprocessing
        multiprocessing.freeze_support()

    env_path = os.environ.get("DOTENV_PATH")
    if env_path and os.path.isfile(env_path):
        from dotenv import load_dotenv
        load_dotenv(env_path, override=False)

    from adbygod_api.core.celery_app import celery_app
    # Use 'solo' pool on Windows — prefork requires fork() which Windows lacks.
    argv = [
        "worker",
        "--queues=offensive_jobs",
        "--loglevel=info",
        "--pool=solo",           # single-threaded, no fork needed
        "--concurrency=1",
        "--without-gossip",
        "--without-mingle",
    ]
    celery_app.worker_main(argv=argv)

if __name__ == "__main__":
    main()
