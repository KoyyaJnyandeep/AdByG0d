"""Entrypoint for `python -m adbygod_api` and PyInstaller frozen EXE."""
from __future__ import annotations
import os
import sys

def _load_env() -> None:
    env_path = os.environ.get("DOTENV_PATH")
    if env_path and os.path.isfile(env_path):
        from dotenv import load_dotenv
        load_dotenv(env_path, override=False)

def main() -> None:
    # Windows: asyncio must use ProactorEventLoop (Python 3.8+ default on Win)
    if sys.platform == "win32":
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    _load_env()

    import uvicorn
    uvicorn.run(
        "adbygod_api.main:app",
        host="127.0.0.1",
        port=int(os.environ.get("API_PORT", "8000")),
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
        reload=False,
    )

if __name__ == "__main__":
    main()
