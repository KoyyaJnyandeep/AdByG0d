from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adbygod_api.main import app  # noqa: E402
from adbygod_api.main import settings  # noqa: E402


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "adbygod_api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
