from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.base import Base
from app.db.session import engine
from app.routers import auth, compat, jobs, reports, uploads


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit_per_minute = limit_per_minute
        self._hits: dict[str, Deque[float]] = defaultdict(deque)

    def hit(self, key: str) -> bool:
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - 60
        bucket = self._hits[key]
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= self.limit_per_minute:
            return False
        bucket.append(now)
        return True


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging()
    app = FastAPI(title=settings.app_name, debug=settings.debug)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    limiter = RateLimiter(settings.rate_limit_per_minute)

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        key = request.client.host if request.client else "unknown"
        if not limiter.hit(key):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
        return await call_next(request)

    app.include_router(auth.router)
    app.include_router(uploads.router)
    app.include_router(jobs.router)
    app.include_router(reports.router)
    app.include_router(compat.router)

    @app.on_event("startup")
    def startup() -> None:
        if settings.auto_create_tables:
            Base.metadata.create_all(bind=engine)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/")
    def root() -> FileResponse:
        return FileResponse(Path("index.html"))

    return app


app = create_app()
