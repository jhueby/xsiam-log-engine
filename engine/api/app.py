from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import sources, config, stats, control
from main import get_engine
from utils.logger import get_logger
from config.settings import settings

logger = get_logger(__name__, settings.engine_log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    logger.info({"event": "api_start", "sources": len(engine.sources)})
    # Start any pre-enabled sources
    for sid, state in engine.sources.items():
        if state.enabled:
            await engine.start_source(sid)
    yield
    await engine.close()
    logger.info({"event": "api_shutdown"})


app = FastAPI(
    title="XSIAM Log Engine",
    version="1.0.0",
    description="Enterprise log simulation engine for XSIAM / Cortex XDR",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sources.router)
app.include_router(config.router)
app.include_router(stats.router)
app.include_router(control.router)


@app.get("/")
async def root():
    return {"service": "xsiam-log-engine", "version": "1.0.0"}
