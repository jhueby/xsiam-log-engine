from __future__ import annotations

import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.routers import sources, config, stats, control, correlations, scenarios, diagnostics, certs
from main import get_engine
from utils.logger import get_logger
from config.settings import settings

logger = get_logger(__name__, settings.engine_log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    logger.info({"event": "api_start", "sources": len(engine.sources)})
    if not settings.engine_api_token:
        logger.warning({"event": "api_auth_disabled", "hint": "set ENGINE_API_TOKEN to require authentication"})
    # Start any pre-enabled sources
    for sid, state in engine.sources.items():
        if state.enabled:
            await engine.start_source(sid)
    yield
    await engine.close()
    from xsiam_api import xsiam_api_client
    await xsiam_api_client.close()
    logger.info({"event": "api_shutdown"})


app = FastAPI(
    title="XSIAM Log Engine",
    version="1.0.0",
    description="Enterprise log simulation engine for XSIAM / Cortex XDR",
    lifespan=lifespan,
)

# No CORS middleware: the GUI is served same-origin (nginx in prod, vite proxy
# in dev), so cross-origin access to this API is intentionally blocked.


# The OpenAPI docs UI/schema expose the full API surface (routes, models,
# example payloads) and, unlike /api/*, aren't behind this middleware by
# default in FastAPI — so gate them the same way once a token is configured.
_TOKEN_GUARDED_PATHS = ("/api", "/docs", "/redoc", "/openapi.json")


@app.middleware("http")
async def require_api_token(request: Request, call_next):
    token = settings.engine_api_token
    if token and request.url.path.startswith(_TOKEN_GUARDED_PATHS):
        # EventSource cannot set headers, so SSE clients pass ?token= instead.
        presented = request.headers.get("x-engine-token") or request.query_params.get("token") or ""
        if not secrets.compare_digest(presented, token):
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API token"})
    return await call_next(request)


app.include_router(sources.router)
app.include_router(config.router)
app.include_router(certs.router)
app.include_router(stats.router)
app.include_router(control.router)
app.include_router(correlations.router)
app.include_router(scenarios.router)
app.include_router(diagnostics.router)


@app.get("/")
async def root():
    return {"service": "xsiam-log-engine", "version": "1.0.0"}
