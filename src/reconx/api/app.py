"""The HTTP API.

Read access to everything the pipeline has recorded, plus one endpoint to start a
scan. It exists so a dashboard, a script, or another tool can use ReconX's data
without going through the CLI.

Two things about exposure, because this serves findings:

* It binds to loopback by default.
* It **refuses to start on a non-loopback address unless a token is set**. Scan
  data is a list of someone else's weak points; publishing it unauthenticated on
  a network interface would be worse than not having the API at all.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from reconx import __version__
from reconx.config import Settings, get_settings
from reconx.db.session import get_session_factory, init_db

__all__ = ["create_app", "require_token", "get_session", "LOOPBACK_HOSTS"]

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class ApiExposureError(RuntimeError):
    """The API was asked to listen somewhere it should not without a token."""


def assert_safe_binding(host: str, token: str) -> None:
    """Refuse to serve findings unauthenticated off loopback."""
    if host in LOOPBACK_HOSTS:
        return
    if not token:
        raise ApiExposureError(
            f"refusing to bind the API to {host!r} without a token. This API serves "
            "findings, which are a list of another organisation's weaknesses. Either "
            "bind to 127.0.0.1, or set RECONX_API_TOKEN and use it in an "
            "Authorization: Bearer header."
        )


async def get_session() -> AsyncIterator[AsyncSession]:
    """A database session per request."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


async def require_token(request: Request) -> None:
    """Check the bearer token, when one is configured.

    No token configured means no check, which is the right default for a
    loopback-only service and is why the binding check above exists.
    """
    settings: Settings = request.app.state.settings
    expected = getattr(settings, "api_token", "") or ""
    if not expected:
        return

    header = request.headers.get("authorization", "")
    supplied = header[7:].strip() if header.lower().startswith("bearer ") else ""
    # Constant-time comparison: this is a shared secret over HTTP.
    import hmac

    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a valid bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application."""
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await init_db(resolved)
        yield

    app = FastAPI(
        title="ReconX",
        version=__version__,
        summary="Continuous reconnaissance and vulnerability verification",
        description=(
            "Read access to discovered assets, endpoints and verified findings, plus "
            "an endpoint to start a scan. Findings carry the verification verdict and "
            "the reason behind it, including for candidates that were discarded."
        ),
        lifespan=lifespan,
    )
    app.state.settings = resolved

    from reconx.api.routes import actions, data

    app.include_router(data.router, dependencies=[Depends(require_token)])
    app.include_router(actions.router, dependencies=[Depends(require_token)])

    @app.get("/health", tags=["meta"])
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app
