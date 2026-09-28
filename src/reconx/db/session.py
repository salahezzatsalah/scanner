"""Async database engine and session management.

SQLite is the default because a researcher running this locally should not have
to stand up a database server first. Postgres is one ``DATABASE_URL`` change
away for heavier use.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from reconx.config import Settings, get_settings

__all__ = [
    "get_engine",
    "sqlite_journal_mode",
    "get_session_factory",
    "session_scope",
    "init_db",
    "dispose_engine",
]

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _prepare_sqlite_path(url: str) -> None:
    """Create the parent directory for a file-backed SQLite database."""
    marker = "sqlite+aiosqlite:///"
    if not url.startswith(marker):
        return
    raw = url[len(marker) :]
    if not raw or raw.startswith(":memory:"):
        return
    Path(raw).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def _configure_sqlite(engine: AsyncEngine, *, file_backed: bool) -> None:
    """Make SQLite usable by more than one writer.

    In its default journal mode SQLite fails a concurrent write immediately with
    "database is locked", which breaks stages that run in parallel. Two pragmas
    fix it:

    * **WAL** lets a writer proceed alongside readers and shrinks the window in
      which a second writer is blocked at all. It needs a file, so it is skipped
      for in-memory databases.
    * **busy_timeout** makes a blocked writer wait for its turn instead of
      raising. Without it, WAL alone still loses races.

    ``synchronous=NORMAL`` is the recommended pairing with WAL: durable against
    a process crash, and much faster than the default.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_pragmas(dbapi_connection, _record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        try:
            if file_backed:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=15000")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


def get_engine(settings: Settings | None = None, *, url: str | None = None) -> AsyncEngine:
    """Return the process-wide engine, creating it on first use."""
    global _engine, _session_factory
    if _engine is not None and url is None:
        return _engine

    resolved = url or (settings or get_settings()).database_url
    _prepare_sqlite_path(resolved)

    kwargs: dict = {"echo": False, "future": True}
    if ":memory:" in resolved:
        # Keep one connection so an in-memory database survives between
        # sessions, which is what tests need.
        kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = {"check_same_thread": False}

    engine = create_async_engine(resolved, **kwargs)
    if resolved.startswith("sqlite"):
        _configure_sqlite(engine, file_backed=":memory:" not in resolved)
    if url is None:
        _engine = engine
        _session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return engine


def get_session_factory(
    settings: Settings | None = None,
) -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        get_engine(settings)
    assert _session_factory is not None
    return _session_factory


@asynccontextmanager
async def session_scope(
    settings: Settings | None = None,
) -> AsyncIterator[AsyncSession]:
    """A session that commits on success and rolls back on failure."""
    factory = get_session_factory(settings)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db(settings: Settings | None = None, *, engine: AsyncEngine | None = None) -> None:
    """Create any missing tables.

    Alembic owns schema *changes*; this is the first-run path so a new install
    works without running a migration.
    """
    target = engine or get_engine(settings)
    async with target.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)


async def sqlite_journal_mode(engine: AsyncEngine) -> str | None:
    """The journal mode actually in force. Used by tests and diagnostics."""
    if not engine.url.drivername.startswith("sqlite"):
        return None
    async with engine.connect() as connection:
        result = await connection.execute(text("PRAGMA journal_mode"))
        row = result.first()
    return str(row[0]).lower() if row else None


async def dispose_engine() -> None:
    """Tear down the engine. Used by tests and on shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
