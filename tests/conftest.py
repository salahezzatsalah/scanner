"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reconx.db.models import Program
from reconx.db.session import init_db
from reconx.scope.guard import ScopeGuard
from reconx.scope.model import Scope

VALID_AUTH = {
    "authorized_by": "researcher@example.com",
    "date": "2026-09-28",
    "attestation": "I am authorized to test this scope.",
}


def make_scope(**overrides) -> Scope:
    """Build a valid scope, overriding any field."""
    payload = {
        "program": "Example Corp VDP",
        "authorization": VALID_AUTH,
        "in_scope": ["*.example.com", "api.example.io", "203.0.113.0/24"],
        "out_of_scope": ["payments.example.com", "*.internal.example.com"],
    }
    payload.update(overrides)
    return Scope.model_validate(payload)


@pytest.fixture
def scope() -> Scope:
    return make_scope()


@pytest.fixture
def guard(scope: Scope) -> ScopeGuard:
    return ScopeGuard(scope)


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """A fresh in-memory database per test.

    StaticPool keeps the single connection alive so the schema persists across
    sessions within one test.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    await init_db(engine=engine)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def program(db_session: AsyncSession) -> Program:
    """A persisted program to hang test data off."""
    from reconx.db.store import upsert_program

    scope = make_scope()
    created = await upsert_program(db_session, scope, scope_yaml="program: Example Corp VDP")
    await db_session.commit()
    return created
