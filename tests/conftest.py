"""Shared test fixtures."""

from __future__ import annotations

import pytest

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
