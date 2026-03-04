"""Shared fixtures and factories for 1password-dedupe tests."""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import patch

import pytest

import op_cache

# The module name starts with a digit, so we use importlib to import it.
dedupe = importlib.import_module("1password_dedupe")
trash_aliases = importlib.import_module("1password_trash_aliases")


def make_login_item(
    item_id: str = "abc123",
    title: str = "Example Login",
    username: str = "user@example.com",
    password: str | None = "s3cret",
    urls: list[dict[str, Any]] | None = None,
    tags: list[str] | None = None,
    notes: str = "",
    totp: str | None = None,
    extra_fields: list[dict[str, Any]] | None = None,
    updated_at: str = "2025-01-01T00:00:00Z",
    created_at: str = "2024-01-01T00:00:00Z",
    password_history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a realistic 1Password Login item dict for testing."""
    fields: list[dict[str, Any]] = []

    if username is not None:
        fields.append({"id": "username", "type": "STRING", "label": "username", "value": username})

    if password is not None:
        fields.append(
            {"id": "password", "type": "CONCEALED", "label": "password", "value": password}
        )

    if totp is not None:
        fields.append({"id": "totp", "type": "OTP", "label": "one-time password", "value": totp})

    if extra_fields:
        fields.extend(extra_fields)

    item: dict[str, Any] = {
        "id": item_id,
        "title": title,
        "category": "LOGIN",
        "vault": {"id": "vault1", "name": "TestVault"},
        "fields": fields,
        "urls": urls or [{"href": "https://example.com"}],
        "tags": tags or [],
        "notesPlain": notes,
        "createdAt": created_at,
        "updatedAt": updated_at,
    }

    if password_history is not None:
        item["passwordHistory"] = password_history

    return item


def make_item_summary(
    item_id: str = "abc123",
    title: str = "Example Login",
    category: str = "LOGIN",
) -> dict[str, Any]:
    """Build a minimal item summary as returned by ``op item list``."""
    return {
        "id": item_id,
        "title": title,
        "category": category,
        "vault": {"id": "vault1", "name": "TestVault"},
    }


@pytest.fixture()
def mock_op():
    """Patch ``run_op`` in both modules to prevent real CLI calls.

    Returns a dict with 'dedupe' and 'trash' keys, each holding the
    respective MagicMock for run_op.
    """
    with (
        patch.object(dedupe, "run_op", return_value="{}") as mock_d,
        patch.object(trash_aliases, "run_op", return_value="{}") as mock_t,
    ):
        yield {"dedupe": mock_d, "trash": mock_t}


@pytest.fixture(autouse=True)
def _no_disk_cache(request):
    """Prevent tests from touching the real disk cache.

    Patches ``load_cache`` to return ``None`` (cache miss) and
    ``save_cache`` to no-op so that tests always exercise the ``run_op``
    path without filesystem side-effects.

    Skipped for ``test_cache.py`` which tests the cache module directly.
    """
    if request.fspath.basename == "test_cache.py":
        yield
        return
    with (
        patch.object(op_cache, "load_cache", return_value=None),
        patch.object(op_cache, "save_cache"),
        patch.object(
            op_cache, "load_run_state", return_value={"completed": [], "failures": []}
        ),
        patch.object(op_cache, "save_run_state", return_value=None),
        patch.object(op_cache, "clear_run_state"),
    ):
        yield
