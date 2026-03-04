"""Tests for proton_type=alias detection and trashing."""

from __future__ import annotations

import importlib
import json
from unittest.mock import patch

from tests.conftest import make_login_item

trash_aliases = importlib.import_module("1password_trash_aliases")


class TestIsProtonAlias:
    def test_true(self):
        item = make_login_item(
            extra_fields=[{"id": "custom1", "label": "proton_type", "value": "alias"}]
        )
        assert trash_aliases.is_proton_alias(item) is True

    def test_false_different_value(self):
        item = make_login_item(
            extra_fields=[{"id": "custom1", "label": "proton_type", "value": "login"}]
        )
        assert trash_aliases.is_proton_alias(item) is False

    def test_false_no_field(self):
        item = make_login_item()
        assert trash_aliases.is_proton_alias(item) is False

    def test_case_insensitive(self):
        item = make_login_item(
            extra_fields=[{"id": "custom1", "label": "Proton_Type", "value": "ALIAS"}]
        )
        assert trash_aliases.is_proton_alias(item) is True


class TestTrashAliasesIntegration:
    def test_trashes_with_apply(self):
        alias_item = make_login_item(
            item_id="alias1",
            title="Alias Item",
            extra_fields=[{"id": "c", "label": "proton_type", "value": "alias"}],
        )
        normal_item = make_login_item(item_id="normal1", title="Normal Item")
        summaries = [
            {"id": "alias1", "title": "Alias Item", "category": "LOGIN"},
            {"id": "normal1", "title": "Normal Item", "category": "LOGIN"},
        ]
        items_by_id = {"alias1": alias_item, "normal1": normal_item}

        def fake_run_op(args, *, stdin_data=None):
            if args[0:2] == ["item", "list"]:
                return json.dumps(summaries)
            if args[0:2] == ["item", "get"] and "-" in args:
                ids = [s["id"] for s in json.loads(stdin_data)]
                return "\n".join(json.dumps(items_by_id[iid]) for iid in ids if iid in items_by_id)
            if args[0:2] == ["item", "delete"]:
                return ""
            return "{}"

        with (
            patch.object(trash_aliases, "run_op", side_effect=fake_run_op) as mock_op,
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            result = trash_aliases.main()

        assert result == 0
        # Verify delete was called for alias but not normal
        delete_calls = [c for c in mock_op.call_args_list if c[0][0][0:2] == ["item", "delete"]]
        assert len(delete_calls) == 1
        assert "alias1" in delete_calls[0][0][0]

    def test_dry_run_no_deletes(self):
        alias_item = make_login_item(
            item_id="alias1",
            extra_fields=[{"id": "c", "label": "proton_type", "value": "alias"}],
        )
        summaries = [{"id": "alias1", "title": "Alias", "category": "LOGIN"}]

        def fake_run_op(args, *, stdin_data=None):
            if args[0:2] == ["item", "list"]:
                return json.dumps(summaries)
            if args[0:2] == ["item", "get"] and "-" in args:
                ids = [s["id"] for s in json.loads(stdin_data)]
                items = {"alias1": alias_item}
                return "\n".join(json.dumps(items[iid]) for iid in ids if iid in items)
            if args[0:2] == ["item", "delete"]:
                raise AssertionError("delete should not be called in dry-run")
            return "{}"

        with (
            patch.object(trash_aliases, "run_op", side_effect=fake_run_op),
            patch("sys.argv", ["prog", "--vault", "v"]),
        ):
            result = trash_aliases.main()

        assert result == 0
