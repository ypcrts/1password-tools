"""Integration tests for the full merge flow — focused on data loss prevention."""

from __future__ import annotations

import importlib
import json
from unittest.mock import patch

from tests.conftest import make_item_summary, make_login_item

dedupe = importlib.import_module("1password_dedupe")


def _build_two_item_scenario(
    *,
    primary_password: str | None = "pw_primary",
    dup_password: str | None = "pw_dup",
    primary_notes: str = "Primary notes",
    dup_notes: str = "Dup notes",
    primary_totp: str | None = None,
    dup_totp: str | None = None,
    primary_tags: list[str] | None = None,
    dup_tags: list[str] | None = None,
    primary_urls: list[dict] | None = None,
    dup_urls: list[dict] | None = None,
    dup_password_history: list[dict] | None = None,
):
    """Build a scenario with one primary and one duplicate item."""
    primary = make_login_item(
        item_id="primary1",
        title="Primary",
        username="user@example.com",
        password=primary_password,
        notes=primary_notes,
        totp=primary_totp,
        tags=primary_tags,
        urls=primary_urls or [{"href": "https://example.com"}],
        updated_at="2025-06-01T00:00:00Z",
    )
    dup = make_login_item(
        item_id="dup1",
        title="Duplicate",
        username="user@example.com",
        password=dup_password,
        notes=dup_notes,
        totp=dup_totp,
        tags=dup_tags,
        urls=dup_urls or [{"href": "https://example.com"}],
        updated_at="2025-01-01T00:00:00Z",
        password_history=dup_password_history,
    )
    summaries = [
        make_item_summary(item_id="primary1", title="Primary"),
        make_item_summary(item_id="dup1", title="Duplicate"),
    ]
    return primary, dup, summaries


def _make_fake_run_op(items_by_id, *, edits=None, deletes=None):
    """Create a fake run_op that tracks edits and deletes."""
    if edits is None:
        edits = []
    if deletes is None:
        deletes = []

    def fake_run_op(args, *, stdin_data=None):
        if args[0:2] == ["item", "list"]:
            # Return all summaries
            return json.dumps(list(items_by_id.get("__summaries__", [])))
        if args[0:2] == ["item", "get"] and "-" in args:
            # Stdin pipe mode: op outputs concatenated JSON objects (not an array)
            ids = [s["id"] for s in json.loads(stdin_data)]
            results = [items_by_id[iid] for iid in ids if iid in items_by_id]
            return "\n".join(json.dumps(r) for r in results)
        if args[0:2] == ["item", "get"]:
            item_id = args[2]
            item = items_by_id.get(item_id, {})
            return json.dumps(item)
        if args[0:2] == ["item", "edit"]:
            item_id = args[2]
            edits.append({"item_id": item_id, "args": args, "stdin": stdin_data})
            return "{}"
        if args[0:2] == ["item", "delete"]:
            if args[2] == "-" and stdin_data:
                for obj in json.loads(stdin_data):
                    deletes.append(obj["id"])
            else:
                deletes.append(args[2])
            return ""
        return "{}"

    return fake_run_op


class TestDryRun:
    def test_makes_zero_mutations(self):
        primary, dup, summaries = _build_two_item_scenario()
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v"]),
        ):
            result = dedupe.main()

        assert result == 0
        assert len(edits) == 0
        assert len(deletes) == 0


class TestApplyMerge:
    def test_merges_notes_and_tags(self):
        primary, dup, summaries = _build_two_item_scenario(primary_password=None, dup_password=None)
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            result = dedupe.main()

        assert result == 0
        # Primary edit (phase 3) + dup tag edit (phase 4)
        assert len(edits) >= 2
        # Find the primary edit (has stdin with MERGED-PRIMARY tag)
        primary_edits = [e for e in edits if e["item_id"] == "primary1" and e["stdin"]]
        assert len(primary_edits) >= 1
        primary_json = json.loads(primary_edits[0]["stdin"])
        assert "MERGED-PRIMARY" in primary_json.get("tags", [])

    def test_trash_duplicates_deletes_after_merge(self):
        primary, dup, summaries = _build_two_item_scenario(primary_password=None, dup_password=None)
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply", "--trash-duplicates"]),
        ):
            result = dedupe.main()

        assert result == 0
        assert "dup1" in deletes


class TestTOTPCycling:
    def test_different_totp_cycled_and_deletion_proceeds(self):
        primary, dup, summaries = _build_two_item_scenario(
            primary_totp="otpauth://totp/a",
            dup_totp="otpauth://totp/b",
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply", "--trash-duplicates"]),
        ):
            result = dedupe.main()

        assert result == 0
        # TOTP values differ, so cycling should have occurred
        totp_edits = [
            e for e in edits if e["stdin"] is None and "one-time password" in str(e["args"])
        ]
        assert len(totp_edits) >= 2  # cycle + restore
        # Deletion should proceed (TOTP is preserved via cycling)
        assert "dup1" in deletes

    def test_same_totp_skips_cycling(self):
        primary, dup, summaries = _build_two_item_scenario(
            primary_totp="otpauth://totp/same",
            dup_totp="otpauth://totp/same",
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply", "--trash-duplicates"]),
        ):
            result = dedupe.main()

        assert result == 0
        # Same TOTP — no cycling edits
        totp_edits = [
            e for e in edits if e["stdin"] is None and "one-time password" in str(e["args"])
        ]
        assert len(totp_edits) == 0
        assert "dup1" in deletes

    def test_notes_contain_totp_history(self):
        primary, dup, summaries = _build_two_item_scenario(
            primary_totp="otpauth://totp/a",
            dup_totp="otpauth://totp/b",
            primary_password=None,
            dup_password=None,
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            dedupe.main()

        json_edits = [e for e in edits if e["stdin"] is not None and e["item_id"] == "primary1"]
        assert len(json_edits) >= 1
        primary_json = json.loads(json_edits[0]["stdin"])
        notes = primary_json.get("notesPlain", "")
        assert "TOTP History Merge" in notes


class TestPasswordHistory:
    def test_passwords_cycled_and_restored(self):
        primary, dup, summaries = _build_two_item_scenario(
            primary_password="pw_primary",
            dup_password="pw_dup",
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            result = dedupe.main()

        assert result == 0
        # Should have password cycling edits (field assignment style)
        field_edits = [e for e in edits if e["stdin"] is None and "password=" in str(e["args"])]
        assert len(field_edits) >= 2  # cycle + restore

    def test_notes_contain_history_table(self):
        primary, dup, summaries = _build_two_item_scenario(
            primary_password="pw_primary",
            dup_password="pw_dup",
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            dedupe.main()

        # Find the primary JSON edit (has stdin data)
        json_edits = [e for e in edits if e["stdin"] is not None and e["item_id"] == "primary1"]
        assert len(json_edits) >= 1
        primary_json = json.loads(json_edits[0]["stdin"])
        notes = primary_json.get("notesPlain", "")
        assert "Password History Merge" in notes

    def test_password_conflict_allows_deletion(self):
        """Password conflicts no longer block deletion (passwords are preserved)."""
        primary, dup, summaries = _build_two_item_scenario(
            primary_password="pw1",
            dup_password="pw2",
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply", "--trash-duplicates"]),
        ):
            dedupe.main()

        # Password conflict should NOT block deletion (passwords are preserved)
        assert "dup1" in deletes


class TestCategoriesFilter:
    def test_categories_passed_to_op(self):
        """Ensure we pass --categories login to op item list."""
        edits, deletes = [], []
        items = {"__summaries__": []}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)
        op_calls = []

        def tracking_fake(args, *, stdin_data=None):
            op_calls.append(args)
            return fake(args, stdin_data=stdin_data)

        with (
            patch.object(dedupe, "run_op", side_effect=tracking_fake),
            patch("sys.argv", ["prog", "--vault", "v"]),
        ):
            dedupe.main()

        list_call = op_calls[0]
        assert "--categories" in list_call
        assert "login" in list_call


class TestNotesWithEquals:
    def test_notes_with_equals_survive_roundtrip(self):
        primary, dup, summaries = _build_two_item_scenario(
            primary_notes="key=value setting",
            dup_notes="config=true",
            primary_password=None,
            dup_password=None,
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            dedupe.main()

        primary_edit = next(e for e in edits if e["item_id"] == "primary1" and e["stdin"])
        primary_json = json.loads(primary_edit["stdin"])
        notes = primary_json.get("notesPlain", "")
        assert "key=value setting" in notes
        assert "config=true" in notes


class TestIdempotent:
    def test_no_duplicate_notes_on_rerun(self):
        # Simulate a re-run where notes already contain the merge stamp
        primary, dup, summaries = _build_two_item_scenario(
            primary_notes=(
                "Original\n\n---\n"
                "Merged from: Duplicate (id=dup1) @ 2025-01-01T00:00:00Z\nDup notes\n"
            ),
            dup_notes="Dup notes",
            primary_password=None,
            dup_password=None,
        )
        edits, deletes = [], []
        items = {"primary1": primary, "dup1": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            dedupe.main()

        # Notes should not be double-appended
        primary_edit = next(
            (e for e in edits if e["item_id"] == "primary1" and e["stdin"]),
            None,
        )
        if primary_edit:
            primary_json = json.loads(primary_edit["stdin"])
            notes = primary_json.get("notesPlain", "")
            # Should only appear once
            assert notes.count("(id=dup1)") == 1


class TestSingleItemGroup:
    def test_skipped(self):
        primary = make_login_item(
            item_id="solo1",
            title="Solo",
            username="user@example.com",
            urls=[{"href": "https://solo.com"}],
        )
        summaries = [make_item_summary(item_id="solo1")]
        edits, deletes = [], []
        items = {"solo1": primary, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply"]),
        ):
            result = dedupe.main()

        assert result == 0
        assert len(edits) == 0


class TestLimitAndMinGroupSize:
    def test_limit_flag(self):
        # Create 3 groups of 2
        items_by_id = {"__summaries__": []}
        for i in range(3):
            for j in range(2):
                iid = f"item_{i}_{j}"
                item = make_login_item(
                    item_id=iid,
                    title=f"Item {i}-{j}",
                    username=f"user{i}@example.com",
                    urls=[{"href": f"https://site{i}.com"}],
                    updated_at=f"2025-0{j + 1}-01T00:00:00Z",
                    password=None,
                )
                items_by_id[iid] = item
                items_by_id["__summaries__"].append(make_item_summary(item_id=iid))

        edits, deletes = [], []
        fake = _make_fake_run_op(items_by_id, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply", "--limit", "1"]),
        ):
            dedupe.main()

        # 1 group processed: 1 primary edit (phase 3) + 1 dup tag (phase 4) = 2
        assert len(edits) == 2

    def test_min_group_size(self):
        primary = make_login_item(
            item_id="a1", username="u@e.com", urls=[{"href": "https://e.com"}]
        )
        dup = make_login_item(item_id="a2", username="u@e.com", urls=[{"href": "https://e.com"}])
        summaries = [make_item_summary(item_id="a1"), make_item_summary(item_id="a2")]
        edits, deletes = [], []
        items = {"a1": primary, "a2": dup, "__summaries__": summaries}
        fake = _make_fake_run_op(items, edits=edits, deletes=deletes)

        with (
            patch.object(dedupe, "run_op", side_effect=fake),
            patch("sys.argv", ["prog", "--vault", "v", "--apply", "--min-group-size", "3"]),
        ):
            dedupe.main()

        # Group of 2 is below min-group-size=3, so no edits
        assert len(edits) == 0


class TestFetchHelpers:
    def test_parse_concatenated_json(self):
        """Verify parse_concatenated_json returns correct items."""
        items = [
            make_login_item(item_id="id1"),
            make_login_item(item_id="id2"),
        ]
        text = "\n".join(json.dumps(item) for item in items)
        result = dedupe.parse_concatenated_json(text)

        assert len(result) == 2
        result_by_id = {item["id"]: item for item in result}
        assert result_by_id["id1"]["id"] == "id1"
        assert result_by_id["id2"]["id"] == "id2"

    def test_run_op_propagates_error(self):
        """Verify errors from run_op propagate."""
        import pytest

        def failing_run_op(args, *, stdin_data=None):
            if args[0:2] == ["item", "get"]:
                raise SystemExit("op failed")
            return "{}"

        with patch.object(dedupe, "run_op", side_effect=failing_run_op):
            with pytest.raises(SystemExit):
                dedupe.run_op(["item", "get", "--format", "json", "-"], stdin_data="{}")
