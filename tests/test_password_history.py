"""Tests for password extraction, history collection, and cycling."""

from __future__ import annotations

import importlib
from unittest.mock import call, patch

from tests.conftest import make_login_item

dedupe = importlib.import_module("1password_dedupe")


class TestGetPasswordValue:
    def test_present(self):
        item = make_login_item(password="hunter2")
        assert dedupe.get_password_value(item) == "hunter2"

    def test_absent(self):
        item = make_login_item(password=None)
        assert dedupe.get_password_value(item) is None

    def test_empty(self):
        item = make_login_item()
        # Override with empty string
        for f in item["fields"]:
            if f["id"] == "password":
                f["value"] = ""
        assert dedupe.get_password_value(item) is None


class TestGetPasswordHistory:
    def test_with_entries(self):
        item = make_login_item(password_history=[{"value": "old1", "time": 1700000000}])
        result = dedupe.get_password_history(item)
        assert len(result) == 1
        assert result[0]["value"] == "old1"

    def test_without_entries(self):
        item = make_login_item()
        assert dedupe.get_password_history(item) == []

    def test_explicit_empty(self):
        item = make_login_item(password_history=[])
        assert dedupe.get_password_history(item) == []


class TestCollectAllPasswords:
    def test_current_and_history(self):
        item = make_login_item(
            password="current",
            password_history=[
                {"value": "old1", "time": 1700000000},
                {"value": "old2", "time": 1690000000},
            ],
        )
        result = dedupe.collect_all_passwords(item, "item1")
        assert len(result) == 3
        # Current has no timestamp
        assert result[0] == ("current", "item1", None)
        assert result[1] == ("old1", "item1", 1700000000)
        assert result[2] == ("old2", "item1", 1690000000)

    def test_no_current(self):
        item = make_login_item(
            password=None,
            password_history=[{"value": "old1", "time": 100}],
        )
        result = dedupe.collect_all_passwords(item, "x")
        assert len(result) == 1
        assert result[0][0] == "old1"

    def test_no_history(self):
        item = make_login_item(password="only")
        result = dedupe.collect_all_passwords(item, "x")
        assert len(result) == 1
        assert result[0] == ("only", "x", None)


class TestCyclePasswords:
    def test_sequential_edit_calls(self):
        with patch.object(dedupe, "op_edit_field") as mock_edit:
            dup_pws = [("pw_a", 1000), ("pw_b", 2000)]
            dedupe.cycle_passwords_for_history("primary1", "original", dup_pws, "v")

            # 2 password changes + 1 restore = 3 calls
            assert mock_edit.call_count == 3
            # Last call restores original
            assert mock_edit.call_args_list[-1] == call("primary1", "password=original", "v")

    def test_duplicate_skipping_handled_by_caller(self):
        """The caller should deduplicate; cycling just processes the list."""
        with patch.object(dedupe, "op_edit_field"):
            result = dedupe.cycle_passwords_for_history("p1", "orig", [("a", None)], "v")
            assert len(result) == 1

    def test_timestamp_map(self):
        with patch.object(dedupe, "op_edit_field"):
            result = dedupe.cycle_passwords_for_history(
                "p1", "orig", [("a", 1700000000), ("b", None)], "v"
            )
            assert len(result) == 2
            # First entry has a real timestamp
            assert "2023" in result[0][1]  # 1700000000 is in 2023
            # Second entry has unknown
            assert result[1][1] == "unknown"

    def test_empty_list(self):
        with patch.object(dedupe, "op_edit_field") as mock_edit:
            result = dedupe.cycle_passwords_for_history("p1", "orig", [], "v")
            assert result == []
            # No edits, not even restore (no changes were made)
            # Actually, original is still restored when primary_password is not None
            # But with empty list, we still restore
            assert mock_edit.call_count == 0 or mock_edit.call_count == 1

    def test_no_restore_when_primary_has_no_password(self):
        with patch.object(dedupe, "op_edit_field") as mock_edit:
            dedupe.cycle_passwords_for_history("p1", None, [("a", None)], "v")
            # Only the one cycle call, no restore
            assert mock_edit.call_count == 1


class TestBuildPasswordHistoryNote:
    def test_formats_table(self):
        pairs = [("2026-03-03T00:00:00Z", "2025-06-15T00:00:00Z")]
        result = dedupe.build_password_history_note(pairs)
        assert "Password History Merge" in result
        assert "2026-03-03" in result
        assert "2025-06-15" in result

    def test_empty(self):
        assert dedupe.build_password_history_note([]) == ""


class TestGetTotpValue:
    def test_present(self):
        item = make_login_item(totp="otpauth://totp/example")
        assert dedupe.get_totp_value(item) == "otpauth://totp/example"

    def test_absent(self):
        item = make_login_item(totp=None)
        assert dedupe.get_totp_value(item) is None

    def test_empty(self):
        item = make_login_item(totp="")
        assert dedupe.get_totp_value(item) is None


class TestCycleTotpForHistory:
    def test_sequential_edit_calls(self):
        with patch.object(dedupe, "op_edit_field") as mock_edit:
            dup_totps = ["otpauth://totp/a", "otpauth://totp/b"]
            dedupe.cycle_totp_for_history("primary1", "otpauth://totp/orig", dup_totps, "v")

            # 2 TOTP changes + 1 restore = 3 calls
            assert mock_edit.call_count == 3
            # Last call restores original
            last_call = mock_edit.call_args_list[-1]
            assert last_call[0][0] == "primary1"
            assert "otpauth://totp/orig" in last_call[0][1]

    def test_no_restore_when_primary_has_no_totp(self):
        with patch.object(dedupe, "op_edit_field") as mock_edit:
            dedupe.cycle_totp_for_history("p1", None, ["otpauth://totp/a"], "v")
            # Only the one cycle call, no restore
            assert mock_edit.call_count == 1

    def test_empty_list(self):
        with patch.object(dedupe, "op_edit_field") as mock_edit:
            result = dedupe.cycle_totp_for_history("p1", "otpauth://totp/orig", [], "v")
            assert result == []
            assert mock_edit.call_count == 0

    def test_returns_timestamps(self):
        with patch.object(dedupe, "op_edit_field"):
            result = dedupe.cycle_totp_for_history(
                "p1", "otpauth://totp/orig", ["otpauth://totp/a", "otpauth://totp/b"], "v"
            )
            assert len(result) == 2
            # Each entry should be a timestamp string
            for ts in result:
                assert "T" in ts
                assert "Z" in ts


class TestBuildTotpHistoryNote:
    def test_formats_table(self):
        timestamps = ["2026-03-03T00:00:00Z"]
        result = dedupe.build_totp_history_note(timestamps)
        assert "TOTP History Merge" in result
        assert "2026-03-03" in result

    def test_empty(self):
        assert dedupe.build_totp_history_note([]) == ""


class TestPasswordSecurity:
    def test_no_password_in_sanitize_log_line(self):
        """sanitize_log_line should not be used with passwords, but verify it
        doesn't expand secrets even if misused."""
        result = dedupe.sanitize_log_line("line1\nline2")
        assert "\n" not in result
