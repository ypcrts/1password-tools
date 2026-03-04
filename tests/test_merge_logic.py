"""Tests for notes merge, primary selection, and conflict detection."""

from __future__ import annotations

import importlib

from tests.conftest import make_login_item

dedupe = importlib.import_module("1password_dedupe")


class TestMergeNotes:
    def test_append(self):
        result = dedupe.merge_notes("Primary notes", "Dup notes", "DupTitle", "dup1")
        assert "Primary notes" in result
        assert "Dup notes" in result
        assert "(id=dup1)" in result

    def test_empty_dup_notes(self):
        result = dedupe.merge_notes("Primary notes", "", "DupTitle", "dup1")
        assert result == "Primary notes"

    def test_empty_dup_notes_whitespace(self):
        result = dedupe.merge_notes("Primary notes", "   ", "DupTitle", "dup1")
        assert result == "Primary notes"

    def test_idempotent(self):
        first = dedupe.merge_notes("Primary", "Dup content", "DupTitle", "dup1")
        second = dedupe.merge_notes(first, "Dup content", "DupTitle", "dup1")
        assert first == second

    def test_preserves_primary(self):
        result = dedupe.merge_notes("Important primary notes", "Extra", "D", "d1")
        assert result.startswith("Important primary notes")


class TestChoosePrimary:
    def test_highest_field_score(self):
        c1 = dedupe.Candidate("id1", "A", "d.com", "u", "2025-01-01", 3, True, False)
        c2 = dedupe.Candidate("id2", "B", "d.com", "u", "2025-01-01", 5, True, False)
        assert dedupe.choose_primary([c1, c2]).item_id == "id2"

    def test_tiebreak_on_updated_at(self):
        c1 = dedupe.Candidate("id1", "A", "d.com", "u", "2025-06-01", 3, True, False)
        c2 = dedupe.Candidate("id2", "B", "d.com", "u", "2025-01-01", 3, True, False)
        assert dedupe.choose_primary([c1, c2]).item_id == "id1"

    def test_single_candidate(self):
        c1 = dedupe.Candidate("id1", "A", "d.com", "u", "2025-01-01", 3, True, False)
        assert dedupe.choose_primary([c1]).item_id == "id1"


class TestConflictDetection:
    def test_both_have_password(self):
        item = make_login_item(password="pw1")
        assert dedupe.get_password_fingerprint(item) == "present"

    def test_only_one_has_password(self):
        item = make_login_item(password=None)
        assert dedupe.get_password_fingerprint(item) is None

    def test_no_password(self):
        item = make_login_item(password=None)
        assert dedupe.get_password_fingerprint(item) is None

    def test_totp_present(self):
        item = make_login_item(totp="otpauth://totp/example")
        assert dedupe.get_totp_present(item) is True

    def test_totp_absent(self):
        item = make_login_item(totp=None)
        assert dedupe.get_totp_present(item) is False

    def test_totp_empty_string(self):
        item = make_login_item(totp="")
        assert dedupe.get_totp_present(item) is False
