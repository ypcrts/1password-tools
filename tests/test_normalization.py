"""Tests for domain normalization, username extraction, URL/tag helpers."""

from __future__ import annotations

import importlib

dedupe = importlib.import_module("1password_dedupe")


class TestNormalizeDomain:
    def test_basic_url(self):
        urls = [{"href": "https://example.com/login"}]
        assert dedupe.normalize_domain_from_urls(urls) == "example.com"

    def test_www_stripped(self):
        urls = [{"href": "https://www.example.com/login"}]
        assert dedupe.normalize_domain_from_urls(urls) == "example.com"

    def test_other_subdomain_preserved(self):
        urls = [{"href": "https://login.example.com"}]
        assert dedupe.normalize_domain_from_urls(urls) == "login.example.com"

    def test_country_tld(self):
        urls = [{"href": "https://www.example.co.uk/path"}]
        assert dedupe.normalize_domain_from_urls(urls) == "example.co.uk"

    def test_no_urls(self):
        assert dedupe.normalize_domain_from_urls([]) is None
        assert dedupe.normalize_domain_from_urls(None) is None

    def test_invalid_url(self):
        urls = [{"href": "not-a-url"}]
        # tldextract may still extract something or return empty
        result = dedupe.normalize_domain_from_urls(urls)
        # Either None or a valid domain is acceptable
        assert result is None or isinstance(result, str)

    def test_multiple_urls_returns_first(self):
        urls = [
            {"href": "https://login.example.com"},
            {"href": "https://www.example.com/path"},
        ]
        assert dedupe.normalize_domain_from_urls(urls) == "login.example.com"

    def test_empty_href(self):
        urls = [{"href": ""}, {}]
        assert dedupe.normalize_domain_from_urls(urls) is None


class TestGetLoginUsername:
    def test_by_id(self):
        item = {"fields": [{"id": "username", "type": "STRING", "value": "alice"}]}
        assert dedupe.get_login_username(item) == "alice"

    def test_by_label(self):
        item = {"fields": [{"id": "other", "type": "STRING", "label": "Username", "value": "bob"}]}
        assert dedupe.get_login_username(item) == "bob"

    def test_missing(self):
        item = {"fields": []}
        assert dedupe.get_login_username(item) is None

    def test_empty_value(self):
        item = {"fields": [{"id": "username", "type": "STRING", "value": "   "}]}
        assert dedupe.get_login_username(item) is None

    def test_no_fields_key(self):
        item = {}
        assert dedupe.get_login_username(item) is None


class TestUnionUrls:
    def test_dedup(self):
        a = [{"href": "https://a.com"}, {"href": "https://b.com"}]
        b = [{"href": "https://b.com"}, {"href": "https://c.com"}]
        result = dedupe.union_urls(a, b)
        hrefs = [u["href"] for u in result]
        assert hrefs == ["https://a.com", "https://b.com", "https://c.com"]

    def test_empty(self):
        assert dedupe.union_urls([], []) == []
        assert dedupe.union_urls(None, None) == []

    def test_order_preserved(self):
        a = [{"href": "https://z.com"}, {"href": "https://a.com"}]
        result = dedupe.union_urls(a, [])
        assert [u["href"] for u in result] == ["https://z.com", "https://a.com"]


class TestUnionTags:
    def test_dedup(self):
        assert dedupe.union_tags(["a", "b"], ["b", "c"]) == ["a", "b", "c"]

    def test_whitespace_trim(self):
        assert dedupe.union_tags([" a ", "b"], ["  b  "]) == ["a", "b"]

    def test_empty(self):
        assert dedupe.union_tags([], []) == []
        assert dedupe.union_tags(None, None) == []

    def test_sorted_output(self):
        result = dedupe.union_tags(["z", "a", "m"], [])
        assert result == ["a", "m", "z"]
