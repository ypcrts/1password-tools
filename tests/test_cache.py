"""Tests for the op_cache module."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import op_cache


class TestParseConcatenatedJson:
    def test_single_object(self):
        result = op_cache.parse_concatenated_json('{"id": "a"}')
        assert result == [{"id": "a"}]

    def test_multiple_objects(self):
        text = '{"id": "a"}\n{"id": "b"}\n{"id": "c"}'
        result = op_cache.parse_concatenated_json(text)
        assert len(result) == 3
        assert result[0]["id"] == "a"
        assert result[1]["id"] == "b"
        assert result[2]["id"] == "c"

    def test_empty_string(self):
        result = op_cache.parse_concatenated_json("")
        assert result == []

    def test_whitespace_between_objects(self):
        text = '  {"id": "x"}  \n\n  {"id": "y"}  '
        result = op_cache.parse_concatenated_json(text)
        assert len(result) == 2
        assert result[0]["id"] == "x"
        assert result[1]["id"] == "y"


class TestCacheFilename:
    def test_deterministic(self):
        name1 = op_cache._cache_filename("MyVault")
        name2 = op_cache._cache_filename("MyVault")
        assert name1 == name2

    def test_safe_characters(self):
        name = op_cache._cache_filename("My Vault / Special")
        assert name.startswith("items-")
        assert name.endswith(".json")
        # Only hex chars in the hash portion
        hash_part = name[len("items-") : -len(".json")]
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_vault_none_handled(self):
        name = op_cache._cache_filename(None)
        assert name.startswith("items-")
        assert name.endswith(".json")

    def test_different_vaults_differ(self):
        name1 = op_cache._cache_filename("Vault1")
        name2 = op_cache._cache_filename("Vault2")
        assert name1 != name2


class TestEnsureCacheDir:
    def test_creates_dir_with_0o700(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        # Patch uuid to get a predictable directory name
        fake_uuid = type("U", (), {"hex": "abcdef123456" + "0" * 20})()
        monkeypatch.setattr(op_cache.uuid, "uuid4", lambda: fake_uuid)

        # Patch to create under tmp_path instead of /tmp
        original_mkdir = os.mkdir

        def patched_mkdir(path, mode):
            # Redirect /tmp paths to tmp_path
            if path.startswith("/tmp/1password-cache-"):
                path = str(tmp_path / Path(path).name)
            original_mkdir(path, mode)

        monkeypatch.setattr(os, "mkdir", patched_mkdir)
        monkeypatch.setattr(
            op_cache,
            "ensure_cache_dir",
            lambda: _ensure_cache_dir_in_tmp(tmp_path, config_path),
        )

        cache_dir = _ensure_cache_dir_in_tmp(tmp_path, config_path)
        assert cache_dir.is_dir()
        assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700

    def test_reuses_existing(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        cache_dir = tmp_path / "existing-cache"
        cache_dir.mkdir(mode=0o700)
        config_path.write_text(json.dumps({"cache_dir": str(cache_dir)}))

        result = op_cache.ensure_cache_dir()
        assert result == cache_dir

    def test_saves_to_config(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        cache_dir = tmp_path / "existing-cache"
        cache_dir.mkdir(mode=0o700)
        config_path.write_text(json.dumps({"cache_dir": str(cache_dir)}))

        op_cache.ensure_cache_dir()
        config = json.loads(config_path.read_text())
        assert "cache_dir" in config


class TestCacheReadWrite:
    def test_roundtrip(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(mode=0o700)
        config_path.write_text(json.dumps({"cache_dir": str(cache_dir)}))

        data = '{"id": "abc"}\n{"id": "def"}'
        op_cache.save_cache("testvault", data)
        result = op_cache.load_cache("testvault")
        assert result == data

    def test_file_perms_0o600(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(mode=0o700)
        config_path.write_text(json.dumps({"cache_dir": str(cache_dir)}))

        op_cache.save_cache("testvault", "test data")

        cache_file = cache_dir / op_cache._cache_filename("testvault")
        mode = stat.S_IMODE(cache_file.stat().st_mode)
        assert mode == 0o600

    def test_returns_none_when_missing(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(mode=0o700)
        config_path.write_text(json.dumps({"cache_dir": str(cache_dir)}))

        result = op_cache.load_cache("nonexistent-vault")
        assert result is None

    def test_returns_none_when_no_config(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)
        # No config file exists
        result = op_cache.load_cache("vault")
        assert result is None


class TestZeroizeFile:
    def test_overwrites_with_zeros_then_deletes(self, tmp_path):
        f = tmp_path / "secret.json"
        f.write_text("super secret password data")
        original_size = f.stat().st_size

        # Patch unlink to check content before deletion
        content_before_delete = []
        original_unlink = Path.unlink

        def capturing_unlink(self_path, *a, **kw):
            content_before_delete.append(self_path.read_bytes())
            original_unlink(self_path, *a, **kw)

        with patch.object(Path, "unlink", capturing_unlink):
            op_cache.zeroize_file(f)

        assert not f.exists()
        assert len(content_before_delete) == 1
        assert content_before_delete[0] == b"\x00" * original_size

    def test_file_gone_after(self, tmp_path):
        f = tmp_path / "to_delete.json"
        f.write_text("data")
        op_cache.zeroize_file(f)
        assert not f.exists()

    def test_missing_file_is_noop(self, tmp_path):
        f = tmp_path / "nonexistent.json"
        op_cache.zeroize_file(f)  # Should not raise


class TestClearCache:
    def test_clears_all_files_and_removes_dir(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(mode=0o700)
        (cache_dir / "items-abc123.json").write_text("secret1")
        (cache_dir / "items-def456.json").write_text("secret2")
        config_path.write_text(json.dumps({"cache_dir": str(cache_dir)}))

        op_cache.clear_cache()

        assert not cache_dir.exists()
        config = json.loads(config_path.read_text())
        assert "cache_dir" not in config

    def test_no_config_prints_message(self, tmp_path, monkeypatch, capsys):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)

        op_cache.clear_cache()
        captured = capsys.readouterr()
        assert "Nothing to clear" in captured.out

    def test_missing_dir_cleans_config(self, tmp_path, monkeypatch, capsys):
        config_path = tmp_path / "config.json"
        monkeypatch.setattr(op_cache, "CONFIG_PATH", config_path)
        config_path.write_text(json.dumps({"cache_dir": "/tmp/nonexistent-dir-12345"}))

        op_cache.clear_cache()
        config = json.loads(config_path.read_text())
        assert "cache_dir" not in config
        captured = capsys.readouterr()
        assert "Cleaning config" in captured.out


# ---------------------------------------------------------------------------
# Helper for TestEnsureCacheDir that avoids touching real /tmp
# ---------------------------------------------------------------------------


def _ensure_cache_dir_in_tmp(tmp_path: Path, config_path: Path) -> Path:
    """Version of ensure_cache_dir that creates under *tmp_path*."""
    config = op_cache._read_config()
    cache_dir_str = config.get("cache_dir")

    if cache_dir_str:
        cache_dir = Path(cache_dir_str)
        if cache_dir.is_dir():
            return cache_dir

    cache_dir = tmp_path / "1password-cache-test"
    os.mkdir(str(cache_dir), 0o700)

    config["cache_dir"] = str(cache_dir)
    op_cache._write_config(config)
    return cache_dir
