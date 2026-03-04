"""Shared on-disk cache for 1Password item JSON.

The cache is **opt-in** via ``--dangerously-use-disk-cache`` on the CLI tools.
It stores full item JSON (including passwords and TOTP seeds) under ``/tmp``
in a directory with restrictive permissions.

**Why dangerous**: cached files contain secrets.  ``/tmp`` may persist across
reboots on some systems, and SSD wear-leveling can retain data even after
zeroizing.  Use ``1password_clear_cache.py`` to securely clean up.

Public API
----------
- ``parse_concatenated_json(text)`` — parse ``op`` concatenated JSON output
- ``ensure_cache_dir()`` — create/reuse cache directory, return its ``Path``
- ``load_cache(vault)`` — return cached raw string or ``None``
- ``save_cache(vault, raw_data)`` — write raw string to cache file
- ``zeroize_file(path)`` — overwrite with zeros, fsync, then delete
- ``clear_cache()`` — zeroize all cached files, remove dir, clean config
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from pathlib import Path

LOG = logging.getLogger("op-cache")

CONFIG_PATH = Path.home() / ".config" / "1password-tools-config.json"


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _read_config() -> dict:
    """Read the JSON config file, returning ``{}`` if missing or invalid."""
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _write_config(config: dict) -> None:
    """Write *config* as JSON to ``CONFIG_PATH`` with mode ``0o600``."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(CONFIG_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
    except BaseException:
        # fd is closed by os.fdopen even on error
        raise


def _cache_filename(vault: str | None) -> str:
    """Return a deterministic cache filename for *vault*."""
    key = vault or "__all__"
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    return f"items-{digest}.json"


def _state_dir() -> Path:
    """Return (and create) the directory for run-state files.

    State files don't contain secrets (only item IDs, domains, usernames,
    and error messages), so they live under ``~/.cache/1password-tools/``
    rather than the dangerous ``/tmp`` cache.
    """
    d = Path.home() / ".cache" / "1password-tools"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _vault_hash(vault: str | None) -> str:
    key = vault or "__all__"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# JSON parsing (moved from both scripts to deduplicate)
# ---------------------------------------------------------------------------


def parse_concatenated_json(text: str) -> list[dict]:
    """Parse concatenated JSON objects from *text* into a list.

    The ``op`` CLI outputs concatenated JSON objects (not a JSON array)
    when fetching multiple items via stdin pipe.  This function handles
    that format using ``json.JSONDecoder.raw_decode``.
    """
    decoder = json.JSONDecoder()
    results: list[dict] = []
    idx = 0
    text = text.strip()
    while idx < len(text):
        obj, end = decoder.raw_decode(text, idx)
        results.append(obj)
        # Skip whitespace between objects
        idx = end
        while idx < len(text) and text[idx] in " \t\n\r":
            idx += 1
    return results


# ---------------------------------------------------------------------------
# Cache directory management
# ---------------------------------------------------------------------------


def ensure_cache_dir() -> Path:
    """Return the cache directory path, creating it if necessary.

    On first call, creates ``/tmp/1password-cache-<uuid>`` with mode ``0o700``
    and saves the path to the config file.  Subsequent calls reuse the
    existing directory if it still exists.

    Logs a warning that ``/tmp`` may persist to disk on some systems.
    """
    config = _read_config()
    cache_dir_str = config.get("cache_dir")

    if cache_dir_str:
        cache_dir = Path(cache_dir_str)
        if cache_dir.is_dir():
            return cache_dir

    # Create a new cache directory
    short_uuid = uuid.uuid4().hex[:12]
    cache_dir = Path(f"/tmp/1password-cache-{short_uuid}")
    os.mkdir(str(cache_dir), 0o700)

    config["cache_dir"] = str(cache_dir)
    _write_config(config)

    LOG.warning(
        "Created cache directory: %s — WARNING: /tmp may persist to disk on some systems.",
        cache_dir,
    )
    return cache_dir


# ---------------------------------------------------------------------------
# Cache read/write
# ---------------------------------------------------------------------------


def load_cache(vault: str | None) -> str | None:
    """Return the raw cached string for *vault*, or ``None`` if not cached."""
    config = _read_config()
    cache_dir_str = config.get("cache_dir")
    if not cache_dir_str:
        return None
    cache_file = Path(cache_dir_str) / _cache_filename(vault)
    try:
        return cache_file.read_text()
    except (FileNotFoundError, OSError):
        return None


def save_cache(vault: str | None, raw_data: str) -> None:
    """Write *raw_data* to the cache file for *vault* with mode ``0o600``."""
    cache_dir = ensure_cache_dir()
    cache_file = cache_dir / _cache_filename(vault)
    fd = os.open(str(cache_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(raw_data)
    except BaseException:
        raise


# ---------------------------------------------------------------------------
# Secure cleanup
# ---------------------------------------------------------------------------


def zeroize_file(path: Path) -> None:
    """Overwrite *path* with zero bytes of the same size, fsync, then delete."""
    try:
        size = path.stat().st_size
    except (FileNotFoundError, OSError):
        return
    if size > 0:
        fd = os.open(str(path), os.O_WRONLY)
        try:
            os.write(fd, b"\x00" * size)
            os.fsync(fd)
        finally:
            os.close(fd)
    path.unlink()


def clear_cache() -> None:
    """Zeroize and delete all cached files, remove the directory, and clean config."""
    config = _read_config()
    cache_dir_str = config.get("cache_dir")
    if not cache_dir_str:
        print("No cache directory configured. Nothing to clear.")
        return

    cache_dir = Path(cache_dir_str)
    if not cache_dir.is_dir():
        print(f"Cache directory {cache_dir} does not exist. Cleaning config.")
        del config["cache_dir"]
        _write_config(config)
        return

    count = 0
    for child in cache_dir.iterdir():
        if child.is_file():
            zeroize_file(child)
            count += 1
            print(f"  Zeroized and deleted: {child.name}")

    try:
        cache_dir.rmdir()
    except OSError as exc:
        print(f"  Warning: could not remove directory {cache_dir}: {exc}")

    del config["cache_dir"]
    _write_config(config)
    print(f"Cleared {count} cached file(s). Cache directory removed.")


# ---------------------------------------------------------------------------
# Run-state persistence (no secrets — safe to store outside /tmp)
# ---------------------------------------------------------------------------


def load_run_state(vault: str | None) -> dict:
    """Load the run-state file for *vault*.

    Returns a dict with keys ``completed`` (list of ``[domain, username]``
    pairs) and ``failures`` (list of failure dicts).  Returns empty
    structures if no state file exists.
    """
    path = _state_dir() / f"dedupe-state-{_vault_hash(vault)}.json"
    try:
        data = json.loads(path.read_text())
        # Ensure expected keys
        data.setdefault("completed", [])
        data.setdefault("failures", [])
        return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"completed": [], "failures": []}


def save_run_state(vault: str | None, state: dict) -> Path:
    """Write *state* to the run-state file for *vault*.  Returns the path."""
    path = _state_dir() / f"dedupe-state-{_vault_hash(vault)}.json"
    path.write_text(json.dumps(state, indent=2) + "\n")
    return path


def clear_run_state(vault: str | None) -> None:
    """Delete the run-state file for *vault* if it exists."""
    path = _state_dir() / f"dedupe-state-{_vault_hash(vault)}.json"
    try:
        path.unlink()
    except FileNotFoundError:
        pass
