#!/usr/bin/env python3
"""Securely clear the 1Password tools disk cache.

Zeroizes all cached item files (overwriting with null bytes and fsyncing)
before deleting them, then removes the cache directory and cleans up the
config file.

Usage
-----
::

    python 1password_clear_cache.py
"""

from __future__ import annotations

from op_cache import clear_cache


def main() -> int:
    """Entry point for the cache-clearing script."""
    clear_cache()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
