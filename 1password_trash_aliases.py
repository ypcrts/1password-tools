#!/usr/bin/env python3
"""Trash Proton Mail alias items from 1Password.

Proton Mail creates ``proton_type=alias`` Login items in 1Password for email
aliases.  These often clutter the vault and are not useful as standalone
credentials.  This tool finds and trashes them.

Safety properties
-----------------
- **DRY-RUN by default.**  No mutations unless ``--apply`` is passed.
- **Never prints secrets** (passwords, TOTP seeds).

Disk cache (opt-in)
-------------------
Pass ``--dangerously-use-disk-cache`` to cache fetched item details to
``/tmp``.  This avoids re-fetching when iterating on dry-runs with large
vaults.  **The cache contains secrets.**  Run ``python 1password_clear_cache.py``
to securely clean up.

Requirements
------------
- Python 3.9+
- 1Password CLI v2 installed and signed in: ``op signin``

Usage
-----
::

    # Dry-run — see which items would be trashed
    python 1password_trash_aliases.py --vault MyVault

    # Actually trash them
    python 1password_trash_aliases.py --vault MyVault --apply

    # Use disk cache for faster dry-run iteration (DANGEROUS: caches secrets)
    python 1password_trash_aliases.py --vault MyVault --dangerously-use-disk-cache
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, TypedDict

from rich.logging import RichHandler
from rich.progress import Progress, TaskID

from op_cache import load_cache, parse_concatenated_json, save_cache

LOG = logging.getLogger("op-trash-aliases")


# ---------------------------------------------------------------------------
# TypedDict definitions (minimal subset needed for this script)
# ---------------------------------------------------------------------------


class OpField(TypedDict, total=False):
    """A single field on a 1Password item."""

    id: str
    type: str
    label: str
    value: str
    section: dict[str, Any]


class OpVaultRef(TypedDict, total=False):
    """Reference to a vault in item JSON."""

    id: str
    name: str


class OpItemDetail(TypedDict, total=False):
    """Shape returned by ``op item get``."""

    id: str
    title: str
    category: str
    vault: OpVaultRef
    fields: list[OpField]


# ---------------------------------------------------------------------------
# op CLI helpers (duplicated from 1password_dedupe.py for standalone use)
# ---------------------------------------------------------------------------


def run_op(
    args: list[str],
    *,
    stdin_data: str | None = None,
) -> str:
    """Run an ``op`` CLI command and return its stdout.

    Parameters
    ----------
    args:
        Arguments to pass after the ``op`` binary.
    stdin_data:
        If provided, piped to the process on stdin.

    Raises
    ------
    SystemExit
        On missing ``op`` binary or non-zero exit.

    """
    cmd = ["op", *args]
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            check=True,
            capture_output=True,
            text=True,
        )
        return proc.stdout
    except FileNotFoundError:
        raise SystemExit(
            "ERROR: `op` not found. Install 1Password CLI v2 and ensure it is on PATH."
        )
    except subprocess.CalledProcessError as exc:
        msg = exc.stderr.strip() or exc.stdout.strip()
        raise SystemExit(f"ERROR running `{' '.join(cmd)}`: {msg}")


def op_delete_item(item_id: str, vault: str | None) -> None:
    """Trash (archive) an item by *item_id*."""
    args = ["item", "delete", item_id]
    if vault:
        args += ["--vault", vault]
    run_op(args)


# ---------------------------------------------------------------------------
# Concurrent op CLI helpers
# ---------------------------------------------------------------------------


def delete_items_concurrent(
    item_ids: list[str],
    vault: str | None,
    max_workers: int,
    progress: Progress,
    task_id: TaskID,
) -> None:
    """Delete (trash) items concurrently."""
    if not item_ids:
        return

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_id = {pool.submit(op_delete_item, iid, vault): iid for iid in item_ids}
        for future in as_completed(future_to_id):
            future.result()
            progress.advance(task_id)


# ---------------------------------------------------------------------------
# Alias detection
# ---------------------------------------------------------------------------


def is_proton_alias(item: OpItemDetail) -> bool:
    """Return ``True`` if *item* has a custom field ``proton_type=alias``.

    The check is case-insensitive on both label and value.
    """
    for f in item.get("fields", []) or []:
        label = (f.get("label") or "").lower()
        value = (f.get("value") or "").lower()
        if label == "proton_type" and value == "alias":
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point for the alias-trashing CLI.

    Returns ``0`` on success; raises ``SystemExit`` on fatal errors.
    """
    ap = argparse.ArgumentParser(
        description="Trash Proton Mail alias items from 1Password.",
    )
    ap.add_argument("--vault", help="Vault name or UUID to scope operations.")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Actually trash alias items (default: dry-run).",
    )
    ap.add_argument(
        "--max-workers",
        type=int,
        default=max((os.cpu_count() or 4) // 2, 2),
        help="Max concurrent op CLI calls (default: CPU count).",
    )
    ap.add_argument(
        "--dangerously-use-disk-cache",
        action="store_true",
        help="Cache fetched item details to /tmp (DANGEROUS: contains secrets).",
    )
    ap.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = ap.parse_args()

    log_level = getattr(logging, args.log_level)
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )

    max_workers = args.max_workers

    # ── Phase A: List items ──────────────────────────────────────────
    with Progress() as progress:
        list_task = progress.add_task("Listing login items\u2026", total=None)
        list_args = ["item", "list", "--format", "json"]
        if args.vault:
            list_args += ["--vault", args.vault]
        list_args += ["--categories", "login"]
        summaries_json = run_op(list_args)
        progress.update(list_task, total=1, completed=1)

        # ── Phase B: Fetch all details (with optional disk cache) ────
        fetch_task = progress.add_task("Fetching item details\u2026", total=None)

        use_cache = args.dangerously_use_disk_cache
        raw = load_cache(args.vault) if use_cache else None
        if raw is not None:
            source = "cache"
        else:
            op_args = ["item", "get", "--format", "json", "-"]
            if args.vault:
                op_args += ["--vault", args.vault]
            raw = run_op(op_args, stdin_data=summaries_json)
            if use_cache:
                save_cache(args.vault, raw)
            source = "op"

        item_cache_list = parse_concatenated_json(raw)
        item_cache = {item["id"]: item for item in item_cache_list}

        # Filter to items that still exist (cache may contain deleted/merged items)
        live_ids = {s["id"] for s in json.loads(summaries_json)}
        stale = len(item_cache) - len(live_ids & set(item_cache))
        item_cache = {iid: v for iid, v in item_cache.items() if iid in live_ids}
        n = len(item_cache)
        desc = f"Loaded {n} items from {source}"
        if stale:
            desc += f" ({stale} stale items skipped)"
        progress.update(fetch_task, description=desc, total=1, completed=1)

    # ── Phase C: Filter for aliases (in-memory) ─────────────────────
    alias_ids: list[str] = []
    for item_id, item in item_cache.items():
        if not is_proton_alias(item):
            continue
        title = (item.get("title") or "(untitled)").replace("\n", "\\n")
        if args.apply:
            LOG.info("TRASH: %s (id=%s)", title, item_id)
        else:
            LOG.info("DRY-RUN would trash: %s (id=%s)", title, item_id)
        alias_ids.append(item_id)

    # ── Phase D: Delete aliases concurrently ─────────────────────────
    if args.apply and alias_ids:
        with Progress() as progress:
            del_task = progress.add_task("Deleting aliases\u2026", total=len(alias_ids))
            delete_items_concurrent(alias_ids, args.vault, max_workers, progress, del_task)

    LOG.info(
        "Done. %s %d alias item(s).",
        "Trashed" if args.apply else "Would trash",
        len(alias_ids),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
