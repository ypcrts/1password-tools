#!/usr/bin/env python3
"""Fill empty usernames from Email fields.

Finds items (optionally filtered by ``--tag``) where the username field is
empty but an ``Email`` field exists, and copies the Email value into the
username.

Safety properties
-----------------
- **DRY-RUN by default.**  No mutations unless ``--apply`` is passed.
- **Never prints secrets.**

Usage
-----
::

    # Dry-run — see what would be updated
    python 1password_fill_username_from_email.py --vault MyVault

    # Filter by tag
    python 1password_fill_username_from_email.py --vault MyVault --tag "Imported"

    # Apply changes
    python 1password_fill_username_from_email.py --vault MyVault --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
from typing import Any

from rich.logging import RichHandler
from rich.progress import Progress

from op_cache import load_cache, parse_concatenated_json, save_cache

LOG = logging.getLogger("op-fill-username")


def run_op(
    args: list[str],
    *,
    stdin_data: str | None = None,
) -> str:
    """Run an ``op`` CLI command and return its stdout."""
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


def get_username(item: dict[str, Any]) -> str | None:
    """Return the username value, or ``None`` if empty/absent."""
    for f in item.get("fields", []) or []:
        if f.get("id") == "username" and f.get("type") == "STRING":
            v = f.get("value")
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def get_email_field(item: dict[str, Any]) -> str | None:
    """Return the value of the ``Email`` field, or ``None`` if empty/absent."""
    for f in item.get("fields", []) or []:
        if (f.get("label") or "").lower() == "email":
            v = f.get("value")
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def main() -> int:
    """Entry point."""
    ap = argparse.ArgumentParser(
        description="Fill empty usernames from Email fields.",
    )
    ap.add_argument("--vault", help="Vault name or UUID to scope operations.")
    ap.add_argument("--tag", help="Only process items with this tag (omit for all items).")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes (default: dry-run).",
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

    with Progress() as progress:
        # ── Phase 1: List items ───────────────────────────────────────
        list_task = progress.add_task("Listing items\u2026", total=None)
        list_args = ["item", "list", "--format", "json"]
        if args.tag:
            list_args += ["--tags", args.tag]
        if args.vault:
            list_args += ["--vault", args.vault]
        summaries_json = run_op(list_args)
        summaries = json.loads(summaries_json)
        progress.update(list_task, total=1, completed=1)

        if not summaries:
            LOG.info("No items found%s.", f" with tag {args.tag!r}" if args.tag else "")
            return 0

        # ── Phase 2: Fetch full details (with optional disk cache) ────
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

        all_items = parse_concatenated_json(raw)
        all_items_by_id = {item["id"]: item for item in all_items}

        # Filter to items that still exist in the listing
        live_ids = {s["id"] for s in summaries}
        items = [all_items_by_id[iid] for iid in live_ids if iid in all_items_by_id]
        n = len(items)
        stale = len(all_items_by_id) - len(live_ids & set(all_items_by_id))
        desc = f"Loaded {n} items from {source}"
        if stale:
            desc += f" ({stale} stale items skipped)"
        progress.update(fetch_task, description=desc, total=1, completed=1)

    # ── Phase 3: Find items needing username fill ─────────────────
    to_fix: list[tuple[dict[str, Any], str]] = []  # (item, email)
    for item in items:
        username = get_username(item)
        if username:
            continue
        email = get_email_field(item)
        if not email:
            continue
        to_fix.append((item, email))

    LOG.info(
        "Found %d item(s) with empty username and non-empty Email (out of %d).",
        len(to_fix),
        len(items),
    )

    # ── Phase 4: Apply ────────────────────────────────────────────
    errors: list[tuple[str, Exception]] = []
    if to_fix:
        with Progress() as progress:
            fix_task = progress.add_task("Updating usernames\u2026", total=len(to_fix))
            for item, email in to_fix:
                item_id = item["id"]
                title = (item.get("title") or "(untitled)").replace("\n", "\\n")
                if args.apply:
                    LOG.info("FIX: %s (id=%s) username=%s", title, item_id, email)
                    try:
                        edit_args = ["item", "edit", item_id, f"username={email}"]
                        if args.vault:
                            edit_args += ["--vault", args.vault]
                        run_op(edit_args)
                    except Exception as exc:  # noqa: BLE001
                        errors.append((f"{title} (id={item_id})", exc))
                        LOG.warning("  ERROR: %s", exc)
                else:
                    LOG.info("DRY-RUN would fix: %s (id=%s) username=%s", title, item_id, email)
                progress.advance(fix_task)

    if errors:
        LOG.error("Finished with %d error(s):", len(errors))
        for ctx, exc in errors:
            LOG.error("  [%s] %s: %s", type(exc).__name__, ctx, exc)

    LOG.info(
        "Done. %s %d item(s).",
        "Updated" if args.apply else "Would update",
        len(to_fix) - len(errors),
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
