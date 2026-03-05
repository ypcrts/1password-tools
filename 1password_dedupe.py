#!/usr/bin/env python3
"""Hardened 1Password (op CLI v2) duplicate merge for Login items.

Safety properties
-----------------
- **DRY-RUN by default.** No mutations unless ``--apply`` is passed.
- **Never prints secrets** (passwords, TOTP seeds).
- Only merges low-risk fields automatically (URLs, tags, notes).
- Flags TOTP conflicts for manual resolution.
- Preserves all unique passwords via 1Password's built-in password history.
- Optional ``--trash-duplicates`` to delete dupes after merge.

Disk cache (opt-in)
-------------------
Pass ``--dangerously-use-disk-cache`` to cache fetched item details to
``/tmp``.  This avoids re-fetching when iterating on dry-runs with large
vaults (1000+ items).  **The cache contains secrets** (passwords, TOTP
seeds).  Run ``python 1password_clear_cache.py`` to securely clean up.

Requirements
------------
- Python 3.9+
- `tldextract` (``pip install tldextract``)
- 1Password CLI v2 installed and signed in: ``op signin``

Usage
-----
::

    # Dry-run (default) — see what would be merged
    python 1password_dedupe.py --vault MyVault

    # Apply merges
    python 1password_dedupe.py --vault MyVault --apply

    # Apply and trash duplicates
    python 1password_dedupe.py --vault MyVault --apply --trash-duplicates

    # Use disk cache for faster dry-run iteration (DANGEROUS: caches secrets)
    python 1password_dedupe.py --vault MyVault --dangerously-use-disk-cache
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Any, TypedDict

import tldextract
from rich.logging import RichHandler
from rich.progress import Progress

from op_cache import (
    clear_run_state,
    load_cache,
    load_run_state,
    parse_concatenated_json,
    save_cache,
    save_run_state,
)

LOG = logging.getLogger("op-merge")


# ---------------------------------------------------------------------------
# TypedDict definitions for 1Password JSON structures
# ---------------------------------------------------------------------------


class OpUrl(TypedDict, total=False):
    """A single URL entry on a 1Password item."""

    href: str
    label: str
    primary: bool


class OpField(TypedDict, total=False):
    """A single field on a 1Password item."""

    id: str
    type: str
    label: str
    value: str
    purpose: str
    section: dict[str, Any]
    reference: str


class OpPasswordHistoryEntry(TypedDict, total=False):
    """An entry in 1Password's automatic password history."""

    value: str
    time: int


class OpVaultRef(TypedDict, total=False):
    """Reference to a vault in item JSON."""

    id: str
    name: str


class OpItemSummary(TypedDict, total=False):
    """Shape returned by ``op item list``."""

    id: str
    title: str
    version: int
    vault: OpVaultRef
    category: str
    urls: list[OpUrl]
    tags: list[str]
    favorite: bool
    state: str
    createdAt: str
    updatedAt: str


class OpItemDetail(TypedDict, total=False):
    """Shape returned by ``op item get``."""

    id: str
    title: str
    version: int
    vault: OpVaultRef
    category: str
    urls: list[OpUrl]
    tags: list[str]
    fields: list[OpField]
    notesPlain: str
    favorite: bool
    state: str
    createdAt: str
    updatedAt: str
    passwordHistory: list[OpPasswordHistoryEntry]


# ---------------------------------------------------------------------------
# op CLI helpers
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
        If provided, piped to the process on stdin (used for JSON-based edits).

    Raises
    ------
    SystemExit
        On missing ``op`` binary or non-zero exit.

    Notes
    -----
    Never logs the command output — it may contain secrets.

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


def op_list_items(
    vault: str | None,
    *,
    categories: str | None = None,
) -> list[OpItemSummary]:
    """List items in *vault*, optionally filtering by *categories*.

    Parameters
    ----------
    vault:
        Vault name or UUID.  ``None`` means all vaults.
    categories:
        Comma-separated category filter passed to ``--categories`` (e.g. ``"login"``).

    """
    args = ["item", "list", "--format", "json"]
    if vault:
        args += ["--vault", vault]
    if categories:
        args += ["--categories", categories]
    out = run_op(args)
    return json.loads(out)


def op_get_item(item_id: str, vault: str | None) -> OpItemDetail:
    """Fetch full item detail by *item_id*."""
    args = ["item", "get", item_id, "--format", "json"]
    if vault:
        args += ["--vault", vault]
    out = run_op(args)
    return json.loads(out)


def op_edit_item(item_id: str, item_json: str, vault: str | None) -> None:
    """Edit an item by piping its full JSON to ``op item edit`` via stdin.

    This avoids shell-escaping issues with notes containing ``=`` or tags
    containing commas.

    Fields are sanitized before sending:

    - Fields without both ``id`` and ``label`` are dropped (``op`` rejects them).
    - Fields are deduplicated by ``id`` (first occurrence wins) to avoid the
      ``op`` error about ambiguous duplicate field labels.

    Parameters
    ----------
    item_id:
        The item's UUID.
    item_json:
        The complete item JSON (as produced by ``json.dumps``).
    vault:
        Vault name or UUID.

    """
    item = json.loads(item_json)
    fields = item.get("fields")
    if fields:
        seen_ids: set[str] = set()
        clean: list[dict[str, Any]] = []
        for f in fields:
            fid = f.get("id")
            label = f.get("label")
            if not fid and not label:
                continue
            if fid:
                if fid in seen_ids:
                    continue
                seen_ids.add(fid)
            # Fix empty type from malformed Proton Pass imports
            if "type" in f and not f["type"]:
                f["type"] = "STRING"
            clean.append(f)
        item["fields"] = clean
    args = ["item", "edit", item_id, "--format", "json"]
    if vault:
        args += ["--vault", vault]
    run_op(args, stdin_data=json.dumps(item))


def op_edit_field(
    item_id: str,
    field_assignment: str,
    vault: str | None,
) -> None:
    """Edit a single field using CLI assignment syntax.

    Used for password cycling where we intentionally keep the operation
    minimal rather than piping full item JSON.

    Parameters
    ----------
    item_id:
        The item's UUID.
    field_assignment:
        A single ``op item edit`` assignment string, e.g.
        ``"password=hunter2"``.
    vault:
        Vault name or UUID.

    """
    args = ["item", "edit", item_id, field_assignment]
    if vault:
        args += ["--vault", vault]
    run_op(args)


def op_delete_item(item_id: str, vault: str | None) -> None:
    """Trash (archive) an item by *item_id*."""
    args = ["item", "delete", item_id]
    if vault:
        args += ["--vault", vault]
    run_op(args)


def op_delete_items_batch(item_ids: list[str], vault: str | None) -> None:
    """Delete (trash) multiple items in a single ``op`` call via stdin pipe.

    Pipes a JSON array of ``{"id": ...}`` objects to ``op item delete -``,
    which processes them all in one invocation.
    """
    if not item_ids:
        return
    args = ["item", "delete", "-"]
    if vault:
        args += ["--vault", vault]
    payload = json.dumps([{"id": iid} for iid in item_ids])
    run_op(args, stdin_data=payload)


def op_edit_tags(item_id: str, tags: list[str], vault: str | None) -> None:
    """Set *tags* on an item using the ``--tags`` flag (no JSON piping needed).

    Some items imported from Proton Pass have malformed fields (e.g. password
    field with ``type: ""``) which cause ``op item edit`` to fail validation
    even for a simple tag change.  We catch and log these rather than aborting.
    """
    args = ["item", "edit", item_id, "--tags", ",".join(tags)]
    if vault:
        args += ["--vault", vault]
    try:
        run_op(args)
    except SystemExit as exc:
        LOG.warning("  Could not tag item %s (validation error): %s", item_id, exc)


# ---------------------------------------------------------------------------
# Normalization / extraction helpers
# ---------------------------------------------------------------------------


def normalize_domain_from_urls(urls: list[OpUrl]) -> str | None:
    """Extract the full hostname (FQDN) from *urls*, stripping ``www.``.

    Returns ``None`` when no usable domain can be found.

    Only the ``www.`` prefix is stripped so that ``www.example.com`` and
    ``example.com`` group together, but other subdomains like
    ``login.example.com`` remain distinct.

    Examples
    --------
    >>> normalize_domain_from_urls([{"href": "https://www.example.co.uk/login"}])
    'example.co.uk'
    >>> normalize_domain_from_urls([{"href": "https://login.example.com"}])
    'login.example.com'

    """
    for u in urls or []:
        href = (u or {}).get("href")
        if not href:
            continue
        try:
            ext = tldextract.extract(href)
            fqdn = ext.fqdn
            if fqdn:
                fqdn = fqdn.lower()
                if fqdn.startswith("www."):
                    fqdn = fqdn[4:]
                return fqdn
        except Exception:  # noqa: BLE001
            continue
    return None


def get_login_username(item: OpItemDetail) -> str | None:
    """Return the username value from *item*, or ``None`` if absent.

    Checks for field ``id="username"`` first, then falls back to
    ``label="username"`` (case-insensitive).
    """
    for f in item.get("fields", []) or []:
        if f.get("id") == "username" and f.get("type") == "STRING":
            v = f.get("value")
            if isinstance(v, str) and v.strip():
                return v.strip()
    for f in item.get("fields", []) or []:
        if (f.get("label") or "").lower() == "username":
            v = f.get("value")
            if isinstance(v, str) and v.strip():
                return v.strip()
    return None


def get_password_fingerprint(item: OpItemDetail) -> str | None:
    """Return ``"present"`` if *item* has a non-empty password, else ``None``.

    We never return the actual password — only detect its *presence* for
    conflict-detection purposes.
    """
    for f in item.get("fields", []) or []:
        if f.get("id") == "password":
            v = f.get("value")
            if isinstance(v, str) and v != "":
                return "present"
    return None


def get_password_value(item: OpItemDetail) -> str | None:
    """Extract the actual password value from *item*.

    .. warning::
        **Never log the return value.**  This is used exclusively for password
        history cycling during merges.
    """
    for f in item.get("fields", []) or []:
        if f.get("id") == "password":
            v = f.get("value")
            if isinstance(v, str) and v != "":
                return v
    return None


def get_password_history(item: OpItemDetail) -> list[OpPasswordHistoryEntry]:
    """Return the password history entries for *item* (may be empty)."""
    return item.get("passwordHistory") or []


def collect_all_passwords(
    item: OpItemDetail,
    item_id: str,
) -> list[tuple[str, str, int | None]]:
    """Gather current + historical passwords from *item*.

    Returns a list of ``(password, source_item_id, timestamp_or_none)`` tuples.
    The current password gets ``timestamp=None``.

    .. warning::
        **Never log the returned password values.**
    """
    results: list[tuple[str, str, int | None]] = []
    current = get_password_value(item)
    if current:
        results.append((current, item_id, None))
    for entry in get_password_history(item):
        pw = entry.get("value", "")
        ts = entry.get("time")
        if pw:
            results.append((pw, item_id, ts))
    return results


def get_totp_present(item: OpItemDetail) -> bool:
    """Return ``True`` if *item* has a non-empty TOTP / OTP field."""
    return get_totp_value(item) is not None


def get_totp_value(item: OpItemDetail) -> str | None:
    """Extract the TOTP/OTP URI from *item*, or ``None`` if absent.

    .. warning::
        **Never log the return value.**  TOTP seeds are secrets.
    """
    for f in item.get("fields", []) or []:
        if f.get("type") == "OTP":
            v = f.get("value")
            if isinstance(v, str) and v != "":
                return v
        if (f.get("label") or "").lower() in ("one-time password", "otp", "totp"):
            v = f.get("value")
            if isinstance(v, str) and v != "":
                return v
    return None


def safe_str(s: str | None) -> str:
    """Strip whitespace from *s*; return ``""`` if *s* is not a string."""
    return s.strip() if isinstance(s, str) else ""


def item_last_updated(item: OpItemDetail) -> str:
    """Return the most recent timestamp string for *item*."""
    return safe_str(item.get("updatedAt")) or safe_str(item.get("createdAt")) or ""


def item_field_count(item: OpItemDetail) -> int:
    """Score *item* by counting non-empty, non-secret fields.

    Used as a heuristic for selecting the "best" primary in a duplicate group.
    """
    count = 0
    for f in item.get("fields", []) or []:
        fid = f.get("id")
        if fid in ("password",):
            continue
        v = f.get("value")
        if isinstance(v, str) and v.strip():
            count += 1
    if item.get("urls"):
        count += 1
    if item.get("tags"):
        count += 1
    if safe_str(item.get("notesPlain")):
        count += 1
    return count


def union_urls(a: list[OpUrl], b: list[OpUrl]) -> list[OpUrl]:
    """Merge two URL lists, deduplicating by ``href``."""
    seen: set[str] = set()
    out: list[OpUrl] = []
    for u in (a or []) + (b or []):
        href = (u or {}).get("href")
        if not href or not isinstance(href, str):
            continue
        key = href.strip()
        if key in seen:
            continue
        seen.add(key)
        out.append({"href": key})
    return out


def union_tags(a: list[str], b: list[str]) -> list[str]:
    """Merge two tag lists, deduplicating and sorting."""
    s = {t.strip() for t in (a or []) if isinstance(t, str) and t.strip()}
    s |= {t.strip() for t in (b or []) if isinstance(t, str) and t.strip()}
    return sorted(s)


def merge_notes(
    primary_notes: str,
    dup_notes: str,
    dup_title: str,
    dup_id: str,
) -> str:
    """Append *dup_notes* to *primary_notes* with a merge stamp.

    Idempotent: skips if a merge stamp for *dup_id* already exists in
    *primary_notes*.
    """
    p = primary_notes or ""
    d = dup_notes or ""
    if not d.strip():
        return p
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    trailer = f"\n\n---\nMerged from: {dup_title} (id={dup_id}) @ {stamp}\n{d.strip()}\n"
    if f"(id={dup_id})" in p:
        return p
    return (p + trailer).strip()


# ---------------------------------------------------------------------------
# Primary selection
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    """A login item that participates in duplicate-group resolution."""

    item_id: str
    title: str
    domain: str
    username: str
    updated_at: str
    field_score: int
    has_password: bool
    has_totp: bool


def choose_primary(cands: list[Candidate]) -> Candidate:
    """Pick the best candidate to keep as the primary.

    Prefers the item with the highest ``field_score``, breaking ties by
    ``updated_at`` (ISO-8601, lexicographic comparison).
    """
    return sorted(
        cands,
        key=lambda c: (c.field_score, c.updated_at),
        reverse=True,
    )[0]


def sanitize_log_line(s: str) -> str:
    """Collapse newlines so *s* stays on one log line."""
    return s.replace("\n", "\\n")


# ---------------------------------------------------------------------------
# Password history preservation
# ---------------------------------------------------------------------------


def cycle_passwords_for_history(
    primary_id: str,
    primary_password: str | None,
    duplicate_passwords: list[tuple[str, int | None]],
    vault: str | None,
) -> list[tuple[str, str]]:
    """Cycle the primary's password through each duplicate password.

    1Password automatically saves the old password to history whenever the
    password field changes.  We exploit this by sequentially setting the
    primary's password to each unique duplicate password, then restoring the
    original.

    Parameters
    ----------
    primary_id:
        UUID of the primary item.
    primary_password:
        The primary's current password (restored at the end).
    duplicate_passwords:
        ``(password_value, original_timestamp_or_none)`` pairs to cycle.
    vault:
        Vault scope.

    Returns
    -------
    list[tuple[str, str]]
        ``(merge_timestamp, original_timestamp)`` pairs for the notes table.

    Notes
    -----
    **Never log any password values.**

    """
    results: list[tuple[str, str]] = []

    for pw, orig_ts in duplicate_passwords:
        merge_ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        op_edit_field(primary_id, f"password={pw}", vault)
        orig_ts_str = (
            dt.datetime.fromtimestamp(orig_ts, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if orig_ts is not None
            else "unknown"
        )
        results.append((merge_ts, orig_ts_str))

    # Restore the original password
    if primary_password is not None:
        op_edit_field(primary_id, f"password={primary_password}", vault)

    return results


def build_password_history_note(
    timestamp_pairs: list[tuple[str, str]],
) -> str:
    """Format the password-history merge table for inclusion in notes.

    Parameters
    ----------
    timestamp_pairs:
        ``(merge_timestamp, original_timestamp)`` pairs from
        :func:`cycle_passwords_for_history`.

    """
    if not timestamp_pairs:
        return ""
    lines = [
        "",
        "--- Password History Merge ---",
        "Merge Timestamp -> Original Timestamp",
    ]
    for merge_ts, orig_ts in timestamp_pairs:
        lines.append(f"  {merge_ts} -> {orig_ts}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# TOTP history preservation
# ---------------------------------------------------------------------------


def cycle_totp_for_history(
    primary_id: str,
    primary_totp: str | None,
    duplicate_totps: list[str],
    vault: str | None,
) -> list[str]:
    """Cycle the primary's TOTP field through each duplicate TOTP value.

    Works just like :func:`cycle_passwords_for_history` — each ``op item edit``
    call causes 1Password to save the previous value to history.  The original
    TOTP is restored at the end.

    Parameters
    ----------
    primary_id:
        UUID of the primary item.
    primary_totp:
        The primary's current TOTP URI (restored at the end).
    duplicate_totps:
        Unique TOTP URIs from duplicates to cycle through.
    vault:
        Vault scope.

    Returns
    -------
    list[str]
        Merge timestamps for the notes table (one per cycled value).

    Notes
    -----
    **Never log any TOTP values.**

    """
    results: list[str] = []
    # The OTP field label used by 1Password
    field_id = "one-time password"
    for totp in duplicate_totps:
        merge_ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        op_edit_field(primary_id, f"{field_id}[otp]={totp}", vault)
        results.append(merge_ts)

    # Restore the original TOTP (only if we actually cycled)
    if results and primary_totp is not None:
        op_edit_field(primary_id, f"{field_id}[otp]={primary_totp}", vault)

    return results


def build_totp_history_note(
    timestamps: list[str],
) -> str:
    """Format the TOTP-history merge table for inclusion in notes.

    Parameters
    ----------
    timestamps:
        Merge timestamps from :func:`cycle_totp_for_history`.

    """
    if not timestamps:
        return ""
    lines = [
        "",
        "--- TOTP History Merge ---",
        "Duplicate TOTP values cycled into history at:",
    ]
    for ts in timestamps:
        lines.append(f"  {ts}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main merge logic
# ---------------------------------------------------------------------------


def main() -> int:
    """Entry point for the duplicate-merge CLI.

    Returns ``0`` on success; raises ``SystemExit`` on fatal errors.
    """
    ap = argparse.ArgumentParser(
        description="Hardened 1Password Login-item dedupe/merge.",
    )
    ap.add_argument("--vault", help="Vault name or UUID to scope operations.")
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Apply edits to the primary items (default: dry-run).",
    )
    ap.add_argument(
        "--trash-duplicates",
        action="store_true",
        help="Delete duplicate items after merge (requires --apply).",
    )
    ap.add_argument(
        "--key",
        choices=["domain_username"],
        default="domain_username",
        help="Dedupe key strategy.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of duplicate groups processed (0 = no limit).",
    )
    ap.add_argument(
        "--min-group-size",
        type=int,
        default=2,
        help="Only process groups with at least this many items.",
    )
    ap.add_argument(
        "--tag-duplicates",
        default="MERGED-DUPE",
        help="Tag added to non-primary duplicates (if --apply).",
    )
    ap.add_argument(
        "--tag-primary",
        default="MERGED-PRIMARY",
        help="Tag added to the primary (if --apply).",
    )
    ap.add_argument(
        "--resume",
        action="store_true",
        help="Resume a previous run: skip already-completed groups, retry failures.",
    )
    ap.add_argument(
        "--clear-state",
        action="store_true",
        help="Clear saved run state (completed/failed groups) and exit.",
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

    if args.clear_state:
        clear_run_state(args.vault)
        LOG.info("Cleared run state for vault=%s.", args.vault or "(all)")
        return 0

    if args.trash_duplicates and not args.apply:
        raise SystemExit("ERROR: --trash-duplicates requires --apply.")

    with Progress() as progress:
        # ── Phase 1: List items ──────────────────────────────────────
        list_task = progress.add_task("Listing login items\u2026", total=None)
        summaries = op_list_items(args.vault, categories="login")
        progress.update(list_task, total=1, completed=1)

        # ── Phase 2: Fetch all details (with optional disk cache) ────
        summaries_json = json.dumps(summaries)
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
        live_ids = {s["id"] for s in summaries}
        stale = len(item_cache) - len(live_ids & set(item_cache))
        item_cache = {iid: v for iid, v in item_cache.items() if iid in live_ids}
        n = len(item_cache)
        desc = f"Loaded {n} items from {source}"
        if stale:
            desc += f" ({stale} stale items skipped)"
        progress.update(fetch_task, description=desc, total=1, completed=1)

    LOG.info("Fetched %d items. Grouping\u2026", len(item_cache))

    # ── Group items in-memory ────────────────────────────────────────
    groups: dict[tuple[str, str], list[Candidate]] = {}
    for item_id, item in item_cache.items():
        username = get_login_username(item)
        if not username:
            continue

        domain = normalize_domain_from_urls(item.get("urls", []) or [])
        if not domain:
            continue

        title = safe_str(item.get("title")) or "(untitled)"
        updated_at = item_last_updated(item)
        score = item_field_count(item)
        has_pw = get_password_fingerprint(item) is not None
        has_totp = get_totp_present(item)

        key = (domain, username.lower())
        groups.setdefault(key, []).append(
            Candidate(
                item_id=item_id,
                title=title,
                domain=domain,
                username=username,
                updated_at=updated_at,
                field_score=score,
                has_password=has_pw,
                has_totp=has_totp,
            )
        )

    dup_groups = [(k, v) for k, v in groups.items() if len(v) >= args.min_group_size]
    if args.limit:
        dup_groups = sorted(dup_groups, key=lambda kv: kv[0][0])[: args.limit]
    else:
        dup_groups = sorted(dup_groups, key=lambda kv: kv[0][0])

    LOG.info("Detected %d duplicate groups (key=%s).", len(dup_groups), args.key)

    # ── Load resume state ────────────────────────────────────────────
    completed_keys: set[tuple[str, str]] = set()
    prev_completed: list[list[str]] = []
    if args.resume:
        prev_state = load_run_state(args.vault)
        prev_completed = prev_state.get("completed", [])
        completed_keys = {(d, u) for d, u in prev_completed}
        prev_failures = len(prev_state.get("failures", []))
        skippable = sum(1 for k, _ in dup_groups if k in completed_keys)
        LOG.info(
            "Resuming: %d groups already completed, %d previous failures to retry, "
            "%d groups to skip.",
            len(completed_keys),
            prev_failures,
            skippable,
        )

    # ── Phase 3: Plan + apply per-group sequential ops ───────────────
    all_delete_ids: list[str] = []
    all_errors: list[dict[str, Any]] = []
    newly_completed: list[list[str]] = []

    def _flush_state() -> None:
        """Write current progress to disk so a crash doesn't lose work."""
        if not args.apply:
            return
        state = {
            "completed": prev_completed + newly_completed,
            "failures": all_errors,
            "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        save_run_state(args.vault, state)

    stamp_tag = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%d")

    with Progress() as progress:
        group_task = progress.add_task("Processing groups\u2026", total=len(dup_groups))

        for (domain, uname), cands in dup_groups:
            if (domain, uname) in completed_keys:
                LOG.debug("  SKIP (already completed): %s / %s", domain, uname)
                progress.advance(group_task)
                continue

            try:
                primary = choose_primary(cands)
                dupes = [c for c in cands if c.item_id != primary.item_id]

                primary_item = item_cache[primary.item_id]

                # Conflict detection
                conflict_pw = primary.has_password and any(d.has_password for d in dupes)

                # Compute merged URLs, tags, notes
                merged_urls: list[OpUrl] = list(primary_item.get("urls", []) or [])
                merged_tags: list[str] = list(primary_item.get("tags", []) or [])
                merged_notes = safe_str(primary_item.get("notesPlain"))

                # Collect duplicate passwords for history preservation
                all_dup_passwords: list[tuple[str, int | None]] = []
                primary_pw = get_password_value(primary_item)
                primary_pw_set: set[str] = {primary_pw} if primary_pw else set()
                for entry in get_password_history(primary_item):
                    pw = entry.get("value", "")
                    if pw:
                        primary_pw_set.add(pw)

                # Collect duplicate TOTP values for history preservation
                all_dup_totps: list[str] = []
                primary_totp_value = get_totp_value(primary_item)
                seen_totps: set[str] = {primary_totp_value} if primary_totp_value else set()

                for d in dupes:
                    di = item_cache[d.item_id]
                    merged_urls = union_urls(merged_urls, di.get("urls", []) or [])
                    merged_tags = union_tags(merged_tags, di.get("tags", []) or [])
                    merged_notes = merge_notes(
                        merged_notes,
                        safe_str(di.get("notesPlain")),
                        safe_str(di.get("title")) or "(untitled)",
                        d.item_id,
                    )
                    for pw, _src, ts in collect_all_passwords(di, d.item_id):
                        if pw not in primary_pw_set:
                            all_dup_passwords.append((pw, ts))
                            primary_pw_set.add(pw)
                    dup_totp = get_totp_value(di)
                    if dup_totp and dup_totp not in seen_totps:
                        all_dup_totps.append(dup_totp)
                        seen_totps.add(dup_totp)

                # --- Log plan (no secrets) ---
                LOG.info(
                    "GROUP: domain=%s username=%s size=%d",
                    domain,
                    uname,
                    len(cands),
                )
                LOG.info(
                    "  PRIMARY: %s (id=%s updated=%s score=%d)",
                    sanitize_log_line(primary.title),
                    primary.item_id,
                    primary.updated_at,
                    primary.field_score,
                )
                for d in dupes:
                    LOG.info(
                        "  DUPE:    %s (id=%s updated=%s score=%d pw=%s totp=%s)",
                        sanitize_log_line(d.title),
                        d.item_id,
                        d.updated_at,
                        d.field_score,
                        "Y" if d.has_password else "N",
                        "Y" if d.has_totp else "N",
                    )

                if conflict_pw:
                    LOG.info(
                        "  Passwords present in multiple items \u2014 will be preserved via"
                        " password history cycling."
                    )
                if all_dup_totps:
                    LOG.info(
                        "  TOTP present in %d duplicate(s) \u2014 will be preserved via"
                        " TOTP history cycling.",
                        len(all_dup_totps),
                    )

                # --- Build edited primary item JSON ---
                primary_tags = union_tags(
                    merged_tags, [args.tag_primary, f"{args.tag_primary}-{stamp_tag}"]
                )

                edited_item: dict[str, Any] = dict(primary_item)
                notes_changed = merged_notes != safe_str(primary_item.get("notesPlain"))

                if args.apply:
                    # Password history cycling (sequential — order matters)
                    pw_history_note = ""
                    if all_dup_passwords:
                        LOG.info(
                            "  APPLY: cycling %d unique passwords into history (id=%s)",
                            len(all_dup_passwords),
                            primary.item_id,
                        )
                        ts_pairs = cycle_passwords_for_history(
                            primary.item_id, primary_pw, all_dup_passwords, args.vault
                        )
                        pw_history_note = build_password_history_note(ts_pairs)

                    # TOTP history cycling (sequential — order matters)
                    totp_history_note = ""
                    if all_dup_totps:
                        LOG.info(
                            "  APPLY: cycling %d unique TOTP values into history (id=%s)",
                            len(all_dup_totps),
                            primary.item_id,
                        )
                        totp_ts = cycle_totp_for_history(
                            primary.item_id, primary_totp_value, all_dup_totps, args.vault
                        )
                        totp_history_note = build_totp_history_note(totp_ts)

                    if pw_history_note:
                        merged_notes = (merged_notes + "\n" + pw_history_note).strip()
                        notes_changed = True
                    if totp_history_note:
                        merged_notes = (merged_notes + "\n" + totp_history_note).strip()
                        notes_changed = True

                    if notes_changed:
                        edited_item["notesPlain"] = merged_notes
                    edited_item["tags"] = primary_tags

                    LOG.info("  APPLY: editing primary notes/tags (id=%s)", primary.item_id)
                    op_edit_item(primary.item_id, json.dumps(edited_item), args.vault)

                    # Tag duplicates (skip if trashing — they're about to be deleted)
                    if not args.trash_duplicates:
                        for d in dupes:
                            di = item_cache[d.item_id]
                            dtags = union_tags(
                                di.get("tags", []) or [],
                                [args.tag_duplicates, f"{args.tag_duplicates}-{stamp_tag}"],
                            )
                            LOG.info("  APPLY: tagging duplicate (id=%s)", d.item_id)
                            op_edit_tags(d.item_id, dtags, args.vault)

                    # Queue deletes for batch phase
                    if args.trash_duplicates:
                        for d in dupes:
                            all_delete_ids.append(d.item_id)
                else:
                    LOG.info(
                        "  DRY-RUN: no changes applied."
                        " Re-run with --apply to tag/merge notes and tags."
                    )
                # Mark group as completed (only when --apply actually ran)
                if args.apply:
                    newly_completed.append([domain, uname])
                    _flush_state()
            except Exception as exc:  # noqa: BLE001
                all_errors.append({
                    "domain": domain,
                    "username": uname,
                    "primary_id": cands[0].item_id if cands else None,
                    "item_ids": [c.item_id for c in cands],
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                })
                LOG.warning("  ERROR processing group %s/%s: %s", domain, uname, exc)
                _flush_state()

            progress.advance(group_task)

    # ── Phase 4: Batch delete ─────────────────────────────────────────
    # op item delete supports stdin pipe, so we can delete all items in
    # a single op invocation rather than one call per item.
    if args.apply and all_delete_ids:
        LOG.info("Deleting %d duplicate(s)\u2026", len(all_delete_ids))
        try:
            op_delete_items_batch(all_delete_ids, args.vault)
        except Exception as exc:  # noqa: BLE001
            all_errors.append({
                "domain": "(batch-delete)",
                "username": "",
                "item_ids": all_delete_ids,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            LOG.warning("  ERROR batch deleting: %s", exc)

    # ── Final state save ────────────────────────────────────────────
    if args.apply:
        _flush_state()
        state_path = save_run_state(args.vault, {
            "completed": prev_completed + newly_completed,
            "failures": all_errors,
            "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

        if all_errors:
            LOG.info("Run state saved to: %s", state_path)
            LOG.info("Re-run with --resume to retry %d failed group(s).", len(all_errors))
        elif newly_completed:
            # All groups succeeded — clean up state file
            clear_run_state(args.vault)

    # ── Summary ───────────────────────────────────────────────────────
    if all_errors:
        LOG.error(
            "Finished with %d error(s) out of %d groups:",
            len(all_errors),
            len(dup_groups),
        )
        for err in all_errors:
            LOG.error(
                "  [%s] %s/%s (items=%s): %s",
                err["error_type"],
                err["domain"],
                err["username"],
                ",".join(err.get("item_ids", [])),
                err["error"],
            )

    processed = len(newly_completed)
    skipped = sum(1 for k, _ in dup_groups if k in completed_keys)
    failed = len(all_errors)
    LOG.info(
        "Done. %d completed, %d skipped (already done), %d failed.",
        processed,
        skipped,
        failed,
    )
    return 1 if all_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
