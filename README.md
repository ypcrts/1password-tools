# Proton Pass to 1Password Migration Tools

Tools for importing Proton Pass CSV exports into 1Password and cleaning up the result. Proton Pass exports don't map cleanly to 1Password's data model, so a few post-import transforms are needed to get everything right.

## The Problem

When you export from Proton Pass and import into 1Password:

1. **Usernames are lost** — Proton Pass leaves the login field empty when the username is an email address, so 1Password doesn't know a username is set.
2. **Alias entries are useless** — Proton Pass exports email alias entries alongside logins. These have no passwords and serve no purpose in 1Password.
3. **Duplicates pile up** — If you're merging a Proton Pass export with an existing 1Password vault, you end up with duplicate entries for the same site and username. 1Password's Watchtower has a built-in duplicate merge feature, but I couldn't get it to work reliably with Proton Pass imports — and since 1Password isn't open source, there's no way to debug why. So I wrote the dedupe job.

## Workflow

Run these in order after importing a Proton Pass CSV into 1Password:

### 1. Backfill Usernames from Email Fields

Proton Pass stores the login as an `Email` field but leaves the `username` field empty. This copies the Email value into the username so 1Password recognizes it.

```bash
# Dry-run — see what would be updated
python 1password_fill_username_from_email.py --vault MyVault

# Filter by import tag
python 1password_fill_username_from_email.py --vault MyVault --tag "Imported"

# Apply changes
python 1password_fill_username_from_email.py --vault MyVault --apply
```

### 2. Delete Proton Alias Entries

Proton Pass exports include `type=alias` entries for email aliases. These don't have passwords and are useless in 1Password — actual logins always get their own entry. This works if you import Proton's `type` field as `proton_type` so the tool can identify alias entries.

```bash
# Dry-run — see which alias items would be trashed
python 1password_trash_aliases.py --vault MyVault

# Actually trash them
python 1password_trash_aliases.py --vault MyVault --apply
```

### 3. Deduplicate & Merge

If you're merging a Proton Pass import with a pre-existing 1Password vault, you'll end up with duplicates. This groups items by (domain, username) and merges them — notes, tags, and URLs from duplicates are folded into a single primary item.

Passwords and TOTP seeds from duplicates are preserved as **history** in 1Password's built-in password history (via field cycling), not in notes or custom fields.

```bash
# Dry-run (default) — see what would be merged
python 1password_dedupe.py --vault MyVault

# Apply merges (edit notes, tags on primary; tag duplicates)
python 1password_dedupe.py --vault MyVault --apply

# Apply and trash duplicates after merge
python 1password_dedupe.py --vault MyVault --apply --trash-duplicates

# Limit to first 5 groups
python 1password_dedupe.py --vault MyVault --apply --limit 5

# Only process groups with 3+ duplicates
python 1password_dedupe.py --vault MyVault --min-group-size 3
```

## Requirements

- Python 3.9+
- [1Password CLI v2](https://developer.1password.com/docs/cli/) installed and signed in (`op signin`)

## Installation

```bash
pip install -e ".[dev]"
```

## Disk Cache

All tools support `--dangerously-use-disk-cache` to cache fetched item details to `/tmp`. This avoids re-fetching when iterating on dry-runs with large vaults (1000+ items).

**Why it's dangerous**: cache files contain full item JSON including passwords, TOTP seeds, and secure notes.

**Safety measures**:
- Opt-in only — never enabled by default
- Stored in `/tmp` (typically cleared on reboot)
- Cache files are `0o600` (owner read/write only)
- Cache directory is `0o700` (owner access only)
- Cleanup script zeroizes file contents before deleting

**Cleanup**:
```bash
python 1password_clear_cache.py
```

**Residual risks**:
- `/tmp` may be on-disk (not tmpfs) on some systems, so data may persist across reboots
- SSD wear-leveling may retain data even after zeroizing
- OS swap could page secrets to disk

## Safety

- **Dry-run by default**: no mutations unless `--apply` is passed
- **Never prints secrets**: passwords and TOTP seeds are never logged
- **Password history preservation**: all unique passwords from duplicates are cycled into 1Password's built-in password history
- **TOTP history preservation**: unique TOTP seeds from duplicates are cycled into 1Password's built-in TOTP history
- **Idempotent**: merged notes include item IDs to prevent re-appending

## How Deduplication Works

1. Lists all Login items (filtered at the API level via `--categories login`)
2. Groups items by `(domain, username)` — strips `www.` prefix but preserves other subdomains
3. Picks a primary per group (highest field count, then most recently updated)
4. Merges notes, tags, and URLs from duplicates into the primary
5. Cycles duplicate passwords through the primary's password field to preserve them in 1Password's built-in history
6. Cycles duplicate TOTP seeds the same way (skipped if values match)
7. Optionally trashes duplicates after merge

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check .

# Format
ruff format .
```

## License

MIT
