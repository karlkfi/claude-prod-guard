# Project Status

Single source of truth for progress and priorities in prod-guard. Pick the next task from the top of the Queue.

## Conventions

**Status:** ✅ done · ▶ started · 🔲 ready · 🚫 blocked · 💤 deferred
**Size:** S = one session · M = 2–3 sessions · L = needs a plan doc under `docs/plan/`
**Labels:** `security` `tests` `docs` `infra` `bug` `parsing` `coverage`

**Maintaining this file:** see [`docs/development/maintaining-backlog.md`](development/maintaining-backlog.md) for the full rules. Short version:
- **Starting an S item:** complete it, delete the row.
- **Starting an M/L item:** create or update a plan doc under `docs/plan/`; delete the row here when done. (Skip the `▶ Started` marker unless you have a specific reason — the open PR is the in-flight signal.)
- **New item identified:** append it to the Queue with the next unused ID. Batch audit-discovery items in one commit.
- **`Last touched:` is one line, date only.** Do not append session narrative.

Last touched: 2026-07-04

---

## Queue

Specific actionable items in priority order. Pick from the top; skip 🚫 items until their blocker clears.

| ID | Item | Labels | St | Sz | Notes |
|---|---|---|---|---|---|
| <a id="Q8"></a>Q8 | Read pulumi's ambient selected stack from `~/.pulumi/workspaces/` for ambient classification | `security` | 💤 | M | Today a mutating `pulumi` command with no `--stack` always asks; resolving the selected stack (keyed by a hash of the `Pulumi.yaml` path) would let ambient-prod deny. Parallel to [Q9](#Q9). |
| <a id="Q9"></a>Q9 | Resolve a named `--profile NAME`'s account from `[profile NAME]` in `~/.aws/config` | `security` | 💤 | M | Q7 resolved only the `[default]` profile. An explicit `--profile admin` whose name classifies `unknown` still asks; reading its `sso_start_url`/`role_arn` would let it deny. Must stay additive: content escalates `unknown → deny`, never `unknown → defer`. |
