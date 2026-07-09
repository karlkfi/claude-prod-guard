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

Last touched: 2026-07-09

---

## Queue

Specific actionable items in priority order. Pick from the top; skip 🚫 items until their blocker clears.

| ID | Item | Labels | St | Sz | Notes |
|---|---|---|---|---|---|
| <a id="Q11"></a>Q11 | Expand `$VAR`/`${VAR}` in resolved targets so a var-pinned context (`CTX=… kubectl --context $CTX`) classifies by its value, not the literal `$CTX` | `parsing` `security` `bug` | 🔲 | M | Friction report: ~68% of prompts are var-expanded targets; also a hole — a prod target behind a var downgrades deny→ask. Plan: [`docs/plan/variable-expansion.md`](plan/variable-expansion.md) |
