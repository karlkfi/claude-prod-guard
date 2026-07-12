# Project Status

Single source of truth for progress and priorities in prod-guard. Pick the next task from the top of the Queue.

**Status:** 🔲 ready · 🚫 blocked
**Size:** S = one session · M = 2–3 sessions · L = needs a plan doc under `docs/plan/`
**Labels:** `security` `tests` `docs` `infra` `bug` `parsing` `coverage`
**Next ID:** Q13

## Queue

| ID | Item | Labels | St | Sz | Notes |
|---|---|---|---|---|---|
| _(empty)_ | | | | | |

## Deferred

| ID | Item | Labels | Sz | Trigger to revive |
|---|---|---|---|---|
| <a id="Q12"></a>Q12 | Session-scoped override for the mixed prod/dev dogfood cluster | `security` | M | **Event:** a friction re-measurement after Q11's shell-variable expansion shows the dogfood cluster still drives most prompts. |
