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
| <a id="Q1"></a>Q1 | Cover `oc` (OpenShift) and `podman`/`nerdctl` as aliases of existing evaluators | `coverage` | 🔲 | S | `oc` shares kubectl's verb/flag model; podman/nerdctl share docker's. Alias rows + tests. |
| <a id="Q2"></a>Q2 | Classify kube contexts by cluster server URL, not just context name | `security` `parsing` | 💤 | M | A prod context named `blue-2` evades name patterns. The kubeconfig maps context→cluster→server; matching patterns against the server URL too would catch it. Needs a slightly deeper (still regex-level) kubeconfig read. |
| <a id="Q3"></a>Q3 | Terraform backend classification (S3 bucket / GCS bucket / TFC workspace) | `security` | 💤 | M | The workspace name is a weak proxy; the backend config in `.terraform/` names the real state location. Parse it locally and classify. |
| <a id="Q4"></a>Q4 | Cover `pulumi`, `ansible`/`ansible-playbook`, and `ssh <prod-host>` | `coverage` | 💤 | M | Each has a different target model (stack, inventory, hostname). Hostname classification for ssh reuses the existing pattern lists. |
| <a id="Q5"></a>Q5 | Classify `docker build --push` per-tag for all `-t` values, and `docker compose` service-level pushes | `coverage` `parsing` | 💤 | S | Today only the first `-t`/`--tag` value is classified when `--push` is present. |
| <a id="Q6"></a>Q6 | Friction report: measure where prod-guard prompts accumulate from session transcripts | `infra` | 💤 | M | Port the workspace-guard `friction-report.py` approach so pattern gaps (unknown targets prompting repeatedly) are visible and fixable. |
| <a id="Q7"></a>Q7 | Read the AWS default profile's `sso_start_url`/account from `~/.aws/config` for ambient classification | `security` | 💤 | M | Today a mutating aws command with no profile always asks; resolving the default profile would let ambient-prod deny and ambient-nonprod still ask with a better message. |
