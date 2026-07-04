# Design

The "why" behind prod-guard. The [`README.md`](../README.md) covers *what* the plugin does; this doc covers *why this approach* and *why not the alternatives*. Read this before proposing a structural change to the parser, the per-tool tables, or the decision semantics.

## Problem

Claude Code's built-in permission system matches commands as string patterns. `Bash(kubectl:*)` allows **every** invocation of kubectl. Users who pre-approve the infrastructure CLIs they use all day — the standard remedy for prompt fatigue — end up implicitly pre-approving `kubectl --context prod delete ns payments` along with the hundreds of legitimate dev-cluster commands.

Two distinct failures hide behind that one permission rule:

1. **Prod blast-radius** — a mutating verb whose resolved target is production. String-pattern permissions cannot see the target; even a human reviewing the prompt can miss that the *ambient* context points at prod when no `--context` flag appears in the command text.
2. **Ambient-context clobbering** — with parallel sessions now the normal way to run Claude Code, the shared current-context/active-config files (`~/.kube/config`, `~/.config/gcloud`, `~/.docker/config.json`) are races waiting to happen. Session A writes `kubectl delete pod x` trusting the kind context; session B runs `gcloud container clusters get-credentials prod-cluster` a moment earlier; session A's delete lands on prod. Neither session did anything individually wrong.

The right granularity is **per resolved target**, not per command name. That's what this plugin adds.

## Approach

A `PreToolUse` hook on `Bash` that:

1. Tokenizes the command with `shlex` (a real POSIX lexer, not a regex) and splits it into simple commands on every shell operator, recursing into `sh -c` bodies and `eval` arguments. Crude splitting is biased so that quoting mistakes can only *add* segments to inspect, never hide one.
2. For each simple command from a covered tool, classifies the **verb** against a per-tool read-only table — any verb not known to be read-only is treated as mutating.
3. Resolves the **effective target**: the explicit flag (`--context`, `--project`, `--profile`, `--subscription`, …) or pinning env assignment if present; otherwise the tool's ambient config file, read locally; otherwise UNKNOWN.
4. Classifies the target against configurable prod/nonprod regex lists (prod checked first) and applies the matrix:
   - PROD + mutating → **deny** (override downgrades to ask)
   - UNKNOWN + mutating → **ask** (fail closed)
   - ambient + mutating → **ask** (deny if the ambient value is prod)
   - context-switching command → **ask** (deny if the new target is prod)
   - everything else → **defer** (no output)

## Why these specific design choices

### Why `deny` for prod when the sibling guards default to `ask`

workspace-guard and branch-guard default to `ask` because their false positives are routine and their worst case is usually recoverable (a file read, a commit that can be reverted). prod-guard's worst case is a production outage or data loss — irreversible and organization-visible. The asymmetry justifies the harder default: a false-positive deny costs one `PROD_GUARD_OVERRIDE=` prefix and one confirmation; a false-negative allow can cost an incident. The override keeps intentional prod work possible in exactly one deliberate, auditable step — the reason travels in the command line itself.

### Why fail-closed on unknown targets

A denylist that silently allows whatever it doesn't recognize protects only orgs whose production is literally named "prod". Real environments have GCP project ids, cluster names, and subscription GUIDs that no built-in pattern can anticipate. Prompting on unknown+mutating makes the gap visible exactly when it matters, and the fix (add a pattern) is one config line. The reverse default — allow on unknown — would make the guard decorative.

### Why the guard never emits `allow`

An `allow` from one hook can ride past both the user's permission settings and the *other* guard hooks (composition order between hooks is not a documented contract). prod-guard's job is to add a boundary, not to reduce prompts, so its only outputs are `deny`, `ask`, and silence. This also means installing it can never weaken any other guard.

### Why ambient state is read from local files, not from the tools

`kubectl config current-context` or `gcloud config list` would give the same answers, but shelling out to the tools is slow (100ms–1s per invocation, per Bash command, forever), can trigger plugin/auth machinery, and in some CLIs can touch the network. The hook must run in single-digit milliseconds on every Bash call. Reading `current-context:` out of a YAML file with a regex is not full YAML parsing — it's the same trade the tools' own shell-prompt integrations (kube-ps1 and friends) make, and a wrong read fails toward a prompt, not an allow.

### Why unknown verbs are treated as mutating

The verb tables are allowlists of *known read-only* verbs, not catalogs of destructive ones. Cataloging destruction is unwinnable — every CLI release adds verbs, and missing one is exactly the false negative this guard exists to prevent. Missing a read-only verb costs one spurious prompt and a one-line table fix.

### Why defer, not allow, for everything else

Same reasoning as the siblings: unparseable commands, uncovered tools, and read-only verbs hand control back to the normal permission flow — the user is no worse off than without the hook. Fail-open applies to *infrastructure* failures only (bad JSON, missing config file, an exception in the hook): a hook bug must never break the session. The *security* decision is where the guard fails closed.

### Why `gh` gets denylist-only treatment

gh's implied target — the cwd repo's `origin` remote — is pinned by the worktree, not shared clobber-prone state, so threat model 2 doesn't apply. And `gh pr create`/`gh pr merge` are the bread and butter of every Claude Code session; prompting on each would train users to disable the guard. So gh only participates in threat model 1: a mutating gh command whose resolved repo matches a prod pattern is denied.

## Alternatives considered and rejected

- **A wrapper script per tool** (`bin/kubectl` shims on PATH). Protects shells too, but requires PATH discipline everywhere, breaks tool auto-update expectations, and doesn't see the assembled command line (a shim can't know it's the third segment of a `&&` chain). The hook sees exactly what will run.
- **OPA/Conftest-style policy engine.** Overkill: a dependency-heavy runtime for what is a string-classification problem, and it would still need this plugin's parsing to produce input. Stdlib-only Python keeps installation to "have python3".
- **Admission control on the cluster** (ValidatingWebhooks, constrained RBAC). The right *server-side* defense, and orgs should have it — but it protects one cluster, requires cluster-admin to deploy, and does nothing for gcloud/aws/az/terraform/docker. The hook is the client-side, cross-tool complement, installable by the person running Claude.
- **Blocking parallel sessions from sharing configs** (per-session `KUBECONFIG`). Solves threat model 2 elegantly where you control the launcher, but it's an environment-management discipline this plugin can't impose; the ask-with-pin-hint teaches the equivalent habit per command.
