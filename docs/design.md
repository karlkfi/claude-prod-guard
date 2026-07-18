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
   - UNKNOWN explicit target + mutating → **ask** (fail closed)
   - no explicit target (ambient) + mutating → **deny** with a self-healing
     fix-it naming the pin flag (deny-with-reason, not ask; override downgrades
     to ask)
   - context-switching command → **ask** (deny if the new target is prod)
   - everything else → **defer** (no output)

## Why these specific design choices

### Why `deny` for prod when the sibling guards default to `ask`

workspace-guard and branch-guard default to `ask` because their false positives are routine and their worst case is usually recoverable (a file read, a commit that can be reverted). prod-guard's worst case is a production outage or data loss — irreversible and organization-visible. The asymmetry justifies the harder default: a false-positive deny costs one `PROD_GUARD_OVERRIDE=` prefix and one confirmation; a false-negative allow can cost an incident. The override keeps intentional prod work possible in exactly one deliberate, auditable step — the reason travels in the command line itself.

### Why fail-closed on unknown targets

A denylist that silently allows whatever it doesn't recognize protects only orgs whose production is literally named "prod". Real environments have GCP project ids, cluster names, and subscription GUIDs that no built-in pattern can anticipate. Prompting on unknown+mutating makes the gap visible exactly when it matters, and the fix (add a pattern) is one config line. The reverse default — allow on unknown — would make the guard decorative.

### Why config outranks the built-in heuristics

The built-in `prod` list is a *word-boundary heuristic*: it fires on any target containing `prod`/`prd`/`live` as a segment. That heuristic is well-calibrated for infrastructure locators (cluster contexts, project ids), where the name reliably tracks blast radius — but it also fires on names that merely mention prod tooling and gate nothing, the canonical case being a **code repository** named after prod tooling. `karlkfi/claude-prod-guard` matched the built-in prod pattern via its `-prod-` segment, so every mutating `gh` command against the guard's own repo (`gh pr create`, `gh issue create`) was denied ([issue #17](https://github.com/karlkfi/claude-prod-guard/issues/17)).

The fix is a **precedence lattice**: config `prod` › config `nonprod` › built-in `prod` › built-in `nonprod`. A human-vetted config `nonprod` entry outranks the built-in prod *heuristic*, so `"nonprod": ["karlkfi/claude-prod-guard"]` clears the false positive for that slug and every future one — no per-command `PROD_GUARD_OVERRIDE`. This does not weaken the boundary: config remains additive to the *set* of patterns (it can add a regex, never delete a built-in), fail-closed ordering is preserved *within* each provenance tier (prod checked before nonprod), and a config `prod` entry still beats everything — so clearing a heuristic can never mask a target an operator has explicitly vetted as production. Narrowing the boundary stays an explicit, reviewable act (a committed `.claude/prod-guard.json` line), never a silent code default. The alternative — scoping the name heuristic away from `gh` repo slugs — is narrower and leaves the unclearable-built-in problem latent for every other tool, so the general precedence fix was chosen.

### Why an unpinned mutation is denied, not prompted

A mutating command that names no explicit target (`kubectl delete pod x` with no
`--context`, `terraform apply` with no `TF_WORKSPACE`) runs against whatever the
shared ambient state — kubeconfig `current-context`, the active gcloud config,
the default AWS profile — happens to point at when it *executes*, which a
parallel session can repoint between the moment the command is written and the
moment it runs. Prompting on this (the earlier behavior) put a human in the loop
on a target that is ambiguous by construction, and taught nothing: the next
unpinned command prompts again. Denying with a fix-it that names the resolved
target and the flag to add is strictly better on both axes this guard cares
about. Security: the command cannot run until the target is explicit, closing
the write-vs-run race instead of asking a human to reason about it. Friction:
the deny is *machine-actionable* — the agent re-runs with `--context <ctx>`
pinned (which then classifies and, if non-prod, defers silently) in one round
trip, rather than stalling on a permission prompt. This is why the unpinned case
is the one deny that is not about prod at all; the `PROD_GUARD_OVERRIDE`
downgrade still applies, so a genuinely un-pinnable command remains runnable in
one deliberate, auditable step. It also machine-generates the target line the
downstream convention used to hand-write: the resolved context/project/namespace
travels in the decision reason, so the human who does see a prompt (an unknown
explicit target, or an overridden deny) always sees where the mutation lands,
with no risk of an agent-authored echo that doesn't match the real flags.

The carve-outs are deliberate. A command whose *whole purpose* is to switch
shared state (`kubectl config use-context`, `kubectx`, `gcloud config set`) has
no per-command target to pin, so it stays an `ask` (a deny for a prod switch).
An *explicit* target that classifies UNKNOWN stays an `ask` too: it is pinned
(not clobber-prone), just unclassified — the fail-closed confirm, not the
unpinned deny. And a tool whose "ambient" is cwd/file-scoped rather than
clobber-prone shared state — docker's local daemon, ansible's `ansible.cfg`
inventory — keeps deferring on a non-prod ambient target, exactly as before;
only its genuinely *unresolved* ambient path (which is where `deny_ambient`
fires) joins the unpinned deny.

### Why kube-contexts also classify by their cluster's server URL

Classifying a kube-context purely by name misses the most dangerous case: a production cluster reached through an innocuous context name (`blue-2`, `cluster-7`). The kubeconfig already records the mapping — context → cluster → `server:` URL — so the guard resolves it locally (the same regex-over-YAML trade as reading `current-context:`) and classifies the server URL alongside the name. The verdict is the worst of the two on the prod > nonprod > unknown lattice, so this is purely additive: a prod server upgrades an unknown or nonprod-looking name to a deny, and an unresolvable server (flow-style YAML, a context defined in a kubeconfig outside `$KUBECONFIG`, a parse miss) simply falls back to name-only — it can never downgrade a name that already classifies prod. Server resolution is deliberately scoped to the kubeconfig tools (`kubectl`/`oc`/`flux`/`helm` and the `kubectx` / `use-context` switches); other tools' targets (project ids, subscriptions, profiles) have no comparable cheap local URL to resolve.

### Why terraform also classifies the backend state location

The same weak-proxy problem applies to terraform: the selected workspace (`default`, `main`, a `TF_WORKSPACE` value) is a poor stand-in for what an `apply`/`destroy` actually rewrites — a single S3/GCS bucket or Terraform Cloud organization commonly holds many workspaces, prod among them. `terraform init` records the resolved backend in `.terraform/terraform.tfstate`, so the guard reads that JSON and classifies the state-location fields (bucket + key, GCS prefix, TFC org/workspace/tags) alongside the workspace name. This is deliberately one-directional — a prod backend only *escalates* the decision to a prod deny; a nonprod or unresolvable backend never silences the underlying decision (an explicit non-prod workspace still defers; an unpinned one still denies with the pin-required reason) — which keeps it purely additive like the kube-server case. Credentials are never fed into a user-visible message: known backend types echo only the location, and the catch-all for unknown/future backend types classifies every config string but reports just the backend type. A missing file, a `local` backend, or an un-`init`ed directory resolves nothing and leaves the workspace-only behavior unchanged.

The AWS `[default]` profile gets the same treatment on the ambient path. A mutating `aws` command with no `--profile`/`AWS_PROFILE` runs against `[default]`, whose `~/.aws/config` entry records where it reaches — an `sso_start_url`, an assumed `role_arn`, an `sso_session` name (followed into its `[sso-session]` block). The guard classifies those: a prod default profile denies with the prod reason, while a nonprod/unknown/unresolvable one is denied as an unpinned mutation (pin `--profile`), now naming what resolved so the reason still shows where it would land. Only well-known location fields are echoed; any other key's value (a `credential_process` command) is classify-only, and `~/.aws/credentials` — which holds the secret keys — is never read. Like the terraform backend this is one-directional: the resolution can only escalate the unpinned deny to a prod deny, never silence it. An explicit `--profile NAME`/`AWS_PROFILE` gets the same resolution when its *name* classifies unknown: the guard reads the profile's `[profile NAME]` section (the AWS convention for non-default profiles) and denies if the resolved account is prod, so a prod profile behind an innocuous name (`admin`, `ops`) still blocks. That resolution is scoped to the unknown-name case — a name the user spelled `dev` classifies nonprod and defers even if it references an org-wide prod-looking `sso_start_url`, since the explicit name is a stronger signal than a possibly-shared SSO portal URL. `eksctl` reaches AWS through the same default-profile chain.

### Why pulumi and ansible each have their own target model

Coverage isn't one shape — each tool's "target" is whatever it actually acts against. For **pulumi** that's the *stack* (`--stack`/`-s`, else the per-project selected stack); the explicit flag is classified, and the ambient selected stack is read from `~/.pulumi/workspaces/` (whose per-project file is keyed by the sha1 of the project path) so an unpinned mutation against a prod selection denies with the prod reason, while a nonprod/unresolved selection is denied as an unpinned mutation (pin `--stack`) — the selection is clobber-prone shared state, so it never defers. `pulumi stack select <prod>` is still denied, so the moment a prod stack is chosen is caught. For **ansible** the target is the *inventory* (`-i`, else `ANSIBLE_INVENTORY`/`ansible.cfg`); the inventory is authoritative, and the host pattern / `--limit` can only *escalate* to a deny — never force a prompt on an unknown word (`webservers`) when the inventory itself resolves nonprod. Running a playbook is inherently mutating, so `ansible-playbook` has no read-only verb split; only the never-connecting flags (`--syntax-check`, `--list-*`) and ad-hoc read-only modules (`ping`/`setup`/`debug`) defer. Both fit the existing `EVALUATORS` model with no parser change — a new tool is a new evaluator plus a read-only allowlist.

### Why the guard never emits `allow`

An `allow` from one hook can ride past both the user's permission settings and the *other* guard hooks (composition order between hooks is not a documented contract). prod-guard's job is to add a boundary, not to reduce prompts, so its only outputs are `deny`, `ask`, and silence. This also means installing it can never weaken any other guard.

### Why ambient state is read from local files, not from the tools

`kubectl config current-context` or `gcloud config list` would give the same answers, but shelling out to the tools is slow (100ms–1s per invocation, per Bash command, forever), can trigger plugin/auth machinery, and in some CLIs can touch the network. The hook must run in single-digit milliseconds on every Bash call. Reading `current-context:` out of a YAML file with a regex is not full YAML parsing — it's the same trade the tools' own shell-prompt integrations (kube-ps1 and friends) make, and a wrong read fails toward a prompt, not an allow.

### Why unknown verbs are treated as mutating

The verb tables are allowlists of *known read-only* verbs, not catalogs of destructive ones. Cataloging destruction is unwinnable — every CLI release adds verbs, and missing one is exactly the false negative this guard exists to prevent. Missing a read-only verb costs one spurious prompt and a one-line table fix.

### Why shell variables in resolved targets are expanded

The target of a mutating command is frequently pinned through a shell variable — `CTX=<ctx> kubectl --context $CTX …`, or a chain that assembles it (`P=…; Z=…; CTX=gke_${P}_${Z}_… kubectl --context $CTX …`). Because `shlex` tokenizes without expanding, the value the guard originally classified was the literal string `$CTX`, which matches no pattern and prompts (UNKNOWN + mutating → `ask`). That was the single largest source of prompt fatigue in practice — and worse, a *silent security hole*: a production context pinned through a variable slid from `deny` down to `ask`, because the guard never saw the prod name. Expanding the variable fixes both directions at once — it silences the nonprod case and restores the prod `deny` — so it is strictly an improvement, not a security/convenience trade.

The expansion is safe because it can only ever make classification *more specific*, never silently allow. It is bounded to the two directions that are unambiguous:

- **Only simple `$NAME` / `${NAME}` references are expanded.** Command substitution `$(…)`, arithmetic `$((…))`, and every `${…}` operator form (`${V:-default}`, `${#V}`, `${!V}`, …) are left literal, so a target the guard can't evaluate with certainty falls back to the existing prompt/deny rather than a guessed value. Under-expanding is always the safe direction: an unresolved target stays UNKNOWN (or, unpinned, denies).
- **An undefined variable is left literal, never blanked.** `$NOPE` stays `$NOPE` and classifies UNKNOWN → prompt, rather than expanding to empty and possibly changing the decision. This mirrors the fail-closed rule everywhere else: the guard never resolves ambiguity in favor of allowing a mutation.

The one subtlety is scope. A bare `P=x` (or same-shell) assignment is a shell variable, not exported; a child process — the body of `bash -c '…'` / `eval` — sees only *exported* variables. So the guard tracks two scopes: same-shell expansion resolves the full set (bare + exported + inline), while a nested `sh -c` body is expanded only against what the invoking segment exports. Getting this wrong in the lenient direction would be a real false negative — a bare var leaking into a child body could turn a genuinely-unpinned mutation into a false defer — which is exactly the failure mode this guard exists to prevent, so the nested body deliberately under-expands. Inline `A=x cmd` assignments *are* exported to that command's own children (bash semantics), so `CTX=x bash -c '… $CTX …'` still resolves, while `CTX=x; bash -c '… $CTX …'` does not.

### Why defer, not allow, for everything else

Same reasoning as the siblings: unparseable commands, uncovered tools, and read-only verbs hand control back to the normal permission flow — the user is no worse off than without the hook. Fail-open applies to *infrastructure* failures only (bad JSON, missing config file, an exception in the hook): a hook bug must never break the session. The *security* decision is where the guard fails closed.

### Why `gh` and `ssh` get denylist-only treatment

gh's implied target — the cwd repo's `origin` remote — is pinned by the worktree, not shared clobber-prone state, so threat model 2 doesn't apply. And `gh pr create`/`gh pr merge` are the bread and butter of every Claude Code session; prompting on each would train users to disable the guard. So gh only participates in threat model 1: a mutating gh command whose resolved repo matches a prod pattern is denied.

`ssh` has the same shape: its destination host is spelled out on the command line (`ssh user@host`, or a `-J` jump host), not read from clobberable ambient state, so only threat model 1 applies. Prompting on every `ssh dev-box` — the vast majority of which target unremarkable hosts that match no pattern — would be the same disable-the-guard noise, so an unknown host defers rather than asking. Unlike the other tools ssh has no read-only/mutating verb split to lean on: the "verb" is an arbitrary remote command the hook can't see, and an interactive shell has no verb at all. Since a prod shell *is* the blast radius, every ssh into a prod-classified host is treated as mutating and denied. This is purely additive coverage — ssh was previously uncovered (always deferred), so denylist-only only ever adds a deny, never removes a prompt.

## Alternatives considered and rejected

- **A wrapper script per tool** (`bin/kubectl` shims on PATH). Protects shells too, but requires PATH discipline everywhere, breaks tool auto-update expectations, and doesn't see the assembled command line (a shim can't know it's the third segment of a `&&` chain). The hook sees exactly what will run.
- **OPA/Conftest-style policy engine.** Overkill: a dependency-heavy runtime for what is a string-classification problem, and it would still need this plugin's parsing to produce input. Stdlib-only Python keeps installation to "have python3".
- **Admission control on the cluster** (ValidatingWebhooks, constrained RBAC). The right *server-side* defense, and orgs should have it — but it protects one cluster, requires cluster-admin to deploy, and does nothing for gcloud/aws/az/terraform/docker. The hook is the client-side, cross-tool complement, installable by the person running Claude.
- **Blocking parallel sessions from sharing configs** (per-session `KUBECONFIG`). Solves threat model 2 elegantly where you control the launcher, but it's an environment-management discipline this plugin can't impose; the deny-with-pin-hint enforces the equivalent habit per command.
