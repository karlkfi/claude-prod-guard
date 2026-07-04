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

### Why kube-contexts also classify by their cluster's server URL

Classifying a kube-context purely by name misses the most dangerous case: a production cluster reached through an innocuous context name (`blue-2`, `cluster-7`). The kubeconfig already records the mapping — context → cluster → `server:` URL — so the guard resolves it locally (the same regex-over-YAML trade as reading `current-context:`) and classifies the server URL alongside the name. The verdict is the worst of the two on the prod > nonprod > unknown lattice, so this is purely additive: a prod server upgrades an unknown or nonprod-looking name to a deny, and an unresolvable server (flow-style YAML, a context defined in a kubeconfig outside `$KUBECONFIG`, a parse miss) simply falls back to name-only — it can never downgrade a name that already classifies prod. Server resolution is deliberately scoped to the kubeconfig tools (`kubectl`/`oc`/`flux`/`helm` and the `kubectx` / `use-context` switches); other tools' targets (project ids, subscriptions, profiles) have no comparable cheap local URL to resolve.

### Why terraform also classifies the backend state location

The same weak-proxy problem applies to terraform: the selected workspace (`default`, `main`, a `TF_WORKSPACE` value) is a poor stand-in for what an `apply`/`destroy` actually rewrites — a single S3/GCS bucket or Terraform Cloud organization commonly holds many workspaces, prod among them. `terraform init` records the resolved backend in `.terraform/terraform.tfstate`, so the guard reads that JSON and classifies the state-location fields (bucket + key, GCS prefix, TFC org/workspace/tags) alongside the workspace name. This is deliberately one-directional — a prod backend only *escalates* a decision to deny; a nonprod or unresolvable backend never silences an existing prompt — which keeps it purely additive like the kube-server case. Credentials are never fed into a user-visible message: known backend types echo only the location, and the catch-all for unknown/future backend types classifies every config string but reports just the backend type. A missing file, a `local` backend, or an un-`init`ed directory resolves nothing and leaves the workspace-only behavior unchanged.

The AWS `[default]` profile gets the same treatment on the ambient path. A mutating `aws` command with no `--profile`/`AWS_PROFILE` runs against `[default]`, whose `~/.aws/config` entry records where it reaches — an `sso_start_url`, an assumed `role_arn`, an `sso_session` name (followed into its `[sso-session]` block). The guard classifies those: a prod default profile denies, while a nonprod/unknown/unresolvable one still prompts, now naming what resolved. Only well-known location fields are echoed; any other key's value (a `credential_process` command) is classify-only, and `~/.aws/credentials` — which holds the secret keys — is never read. Like the terraform backend this is one-directional over the prior always-ask: it can only escalate the ambient prompt to a deny, never silence it. An explicit `--profile NAME`/`AWS_PROFILE` gets the same resolution when its *name* classifies unknown: the guard reads the profile's `[profile NAME]` section (the AWS convention for non-default profiles) and denies if the resolved account is prod, so a prod profile behind an innocuous name (`admin`, `ops`) still blocks. That resolution is scoped to the unknown-name case — a name the user spelled `dev` classifies nonprod and defers even if it references an org-wide prod-looking `sso_start_url`, since the explicit name is a stronger signal than a possibly-shared SSO portal URL. `eksctl` reaches AWS through the same default-profile chain.

### Why pulumi and ansible each have their own target model

Coverage isn't one shape — each tool's "target" is whatever it actually acts against. For **pulumi** that's the *stack* (`--stack`/`-s`, else the per-project selected stack); the explicit flag is classified, and the ambient selected stack is not read from disk (its on-disk location is keyed by a hash of the project path, fragile to reproduce), so an unpinned mutation prompts. `pulumi stack select <prod>` is still denied, so the moment a prod stack is chosen is caught. For **ansible** the target is the *inventory* (`-i`, else `ANSIBLE_INVENTORY`/`ansible.cfg`); the inventory is authoritative, and the host pattern / `--limit` can only *escalate* to a deny — never force a prompt on an unknown word (`webservers`) when the inventory itself resolves nonprod. Running a playbook is inherently mutating, so `ansible-playbook` has no read-only verb split; only the never-connecting flags (`--syntax-check`, `--list-*`) and ad-hoc read-only modules (`ping`/`setup`/`debug`) defer. Both fit the existing `EVALUATORS` model with no parser change — a new tool is a new evaluator plus a read-only allowlist.

### Why the guard never emits `allow`

An `allow` from one hook can ride past both the user's permission settings and the *other* guard hooks (composition order between hooks is not a documented contract). prod-guard's job is to add a boundary, not to reduce prompts, so its only outputs are `deny`, `ask`, and silence. This also means installing it can never weaken any other guard.

### Why ambient state is read from local files, not from the tools

`kubectl config current-context` or `gcloud config list` would give the same answers, but shelling out to the tools is slow (100ms–1s per invocation, per Bash command, forever), can trigger plugin/auth machinery, and in some CLIs can touch the network. The hook must run in single-digit milliseconds on every Bash call. Reading `current-context:` out of a YAML file with a regex is not full YAML parsing — it's the same trade the tools' own shell-prompt integrations (kube-ps1 and friends) make, and a wrong read fails toward a prompt, not an allow.

### Why unknown verbs are treated as mutating

The verb tables are allowlists of *known read-only* verbs, not catalogs of destructive ones. Cataloging destruction is unwinnable — every CLI release adds verbs, and missing one is exactly the false negative this guard exists to prevent. Missing a read-only verb costs one spurious prompt and a one-line table fix.

### Why defer, not allow, for everything else

Same reasoning as the siblings: unparseable commands, uncovered tools, and read-only verbs hand control back to the normal permission flow — the user is no worse off than without the hook. Fail-open applies to *infrastructure* failures only (bad JSON, missing config file, an exception in the hook): a hook bug must never break the session. The *security* decision is where the guard fails closed.

### Why `gh` and `ssh` get denylist-only treatment

gh's implied target — the cwd repo's `origin` remote — is pinned by the worktree, not shared clobber-prone state, so threat model 2 doesn't apply. And `gh pr create`/`gh pr merge` are the bread and butter of every Claude Code session; prompting on each would train users to disable the guard. So gh only participates in threat model 1: a mutating gh command whose resolved repo matches a prod pattern is denied.

`ssh` has the same shape: its destination host is spelled out on the command line (`ssh user@host`, or a `-J` jump host), not read from clobberable ambient state, so only threat model 1 applies. Prompting on every `ssh dev-box` — the vast majority of which target unremarkable hosts that match no pattern — would be the same disable-the-guard noise, so an unknown host defers rather than asking. Unlike the other tools ssh has no read-only/mutating verb split to lean on: the "verb" is an arbitrary remote command the hook can't see, and an interactive shell has no verb at all. Since a prod shell *is* the blast radius, every ssh into a prod-classified host is treated as mutating and denied. This is purely additive coverage — ssh was previously uncovered (always deferred), so denylist-only only ever adds a deny, never removes a prompt.

## Alternatives considered and rejected

- **A wrapper script per tool** (`bin/kubectl` shims on PATH). Protects shells too, but requires PATH discipline everywhere, breaks tool auto-update expectations, and doesn't see the assembled command line (a shim can't know it's the third segment of a `&&` chain). The hook sees exactly what will run.
- **OPA/Conftest-style policy engine.** Overkill: a dependency-heavy runtime for what is a string-classification problem, and it would still need this plugin's parsing to produce input. Stdlib-only Python keeps installation to "have python3".
- **Admission control on the cluster** (ValidatingWebhooks, constrained RBAC). The right *server-side* defense, and orgs should have it — but it protects one cluster, requires cluster-admin to deploy, and does nothing for gcloud/aws/az/terraform/docker. The hook is the client-side, cross-tool complement, installable by the person running Claude.
- **Blocking parallel sessions from sharing configs** (per-session `KUBECONFIG`). Solves threat model 2 elegantly where you control the launcher, but it's an environment-management discipline this plugin can't impose; the ask-with-pin-hint teaches the equivalent habit per command.
