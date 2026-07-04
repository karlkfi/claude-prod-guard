# prod-guard

**Production-target guard rails for Claude Code Bash commands.**

[![release](https://img.shields.io/github/v/release/karlkfi/claude-prod-guard)](https://github.com/karlkfi/claude-prod-guard/releases) [![tests](https://img.shields.io/github/actions/workflow/status/karlkfi/claude-prod-guard/tests.yml?branch=main&label=tests)](https://github.com/karlkfi/claude-prod-guard/actions/workflows/tests.yml) [![License: MIT](https://img.shields.io/github/license/karlkfi/claude-prod-guard.svg)](LICENSE) [![Claude Code plugin](https://img.shields.io/badge/Claude_Code-plugin-7e57c2)](#install)

> Let Claude mutate kind and dev clusters all day. Stop it at prod.

You ask Claude to "clean up the failed rollout." It runs `kubectl delete ns
app-staging` — against whatever context `~/.kube/config` currently points at.
Or `terraform destroy` in a directory whose selected workspace is `prod`. Or
`gcloud compute instances delete` against the active gcloud project, which a
*parallel* Claude session just repointed with `gcloud config set project`.
The default `Bash(kubectl:*)` permission rules can't tell these apart from
the dozens of harmless dev-cluster commands Claude runs every session.

prod-guard is a `PreToolUse` hook for `Bash` that resolves where each
infrastructure command will actually land — the explicit `--context` /
`--project` / `--profile` flag if present, otherwise the tool's ambient
config — classifies that target against configurable patterns, and:

- **blocks** mutating commands aimed at a **production** target;
- **prompts** for mutating commands whose target is **unknown** or comes
  from **shared ambient state** a parallel session can silently repoint;
- **stays silent** for everything else, so your normal permissions apply.

## Contents

- [The two threat models](#the-two-threat-models)
- [What it does](#what-it-does)
- [Install](#install)
- [Upgrade](#upgrade)
- [Covered tools](#covered-tools)
- [Configuration](#configuration)
- [The override escape hatch](#the-override-escape-hatch)
- [Agent guidance: avoiding prompts](#agent-guidance-avoiding-prompts)
- [Limitations](#limitations)
- [Companion plugins](#companion-plugins)
- [Design](#design)
- [Privacy](#privacy)
- [Contributing](#contributing)
- [License](#license)

## The two threat models

**1. Prod blast-radius.** A mutating verb whose *resolved* target is a
production environment. Explicit targeting doesn't prevent this —
`kubectl --context prod delete ns x` is perfectly explicit and perfectly
catastrophic. Only a guard that classifies the target can. prod-guard
hard-blocks (`deny`) these, with a deliberate [override](#the-override-escape-hatch)
for the rare intentional prod operation.

**2. Ambient-context clobbering.** A mutating command that doesn't pin its
target relies on shared mutable state: the kubeconfig `current-context`, the
active gcloud configuration, the docker context, the default AWS profile.
When several Claude Code sessions run in parallel — increasingly the normal
way to work — any of them can repoint that state between the moment a command
is written and the moment it runs. prod-guard prompts (`ask`) on these and
tells the agent which flag pins the target.

## What it does

The hook produces one of three outcomes per command (worst segment wins
across `&&`/`|`/`;`/`$( )` chains):

- **deny** — the command is blocked with a reason naming the resolved target
  and the override. This is the outcome for *mutating verb + production
  target*, however the target was resolved (explicit flag or ambient state).
- **ask** — Claude Code shows its standard permission prompt. This is the
  outcome for *mutating verb + unknown target* (fail closed: unknown is never
  silently allowed) and *mutating verb + ambient target* (the clobbering
  risk), and for commands that repoint shared state itself (`kubectl config
  use-context`, `kubectx`, `gcloud config set`, `az account set`,
  `docker context use`, `aws configure`, …).
- **defer** — the hook stays silent; your normal permission settings apply.
  This is the outcome for read-only verbs, non-production targets, and
  uncovered tools. prod-guard never emits `allow`, so it composes with other
  guards instead of overriding them.

| Command | Decision |
| --- | --- |
| `kubectl --context kind-ci delete pod x` | defer |
| `kubectl --context prod-us get pods` | defer |
| `helm template api ./chart` | defer |
| `terraform plan` | defer |
| `gcloud compute instances list --project acme-prod` | defer |
| `docker rm -f app` (local daemon) | defer |
| `kubectl --context prod-us delete ns x` | **deny** |
| `kubectl --context blue-2 delete ns x` (cluster server is `api.prod…`) | **deny** |
| `kubectl scale deploy x --replicas=0` (current-context is prod) | **deny** |
| `TF_WORKSPACE=prod terraform apply` | **deny** |
| `TF_WORKSPACE=dev terraform apply` (S3 backend bucket is `acme-prod-tfstate`) | **deny** |
| `gcloud compute instances delete vm1 --project acme-prod` | **deny** |
| `docker push registry.prod.acme.io/app:1` | **deny** |
| `ssh deploy@prod-web-1 uptime` | **deny** |
| `ssh dev-box uptime` | defer |
| `pulumi up --stack acme/prod` | **deny** |
| `pulumi up` (no stack pinned) | **ask** |
| `ansible-playbook -i inventories/prod site.yml` | **deny** |
| `ansible prod-db -m ping` (read-only module) | defer |
| `echo done && kubectl --context prod-us delete ns x` | **deny** |
| `bash -c 'kubectl --context prod-us delete ns x'` | **deny** |
| `kubectl delete pod x` (ambient kind context) | **ask** |
| `kubectl --context bluefin apply -f m.yaml` (unclassified) | **ask** |
| `terraform apply` (no workspace pinned) | **ask** |
| `aws s3 rm s3://bucket/key` (no profile pinned) | **ask** |
| `kubectl config use-context kind-ci` | **ask** |
| `kubectx prod-us` | **deny** |
| `PROD_GUARD_OVERRIDE=incident-42 kubectl --context prod-us delete ns x` | **ask** |

## Install

Install on any Claude Code surface that runs plugin `PreToolUse` hooks — the
CLI, the IDE extensions, or **Claude Code for Claude Desktop**.

**Claude Code (CLI or IDE extension)** — run the slash commands:

```
/plugin marketplace add karlkfi/claude-prod-guard
/plugin install prod-guard@prod-guard
```

**Claude Code for Claude Desktop** — use the **Customize** tab:

1. Open the **Customize** tab and go to its plugins / marketplaces section.
2. Add `karlkfi/claude-prod-guard` as a marketplace.
3. Find **prod-guard** in that marketplace, install it, and enable it.

After installing with either method:

- Requires `python3` on your PATH.
- Restart Claude Code (or `/reload-plugins`) so the hook is registered.
- **Add your real production identifiers to the config** — the built-in
  patterns catch names containing `prod`/`production`/`prd`/`live`, but your
  GCP project ids, cluster names, and subscriptions deserve explicit
  patterns. See [Configuration](#configuration).

To verify, ask Claude to run `kubectl --context fake-prod delete ns test` —
it should be blocked with a prod-guard reason. A `kubectl --context kind-...
get pods` should run without any prod-guard output.

## Upgrade

prod-guard installs from a GitHub marketplace, which Claude Code tracks at
the repository's default branch (`main`). It does **not** auto-update by
default:

```
/plugin marketplace update prod-guard
/plugin uninstall prod-guard@prod-guard
/plugin install prod-guard@prod-guard
```

Then `/reload-plugins` (or restart) and compare the `/plugin` menu's
installed version against the
[latest release](https://github.com/karlkfi/claude-prod-guard/releases).

## Covered tools

For each tool the guard knows the **explicit target flag**, the **ambient
state** consulted when the flag is absent, and which verbs mutate. Verbs the
tables have never heard of are treated as **mutating** — when unsure, the
guard errs toward a prompt, because a missed destructive form is the failure
mode that matters.

| Tool | Explicit target | Ambient fallback |
| --- | --- | --- |
| `kubectl`, `oc`, `flux` | `--context` | `current-context` in `$KUBECONFIG` / `~/.kube/config`; `oc login` / `oc project` prompt as kubeconfig writers. A context resolves to its cluster's `server:` URL in the kubeconfig, which is classified alongside the context name — so a prod cluster reached through an innocuously named context is still denied |
| `helm` | `--kube-context` | same kubeconfig `current-context` |
| `gcloud` | `--project` / `--zone` / `--region` / `--account`, `CLOUDSDK_CORE_PROJECT` | project of the active gcloud configuration |
| `aws`, `eksctl` | `--profile` / `--region`, `AWS_PROFILE` | the default profile (never read — always prompts) |
| `az` | `--subscription` | default subscription in `~/.azure/azureProfile.json` |
| `terraform` / `tofu` | `TF_WORKSPACE` | `.terraform/environment` in the working dir; the initialized backend's state location (S3/GCS bucket, Terraform Cloud org/workspace) from `.terraform/terraform.tfstate` is classified too, so a prod state location denies even behind an innocuous workspace name; `apply`/`destroy` are always treated as mutating |
| `docker`, `podman`, `nerdctl`, `docker-compose` | `--context` / `--connection`, `DOCKER_HOST` / `CONTAINER_HOST` | `currentContext` in `~/.docker/config.json`; a local-daemon context defers. `docker push` classifies the image ref's registry; `build --push` classifies **every** `-t` tag; `compose push` fails closed (the registry lives in the compose file, which the hook doesn't parse) |
| `gh` | `-R`/`--repo`, `GH_REPO` | the cwd repo's `origin` remote (denylist-only — see [Limitations](#limitations)) |
| `ssh` | destination host (`user@host`, `-J` jump host) | n/a — denylist-only: a prod destination is denied, everything else defers (see [Limitations](#limitations)) |
| `argocd` | `--server` | `current-context` in `~/.config/argocd/config` |
| `doctl` | `--context` | the doctl auth context (never read — always prompts) |
| `pulumi` | `--stack` / `-s` | the selected stack (never read — always prompts); `pulumi stack select` prompts (denies for a prod stack) |
| `ansible`, `ansible-playbook` | `-i` / `--inventory`, `--limit`, and (ad-hoc) the host pattern | `ANSIBLE_INVENTORY`, then `[defaults] inventory` in `ansible.cfg`. The inventory is the target; `--limit`/pattern can only *escalate* to a prod deny. `--syntax-check`/`--list-hosts`/`--list-tasks`/`--list-tags` and ad-hoc `-m ping`/`setup`/`debug` are read-only |
| `kubectx` / `kubens` | n/a | switching contexts/namespaces *is* the shared-state mutation; prompts (denies for a prod context) |
| `kustomize` | n/a | local-only tool; always defers (the `kubectl apply` it pipes into is guarded separately) |

Ambient resolution is **pure local string work** — the guard parses the flag
or reads the tool's local config file. It never runs the tool, never makes a
network call, never touches a cluster.

Compound commands are split and each segment evaluated: `&&`, `||`, `|`,
`;`, `&`, newlines, subshells, `$(...)`, backticks, plus `bash|sh|zsh -c
'...'` bodies, `eval`, and wrappers (`sudo`, `env`, `timeout`, `xargs`,
`nohup`, `time`). A guard that only inspected the first token would be
trivially bypassed by `echo hi && kubectl --context prod delete ns x`.

## Configuration

Targets are classified by two regex lists (Python syntax, case-insensitive,
searched — not anchored):

- **prod** patterns — a match means PROD. Built-ins: word-bounded
  `prod`/`production`/`prd`/`live`.
- **nonprod** patterns — a match means NON-PROD, checked only after the prod
  list (a name matching both classifies PROD). Built-ins: `kind-`/`k3d-`
  prefixes, `minikube`, `docker-desktop`, `colima`, `rancher-desktop`,
  `orbstack`, `localhost`, `127.0.0.1`, and word-bounded
  `dev`/`test`/`qa`/`e2e`/`ci`/`sandbox`/`stage`/`staging`/`stg`/`local`/`demo`/`lab`/`preview`/`scratch`.

**No match means UNKNOWN, and unknown + mutating prompts.** The default is
fail-closed: the guard never silently allows a mutation to a target it can't
classify. Classify your environments instead of approving the same prompt
repeatedly.

Patterns are merged from all of these (all additive — config can extend the
built-ins, never shrink them):

| Source | Purpose |
| --- | --- |
| `~/.claude/prod-guard.json` | user-level patterns (your orgs' naming) |
| `<project>/.claude/prod-guard.json` | project-level patterns — **versioned and reviewable**, commit it |
| `PROD_GUARD_CONFIG=<path>` | an extra config file |
| `PROD_GUARD_PROD_PATTERNS` / `PROD_GUARD_NONPROD_PATTERNS` | inline patterns, `;`- or newline-separated |

Config file schema:

```json
{
  "prod": ["^gke_acme-platform-prod_", "^acme-(platform|data)-prod", "argocd\\.acme\\.io"],
  "nonprod": ["^gke_acme-platform-dev_", "^acme-sandbox-"]
}
```

A malformed config file loses only itself — the built-in patterns still
apply, so a typo never removes the boundary (fail-open on infrastructure,
fail-closed on the decision).

`PROD_GUARD_DISABLE=1` in the session environment disables the hook entirely
(for CI runs that manage their own credentials scoping, for example).

## The override escape hatch

An intentional production operation should be one deliberate step, not
impossible. Prefixing the command with `PROD_GUARD_OVERRIDE=<reason>`
downgrades a **deny** to an **ask**, so a human still confirms it:

```
PROD_GUARD_OVERRIDE=incident-4711-approved kubectl --context prod-us delete pod stuck-pod
```

The deny message names this escape hatch, so the agent can propose the
override — with its reason on the record in the command itself — and the
human approves or rejects the prompt. The override never turns a deny into a
silent allow, and it has no effect on plain asks.

## Agent guidance: avoiding prompts

Paste this into your project's `CLAUDE.md` (or `AGENTS.md`) so the agent
avoids the prompts instead of triggering them:

```markdown
## Avoiding prod-guard permission prompts

This machine uses prod-guard, a hook that blocks mutating infrastructure
commands aimed at production and prompts when a mutating command relies on
ambient context. To keep work flowing:

- **Pin the target on every mutating command**: `kubectl --context <ctx>`,
  `helm --kube-context <ctx>`, `gcloud --project <id>`,
  `aws --profile <name>`, `az --subscription <id>`,
  `TF_WORKSPACE=<ws> terraform ...`, `docker --context <ctx>`,
  `pulumi --stack <name>`, `ansible-playbook -i <inventory>`. Relying on
  the current context/config prompts every time — a parallel session can
  repoint it.
- **Don't switch shared context** (`kubectl config use-context`, `kubectx`,
  `gcloud config set project`, `az account set`, `docker context use`) —
  that repoints every parallel session. Pin per command instead.
- **Unknown targets prompt.** If a legitimate non-prod target keeps
  prompting, add it to `.claude/prod-guard.json` under `"nonprod"` instead
  of approving repeatedly.
- **Production mutations are blocked.** If one is genuinely intended, ask
  the user; with their sign-off, prefix the command with
  `PROD_GUARD_OVERRIDE=<reason>` and they will confirm via the prompt.
```

## Limitations

- **False negatives are possible; treat the guard as a net, not a wall.**
  Only the listed tools are covered — a mutation through an uncovered CLI
  (a vendor CLI, `pulumi env`, `ansible-pull`) or through a
  script/Makefile that the command merely names (`make deploy`,
  `./scripts/release.sh`) is invisible to the hook. Wrapped commands that
  resolve their own targets are usually the *safe* path — the guard exists
  for the ad-hoc commands.
- **Classification is by name — plus, for kube-contexts, the cluster's
  server URL.** A production context charmingly named `blue-cluster-2` is
  caught if its kubeconfig `server:` URL matches a prod pattern (e.g.
  `https://api.prod-us.example.com`); if the URL is also unremarkable it stays
  UNKNOWN (prompted, not denied) until you add a pattern. The fail-closed
  default means unknown never silently passes, but the hard block needs your
  patterns to know what "prod" means in your org. Server resolution covers
  `kubectl`/`oc`/`flux`/`helm` and context switches (`kubectx`,
  `kubectl config use-context`); other tools classify by name only.
- `gh` and `ssh` are denylist-only: their target is pinned on the command
  line (gh's repo remote, ssh's destination host), not clobber-prone shared
  state, and prompting on every `gh pr create` or `ssh dev-box` would be pure
  noise. Each is only blocked when the resolved target matches a prod pattern
  — an unknown host or repo defers rather than prompting. Any `ssh` into a
  prod host is treated as mutating: an interactive prod shell is the blast
  radius, and a read-only remote command can't be distinguished from a
  destructive one.
- The AWS default profile, doctl auth context, and pulumi's selected stack
  are not read from disk; a mutating command relying on them always prompts
  rather than resolving the ambient value (`pulumi stack select <prod>` is
  still denied, so choosing a prod stack is caught).
- Ambient state is read at *hook* time; a race remains between the hook's
  check and the command's execution. Pinning the target with a flag — which
  the ask message steers toward — is the real fix; the prompt exists to
  force that choice.
- Command parsing is intentionally conservative: an operator inside a quoted
  string can split a segment and produce a spurious prompt (never a missed
  one). Heredoc bodies mentioning covered tools may likewise prompt.
- In full-auto `bypassPermissions` mode there is no one to answer an ask, so
  asks are emitted as denies — equally blocking, but the agent gets the
  reason and can re-route instead of stalling.

## Companion plugins

prod-guard watches the **infrastructure blast-radius** boundary. Two sibling
plugins guard different axes with the same secure-by-default design:

- [**workspace-guard**](https://github.com/karlkfi/claude-workspace-guard) —
  the **filesystem** boundary: prompts before guarded file commands
  (`grep`/`sed`/`cat`/`cp`/`rm`/…) read or write paths outside the project
  root.
- [**branch-guard**](https://github.com/karlkfi/claude-branch-guard) — the
  **git history** boundary: auto-approves safe git on feature branches,
  pauses commits/pushes to `main` and destructive git.

All three run side by side; each defers to normal permissions outside its
own axis.

```
/plugin marketplace add karlkfi/claude-workspace-guard
/plugin install workspace-guard@workspace-guard
/plugin marketplace add karlkfi/claude-branch-guard
/plugin install branch-guard@claude-branch-guard
```

## Design

For the rationale behind the approach (why deny for prod when the siblings
default to ask, why fail-closed on unknown targets, why local file reads
instead of asking the tools, what alternatives were rejected), see
[`docs/design.md`](docs/design.md).

## Privacy

The hook runs entirely on your machine and has no network access, telemetry,
or analytics. It reads the pending Bash command and, when needed, single
values from local CLI config files (kubeconfig `current-context`, gcloud
active config, docker `currentContext`, azure default subscription, the
`origin` remote URL), decides in memory, and writes nothing to disk. See
[`PRIVACY.md`](PRIVACY.md) for the full policy.

## Contributing

Bugs, ideas, and questions go in
[GitHub Issues](https://github.com/karlkfi/claude-prod-guard/issues).
For the development backlog, see [`docs/STATUS.md`](docs/STATUS.md).

## License

MIT — see [LICENSE](LICENSE).
