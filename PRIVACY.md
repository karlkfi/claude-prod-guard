# Privacy Policy — prod-guard

_Last updated: 2026-07-04_

prod-guard is a Claude Code plugin that runs entirely on your local machine
as a `PreToolUse` hook. Its only job is to block or add a confirmation
prompt before certain Bash commands mutate infrastructure targets.

## Data we collect

None. The plugin has no analytics, no telemetry, and no network access. It
ships as a single Python script that uses only the standard library.

## How your data is handled

- The hook receives the Bash command Claude Code is about to run (via
  standard input), the working directory, plus a few optional `PROD_GUARD_*`
  configuration values (via environment variables).
- To resolve a command's ambient target it may read single values from local
  CLI config files you already have: the `current-context` line of your
  kubeconfig, the project of your active gcloud configuration, the
  `currentContext` of `~/.docker/config.json`, the default subscription in
  `~/.azure/azureProfile.json`, the `current-context` of
  `~/.config/argocd/config`, the `.terraform/environment` workspace file,
  and (for `gh` commands) the repository's `origin` remote URL via a local
  `git config` read.
- It processes these **in memory** to decide deny / ask / defer, then writes
  the decision to standard output. It does **not** read credentials, tokens,
  or any other content from those files.
- It never runs the guarded tools, never contacts a cluster or cloud API,
  and writes nothing to disk.

## Third parties

The plugin makes no network connections and shares no data with any third
party.
