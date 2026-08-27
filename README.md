# prod-guard

**This repository is archived and read-only. prod-guard now ships from
[karlkfi/claude-bouncer](https://github.com/karlkfi/claude-bouncer).**

```
/plugin marketplace add karlkfi/claude-bouncer
/plugin install prod-guard@claude-bouncer
```

Those two lines replace the pair this repo used to document. The plugin itself
did not change — same hooks, same `~/.claude/prod-guard.json` and
`.claude/prod-guard.json`, same `PROD_GUARD_OVERRIDE=<reason>` prefix, same
session-scoped grants, same `/prod-guard:friction-report`. Nothing in your own
repo needs editing.

The five guards — `workspace-guard`, `branch-guard`, `prod-guard`,
`exit-status-guard`, `foreground-guard` — all parse the same Bash command
strings, and were re-implementing that parser five times over. They share one
now, so they share a repository, a test suite, and a release pipeline.

## Where the docs went

[`plugins/prod-guard`](https://github.com/karlkfi/claude-bouncer/tree/main/plugins/prod-guard)
in claude-bouncer: the two threat models, decision table, covered tools,
configuration, the override escape hatch, friction report.

Read that rather than anything in this repo. The last release here was `v2.5.1`
and the copy in claude-bouncer is ahead of it. No verdict moved across that
bump — but the deny reasons did, and so did the friction report's tallies, so
the pages under `docs/` here quote text the shipping plugin no longer emits.

## Switching an existing install

The marketplace name changes from `prod-guard` to `claude-bouncer`, so an
existing install has to be removed and re-added — an update will not cross that
boundary, and the old marketplace still clones fine, so nothing tells you it has
gone quiet:

```
claude plugin uninstall prod-guard@prod-guard
claude plugin marketplace remove prod-guard
claude plugin marketplace add karlkfi/claude-bouncer
claude plugin install prod-guard@claude-bouncer
```

Restart Claude Code (or `/reload-plugins`) to apply. The `/plugin` menu does the
same four steps interactively, on the CLI, the IDE extensions, and Claude Code
for Claude Desktop.

**Repoint auto-update too.** If you followed the old install instructions you
have an `extraKnownMarketplaces` entry in `~/.claude/settings.json` naming this
repository, and it will go on refreshing a marketplace that will never publish
another release. Replace it:

```json
{
  "extraKnownMarketplaces": {
    "claude-bouncer": {
      "source": { "source": "git", "url": "https://github.com/karlkfi/claude-bouncer.git" },
      "autoUpdate": true
    }
  }
}
```

A stale pin has teeth on this plugin in particular: the classifier is what
decides whether a mutation reaches production, so a version left behind is
missing later false-negative fixes rather than conveniences.

The four sibling guards are one `install` line each against that same
marketplace — see the
[claude-bouncer README](https://github.com/karlkfi/claude-bouncer#install).

## What is still here

History, and the links that point into it. Archiving keeps every issue, pull
request and tag resolving; it does not delete them. New issues and pull requests
belong on
[claude-bouncer](https://github.com/karlkfi/claude-bouncer/issues). The
pre-move documentation is readable at the
[`v2.5.1`](https://github.com/karlkfi/claude-prod-guard/tree/v2.5.1) tag.

## License

[MIT](LICENSE)
