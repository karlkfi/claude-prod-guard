#!/usr/bin/env python3
"""PreToolUse hook: block mutating commands aimed at production targets and
prompt when a mutating command relies on shared ambient context.

Two distinct threat models, kept distinct in the code:

1. **Prod blast-radius** — a mutating verb (`kubectl delete`, `terraform
   destroy`, `gcloud ... update`) whose *resolved* target is a production
   environment. Explicit targeting does not prevent this — `kubectl --context
   prod delete ns x` is explicit AND catastrophic — so the guard classifies
   the resolved target against a configurable denylist and hard-blocks
   (`deny`) mutations that land on prod.

2. **Ambient-context clobbering** — a mutating command that relies on shared
   mutable state (the kubeconfig current-context, the active gcloud config,
   the docker context, the default aws profile) instead of pinning its
   target. A parallel session can repoint that state between the moment the
   command is written and the moment it runs, silently redirecting the
   mutation. The guard prompts (`ask`) and tells the caller to pin the target
   with the tool's flag.

Decision semantics (per simple command; worst verdict wins across a chain):

  * read-only verb, uncovered tool, or non-prod explicit target -> **defer**
    (no output; normal permission settings apply — this guard never emits
    `allow`, so it composes with other guards instead of overriding them).
  * mutating verb + target classified PROD                      -> **deny**,
    downgradable to `ask` with a `PROD_GUARD_OVERRIDE=<reason>` prefix.
  * mutating verb + explicit target that matches no pattern     -> **ask**
    (fail CLOSED on the security decision: unknown is never silently allowed).
  * mutating verb + no explicit target (ambient context)        -> **ask**
    (deny if the ambient value itself classifies PROD).
  * context-switching commands (`kubectl config use-context`, `kubectx`,
    `docker context use`, `gcloud config set`, `az account set`, ...) -> **ask**
    (deny when the new target classifies PROD): they mutate the very shared
    state threat model 2 is about.

Fail modes: fail OPEN on infrastructure errors (unparseable input, missing
config, unexpected exceptions — the hook stays silent and never breaks the
session), fail CLOSED on the security decision (unknown target + mutating
verb prompts). When unsure whether a verb mutates, it is treated as mutating:
false negatives (an unrecognized destructive form) are the failure mode to
fear; a false positive costs one keystroke.

Target classification is pure local string work: the guard parses the flag or
reads the tool's local config file (kubeconfig current-context, gcloud active
config, docker config.json, azure profile). It never makes a network or
cluster call.

Reads the hook JSON on stdin, emits a PreToolUse decision on stdout.
"""
import json
import os
import re
import shlex
import subprocess
import sys

# ---------------------------------------------------------------------------
# Target classification: PROD / NONPROD / UNKNOWN
# ---------------------------------------------------------------------------

# Built-in production patterns. A target matching any of these is PROD.
# Word-bounded so `prod` matches `gke_acme_prod-us` and `my-prod-cluster`
# but not `product-demo`... it DOES match `product` ("prod" + "uct" is
# blocked by the boundary? no — see the optional `(uction)?` group); the
# bias is deliberate: over-matching prod costs a prompt, under-matching
# costs an outage.
BUILTIN_PROD = [
    r'(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)',
    r'(^|[^a-z0-9])prd([^a-z0-9]|$)',
    r'(^|[^a-z0-9])live([^a-z0-9]|$)',
]

# Built-in non-production patterns: local cluster providers, loopback
# registries, and the common environment names. Checked only after the prod
# list — a name matching both (e.g. `prod-staging-mirror`) classifies PROD.
BUILTIN_NONPROD = [
    r'^kind-', r'^k3d-', r'minikube', r'docker-desktop', r'desktop-linux',
    r'colima', r'rancher-desktop', r'orbstack',
    r'localhost', r'127\.0\.0\.1', r'\[::1\]',
    r'(^|[^a-z0-9])(dev|develop|development|test|testing|qa|e2e|ci|sandbox|sbx'
    r'|stage|staging|stg|local|demo|lab|preview|scratch)([^a-z0-9]|$)',
]

_PATTERNS = None  # (prod_compiled, nonprod_compiled), loaded lazily


def _config_paths():
    """Candidate config files, later entries win nothing — all are additive."""
    paths = []
    home = os.environ.get('HOME')
    if home:
        paths.append(os.path.join(home, '.claude', 'prod-guard.json'))
    proj = os.environ.get('CLAUDE_PROJECT_DIR')
    if proj:
        paths.append(os.path.join(proj, '.claude', 'prod-guard.json'))
    extra = os.environ.get('PROD_GUARD_CONFIG')
    if extra:
        paths.append(extra)
    return paths


def _load_config_file(path):
    """Read {"prod": [...], "nonprod": [...]} from a JSON config file.

    Any error (missing file, bad JSON, wrong shape) loses only that source:
    fail-open on config infrastructure, but the built-in patterns still apply
    so the boundary never disappears because of a typo.
    """
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        prod = [p for p in data.get('prod', []) if isinstance(p, str)]
        nonprod = [p for p in data.get('nonprod', []) if isinstance(p, str)]
        return prod, nonprod
    except (OSError, ValueError, AttributeError):
        return [], []


def _split_pattern_list(raw):
    """Split an env-var pattern list on `;` or newlines (regexes may contain
    `,` and `:`, the separators sibling guards use for path lists)."""
    return [p.strip() for p in re.split(r'[;\n]', raw or '') if p.strip()]


def _compile(patterns):
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue  # a broken pattern loses itself, not the whole list
    return out


def load_patterns():
    """Merge built-ins + user file + project file + PROD_GUARD_CONFIG file
    + PROD_GUARD_{PROD,NONPROD}_PATTERNS env vars. Everything is additive:
    config can only extend the lists, never shrink the built-ins — narrowing
    the boundary must be a code change, not a config drift."""
    global _PATTERNS
    if _PATTERNS is not None:
        return _PATTERNS
    prod = list(BUILTIN_PROD)
    nonprod = list(BUILTIN_NONPROD)
    for path in _config_paths():
        p, n = _load_config_file(path)
        prod += p
        nonprod += n
    prod += _split_pattern_list(os.environ.get('PROD_GUARD_PROD_PATTERNS'))
    nonprod += _split_pattern_list(os.environ.get('PROD_GUARD_NONPROD_PATTERNS'))
    _PATTERNS = (_compile(prod), _compile(nonprod))
    return _PATTERNS


def classify(value):
    """'prod' | 'nonprod' | 'unknown' for a target string (context name,
    project id, profile, subscription, registry ref, repo slug...).

    Prod patterns are checked first so an ambiguous name fails toward the
    stricter class. No match at all is 'unknown' — which the policy treats
    as ask, never allow (deny-on-unknown / fail-closed)."""
    if not value:
        return 'unknown'
    prod_res, nonprod_res = load_patterns()
    for rx in prod_res:
        if rx.search(value):
            return 'prod'
    for rx in nonprod_res:
        if rx.search(value):
            return 'nonprod'
    return 'unknown'


# ---------------------------------------------------------------------------
# Shell parsing: raw command string -> simple commands
# ---------------------------------------------------------------------------

# Every char shlex treats as punctuation with punctuation_chars enabled.
# A token built only from these is a separator/operator run, never a word.
PUNCT_CHARS = frozenset(';()<>|&\n')

ASSIGNMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')

# Shells whose `-c <string>` argument is itself a command to evaluate.
SHELL_NAMES = frozenset({'bash', 'sh', 'zsh', 'dash', 'ksh'})

# Wrappers that prefix another command without changing its meaning for our
# purposes. `xargs` is handled separately (it takes its own flags).
PLAIN_WRAPPERS = frozenset({'command', 'nohup', 'time', 'builtin', 'exec'})


def tokenize(raw):
    """shlex-tokenize with POSIX quoting and punctuation grouping. Backticks
    and newlines are rewritten to `;` first: a backtick-substituted command
    must split into its own simple command instead of hiding inside a word,
    and shlex treats a newline as plain whitespace, which would merge
    `true\ncmd` into one segment (`$(...)` needs no rewrite — `(` / `)` are
    punctuation chars and act as separators). Rewriting inside quotes only
    ever creates extra segments to inspect, never hides one. Returns None on
    unbalanced quotes (caller defers: fail-open on parse errors)."""
    raw = raw.replace('`', ';').replace('\n', ';')
    lex = shlex.shlex(raw, posix=True, punctuation_chars=';()<>|&\n')
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None


def split_simple_commands(tokens):
    """Split a token stream into simple commands on every operator token.

    Any all-punctuation token — `&&`, `|`, `;`, `(`, `)`, and also redirects
    like `>` — ends the current simple command. Treating a redirect as a hard
    break is deliberately crude: the redirect target becomes a one-token
    "command" that matches no covered tool and is ignored, while a covered
    tool AFTER any operator still gets its own segment. Crude splitting only
    ever creates extra segments to inspect (false-positive direction), never
    hides one (false-negative direction)."""
    groups, cur = [], []
    for t in tokens:
        if t and all(c in PUNCT_CHARS for c in t):
            if cur:
                groups.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        groups.append(cur)
    return groups


def extract_env_prefix(argv):
    """Peel leading NAME=VALUE assignments off a simple command. Returns
    (env_dict, remaining_argv). The assignments matter twice over: they can
    pin a target (AWS_PROFILE=dev, TF_WORKSPACE=prod) and they can carry the
    PROD_GUARD_OVERRIDE escape hatch."""
    env = {}
    i = 0
    while i < len(argv) and ASSIGNMENT_RE.match(argv[i]):
        name, _, value = argv[i].partition('=')
        env[name] = value
        i += 1
    return env, argv[i:]


def strip_wrappers(argv, env):
    """Remove leading launcher commands (sudo, env, timeout, xargs, ...) so
    the covered tool underneath is classified, not the wrapper. `env`
    assignments found behind `env`/`sudo` merge into the segment env."""
    while argv:
        head = os.path.basename(argv[0])
        if head == 'sudo':
            argv = argv[1:]
            while argv and argv[0].startswith('-'):
                # value-taking sudo flags: skip flag + value
                if argv[0] in ('-u', '--user', '-g', '--group', '-p', '--prompt'):
                    argv = argv[2:]
                else:
                    argv = argv[1:]
        elif head == 'env':
            argv = argv[1:]
            while argv:
                if argv[0].startswith('-'):
                    argv = argv[2:] if argv[0] in ('-u', '--unset', '-C', '--chdir') else argv[1:]
                elif ASSIGNMENT_RE.match(argv[0]):
                    name, _, value = argv[0].partition('=')
                    env[name] = value
                    argv = argv[1:]
                else:
                    break
        elif head == 'timeout':
            argv = argv[1:]
            while argv and argv[0].startswith('-'):
                argv = argv[2:] if argv[0] in ('-k', '--kill-after', '-s', '--signal') else argv[1:]
            if argv:
                argv = argv[1:]  # the DURATION operand
        elif head == 'xargs':
            # Skip xargs and everything up to the first covered tool; if none
            # appears the segment holds nothing we guard.
            rest = argv[1:]
            for i, t in enumerate(rest):
                if os.path.basename(t) in COVERED_TOOLS or os.path.basename(t) in SHELL_NAMES:
                    return rest[i:]
            return []
        elif head in PLAIN_WRAPPERS:
            argv = argv[1:]
            while argv and argv[0].startswith('-'):
                argv = argv[1:]
        else:
            break
    return argv


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def flag_values(argv, names):
    """Collect values for the given long/short flags, handling both
    `--flag value` and `--flag=value`. Returns {flag_name: value}."""
    out = {}
    nameset = set(names)
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in nameset and i + 1 < len(argv):
            out[tok] = argv[i + 1]
            i += 2
            continue
        if '=' in tok:
            head, _, val = tok.partition('=')
            if head in nameset:
                out[head] = val
        i += 1
    return out


def first_flag_value(argv, names):
    vals = flag_values(argv, names)
    for n in names:
        if n in vals:
            return vals[n]
    return None


def words_of(argv, value_flags=()):
    """Non-flag tokens of a simple command, with the values of known
    value-taking flags removed so `-n foo` doesn't surface `foo` as a verb.
    Unknown value-taking flags leak their value into the word list; that only
    ever errs toward 'mutating' (the conservative direction)."""
    vf = set(value_flags)
    out = []
    i = 1  # skip argv[0], the tool itself
    while i < len(argv):
        tok = argv[i]
        if tok in vf:
            i += 2
            continue
        if tok.startswith('-'):
            i += 1
            continue
        out.append(tok)
        i += 1
    return out


# ---------------------------------------------------------------------------
# Ambient context readers — pure local file reads, no subprocesses except a
# single `git config` lookup for gh (local, no network), no cluster calls.
# ---------------------------------------------------------------------------

def kube_current_context(seg_env):
    """current-context from $KUBECONFIG (first path) or ~/.kube/config."""
    kc = seg_env.get('KUBECONFIG') or os.environ.get('KUBECONFIG')
    if kc:
        path = kc.split(':')[0]
    else:
        home = os.environ.get('HOME')
        if not home:
            return None
        path = os.path.join(home, '.kube', 'config')
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                m = re.match(r'^current-context:\s*["\']?([^"\'\n#]+)', line)
                if m:
                    return m.group(1).strip() or None
    except OSError:
        return None
    return None


def gcloud_active_project():
    """Project of the active gcloud configuration, read from the local config
    files (never `gcloud config list`, which is slow and can hit the net)."""
    cfg_dir = os.environ.get('CLOUDSDK_CONFIG')
    if not cfg_dir:
        home = os.environ.get('HOME')
        if not home:
            return None
        cfg_dir = os.path.join(home, '.config', 'gcloud')
    name = os.environ.get('CLOUDSDK_ACTIVE_CONFIG_NAME')
    if not name:
        try:
            with open(os.path.join(cfg_dir, 'active_config'), encoding='utf-8') as f:
                name = f.read().strip()
        except OSError:
            name = 'default'
    try:
        with open(os.path.join(cfg_dir, 'configurations', 'config_' + name),
                  encoding='utf-8') as f:
            for line in f:
                m = re.match(r'^\s*project\s*=\s*(\S+)', line)
                if m:
                    return m.group(1)
    except OSError:
        return None
    return None


def docker_current_context():
    """currentContext from ~/.docker/config.json (or $DOCKER_CONFIG)."""
    cfg_dir = os.environ.get('DOCKER_CONFIG')
    if not cfg_dir:
        home = os.environ.get('HOME')
        if not home:
            return None
        cfg_dir = os.path.join(home, '.docker')
    try:
        with open(os.path.join(cfg_dir, 'config.json'), encoding='utf-8') as f:
            return json.load(f).get('currentContext')
    except (OSError, ValueError):
        return None


def argocd_current_context():
    """current-context from the argocd CLI config."""
    home = os.environ.get('HOME')
    if not home:
        return None
    path = os.path.join(home, '.config', 'argocd', 'config')
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                m = re.match(r'^current-context:\s*["\']?([^"\'\n#]+)', line)
                if m:
                    return m.group(1).strip() or None
    except OSError:
        return None
    return None


def az_default_subscription():
    """Name of the default subscription in ~/.azure/azureProfile.json.
    Azure CLI writes the file with a UTF-8 BOM, hence utf-8-sig."""
    home = os.environ.get('HOME')
    if not home:
        return None
    path = os.path.join(home, '.azure', 'azureProfile.json')
    try:
        with open(path, encoding='utf-8-sig') as f:
            data = json.load(f)
        for sub in data.get('subscriptions', []):
            if sub.get('isDefault'):
                return sub.get('name') or sub.get('id')
    except (OSError, ValueError, AttributeError):
        return None
    return None


def git_remote_url(cwd):
    """origin URL of the repo at cwd — gh's implied target. A local `git
    config` read (worktree-aware), never a network call."""
    try:
        r = subprocess.run(
            ['git', '-C', cwd or '.', 'config', '--get', 'remote.origin.url'],
            capture_output=True, text=True, timeout=3, check=False)
        url = r.stdout.strip()
        return url or None
    except (OSError, subprocess.SubprocessError):
        return None


def terraform_workspace(cwd):
    """Workspace pinned by the working directory's .terraform/environment
    file (what `terraform workspace select` writes). Absent -> None."""
    try:
        with open(os.path.join(cwd or '.', '.terraform', 'environment'),
                  encoding='utf-8') as f:
            ws = f.read().strip()
            return ws or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Findings and policy
# ---------------------------------------------------------------------------

ASK, DENY = 1, 2

CONFIG_HINT = ('Patterns: built-ins plus .claude/prod-guard.json '
               '(see the prod-guard README).')


def deny_prod(action, target_desc):
    return (DENY,
            'prod-guard: `%s` targets %s, which matches a production pattern. '
            'Mutating commands against production targets are blocked. If this '
            'is intentional, prefix the command with PROD_GUARD_OVERRIDE=<reason> '
            'to downgrade the block to a confirmation prompt. %s'
            % (action, target_desc, CONFIG_HINT))


def ask_unknown(action, target_desc):
    return (ASK,
            'prod-guard: `%s` targets %s, which matches neither a production '
            'nor a non-production pattern — unknown targets are never silently '
            'allowed. Confirm it is safe, or add a nonprod pattern to '
            '.claude/prod-guard.json to classify it. %s'
            % (action, target_desc, CONFIG_HINT))


def ask_ambient(action, ambient_desc, pin_hint):
    return (ASK,
            'prod-guard: `%s` relies on %s — shared mutable state that a '
            'parallel session can repoint before this command runs. Pin the '
            'target explicitly (%s) to make the command unambiguous.'
            % (action, ambient_desc, pin_hint))


def ask_switch(action, what):
    return (ASK,
            'prod-guard: `%s` repoints %s, which is shared by every session '
            'on this machine — parallel sessions relying on ambient context '
            'will silently follow it. Prefer per-command pinning '
            '(--context/--project/--profile) over switching shared state.'
            % (action, what))


def policy(action, explicit_value, explicit_desc,
           ambient_value, ambient_desc, pin_hint):
    """The shared decision matrix for a mutating verb, given how the target
    resolved. Returns a finding tuple or None (defer)."""
    if explicit_value is not None:
        cls = classify(explicit_value)
        if cls == 'prod':
            return deny_prod(action, explicit_desc)
        if cls == 'nonprod':
            return None
        return ask_unknown(action, explicit_desc)
    # No explicit pin: the target is whatever the shared ambient state says.
    if ambient_value is not None:
        if classify(ambient_value) == 'prod':
            return deny_prod(action, ambient_desc + ' (ambient)')
        return ask_ambient(action, ambient_desc, pin_hint)
    return ask_ambient(action, ambient_desc, pin_hint)


# ---------------------------------------------------------------------------
# Per-tool verb tables and evaluators
# ---------------------------------------------------------------------------

def action_of(argv, words):
    """Human-readable label for a finding: the tool plus its first verbs,
    with flags elided so `kubectl --context prod-x delete ns` reads as
    `kubectl delete ns`."""
    return ' '.join([os.path.basename(argv[0])] + list(words[:3]))


# kubectl verbs that only read. Everything else — including verbs this table
# has never heard of — is treated as mutating (unsure => mutating).
KUBECTL_READONLY = frozenset({
    'get', 'describe', 'logs', 'top', 'explain', 'api-resources',
    'api-versions', 'version', 'cluster-info', 'diff', 'events', 'wait',
    'auth', 'completion', 'options', 'kustomize',
})
KUBECTL_CONFIG_READONLY = frozenset({
    'view', 'get-contexts', 'get-clusters', 'get-users', 'current-context',
})
# kube flags whose value must not be mistaken for a verb.
KUBE_VALUE_FLAGS = (
    '--context', '--kube-context', '--kubeconfig', '-n', '--namespace',
    '-o', '--output', '-f', '--filename', '-l', '--selector', '--cluster',
    '--user', '--server',
)

HELM_LOCAL_OR_READONLY = frozenset({
    'list', 'ls', 'status', 'get', 'history', 'show', 'inspect', 'search',
    'template', 'lint', 'version', 'env', 'verify', 'pull', 'fetch',
    'dependency', 'repo', 'registry', 'plugin', 'create', 'package',
    'completion', 'docs', 'help',
})

FLUX_READONLY = frozenset({
    'get', 'logs', 'version', 'check', 'tree', 'events', 'stats', 'trace',
    'export', 'diff', 'build', 'completion',
})

TF_READONLY = frozenset({
    'plan', 'validate', 'fmt', 'show', 'output', 'graph', 'version', 'init',
    'get', 'console', 'providers', 'metadata',
})

DOCKER_READONLY = frozenset({
    'ps', 'images', 'inspect', 'logs', 'version', 'info', 'history', 'top',
    'stats', 'diff', 'events', 'search', 'port', 'save', 'wait',
})

GH_READONLY = frozenset({
    'list', 'view', 'status', 'checks', 'diff', 'download', 'search',
    'browse', 'version', 'auth', 'help', 'completion', 'clone', 'checkout',
})

ARGOCD_MUTATING = frozenset({
    'sync', 'create', 'delete', 'set', 'unset', 'rollback', 'patch', 'edit',
    'terminate-op', 'update', 'add', 'rm', 'remove', 'run',
})
ARGOCD_READONLY = frozenset({
    'list', 'get', 'version', 'logs', 'history', 'resources', 'manifests',
    'diff', 'wait',
})

EKSCTL_READONLY = frozenset({'get', 'version', 'info', 'completion', 'help'})

DOCTL_MUTATING = frozenset({
    'create', 'delete', 'rm', 'update', 'resize', 'reboot', 'power-on',
    'power-off', 'power-cycle', 'shutdown', 'rebuild', 'restore', 'migrate',
    'upgrade', 'save', 'set', 'remove', 'add', 'attach', 'detach',
})
DOCTL_READONLY = frozenset({'list', 'ls', 'get', 'version', 'help'})

# gcloud/aws/az verbs are matched by token scan: a mutating match anywhere in
# the command wins over a read-only match (conservative on mixed signals).
GCLOUD_MUTATING_PREFIXES = (
    'create', 'delete', 'update', 'deploy', 'set-', 'add-', 'remove-',
    'import', 'restart', 'resize', 'promote', 'failover', 'rotate', 'reset',
    'cancel', 'submit', 'patch', 'enable', 'disable', 'attach', 'detach',
    'migrate', 'ssh', 'scp', 'apply', 'start', 'stop', 'restore', 'purge',
    'drain', 'suspend', 'resume', 'upgrade', 'rollback', 'abandon', 'copy-',
    'run-', 'execute', 'invoke', 'trigger',
)
GCLOUD_READONLY = frozenset({
    'list', 'describe', 'help', 'info', 'version', 'topic', 'export',
    'config-helper',
})
GCLOUD_READONLY_PREFIXES = ('print-', 'get-')

AWS_MUTATING_PREFIXES = (
    'create-', 'delete-', 'update-', 'put-', 'terminate-', 'stop-', 'start-',
    'reboot-', 'modify-', 'attach-', 'detach-', 'associate-', 'disassociate-',
    'run-', 'invoke', 'publish', 'purge-', 'set-', 'tag-', 'untag-',
    'register-', 'deregister-', 'enable-', 'disable-', 'restore-', 'reset-',
    'rotate-', 'cancel-', 'revoke-', 'authorize-', 'import-', 'copy-',
    'promote-', 'replace-', 'reencrypt', 'batch-write', 'batch-delete',
    'send-', 'execute-', 'admin-',
)
AWS_MUTATING = frozenset({'cp', 'mv', 'sync', 'rm', 'mb', 'rb'})
AWS_READONLY_PREFIXES = ('describe-', 'list-', 'get-', 'batch-get-', 'head-')
AWS_READONLY = frozenset({'ls', 'help', 'wait', 'presign'})

AZ_MUTATING = frozenset({
    'create', 'delete', 'update', 'set', 'add', 'remove', 'start', 'stop',
    'restart', 'deallocate', 'purge', 'import', 'deploy', 'assign', 'revoke',
    'invoke', 'exec', 'scale', 'upgrade', 'rotate', 'regenerate', 'reset',
    'cancel', 'approve', 'reject', 'enable', 'disable', 'attach', 'detach',
    'move', 'recover', 'restore', 'failover', 'run-command', 'repair',
})
AZ_READONLY = frozenset({
    'list', 'show', 'version', 'find', 'help', 'browse', 'wait', 'export',
})
AZ_READONLY_PREFIXES = ('get-', 'check-', 'list-')


def _scan_verb(tokens, mutating_exact=frozenset(), mutating_prefixes=(),
               readonly_exact=frozenset(), readonly_prefixes=()):
    """Token-scan verb classifier for multi-level CLIs (gcloud/aws/az/doctl).
    Returns ('mutating', token) / ('readonly', token) / ('unknown', None).
    Mutating matches win: on mixed signals the command is treated as
    mutating. Unknown is the caller's problem — and callers treat it as
    mutating too."""
    ro_hit = None
    mut_prefixes = tuple(mutating_prefixes)
    ro_prefixes = tuple(readonly_prefixes)
    for t in tokens:
        tl = t.lower()
        # str.startswith(()) is False, so empty prefix tuples are inert.
        if tl in mutating_exact or (mut_prefixes and tl.startswith(mut_prefixes)):
            return 'mutating', t
        if ro_hit is None and (
                tl in readonly_exact
                or (ro_prefixes and tl.startswith(ro_prefixes))):
            ro_hit = t
    if ro_hit is not None:
        return 'readonly', ro_hit
    return 'unknown', None


def _kube_target(argv, seg_env, context_flags):
    """(explicit_value, explicit_desc, ambient_value, ambient_desc) for a
    kubeconfig-based tool."""
    ctx = first_flag_value(argv, context_flags)
    if ctx is not None:
        return ctx, "kube-context '%s' (from %s)" % (ctx, context_flags[0]), None, ''
    ambient = kube_current_context(seg_env)
    if ambient is not None:
        desc = "the ambient kube-context (currently '%s')" % ambient
    else:
        desc = 'the ambient kube-context (unresolvable at hook time)'
    return None, '', ambient, desc


def eval_kubectl(argv, seg_env, ctx):
    words = words_of(argv, KUBE_VALUE_FLAGS)
    action = action_of(argv, words)
    verb = words[0] if words else None
    if verb is None:
        return []
    if verb == 'config':
        sub = words[1] if len(words) > 1 else None
        if sub in KUBECTL_CONFIG_READONLY:
            return []
        if sub == 'use-context':
            name = words[2] if len(words) > 2 else None
            if name and classify(name) == 'prod':
                return [deny_prod(action, "kube-context '%s'" % name)]
            return [ask_switch(action, 'the shared kubeconfig current-context')]
        # set/set-context/delete-context/rename-context/unset/...: mutations
        # of the shared kubeconfig itself.
        return [ask_switch(action, 'the shared kubeconfig')]
    if verb in KUBECTL_READONLY:
        return []
    if verb == 'rollout' and len(words) > 1 and words[1] in ('status', 'history'):
        return []
    explicit, edesc, ambient, adesc = _kube_target(argv, seg_env, ('--context',))
    f = policy(action, explicit, edesc, ambient, adesc, 'kubectl --context <ctx>')
    return [f] if f else []


def eval_helm(argv, seg_env, ctx):
    words = words_of(argv, KUBE_VALUE_FLAGS)
    action = action_of(argv, words)
    verb = words[0] if words else None
    if verb is None:
        return []
    if verb == 'push':
        # helm push CHART REMOTE — the remote registry ref is the target.
        remote = words[-1] if len(words) >= 3 else None
        cls = classify(remote)
        if cls == 'prod':
            return [deny_prod(action, "registry '%s'" % remote)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "registry '%s'" % (remote or '<unresolved>'))]
    if verb in HELM_LOCAL_OR_READONLY:
        return []
    explicit, edesc, ambient, adesc = _kube_target(argv, seg_env, ('--kube-context',))
    f = policy(action, explicit, edesc, ambient, adesc, 'helm --kube-context <ctx>')
    return [f] if f else []


def eval_flux(argv, seg_env, ctx):
    words = words_of(argv, KUBE_VALUE_FLAGS)
    action = action_of(argv, words)
    verb = words[0] if words else None
    if verb is None or verb in FLUX_READONLY:
        return []
    explicit, edesc, ambient, adesc = _kube_target(argv, seg_env, ('--context',))
    f = policy(action, explicit, edesc, ambient, adesc, 'flux --context <ctx>')
    return [f] if f else []


def eval_kubectx(argv, seg_env, ctx):
    args = [a for a in argv[1:] if not a.startswith('-')]
    flags = [a for a in argv[1:] if a.startswith('-')]
    if '-d' in flags:
        return [ask_switch('kubectx -d', 'the shared kubeconfig')]
    if not args or '-c' in flags or '--current' in flags:
        return []
    name = args[0]
    if name == '-':
        return [ask_switch('kubectx -', 'the shared kubeconfig current-context')]
    if classify(name) == 'prod':
        return [deny_prod('kubectx %s' % name, "kube-context '%s'" % name)]
    return [ask_switch('kubectx %s' % name, 'the shared kubeconfig current-context')]


def eval_kubens(argv, seg_env, ctx):
    args = [a for a in argv[1:] if not a.startswith('-')]
    flags = [a for a in argv[1:] if a.startswith('-')]
    if not args or '-c' in flags or '--current' in flags:
        return []
    return [ask_switch('kubens %s' % args[0],
                       "the shared kubeconfig (default namespace of the current context)")]


def eval_gcloud(argv, seg_env, ctx):
    words = words_of(argv, ('--project', '--zone', '--region', '--account',
                            '--configuration', '--impersonate-service-account'))
    action = action_of(argv, words)
    lw = [w.lower() for w in words]
    # Special cases first: commands that mutate shared local state.
    if 'get-credentials' in lw:
        return [ask_switch(action, 'the shared kubeconfig (writes a new context)')]
    if words[:2] == ['config', 'set'] or words[:2] == ['config', 'unset']:
        value = words[3] if len(words) > 3 else None
        if value and classify(value) == 'prod':
            return [deny_prod(action, "gcloud config value '%s'" % value)]
        return [ask_switch(action, 'the shared active gcloud configuration')]
    if words[:2] == ['config', 'configurations']:
        if len(words) > 2 and words[2] in ('list', 'describe'):
            return []
        return [ask_switch(action, 'the shared active gcloud configuration')]
    if words[:1] == ['auth'] and len(words) > 1 and words[1] not in ('list', 'print-access-token', 'print-identity-token'):
        return [ask_switch(action, 'the shared gcloud credentials')]
    kind, _ = _scan_verb(lw, mutating_prefixes=GCLOUD_MUTATING_PREFIXES,
                         readonly_exact=GCLOUD_READONLY,
                         readonly_prefixes=GCLOUD_READONLY_PREFIXES)
    if kind == 'readonly':
        return []
    # Mutating or unknown (unknown => mutating). Resolve the project.
    flags = flag_values(argv, ('--project', '--zone', '--region', '--account'))
    env_proj = seg_env.get('CLOUDSDK_CORE_PROJECT') or os.environ.get('CLOUDSDK_CORE_PROJECT')
    if flags or env_proj:
        # Explicit pin: classify every provided locator; prod anywhere wins.
        values = list(flags.values()) + ([env_proj] if env_proj else [])
        descs = ', '.join("'%s'" % v for v in values)
        classes = [classify(v) for v in values]
        if 'prod' in classes:
            return [deny_prod(action, 'the gcloud project/locator %s' % descs)]
        if 'nonprod' in classes:
            return []
        return [ask_unknown(action, 'the gcloud project/locator %s' % descs)]
    ambient = gcloud_active_project()
    if ambient is not None and classify(ambient) == 'prod':
        return [deny_prod(action, "the active gcloud config project '%s' (ambient)" % ambient)]
    desc = ("the ambient gcloud active configuration (project '%s')" % ambient
            if ambient else 'the ambient gcloud active configuration (unresolvable at hook time)')
    return [ask_ambient(action, desc, 'gcloud --project <id>')]


def eval_aws(argv, seg_env, ctx):
    words = words_of(argv, ('--profile', '--region', '--output', '--query'))
    action = action_of(argv, words)
    lw = [w.lower() for w in words]
    if lw[:1] == ['configure']:
        return [ask_switch(action, 'the shared aws config/credentials files')]
    if 'update-kubeconfig' in lw:
        return [ask_switch(action, 'the shared kubeconfig (writes a new context)')]
    kind, _ = _scan_verb(lw, mutating_exact=AWS_MUTATING,
                         mutating_prefixes=AWS_MUTATING_PREFIXES,
                         readonly_exact=AWS_READONLY,
                         readonly_prefixes=AWS_READONLY_PREFIXES)
    if kind == 'readonly':
        return []
    profile = (first_flag_value(argv, ('--profile',))
               or seg_env.get('AWS_PROFILE') or os.environ.get('AWS_PROFILE')
               or seg_env.get('AWS_DEFAULT_PROFILE') or os.environ.get('AWS_DEFAULT_PROFILE'))
    region = first_flag_value(argv, ('--region',))
    if profile:
        desc = "aws profile '%s'" % profile
        cls = classify(profile)
        if cls == 'unknown' and region:
            cls = classify(region)
            desc = "aws profile '%s' / region '%s'" % (profile, region)
        if cls == 'prod':
            return [deny_prod(action, desc)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, desc)]
    return [ask_ambient(action, 'the ambient default aws profile',
                        'aws --profile <name> (or AWS_PROFILE=<name>)')]


def eval_az(argv, seg_env, ctx):
    words = words_of(argv, ('--subscription', '--resource-group', '-g',
                            '--name', '-n', '--output', '-o', '--query'))
    action = action_of(argv, words)
    lw = [w.lower() for w in words]
    if lw[:2] == ['account', 'set']:
        sub = first_flag_value(argv, ('--subscription', '-s'))
        if sub and classify(sub) == 'prod':
            return [deny_prod(action, "azure subscription '%s'" % sub)]
        return [ask_switch(action, 'the shared active azure subscription')]
    if lw[:1] == ['login'] or lw[:1] == ['logout'] or lw[:2] == ['account', 'clear']:
        return [ask_switch(action, 'the shared azure credentials')]
    kind, _ = _scan_verb(lw, mutating_exact=AZ_MUTATING,
                         readonly_exact=AZ_READONLY,
                         readonly_prefixes=AZ_READONLY_PREFIXES)
    if kind == 'readonly':
        return []
    sub = first_flag_value(argv, ('--subscription', '-s'))
    if sub:
        cls = classify(sub)
        if cls == 'prod':
            return [deny_prod(action, "azure subscription '%s'" % sub)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "azure subscription '%s'" % sub)]
    ambient = az_default_subscription()
    if ambient is not None and classify(ambient) == 'prod':
        return [deny_prod(action, "the active azure subscription '%s' (ambient)" % ambient)]
    desc = ("the ambient azure subscription (currently '%s')" % ambient
            if ambient else 'the ambient azure subscription (unresolvable at hook time)')
    return [ask_ambient(action, desc, 'az --subscription <id>')]


def eval_terraform(argv, seg_env, ctx):
    words = words_of(argv, ('-chdir',))
    action = action_of(argv, words)
    verb = words[0].lower() if words else None
    if verb is None:
        return []
    if verb == 'workspace':
        sub = words[1] if len(words) > 1 else None
        if sub in ('list', 'show'):
            return []
        name = words[2] if len(words) > 2 else None
        if name and classify(name) == 'prod':
            return [deny_prod(action, "terraform workspace '%s'" % name)]
        return [ask_switch(action, "the directory's selected terraform workspace")]
    if verb == 'state':
        sub = words[1] if len(words) > 1 else None
        if sub in ('list', 'show', 'pull'):
            return []
        # state rm/mv/push/replace-provider rewrite the backend state.
    elif verb == 'login':
        return [ask_switch(action, 'the shared terraform credentials')]
    elif verb in TF_READONLY:
        return []
    # apply/destroy/import/taint/refresh/state-rewrite/unknown: mutating.
    ws = seg_env.get('TF_WORKSPACE') or os.environ.get('TF_WORKSPACE')
    if ws:
        cls = classify(ws)
        if cls == 'prod':
            return [deny_prod(action, "terraform workspace '%s' (TF_WORKSPACE)" % ws)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "terraform workspace '%s' (TF_WORKSPACE)" % ws)]
    ambient = terraform_workspace(ctx.get('cwd'))
    if ambient is not None and classify(ambient) == 'prod':
        return [deny_prod(action, "the selected terraform workspace '%s'" % ambient)]
    desc = ("the selected terraform workspace ('%s') and its backend" % ambient
            if ambient else 'an unresolved terraform workspace/backend')
    return [ask_ambient(action, desc, 'TF_WORKSPACE=<workspace> terraform ...')]


# Docker context names that mean "the local daemon" — mutating the local
# daemon is a workstation concern, not a prod concern, so they defer.
DOCKER_LOCAL_CONTEXTS = frozenset({
    'default', 'desktop-linux', 'docker-desktop', 'colima', 'orbstack',
    'rancher-desktop',
})


def eval_docker(argv, seg_env, ctx):
    words = words_of(argv, ('--context', '-H', '--host'))
    action = action_of(argv, words)
    verb = words[0].lower() if words else None
    if verb is None:
        return []
    if verb == 'context':
        sub = words[1] if len(words) > 1 else None
        if sub == 'use':
            name = words[2] if len(words) > 2 else None
            if name and classify(name) == 'prod':
                return [deny_prod(action, "docker context '%s'" % name)]
            return [ask_switch(action, 'the shared docker context')]
        return []  # ls/show/inspect/create/rm: no daemon mutation
    if verb == 'push':
        ref = words[1] if len(words) > 1 else None
        cls = classify(ref)
        if cls == 'prod':
            return [deny_prod(action, "image ref '%s'" % ref)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "image ref '%s'" % (ref or '<unresolved>'))]
    if verb in ('build', 'buildx', 'bake', 'compose'):
        if '--push' in argv:
            tag = first_flag_value(argv, ('-t', '--tag'))
            cls = classify(tag)
            if cls == 'prod':
                return [deny_prod(action, "image tag '%s'" % tag)]
            if cls == 'nonprod':
                return []
            return [ask_unknown(action, "pushed image tag '%s'" % (tag or '<unresolved>'))]
        return []  # local build
    if verb in DOCKER_READONLY:
        return []
    if verb in ('image', 'volume', 'network', 'system', 'container') and \
            len(words) > 1 and words[1] in ('ls', 'list', 'inspect', 'df', 'events', 'logs'):
        return []
    # Mutating daemon verb (rm/rmi/prune/run/exec/stop/kill/...): where?
    explicit = first_flag_value(argv, ('--context',)) \
        or seg_env.get('DOCKER_HOST') or os.environ.get('DOCKER_HOST')
    if explicit:
        cls = classify(explicit)
        if cls == 'prod':
            return [deny_prod(action, "docker context/host '%s'" % explicit)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "docker context/host '%s'" % explicit)]
    ambient = docker_current_context()
    if ambient is None or ambient in DOCKER_LOCAL_CONTEXTS:
        return []  # local daemon: a workstation concern, not a prod one
    cls = classify(ambient)
    if cls == 'prod':
        return [deny_prod(action, "the ambient docker context '%s'" % ambient)]
    if cls == 'nonprod':
        return []
    return [ask_ambient(action, "the ambient docker context ('%s')" % ambient,
                        'docker --context <ctx>')]


def eval_gh(argv, seg_env, ctx):
    """gh deviates from the ambient rule deliberately: its implied target —
    the cwd repo's origin remote — is pinned by the worktree, not shared
    clobberable state, and prompting on every `gh pr create` would be pure
    noise. So gh gets denylist-only treatment: a mutating gh command whose
    resolved repo matches a prod pattern is denied; everything else defers."""
    words = words_of(argv, ('-R', '--repo', '-t', '--title', '-b', '--body',
                            '-F', '--body-file', '-m', '--method', '-f', '-H'))
    action = action_of(argv, words)
    lw = [w.lower() for w in words]
    mutating = False
    if 'api' in lw[:1]:
        method = (first_flag_value(argv, ('-X', '--method')) or 'GET').upper()
        mutating = method in ('POST', 'PUT', 'PATCH', 'DELETE')
    else:
        mutating = any(
            w in ('delete', 'merge', 'close', 'edit', 'create', 'comment',
                  'review', 'ready', 'lock', 'unlock', 'transfer', 'archive',
                  'unarchive', 'rename', 'set', 'run', 'rerun', 'cancel',
                  'enable', 'disable', 'sync', 'fork', 'reopen')
            for w in lw)
        if lw and lw[0] in GH_READONLY:
            mutating = False
    if not mutating:
        return []
    candidates = [first_flag_value(argv, ('-R', '--repo'))
                  or seg_env.get('GH_REPO') or os.environ.get('GH_REPO')
                  or git_remote_url(ctx.get('cwd'))]
    if lw[:1] == ['repo'] and len(words) > 2:
        candidates.append(words[2])  # `gh repo delete OWNER/REPO` is positional
    for repo in candidates:
        if repo and classify(repo) == 'prod':
            return [deny_prod(action, "repository '%s'" % repo)]
    return []


def eval_argocd(argv, seg_env, ctx):
    words = words_of(argv, ('--server', '--grpc-web-root-path', '--project'))
    action = action_of(argv, words)
    lw = [w.lower() for w in words]
    if lw[:1] == ['login']:
        return [ask_switch(action, 'the shared argocd CLI context')]
    if lw[:1] == ['context']:
        name = words[1] if len(words) > 1 else None
        if not name:
            return []
        if classify(name) == 'prod':
            return [deny_prod(action, "argocd context '%s'" % name)]
        return [ask_switch(action, 'the shared argocd CLI context')]
    kind, _ = _scan_verb(lw, mutating_exact=ARGOCD_MUTATING,
                         readonly_exact=ARGOCD_READONLY)
    if kind == 'readonly':
        return []
    server = first_flag_value(argv, ('--server',))
    if server:
        cls = classify(server)
        if cls == 'prod':
            return [deny_prod(action, "argocd server '%s'" % server)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "argocd server '%s'" % server)]
    ambient = argocd_current_context()
    if ambient is not None and classify(ambient) == 'prod':
        return [deny_prod(action, "the ambient argocd context '%s'" % ambient)]
    desc = ("the ambient argocd context ('%s')" % ambient
            if ambient else 'the ambient argocd context (unresolvable at hook time)')
    return [ask_ambient(action, desc, 'argocd --server <host>')]


def eval_eksctl(argv, seg_env, ctx):
    words = words_of(argv, ('--cluster', '--name', '--region', '--profile'))
    action = action_of(argv, words)
    verb = words[0].lower() if words else None
    if verb is None or verb in EKSCTL_READONLY:
        return []
    if verb == 'utils' and len(words) > 1 and words[1] == 'write-kubeconfig':
        return [ask_switch(action, 'the shared kubeconfig (writes a new context)')]
    flags = flag_values(argv, ('--cluster', '--name', '--region', '--profile'))
    profile = seg_env.get('AWS_PROFILE') or os.environ.get('AWS_PROFILE')
    values = list(flags.values()) + ([profile] if profile else [])
    if values:
        descs = ', '.join("'%s'" % v for v in values)
        classes = [classify(v) for v in values]
        if 'prod' in classes:
            return [deny_prod(action, 'the eks cluster/profile %s' % descs)]
        if 'nonprod' in classes:
            return []
        return [ask_unknown(action, 'the eks cluster/profile %s' % descs)]
    return [ask_ambient(action, 'the ambient aws profile/region',
                        'eksctl --cluster <name> --profile <name>')]


def eval_doctl(argv, seg_env, ctx):
    words = words_of(argv, ('--context', '--region', '--output'))
    action = action_of(argv, words)
    lw = [w.lower() for w in words]
    if 'kubeconfig' in lw and 'save' in lw:
        return [ask_switch(action, 'the shared kubeconfig (writes a new context)')]
    kind, _ = _scan_verb(lw, mutating_exact=DOCTL_MUTATING,
                         readonly_exact=DOCTL_READONLY)
    if kind == 'readonly':
        return []
    ctx_name = first_flag_value(argv, ('--context',))
    if ctx_name:
        cls = classify(ctx_name)
        if cls == 'prod':
            return [deny_prod(action, "doctl context '%s'" % ctx_name)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "doctl context '%s'" % ctx_name)]
    return [ask_ambient(action, 'the ambient doctl auth context',
                        'doctl --context <name>')]


def eval_kustomize(argv, seg_env, ctx):
    # kustomize only renders/edits local files; the cluster mutation happens
    # in whatever kubectl/helm it pipes into, which gets its own segment.
    return []


EVALUATORS = {
    'kubectl': eval_kubectl,
    'helm': eval_helm,
    'flux': eval_flux,
    'kubectx': eval_kubectx,
    'kubens': eval_kubens,
    'gcloud': eval_gcloud,
    'aws': eval_aws,
    'az': eval_az,
    'terraform': eval_terraform,
    'tofu': eval_terraform,
    'docker': eval_docker,
    'gh': eval_gh,
    'argocd': eval_argocd,
    'eksctl': eval_eksctl,
    'doctl': eval_doctl,
    'kustomize': eval_kustomize,
}
COVERED_TOOLS = frozenset(EVALUATORS)


# ---------------------------------------------------------------------------
# Segment evaluation and main
# ---------------------------------------------------------------------------

def evaluate_command_string(raw, ctx, depth=0):
    """Findings for a full command string: tokenize, split into simple
    commands, evaluate each. Recurses (bounded) into `sh -c '...'` and
    `eval ...` bodies so a quoted nested command can't ride past the guard.
    Returns (findings, override_seen)."""
    findings = []
    override = False
    if depth > 3:
        return findings, override
    tokens = tokenize(raw)
    if tokens is None:
        return findings, override  # unparseable: fail-open
    for group in split_simple_commands(tokens):
        seg_env, argv = extract_env_prefix(group)
        if 'PROD_GUARD_OVERRIDE' in seg_env:
            override = True
        argv = strip_wrappers(argv, seg_env)
        if not argv:
            continue
        tool = os.path.basename(argv[0])
        if tool in SHELL_NAMES:
            # bash -c 'kubectl ...': evaluate the -c body as its own command.
            body = first_flag_value(argv, ('-c',))
            if body:
                sub_f, sub_o = evaluate_command_string(body, ctx, depth + 1)
                findings += sub_f
                override = override or sub_o
            continue
        if tool == 'eval':
            sub_f, sub_o = evaluate_command_string(' '.join(argv[1:]), ctx, depth + 1)
            findings += sub_f
            override = override or sub_o
            continue
        evaluator = EVALUATORS.get(tool)
        if evaluator is None:
            continue  # uncovered tool: defer
        if len(argv) == 1:
            continue  # bare tool name prints help; nothing to guard
        findings += evaluator(argv, seg_env, ctx)
    return findings, override


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return  # unparseable input: fail-open
    if data.get('tool_name') != 'Bash':
        return
    command = (data.get('tool_input') or {}).get('command') or ''
    if not command.strip():
        return
    if os.environ.get('PROD_GUARD_DISABLE') == '1':
        return

    ctx = {'cwd': data.get('cwd') or os.getcwd()}
    findings, override = evaluate_command_string(command, ctx)
    if not findings:
        return  # nothing to object to: defer to normal permissions

    severity = max(sev for sev, _ in findings)
    # De-duplicate reasons while keeping order; cap so the prompt stays readable.
    reasons, seen = [], set()
    for sev, reason in sorted(findings, key=lambda f: -f[0]):
        if reason not in seen:
            seen.add(reason)
            reasons.append(reason)
    reason = ' | '.join(reasons[:3])

    if severity == DENY and override:
        severity = ASK
        reason = ('prod-guard override acknowledged (PROD_GUARD_OVERRIDE is '
                  'set) — downgraded from deny to a confirmation prompt. '
                  + reason)

    decision = 'deny' if severity == DENY else 'ask'
    # In bypassPermissions / full-auto mode there is no one to answer an ask;
    # deny blocks identically but feeds the reason back so the agent can
    # route around the target instead of stalling on an unanswerable prompt.
    if decision == 'ask' and data.get('permission_mode') == 'bypassPermissions':
        decision = 'deny'
    print(json.dumps({'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'permissionDecision': decision,
        'permissionDecisionReason': reason}}))


if __name__ == '__main__':
    try:
        main()
    except Exception:  # noqa: BLE001 — fail-open on any infrastructure error
        if os.environ.get('PROD_GUARD_DEBUG') == '1':
            raise
        sys.exit(0)
