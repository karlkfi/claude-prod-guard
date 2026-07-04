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


def all_flag_values(argv, names):
    """Every value of the given flags, in order — for repeatable flags like
    docker's `-t` (flag_values keeps only the last occurrence per flag)."""
    out = []
    nameset = set(names)
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in nameset and i + 1 < len(argv):
            out.append(argv[i + 1])
            i += 2
            continue
        if '=' in tok:
            head, _, val = tok.partition('=')
            if head in nameset:
                out.append(val)
        i += 1
    return out


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

def _kubeconfig_paths(seg_env):
    """Every kubeconfig file to consult: all `:`-separated $KUBECONFIG paths
    (kubectl merges them), else ~/.kube/config. Empty if $HOME is unset and no
    $KUBECONFIG is given."""
    kc = seg_env.get('KUBECONFIG') or os.environ.get('KUBECONFIG')
    if kc:
        return [p for p in kc.split(':') if p]
    home = os.environ.get('HOME')
    if home:
        return [os.path.join(home, '.kube', 'config')]
    return []


def kube_current_context(seg_env):
    """current-context from $KUBECONFIG (first path) or ~/.kube/config."""
    paths = _kubeconfig_paths(seg_env)
    if not paths:
        return None
    try:
        with open(paths[0], encoding='utf-8') as f:
            for line in f:
                m = re.match(r'^current-context:\s*["\']?([^"\'\n#]+)', line)
                if m:
                    return m.group(1).strip() or None
    except OSError:
        return None
    return None


def _kube_yaml_field(item_lines, key):
    """First inline `key: value` in a kubeconfig list item, quotes stripped.
    Block keys (`cluster:` with no inline value, i.e. a nested map) don't
    match, so the same key name resolves to the scalar field, never the map."""
    rx = re.compile(r'^\s*(?:-\s+)?' + re.escape(key) + r':\s*(.+?)\s*$')
    for line in item_lines:
        m = rx.match(line)
        if m:
            return m.group(1).strip('"\'') or None
    return None


def _parse_kubeconfig(path):
    """(ctx_to_cluster, cluster_to_server) from one kubeconfig file.

    Line-oriented parse of the block-style subset `kubectl config` writes:
    track the top-level `clusters:` / `contexts:` section, split each into list
    items on `- ` lines, and read the scalar fields from each item. Anything it
    can't parse (flow style, unreadable file) yields empty maps — the caller
    falls back to name-only classification, so this only ever *adds* a chance
    to classify, never removes one."""
    ctx_to_cluster, cluster_to_server = {}, {}
    try:
        with open(path, encoding='utf-8') as f:
            lines = f.readlines()
    except OSError:
        return ctx_to_cluster, cluster_to_server

    section = None
    item = []

    def flush():
        if not item:
            return
        name = _kube_yaml_field(item, 'name')
        if not name:
            return
        if section == 'clusters':
            server = _kube_yaml_field(item, 'server')
            if server and name not in cluster_to_server:  # first-wins merge
                cluster_to_server[name] = server
        elif section == 'contexts':
            cluster = _kube_yaml_field(item, 'cluster')
            if cluster and name not in ctx_to_cluster:
                ctx_to_cluster[name] = cluster

    for line in lines:
        top = re.match(r'^([A-Za-z0-9_-]+):', line)
        if top:  # a new top-level key ends the current section/item
            flush()
            item = []
            section = top.group(1) if top.group(1) in ('clusters', 'contexts') else None
            continue
        if section is None:
            continue
        if re.match(r'^\s*-\s', line) or re.match(r'^\s*-\s*$', line):
            flush()
            item = [line]
        elif item:
            item.append(line)
    flush()
    return ctx_to_cluster, cluster_to_server


def kube_context_server(name, seg_env):
    """Resolve a context name to its cluster's server URL, merging every
    kubeconfig file. None if the context, its cluster, or the server can't be
    resolved (parse failure, split-across-unread-files, etc.)."""
    if not name:
        return None
    ctx_to_cluster, cluster_to_server = {}, {}
    for path in _kubeconfig_paths(seg_env):
        c2c, c2s = _parse_kubeconfig(path)
        for k, v in c2c.items():
            ctx_to_cluster.setdefault(k, v)
        for k, v in c2s.items():
            cluster_to_server.setdefault(k, v)
    cluster = ctx_to_cluster.get(name)
    if not cluster:
        return None
    return cluster_to_server.get(cluster)


def classify_kube(name, seg_env):
    """Classify a kube-context by the worst (most prod-leaning) of its name
    and its cluster's server URL, on the prod > nonprod > unknown lattice.
    Additive to name-only classify(): a prod server upgrades an innocuously
    named context to prod; an unresolvable server leaves the name verdict
    untouched."""
    name_cls = classify(name)
    if name_cls == 'prod':
        return 'prod'  # prod wins; no need to resolve the server
    server_cls = classify(kube_context_server(name, seg_env))
    if server_cls == 'prod':
        return 'prod'
    if name_cls == 'nonprod' or server_cls == 'nonprod':
        return 'nonprod'
    return 'unknown'


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


# Fields of an aws profile / sso-session that name *where* it reaches and are
# safe to echo in a decision message — never a credential. Ordered by display
# preference so the first present one is the most identifying.
_AWS_ECHOABLE_KEYS = (
    'sso_start_url', 'role_arn', 'sso_session', 'sso_account_id',
    'sso_role_name', 'source_profile', 'sso_region', 'region',
)


def _parse_ini_sections(path):
    """`{section_name: {lower_key: value}}` from an INI file (the AWS config
    shape). Full-line `#`/`;` comments skipped; inline comments are left in the
    value (AWS does not strip them). Unreadable/missing -> {} (fail OPEN)."""
    sections = {}
    try:
        with open(path, encoding='utf-8') as f:
            cur = None
            for line in f:
                s = line.strip()
                if not s or s.startswith('#') or s.startswith(';'):
                    continue
                if s.startswith('[') and s.endswith(']'):
                    cur = s[1:-1].strip()
                    sections.setdefault(cur, {})
                    continue
                if cur is not None and '=' in line:
                    key, _, val = line.partition('=')
                    sections[cur][key.strip().lower()] = val.strip()
    except OSError:
        return {}
    return sections


def aws_default_profile(seg_env):
    """(named, extra) classifiable strings from the `[default]` profile in
    ~/.aws/config (or $AWS_CONFIG_FILE), following an `sso_session` reference
    into its `[sso-session NAME]` block.

    - named = echoable identifiers (sso_start_url/role_arn/...), in display
      preference order so named[0] is the most identifying present field.
    - extra = every other key's value (classify-only, never echoed — a
      credential_process command may live here).

    None when the file or the `[default]` section is missing/unreadable, i.e.
    there is no ambient default profile to resolve (fail OPEN -> generic ask)."""
    path = seg_env.get('AWS_CONFIG_FILE') or os.environ.get('AWS_CONFIG_FILE')
    if not path:
        home = os.environ.get('HOME')
        if not home:
            return None
        path = os.path.join(home, '.aws', 'config')
    sections = _parse_ini_sections(path)
    profile = sections.get('default')
    if profile is None:
        return None
    merged = dict(profile)
    sso = profile.get('sso_session')
    if sso:
        merged.update(sections.get('sso-session ' + sso, {}))
    named = [merged[k] for k in _AWS_ECHOABLE_KEYS if merged.get(k)]
    extra = [v for k, v in merged.items()
             if k not in _AWS_ECHOABLE_KEYS and v]
    return named, extra


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


# Well-known "where the state lives" fields per backend type. These name the
# remote state location (a bucket/key/org/workspace) and are safe to echo in a
# decision message — never a credential.
_TF_BACKEND_FIELDS = {
    's3': ('bucket', 'key'),
    'gcs': ('bucket', 'prefix'),
    'azurerm': ('storage_account_name', 'container_name', 'key'),
    'oss': ('bucket', 'prefix'),   # alibaba
    'cos': ('bucket', 'prefix'),   # tencent
}


def terraform_backend(cwd):
    """The remote state location `terraform init` recorded in
    .terraform/terraform.tfstate, as (type, named, extra):

    - named  = echoable state-location strings (bucket/key/org/workspace) for
      the known backend types.
    - extra  = every string leaf of an unknown/future backend's config
      (classify-only; never echoed, since it may include a credential).

    None when there is no initialized remote backend: missing/unreadable file,
    malformed JSON, no `backend` object, or a `local` backend. Fail OPEN."""
    path = os.path.join(cwd or '.', '.terraform', 'terraform.tfstate')
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    be = data.get('backend')
    if not isinstance(be, dict):
        return None
    btype = be.get('type')
    cfg = be.get('config')
    if not isinstance(btype, str) or not isinstance(cfg, dict):
        return None
    if btype == 'local':
        return None
    if btype in ('remote', 'cloud'):
        named = []
        org = cfg.get('organization')
        if isinstance(org, str):
            named.append(org)
        ws = cfg.get('workspaces')
        if isinstance(ws, dict):
            for key in ('name', 'prefix'):
                val = ws.get(key)
                if isinstance(val, str):
                    named.append(val)
            tags = ws.get('tags')
            if isinstance(tags, list):
                named += [t for t in tags if isinstance(t, str)]
        return (btype, named, [])
    fields = _TF_BACKEND_FIELDS.get(btype)
    if fields is not None:
        named = [cfg[k] for k in fields if isinstance(cfg.get(k), str)]
        return (btype, named, [])
    # Unknown/future backend: classify every string leaf as a secure catch-all,
    # but report only the type — an incidental credential must never be echoed.
    extra = [v for v in cfg.values() if isinstance(v, str)]
    return (btype, [], extra)


def terraform_backend_prod(cwd):
    """Deny description if the initialized backend's state location matches a
    prod pattern, else None. Known types echo the matched location; the
    unknown-type catch-all reports only the backend type. Purely additive:
    only the PROD verdict affects policy (see the Q3 plan doc)."""
    be = terraform_backend(cwd)
    if be is None:
        return None
    btype, named, extra = be
    for val in named:
        if classify(val) == 'prod':
            return "the terraform %s backend (%s)" % (btype, val)
    for val in extra:
        if classify(val) == 'prod':
            return "the terraform %s backend" % btype
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
           ambient_value, ambient_desc, pin_hint, classify_fn=classify):
    """The shared decision matrix for a mutating verb, given how the target
    resolved. Returns a finding tuple or None (defer). `classify_fn` lets a
    tool refine classification (e.g. kube resolves the context's server URL);
    it defaults to the plain name-based classify()."""
    if explicit_value is not None:
        cls = classify_fn(explicit_value)
        if cls == 'prod':
            return deny_prod(action, explicit_desc)
        if cls == 'nonprod':
            return None
        return ask_unknown(action, explicit_desc)
    # No explicit pin: the target is whatever the shared ambient state says.
    if ambient_value is not None:
        if classify_fn(ambient_value) == 'prod':
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
    # oc (OpenShift) shares this evaluator; its read-only extras:
    'status', 'whoami', 'projects', 'process',
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
            if name and classify_kube(name, seg_env) == 'prod':
                return [deny_prod(action, "kube-context '%s'" % name)]
            return [ask_switch(action, 'the shared kubeconfig current-context')]
        # set/set-context/delete-context/rename-context/unset/...: mutations
        # of the shared kubeconfig itself.
        return [ask_switch(action, 'the shared kubeconfig')]
    if verb in KUBECTL_READONLY:
        return []
    if verb == 'rollout' and len(words) > 1 and words[1] in ('status', 'history'):
        return []
    # oc (OpenShift) shares this evaluator; its extra shared-state verbs:
    if verb == 'login':
        # `oc login <server>` writes credentials and a context into the
        # shared kubeconfig (kubectl has no such verb, so no collision).
        return [ask_switch(action, 'the shared kubeconfig (login writes a new context)')]
    if verb == 'project':
        name = words[1] if len(words) > 1 else None
        if name is None:
            return []  # bare `oc project` only prints the current project
        return [ask_switch(action, 'the shared kubeconfig (current project of the context)')]
    explicit, edesc, ambient, adesc = _kube_target(argv, seg_env, ('--context',))
    f = policy(action, explicit, edesc, ambient, adesc, 'kubectl --context <ctx>',
               classify_fn=lambda v: classify_kube(v, seg_env))
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
    f = policy(action, explicit, edesc, ambient, adesc, 'helm --kube-context <ctx>',
               classify_fn=lambda v: classify_kube(v, seg_env))
    return [f] if f else []


def eval_flux(argv, seg_env, ctx):
    words = words_of(argv, KUBE_VALUE_FLAGS)
    action = action_of(argv, words)
    verb = words[0] if words else None
    if verb is None or verb in FLUX_READONLY:
        return []
    explicit, edesc, ambient, adesc = _kube_target(argv, seg_env, ('--context',))
    f = policy(action, explicit, edesc, ambient, adesc, 'flux --context <ctx>',
               classify_fn=lambda v: classify_kube(v, seg_env))
    return [f] if f else []


def eval_kubectx(argv, seg_env, ctx):
    # A lone `-` is the "previous context" operand, not a flag.
    args = [a for a in argv[1:] if a == '-' or not a.startswith('-')]
    flags = [a for a in argv[1:] if a != '-' and a.startswith('-')]
    if '-d' in flags:
        return [ask_switch('kubectx -d', 'the shared kubeconfig')]
    if not args or '-c' in flags or '--current' in flags:
        return []
    name = args[0]
    if name == '-':
        return [ask_switch('kubectx -', 'the shared kubeconfig current-context')]
    if classify_kube(name, seg_env) == 'prod':
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


def ambient_aws_default_profile_decision(action, seg_env, pin,
                                         generic_desc, named_desc):
    """Escalate the ambient ~/.aws/config [default] profile to a decision: a
    prod signal in any resolved field denies; otherwise a naming (or generic)
    ambient ask. Shared by eval_aws and eval_eksctl, which both reach AWS
    through the same default-profile chain. Additive-only: content moves the
    call unknown -> deny, never unknown -> defer.

    named_desc is a %-format template taking the most-identifying resolved
    field; generic_desc is used when nothing echoable resolved."""
    resolved = aws_default_profile(seg_env)
    if resolved is not None:
        named, extra = resolved
        for v in named:
            if classify(v) == 'prod':
                return deny_prod(action,
                                 "the default aws profile (%s) (ambient)" % v)
        for v in extra:
            if classify(v) == 'prod':
                return deny_prod(action, 'the default aws profile (ambient)')
        if named:
            return ask_ambient(action, named_desc % named[0], pin)
    return ask_ambient(action, generic_desc, pin)


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
    # No explicit profile pinned: the target is the `[default]` profile, whose
    # sso_start_url / role_arn / sso_session in ~/.aws/config name the account
    # it reaches. A prod default profile denies; anything else still asks
    # (ambient), now naming what resolved. Purely additive over the prior
    # always-ask — a missing/unreadable config resolves nothing.
    pin = 'aws --profile <name> (or AWS_PROFILE=<name>)'
    return [ambient_aws_default_profile_decision(
        action, seg_env, pin,
        'the ambient default aws profile',
        "the ambient default aws profile (%s)")]


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
    # The backend state location is the real target — a prod bucket/TFC
    # workspace denies regardless of the (weak-proxy) workspace name. Purely
    # additive: it only escalates to deny, never silences an ask.
    cwd = ctx.get('cwd')
    ws = seg_env.get('TF_WORKSPACE') or os.environ.get('TF_WORKSPACE')
    if ws:
        cls = classify(ws)
        if cls == 'prod':
            return [deny_prod(action, "terraform workspace '%s' (TF_WORKSPACE)" % ws)]
        backend = terraform_backend_prod(cwd)
        if backend:
            return [deny_prod(action, backend)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "terraform workspace '%s' (TF_WORKSPACE)" % ws)]
    ambient = terraform_workspace(cwd)
    if ambient is not None and classify(ambient) == 'prod':
        return [deny_prod(action, "the selected terraform workspace '%s'" % ambient)]
    backend = terraform_backend_prod(cwd)
    if backend:
        return [deny_prod(action, backend)]
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
    words = words_of(argv, ('--context', '-H', '--host', '--connection'))
    # The standalone docker-compose binary is `docker compose` without the
    # `docker` prefix; normalize so both spell the same word sequence.
    if os.path.basename(argv[0]) == 'docker-compose':
        words = ['compose'] + words
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
    if verb == 'compose':
        sub = words[1] if len(words) > 1 else None
        if sub in ('config', 'ps', 'ls', 'logs', 'images', 'version',
                   'events', 'top', 'port'):
            return []
        if sub == 'push' or (sub == 'build' and '--push' in argv):
            # The registry lives in the compose file's image: keys, which the
            # hook does not parse — unresolvable target, so fail closed.
            return [ask_unknown(action,
                                'images defined in the compose file '
                                '(registry unresolvable at hook time)')]
        if sub == 'build':
            return []  # local build
        # up/down/rm/stop/kill/exec/run/...: daemon mutations — fall through
        # to the context resolution below.
    elif verb in ('build', 'buildx', 'bake'):
        if '--push' in argv:
            # Classify EVERY -t/--tag: one prod tag among several must deny
            # even when the first tag is a dev registry.
            tags = all_flag_values(argv, ('-t', '--tag'))
            classes = [classify(t) for t in tags]
            if 'prod' in classes:
                bad = tags[classes.index('prod')]
                return [deny_prod(action, "image tag '%s'" % bad)]
            if tags and all(c == 'nonprod' for c in classes):
                return []
            unknowns = [t for t, c in zip(tags, classes) if c == 'unknown']
            return [ask_unknown(action, "pushed image tag(s) %s" %
                                (', '.join("'%s'" % t for t in unknowns)
                                 or '<unresolved>'))]
        return []  # local build
    if verb in DOCKER_READONLY:
        return []
    if verb in ('image', 'volume', 'network', 'system', 'container') and \
            len(words) > 1 and words[1] in ('ls', 'list', 'inspect', 'df', 'events', 'logs'):
        return []
    # Mutating daemon verb (rm/rmi/prune/run/exec/stop/kill/...): where?
    # `--connection` is podman's remote-target flag (shares this evaluator);
    # docker has no such flag, so including it is inert there.
    explicit = first_flag_value(argv, ('--context', '--connection')) \
        or seg_env.get('DOCKER_HOST') or os.environ.get('DOCKER_HOST') \
        or seg_env.get('CONTAINER_HOST') or os.environ.get('CONTAINER_HOST')
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


# ssh flags that consume the following token as their value, so it is never
# mistaken for the destination host. Boolean flags (-v, -N, -t, -4, ...) take
# no value and are simply skipped. All are single-dash (ssh has no --long form).
SSH_VALUE_FLAGS = frozenset({
    '-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m',
    '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w',
})


def _ssh_host(dest):
    """Bare hostname from an ssh destination: strip a `ssh://` scheme and any
    path, a `user@` prefix, and a trailing `:port`. Bracketed IPv6 literals
    (`[::1]:22`) keep their brackets so they still match the loopback pattern;
    an unbracketed IPv6 literal is left whole (it has several colons, so the
    port strip below leaves it untouched)."""
    if not dest:
        return None
    d = dest
    if d.startswith('ssh://'):
        d = d[len('ssh://'):].split('/', 1)[0]
    if '@' in d:
        d = d.rsplit('@', 1)[1]
    if d.startswith('['):
        end = d.find(']')
        if end != -1:
            d = d[:end + 1]  # [::1]:22 -> [::1]
    elif d.count(':') == 1:
        d = d.split(':', 1)[0]  # host:port -> host
    return d or None


def eval_ssh(argv, seg_env, ctx):
    """ssh gets denylist-only treatment like gh: the destination host is
    pinned on the command line, not clobber-prone ambient state, so only the
    prod-blast-radius model applies. Any ssh into a prod host is treated as
    mutating — an interactive prod shell is the blast radius, and a read-only
    remote command can't be told from a destructive one — so a prod
    destination (or `-J` jump host) is denied and everything else defers."""
    hosts = []
    dest = None
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in SSH_VALUE_FLAGS:
            if tok == '-J' and i + 1 < len(argv):
                # `-J [user@]host[:port][,...]` — each hop is a host we transit.
                hosts += [_ssh_host(p) for p in argv[i + 1].split(',')]
            i += 2
            continue
        if tok.startswith('-'):
            i += 1
            continue
        dest = tok  # first bare operand is the destination; the rest is the
        break       # remote command, whose flags must not be reparsed as ssh's
    if dest is not None:
        hosts.append(_ssh_host(dest))
    action = 'ssh %s' % dest if dest else 'ssh'
    for h in hosts:
        if h and classify(h) == 'prod':
            return [deny_prod(action, "host '%s'" % h)]
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
    profile = (seg_env.get('AWS_PROFILE') or os.environ.get('AWS_PROFILE')
               or seg_env.get('AWS_DEFAULT_PROFILE')
               or os.environ.get('AWS_DEFAULT_PROFILE'))
    values = list(flags.values()) + ([profile] if profile else [])
    if values:
        descs = ', '.join("'%s'" % v for v in values)
        classes = [classify(v) for v in values]
        if 'prod' in classes:
            return [deny_prod(action, 'the eks cluster/profile %s' % descs)]
        if 'nonprod' in classes:
            return []
        return [ask_unknown(action, 'the eks cluster/profile %s' % descs)]
    # Nothing pinned (no flags, no AWS_PROFILE/AWS_DEFAULT_PROFILE): eksctl
    # reaches AWS through the ~/.aws/config [default] profile, so resolve it
    # like eval_aws does -> a prod default profile denies, else ambient ask.
    return [ambient_aws_default_profile_decision(
        action, seg_env, 'eksctl --cluster <name> --profile <name>',
        'the ambient aws profile/region',
        'the ambient aws profile/region (default profile %s)')]


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


# pulumi verbs that only read or act locally — everything else (up/update,
# destroy, refresh, import, cancel, watch, state ..., unknown) is mutating.
PULUMI_READONLY = frozenset({
    'preview', 'about', 'version', 'whoami', 'logs', 'console', 'plugin',
    'convert', 'install', 'schema', 'help', 'completion',
})
# pulumi `stack` subcommands that only read.
PULUMI_STACK_READONLY = frozenset({'ls', 'output', 'export', 'history', 'graph'})
# Value-taking flags, so a value placed before the verb isn't read as one.
PULUMI_VALUE_FLAGS = (
    '--stack', '-s', '--cwd', '-C', '--color', '--tracing', '--profiling',
    '--config-file', '--policy-pack', '--secrets-provider', '-m', '--message',
)


def _pulumi_decide(action, explicit):
    """Classify an explicit pulumi stack (flag or positional); no stack pinned
    -> ask_ambient. The ambient selected stack is not read from disk in v1
    (see the pulumi-ansible-coverage plan doc)."""
    if explicit is not None:
        cls = classify(explicit)
        if cls == 'prod':
            return [deny_prod(action, "pulumi stack '%s'" % explicit)]
        if cls == 'nonprod':
            return []
        return [ask_unknown(action, "pulumi stack '%s'" % explicit)]
    return [ask_ambient(action, 'the ambient selected pulumi stack '
                        '(unresolved at hook time)', 'pulumi --stack <name>')]


def eval_pulumi(argv, seg_env, ctx):
    words = words_of(argv, PULUMI_VALUE_FLAGS)
    action = action_of(argv, words)
    verb = words[0].lower() if words else None
    if verb is None or verb in PULUMI_READONLY:
        return []
    if verb in ('login', 'logout'):
        return [ask_switch(action, 'the shared pulumi credentials/backend')]
    if verb == 'stack':
        sub = words[1].lower() if len(words) > 1 else None
        if sub is None or sub in PULUMI_STACK_READONLY:
            return []
        name = words[2] if len(words) > 2 else first_flag_value(argv, ('--stack', '-s'))
        if sub in ('select', 'unselect'):
            if name and classify(name) == 'prod':
                return [deny_prod(action, "pulumi stack '%s'" % name)]
            return [ask_switch(action, 'the selected pulumi stack')]
        # init/rm/rename/tag/import/change-secrets-provider: mutate the stack.
        return _pulumi_decide(action, name)
    if verb == 'config':
        sub = words[1].lower() if len(words) > 1 else None
        if sub is None or sub == 'get':
            return []
        # set/rm/set-all/rm-all/cp/refresh: mutate the selected stack's config.
    return _pulumi_decide(action, first_flag_value(argv, ('--stack', '-s')))


# ansible ad-hoc modules that only read remote state (no change).
ANSIBLE_READONLY_MODULES = frozenset({'ping', 'setup', 'debug', 'gather_facts'})
# Inspection flags that make even ansible-playbook read-only (never connect).
ANSIBLE_READONLY_FLAGS = ('--syntax-check', '--list-hosts', '--list-tasks',
                          '--list-tags')
# Value-taking flags, so their values aren't mistaken for the host pattern.
ANSIBLE_VALUE_FLAGS = frozenset({
    '-i', '--inventory', '--inventory-file', '-l', '--limit',
    '-m', '--module-name', '-a', '--args', '-e', '--extra-vars',
    '-u', '--user', '--become-user', '--become-method',
    '-c', '--connection', '-T', '--timeout', '-f', '--forks',
    '-M', '--module-path', '-t', '--tree', '--start-at-task',
    '--tags', '--skip-tags', '--vault-id', '--vault-password-file',
    '--private-key', '--key-file', '--ssh-common-args', '--ssh-extra-args',
    '--scp-extra-args', '--sftp-extra-args', '-P', '--poll', '-B', '--background',
})


def _ansible_pattern(argv):
    """First positional token of an ad-hoc `ansible` command — the host
    pattern — skipping flags and their values."""
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in ANSIBLE_VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith('-'):
            i += 1
            continue
        return tok
    return None


def _ini_inventory(path):
    """`inventory = <value>` under `[defaults]` in an ansible.cfg (INI). None
    if absent/unreadable — fail OPEN."""
    try:
        with open(path, encoding='utf-8') as f:
            section = None
            for line in f:
                s = line.strip()
                if s.startswith('[') and s.endswith(']'):
                    section = s[1:-1].strip().lower()
                    continue
                if section == 'defaults':
                    m = re.match(r'inventory\s*=\s*(.+?)\s*(?:[;#].*)?$', s)
                    if m:
                        return m.group(1).strip() or None
    except OSError:
        return None
    return None


def ansible_ambient_inventory(seg_env, cwd):
    """The inventory ansible would use with no `-i`: ANSIBLE_INVENTORY, then
    the `[defaults] inventory` of ANSIBLE_CONFIG / ./ansible.cfg. None if
    unresolved (the default /etc/ansible/hosts is unnamed — nothing to
    classify)."""
    inv = seg_env.get('ANSIBLE_INVENTORY') or os.environ.get('ANSIBLE_INVENTORY')
    if inv:
        return inv
    cfg = seg_env.get('ANSIBLE_CONFIG') or os.environ.get('ANSIBLE_CONFIG')
    paths = ([cfg] if cfg else []) + [os.path.join(cwd or '.', 'ansible.cfg')]
    for p in paths:
        val = _ini_inventory(p)
        if val:
            return val
    return None


def eval_ansible(argv, seg_env, ctx):
    """ansible / ansible-playbook target the *inventory* (which hosts a play
    runs against). The inventory is authoritative for classification; the host
    pattern and `--limit` can only escalate a decision to deny, never force an
    ask when the inventory itself resolves nonprod."""
    adhoc = os.path.basename(argv[0]) == 'ansible'
    if any(f in argv for f in ANSIBLE_READONLY_FLAGS):
        return []  # --syntax-check/--list-* never connect or change anything
    if adhoc:
        module = first_flag_value(argv, ('-m', '--module-name'))
        if module and module.split('.')[-1] in ANSIBLE_READONLY_MODULES:
            return []  # ping/setup/debug: read-only even against prod
    invs = all_flag_values(argv, ('-i', '--inventory', '--inventory-file'))
    limits = all_flag_values(argv, ('-l', '--limit'))
    pattern = _ansible_pattern(argv) if adhoc else None
    escalators = list(limits) + ([pattern] if pattern else [])
    action = ('ansible %s' % pattern if adhoc and pattern
              else os.path.basename(argv[0]))
    for t in invs + escalators:
        if classify(t) == 'prod':
            return [deny_prod(action, "the ansible target '%s'" % t)]
    if invs:
        for v in invs:
            if classify(v) == 'unknown':
                return [ask_unknown(action, "the ansible inventory '%s'" % v)]
        return []  # every -i inventory classifies nonprod
    ambient = ansible_ambient_inventory(seg_env, ctx.get('cwd'))
    if ambient is not None:
        cls = classify(ambient)
        if cls == 'prod':
            return [deny_prod(action, "the ambient ansible inventory '%s'" % ambient)]
        if cls == 'nonprod':
            return []
    return [ask_ambient(action, 'the ambient ansible inventory '
                        '(ANSIBLE_INVENTORY / ansible.cfg / /etc/ansible/hosts)',
                        '-i <inventory>')]


def eval_kustomize(argv, seg_env, ctx):
    # kustomize only renders/edits local files; the cluster mutation happens
    # in whatever kubectl/helm it pipes into, which gets its own segment.
    return []


EVALUATORS = {
    'kubectl': eval_kubectl,
    'oc': eval_kubectl,            # OpenShift CLI: kubectl's verb/flag model
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
    'podman': eval_docker,         # daemonless but shares docker's CLI shape
    'nerdctl': eval_docker,
    'docker-compose': eval_docker,  # standalone compose v1 binary
    'gh': eval_gh,
    'ssh': eval_ssh,
    'argocd': eval_argocd,
    'eksctl': eval_eksctl,
    'doctl': eval_doctl,
    'pulumi': eval_pulumi,
    'ansible': eval_ansible,
    'ansible-playbook': eval_ansible,
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
