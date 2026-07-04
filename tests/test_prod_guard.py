#!/usr/bin/env python3
"""Tests for scripts/bash-prod-guard.py.

Run with: python3 -m unittest discover tests
     or:  python3 tests/test_prod_guard.py

Three layers:
  * Unit tests import the module and exercise classification, tokenization,
    wrapper stripping, and flag parsing.
  * End-to-end tests invoke the script as a subprocess with a fixture $HOME
    (synthetic kubeconfig / gcloud / docker / azure configs) and assert the
    emitted PreToolUse decision: deny / ask / defer (no output).
  * Wiring tests assert the plugin config (hooks.json, plugin.json,
    marketplace.json) is valid and points the hook at the real script.

Fixture rule: never use real production names or real credentials paths in
fixtures. Synthetic names (`gke_acme_prod-us`, `kind-ci`, `bluefin`) exercise
identical code paths with zero risk.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib import util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "bash-prod-guard.py"

# Filename has dashes, so import by path.
_spec = util.spec_from_file_location("prod_guard", SCRIPT)
guard = util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


KUBECONFIG_KIND = "apiVersion: v1\nkind: Config\ncurrent-context: kind-ci\n"
KUBECONFIG_PROD = "apiVersion: v1\nkind: Config\ncurrent-context: gke_acme_prod-us\n"


def make_home(kubeconfig=None, gcloud_project=None, docker_context=None,
              az_subscription=None, az_bom=False, argocd_context=None):
    """Build a synthetic $HOME holding whichever ambient configs a test needs."""
    home = tempfile.mkdtemp(prefix="prod-guard-test-home-")
    if kubeconfig is not None:
        kube_dir = os.path.join(home, ".kube")
        os.makedirs(kube_dir)
        with open(os.path.join(kube_dir, "config"), "w", encoding="utf-8") as f:
            f.write(kubeconfig)
    if gcloud_project is not None:
        gdir = os.path.join(home, ".config", "gcloud", "configurations")
        os.makedirs(gdir)
        with open(os.path.join(home, ".config", "gcloud", "active_config"),
                  "w", encoding="utf-8") as f:
            f.write("default")
        with open(os.path.join(gdir, "config_default"), "w", encoding="utf-8") as f:
            f.write("[core]\nproject = %s\n" % gcloud_project)
    if docker_context is not None:
        ddir = os.path.join(home, ".docker")
        os.makedirs(ddir)
        with open(os.path.join(ddir, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"currentContext": docker_context}, f)
    if az_subscription is not None:
        adir = os.path.join(home, ".azure")
        os.makedirs(adir)
        # The Azure CLI writes this file with a UTF-8 byte order mark (BOM);
        # az_bom reproduces that so the utf-8-sig read path is covered.
        enc = "utf-8-sig" if az_bom else "utf-8"
        with open(os.path.join(adir, "azureProfile.json"), "w", encoding=enc) as f:
            json.dump({"subscriptions": [
                {"name": az_subscription, "isDefault": True}]}, f)
    if argocd_context is not None:
        adir = os.path.join(home, ".config", "argocd")
        os.makedirs(adir)
        with open(os.path.join(adir, "config"), "w", encoding="utf-8") as f:
            f.write("current-context: %s\n" % argocd_context)
    return home


def run_hook(command, home=None, env_extra=None, cwd=None,
             permission_mode=None, payload=None):
    """Invoke the hook as a subprocess; return the decision string or None
    (defer). Uses a minimal, controlled environment so the developer's real
    kubeconfig / cloud configs can never leak into a test verdict."""
    if home is None:
        home = make_home()
    env = {
        "HOME": home,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PROD_GUARD_DEBUG": "1",
    }
    if env_extra:
        env.update(env_extra)
    if payload is None:
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}
        if cwd:
            payload["cwd"] = cwd
        if permission_mode:
            payload["permission_mode"] = permission_mode
    r = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload) if isinstance(payload, dict) else payload,
        capture_output=True, text=True, env=env, cwd=home, timeout=30)
    if r.returncode != 0:
        raise AssertionError("hook crashed: %s" % r.stderr)
    if not r.stdout.strip():
        return None, None
    out = json.loads(r.stdout)["hookSpecificOutput"]
    decision = out["permissionDecision"]
    # Invariant enforced on EVERY end-to-end call: the guard's only outputs
    # are deny, ask, or silence. An `allow` would ride past the user's
    # permission settings and the sibling guards — see docs/design.md.
    assert decision in ("ask", "deny"), "guard emitted forbidden decision %r" % decision
    return decision, out["permissionDecisionReason"]


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        guard._PATTERNS = None  # patterns cache is per-process; reset per test

    def test_prod_names(self):
        for name in ("prod", "gke_acme_prod-us", "my-production-cluster",
                     "acme-prd-eu", "live-cluster", "PROD-US"):
            self.assertEqual(guard.classify(name), "prod", name)

    def test_nonprod_names(self):
        for name in ("kind-ci", "k3d-local", "minikube", "docker-desktop",
                     "dev-us", "staging-eu", "acme-qa", "127.0.0.1:5000/app",
                     "localhost:5000/app", "sandbox-2"):
            self.assertEqual(guard.classify(name), "nonprod", name)

    def test_unknown_names(self):
        for name in ("bluefin", "gke_acme_bluefin_us-central1"):
            self.assertEqual(guard.classify(name), "unknown", name)

    def test_prod_beats_nonprod_on_ambiguity(self):
        self.assertEqual(guard.classify("prod-staging-mirror"), "prod")

    def test_word_boundaries(self):
        # `prod` must not fire inside unrelated words.
        self.assertNotEqual(guard.classify("reproduce-bug"), "prod")
        self.assertNotEqual(guard.classify("latest"), "nonprod")  # not `test`

    def test_empty_is_unknown(self):
        self.assertEqual(guard.classify(None), "unknown")
        self.assertEqual(guard.classify(""), "unknown")


class ParsingTests(unittest.TestCase):
    def test_split_on_operators(self):
        tokens = guard.tokenize("echo hi && kubectl get pods | head")
        groups = guard.split_simple_commands(tokens)
        self.assertEqual(groups, [["echo", "hi"], ["kubectl", "get", "pods"], ["head"]])

    def test_command_substitution_splits(self):
        tokens = guard.tokenize("echo $(kubectl delete ns x)")
        groups = guard.split_simple_commands(tokens)
        self.assertIn(["kubectl", "delete", "ns", "x"], groups)

    def test_backticks_split(self):
        tokens = guard.tokenize("echo `kubectl delete ns x`")
        groups = guard.split_simple_commands(tokens)
        self.assertIn(["kubectl", "delete", "ns", "x"], groups)

    def test_unbalanced_quotes_return_none(self):
        self.assertIsNone(guard.tokenize("kubectl delete 'oops"))

    def test_env_prefix_extraction(self):
        env, argv = guard.extract_env_prefix(
            ["TF_WORKSPACE=dev", "PROD_GUARD_OVERRIDE=x", "terraform", "apply"])
        self.assertEqual(env, {"TF_WORKSPACE": "dev", "PROD_GUARD_OVERRIDE": "x"})
        self.assertEqual(argv, ["terraform", "apply"])

    def test_strip_wrappers(self):
        self.assertEqual(
            guard.strip_wrappers(["sudo", "-u", "root", "kubectl", "get"], {}),
            ["kubectl", "get"])
        self.assertEqual(
            guard.strip_wrappers(["timeout", "-s", "KILL", "30", "kubectl", "get"], {}),
            ["kubectl", "get"])
        self.assertEqual(
            guard.strip_wrappers(["xargs", "-n1", "kubectl", "delete", "ns"], {}),
            ["kubectl", "delete", "ns"])
        env = {}
        self.assertEqual(
            guard.strip_wrappers(["env", "AWS_PROFILE=dev", "aws", "s3", "ls"], env),
            ["aws", "s3", "ls"])
        self.assertEqual(env, {"AWS_PROFILE": "dev"})

    def test_flag_values_both_forms(self):
        argv = ["kubectl", "--context=a", "delete", "--namespace", "b"]
        self.assertEqual(guard.first_flag_value(argv, ("--context",)), "a")
        self.assertEqual(guard.first_flag_value(argv, ("--namespace",)), "b")

    def test_words_skip_flag_values(self):
        argv = ["kubectl", "-n", "kube-system", "delete", "pod", "x"]
        self.assertEqual(guard.words_of(argv, guard.KUBE_VALUE_FLAGS),
                         ["delete", "pod", "x"])


class KubectlDecisionTests(unittest.TestCase):
    def test_prod_mutating_denied(self):
        decision, reason = run_hook("kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")
        self.assertIn("gke_acme_prod-us", reason)
        self.assertIn("PROD_GUARD_OVERRIDE", reason)

    def test_prod_readonly_defers(self):
        decision, _ = run_hook("kubectl --context gke_acme_prod-us get pods")
        self.assertIsNone(decision)

    def test_nonprod_explicit_defers(self):
        decision, _ = run_hook("kubectl --context kind-ci delete pod x")
        self.assertIsNone(decision)

    def test_unknown_explicit_asks(self):
        decision, reason = run_hook("kubectl --context bluefin apply -f m.yaml")
        self.assertEqual(decision, "ask")
        self.assertIn("bluefin", reason)

    def test_ambient_mutating_asks(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, reason = run_hook("kubectl delete pod x", home=home)
        self.assertEqual(decision, "ask")
        self.assertIn("kind-ci", reason)
        self.assertIn("--context", reason)

    def test_ambient_prod_denied(self):
        home = make_home(kubeconfig=KUBECONFIG_PROD)
        decision, reason = run_hook("kubectl scale deploy x --replicas=0", home=home)
        self.assertEqual(decision, "deny")
        self.assertIn("gke_acme_prod-us", reason)

    def test_no_kubeconfig_mutating_asks(self):
        decision, _ = run_hook("kubectl apply -f m.yaml")
        self.assertEqual(decision, "ask")

    def test_rollout_status_defers_restart_guarded(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, _ = run_hook("kubectl rollout status deploy/x", home=home)
        self.assertIsNone(decision)
        decision, _ = run_hook("kubectl rollout restart deploy/x", home=home)
        self.assertEqual(decision, "ask")

    def test_exec_is_mutating(self):
        decision, _ = run_hook("kubectl --context gke_acme_prod-us exec -it pod -- sh")
        self.assertEqual(decision, "deny")

    def test_unknown_verb_treated_as_mutating(self):
        decision, _ = run_hook("kubectl --context bluefin frobnicate x")
        self.assertEqual(decision, "ask")

    def test_use_context_prod_denied(self):
        decision, _ = run_hook("kubectl config use-context gke_acme_prod-us")
        self.assertEqual(decision, "deny")

    def test_use_context_nonprod_asks(self):
        decision, reason = run_hook("kubectl config use-context kind-ci")
        self.assertEqual(decision, "ask")
        self.assertIn("shared", reason)

    def test_config_view_defers(self):
        decision, _ = run_hook("kubectl config view")
        self.assertIsNone(decision)
        decision, _ = run_hook("kubectl config current-context")
        self.assertIsNone(decision)


class CompoundBypassTests(unittest.TestCase):
    def test_chained_after_echo_caught(self):
        decision, _ = run_hook(
            "echo hi && kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_pipe_segment_caught(self):
        decision, _ = run_hook(
            "kustomize build overlays/prod | kubectl --context acme-production apply -f -")
        self.assertEqual(decision, "deny")

    def test_command_substitution_caught(self):
        decision, _ = run_hook(
            "echo $(kubectl --context acme-production delete ns x)")
        self.assertEqual(decision, "deny")

    def test_backtick_caught(self):
        decision, _ = run_hook(
            "echo `kubectl --context acme-production delete ns x`")
        self.assertEqual(decision, "deny")

    def test_bash_dash_c_caught(self):
        decision, _ = run_hook(
            "bash -c 'kubectl --context acme-production delete ns x'")
        self.assertEqual(decision, "deny")

    def test_eval_caught(self):
        decision, _ = run_hook(
            "eval kubectl --context acme-production delete ns x")
        self.assertEqual(decision, "deny")

    def test_semicolon_and_newline_caught(self):
        decision, _ = run_hook(
            "true; kubectl --context acme-production delete ns x")
        self.assertEqual(decision, "deny")
        decision, _ = run_hook(
            "true\nkubectl --context acme-production delete ns x")
        self.assertEqual(decision, "deny")

    def test_deny_beats_ask_in_chain(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, _ = run_hook(
            "kubectl delete pod x && kubectl --context acme-production delete ns y",
            home=home)
        self.assertEqual(decision, "deny")

    def test_kustomize_alone_defers(self):
        decision, _ = run_hook("kustomize build overlays/prod")
        self.assertIsNone(decision)


class OverrideTests(unittest.TestCase):
    def test_override_downgrades_deny_to_ask(self):
        decision, reason = run_hook(
            "PROD_GUARD_OVERRIDE=incident-42 "
            "kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "ask")
        self.assertIn("override acknowledged", reason)

    def test_override_does_not_touch_plain_ask(self):
        decision, reason = run_hook(
            "PROD_GUARD_OVERRIDE=x kubectl --context bluefin apply -f m.yaml")
        self.assertEqual(decision, "ask")
        self.assertNotIn("override acknowledged", reason)

    def test_disable_env_defers_everything(self):
        decision, _ = run_hook(
            "kubectl --context gke_acme_prod-us delete ns x",
            env_extra={"PROD_GUARD_DISABLE": "1"})
        self.assertIsNone(decision)


class HelmFluxArgocdTests(unittest.TestCase):
    def test_helm_prod_upgrade_denied(self):
        decision, _ = run_hook(
            "helm --kube-context acme-production upgrade api ./chart")
        self.assertEqual(decision, "deny")

    def test_helm_template_defers(self):
        decision, _ = run_hook("helm template api ./chart")
        self.assertIsNone(decision)

    def test_helm_list_defers(self):
        decision, _ = run_hook("helm list -A")
        self.assertIsNone(decision)

    def test_helm_ambient_install_asks(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, reason = run_hook("helm install api ./chart", home=home)
        self.assertEqual(decision, "ask")
        self.assertIn("--kube-context", reason)

    def test_flux_reconcile_prod_denied(self):
        decision, _ = run_hook(
            "flux reconcile kustomization app --context acme-production")
        self.assertEqual(decision, "deny")

    def test_flux_get_defers(self):
        decision, _ = run_hook("flux get kustomizations")
        self.assertIsNone(decision)

    def test_argocd_sync_prod_server_denied(self):
        decision, _ = run_hook(
            "argocd app sync api --server argocd.prod.acme.io")
        self.assertEqual(decision, "deny")

    def test_argocd_list_defers(self):
        decision, _ = run_hook("argocd app list")
        self.assertIsNone(decision)


class GcloudTests(unittest.TestCase):
    def test_delete_prod_project_denied(self):
        decision, _ = run_hook(
            "gcloud compute instances delete vm1 --project=acme-prod")
        self.assertEqual(decision, "deny")

    def test_list_prod_project_defers(self):
        decision, _ = run_hook(
            "gcloud compute instances list --project=acme-prod")
        self.assertIsNone(decision)

    def test_delete_dev_project_defers(self):
        decision, _ = run_hook(
            "gcloud compute instances delete vm1 --project=acme-dev")
        self.assertIsNone(decision)

    def test_ambient_prod_project_denied(self):
        home = make_home(gcloud_project="acme-prod")
        decision, reason = run_hook("gcloud compute instances delete vm1", home=home)
        self.assertEqual(decision, "deny")
        self.assertIn("acme-prod", reason)

    def test_ambient_dev_project_asks(self):
        home = make_home(gcloud_project="acme-dev")
        decision, reason = run_hook("gcloud compute instances delete vm1", home=home)
        self.assertEqual(decision, "ask")
        self.assertIn("--project", reason)

    def test_get_credentials_asks(self):
        decision, reason = run_hook(
            "gcloud container clusters get-credentials c --project acme-dev")
        self.assertEqual(decision, "ask")
        self.assertIn("kubeconfig", reason)

    def test_config_set_prod_project_denied(self):
        decision, _ = run_hook("gcloud config set project acme-prod")
        self.assertEqual(decision, "deny")

    def test_config_set_dev_project_asks(self):
        decision, _ = run_hook("gcloud config set project acme-dev")
        self.assertEqual(decision, "ask")


class AwsAzTests(unittest.TestCase):
    def test_terminate_prod_profile_denied(self):
        decision, _ = run_hook(
            "aws ec2 terminate-instances --instance-ids i-1 --profile prod")
        self.assertEqual(decision, "deny")

    def test_env_profile_dev_defers(self):
        decision, _ = run_hook(
            "AWS_PROFILE=dev aws ec2 terminate-instances --instance-ids i-1")
        self.assertIsNone(decision)

    def test_describe_defers(self):
        decision, _ = run_hook("aws ec2 describe-instances")
        self.assertIsNone(decision)

    def test_s3_rm_no_profile_asks(self):
        decision, reason = run_hook("aws s3 rm s3://bucket/key")
        self.assertEqual(decision, "ask")
        self.assertIn("--profile", reason)

    def test_aws_configure_asks(self):
        decision, _ = run_hook("aws configure")
        self.assertEqual(decision, "ask")

    def test_update_kubeconfig_asks(self):
        decision, _ = run_hook(
            "aws eks update-kubeconfig --name c --profile dev")
        self.assertEqual(decision, "ask")

    def test_az_delete_prod_subscription_denied(self):
        decision, _ = run_hook(
            "az group delete -n rg --subscription acme-prod-sub")
        self.assertEqual(decision, "deny")

    def test_az_list_defers(self):
        decision, _ = run_hook("az vm list")
        self.assertIsNone(decision)

    def test_az_ambient_prod_denied(self):
        home = make_home(az_subscription="Acme Production")
        decision, _ = run_hook("az vm delete -n vm1 -g rg --yes", home=home)
        self.assertEqual(decision, "deny")

    def test_az_account_set_asks(self):
        decision, _ = run_hook("az account set --subscription acme-dev-sub")
        self.assertEqual(decision, "ask")


class TerraformTests(unittest.TestCase):
    def test_plan_defers(self):
        decision, _ = run_hook("terraform plan")
        self.assertIsNone(decision)

    def test_apply_no_workspace_asks(self):
        decision, reason = run_hook("terraform apply")
        self.assertEqual(decision, "ask")
        self.assertIn("TF_WORKSPACE", reason)

    def test_apply_prod_workspace_denied(self):
        decision, _ = run_hook("TF_WORKSPACE=prod terraform apply")
        self.assertEqual(decision, "deny")

    def test_apply_dev_workspace_defers(self):
        decision, _ = run_hook("TF_WORKSPACE=dev terraform apply")
        self.assertIsNone(decision)

    def test_selected_prod_workspace_denied(self):
        home = make_home()
        tfdir = os.path.join(home, ".terraform")
        os.makedirs(tfdir)
        with open(os.path.join(tfdir, "environment"), "w", encoding="utf-8") as f:
            f.write("prod")
        decision, _ = run_hook("terraform destroy", home=home, cwd=home)
        self.assertEqual(decision, "deny")

    def test_workspace_select_prod_denied(self):
        decision, _ = run_hook("terraform workspace select prod")
        self.assertEqual(decision, "deny")

    def test_workspace_list_defers(self):
        decision, _ = run_hook("terraform workspace list")
        self.assertIsNone(decision)

    def test_state_rm_asks(self):
        decision, _ = run_hook("terraform state rm aws_instance.x")
        self.assertEqual(decision, "ask")

    def test_state_list_defers(self):
        decision, _ = run_hook("terraform state list")
        self.assertIsNone(decision)


class DockerTests(unittest.TestCase):
    def test_local_daemon_mutation_defers(self):
        decision, _ = run_hook("docker rm -f app")
        self.assertIsNone(decision)

    def test_explicit_prod_context_denied(self):
        decision, _ = run_hook("docker --context prod-swarm rm -f app")
        self.assertEqual(decision, "deny")

    def test_ambient_prod_context_denied(self):
        home = make_home(docker_context="prod-swarm")
        decision, _ = run_hook("docker rm -f app", home=home)
        self.assertEqual(decision, "deny")

    def test_ambient_desktop_context_defers(self):
        home = make_home(docker_context="desktop-linux")
        decision, _ = run_hook("docker system prune -f", home=home)
        self.assertIsNone(decision)

    def test_push_prod_registry_denied(self):
        decision, _ = run_hook("docker push registry.prod.acme.io/app:1")
        self.assertEqual(decision, "deny")

    def test_push_local_registry_defers(self):
        decision, _ = run_hook("docker push 127.0.0.1:5000/app:e2e-1")
        self.assertIsNone(decision)

    def test_push_unknown_registry_asks(self):
        decision, _ = run_hook("docker push ghcr.io/acme/app:1")
        self.assertEqual(decision, "ask")

    def test_ps_defers(self):
        decision, _ = run_hook("docker ps -a")
        self.assertIsNone(decision)

    def test_context_use_prod_denied(self):
        decision, _ = run_hook("docker context use prod-swarm")
        self.assertEqual(decision, "deny")

    def test_local_build_defers(self):
        decision, _ = run_hook("docker build -t app:dev .")
        self.assertIsNone(decision)


class GhTests(unittest.TestCase):
    def test_pr_create_defers_without_prod_remote(self):
        decision, _ = run_hook("gh pr create -t x -b y")
        self.assertIsNone(decision)

    def test_repo_delete_prod_name_denied(self):
        decision, _ = run_hook("gh repo delete acme/prod-infra --yes")
        self.assertEqual(decision, "deny")

    def test_pr_list_defers(self):
        decision, _ = run_hook("gh pr list")
        self.assertIsNone(decision)

    def test_prod_remote_merge_denied(self):
        home = make_home()
        repo = os.path.join(home, "repo")
        os.makedirs(repo)
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "remote", "add", "origin",
                        "git@github.com:acme/prod-infra.git"], check=True)
        decision, _ = run_hook("gh pr merge 1 --squash", home=home, cwd=repo)
        self.assertEqual(decision, "deny")

    def test_gh_api_get_defers(self):
        decision, _ = run_hook("gh api repos/acme/prod-infra")
        self.assertIsNone(decision)

    def test_gh_api_delete_prod_repo_flag_denied(self):
        decision, _ = run_hook(
            "gh api -X DELETE repos/x/y -R acme/prod-infra")
        self.assertEqual(decision, "deny")


class ContextSwitcherTests(unittest.TestCase):
    def test_kubectx_prod_denied(self):
        decision, _ = run_hook("kubectx gke_acme_prod-us")
        self.assertEqual(decision, "deny")

    def test_kubectx_nonprod_asks(self):
        decision, _ = run_hook("kubectx kind-ci")
        self.assertEqual(decision, "ask")

    def test_kubectx_bare_defers(self):
        decision, _ = run_hook("kubectx")
        self.assertIsNone(decision)

    def test_kubens_with_arg_asks(self):
        decision, _ = run_hook("kubens kube-system")
        self.assertEqual(decision, "ask")

    def test_kubens_bare_defers(self):
        decision, _ = run_hook("kubens")
        self.assertIsNone(decision)


class EksctlDoctlTests(unittest.TestCase):
    def test_eksctl_delete_prod_cluster_denied(self):
        decision, _ = run_hook("eksctl delete cluster --cluster prod-main")
        self.assertEqual(decision, "deny")

    def test_eksctl_get_defers(self):
        decision, _ = run_hook("eksctl get cluster")
        self.assertIsNone(decision)

    def test_doctl_delete_no_context_asks(self):
        decision, _ = run_hook("doctl kubernetes cluster delete c1")
        self.assertEqual(decision, "ask")

    def test_doctl_list_defers(self):
        decision, _ = run_hook("doctl kubernetes cluster list")
        self.assertIsNone(decision)


class InfrastructureTests(unittest.TestCase):
    def test_uncovered_tool_defers(self):
        decision, _ = run_hook("ls -la")
        self.assertIsNone(decision)

    def test_non_bash_tool_defers(self):
        decision, _ = run_hook(None, payload={
            "tool_name": "Write",
            "tool_input": {"file_path": "/x", "content": "y"}})
        self.assertIsNone(decision)

    def test_empty_command_defers(self):
        decision, _ = run_hook("")
        self.assertIsNone(decision)

    def test_garbage_stdin_defers(self):
        decision, _ = run_hook(None, payload="this is not json")
        self.assertIsNone(decision)

    def test_unbalanced_quotes_defer(self):
        decision, _ = run_hook("kubectl delete 'oops")
        self.assertIsNone(decision)

    def test_bare_tool_name_defers(self):
        decision, _ = run_hook("kubectl")
        self.assertIsNone(decision)

    def test_bypass_permissions_upgrades_ask_to_deny(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, _ = run_hook("kubectl delete pod x", home=home,
                               permission_mode="bypassPermissions")
        self.assertEqual(decision, "deny")

    def test_custom_config_patterns(self):
        home = make_home()
        cdir = os.path.join(home, ".claude")
        os.makedirs(cdir)
        with open(os.path.join(cdir, "prod-guard.json"), "w", encoding="utf-8") as f:
            json.dump({"prod": ["^bluefin$"], "nonprod": ["^greenfin$"]}, f)
        decision, _ = run_hook("kubectl --context bluefin delete ns x", home=home)
        self.assertEqual(decision, "deny")
        decision, _ = run_hook("kubectl --context greenfin delete ns x", home=home)
        self.assertIsNone(decision)

    def test_broken_config_falls_back_to_builtins(self):
        home = make_home()
        cdir = os.path.join(home, ".claude")
        os.makedirs(cdir)
        with open(os.path.join(cdir, "prod-guard.json"), "w", encoding="utf-8") as f:
            f.write("{not json")
        decision, _ = run_hook(
            "kubectl --context gke_acme_prod-us delete ns x", home=home)
        self.assertEqual(decision, "deny")


class BypassBatteryTests(unittest.TestCase):
    """Adversarial command shapes: every case here is a form an agent (or a
    prompt-injected agent) could plausibly emit to slip a prod mutation past
    a naive first-token guard."""

    def test_absolute_path_to_tool(self):
        decision, _ = run_hook(
            "/usr/local/bin/kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_flag_after_verb(self):
        decision, _ = run_hook("kubectl delete ns x --context gke_acme_prod-us")
        self.assertEqual(decision, "deny")

    def test_flag_equals_form_after_verb(self):
        decision, _ = run_hook("kubectl delete ns x --context=gke_acme_prod-us")
        self.assertEqual(decision, "deny")

    def test_sudo_wrapper(self):
        decision, _ = run_hook(
            "sudo kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_command_wrapper(self):
        decision, _ = run_hook(
            "command kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_env_wrapper_with_assignment(self):
        decision, _ = run_hook(
            "env KUBECONFIG=/nonexistent kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_xargs_pipeline(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, _ = run_hook("echo x | xargs kubectl delete ns", home=home)
        self.assertEqual(decision, "ask")

    def test_nested_shell_two_levels(self):
        decision, _ = run_hook(
            "bash -c \"sh -c 'kubectl --context gke_acme_prod-us delete ns x'\"")
        self.assertEqual(decision, "deny")

    def test_recursion_depth_bound_is_a_known_limit(self):
        # Beyond depth 3 the evaluator stops recursing — a DOCUMENTED false
        # negative (README Limitations). This test locks the bound so a
        # change to it is a conscious decision, not drift.
        guard._PATTERNS = None
        findings, override = guard.evaluate_command_string(
            "kubectl --context gke_acme_prod-us delete ns x", {"cwd": "/"}, depth=4)
        self.assertEqual(findings, [])
        findings, _ = guard.evaluate_command_string(
            "kubectl --context gke_acme_prod-us delete ns x", {"cwd": "/"}, depth=3)
        self.assertEqual(len(findings), 1)

    def test_unexpanded_variable_target_asks_not_defers(self):
        # $CTX can't be resolved at hook time; it must classify UNKNOWN and
        # prompt — silently deferring would let `CTX=prod ...` through.
        decision, _ = run_hook("kubectl --context $CTX delete ns x")
        self.assertEqual(decision, "ask")

    def test_override_in_later_segment_applies(self):
        decision, reason = run_hook(
            "true && PROD_GUARD_OVERRIDE=drill kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "ask")
        self.assertIn("override acknowledged", reason)

    def test_assignment_only_segment_then_mutation(self):
        decision, _ = run_hook(
            "FOO=1; kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_subshell_group_caught(self):
        decision, _ = run_hook(
            "(cd /srv && kubectl --context gke_acme_prod-us delete ns x)")
        self.assertEqual(decision, "deny")

    def test_or_chain_caught(self):
        decision, _ = run_hook(
            "true || kubectl --context gke_acme_prod-us delete ns x")
        self.assertEqual(decision, "deny")

    def test_background_ampersand_caught(self):
        decision, _ = run_hook(
            "kubectl --context gke_acme_prod-us delete ns x &")
        self.assertEqual(decision, "deny")


class VerbSweepTests(unittest.TestCase):
    """Table-driven sweep: read-only verbs must defer even against an
    explicit prod target; mutating verbs must deny against it. Locks the
    verb tables against silent narrowing."""

    KUBECTL_RO = [
        "get pods", "describe pod x", "logs pod/x", "top pods", "diff -f m.yaml",
        "explain deploy", "api-resources", "api-versions", "events",
        "wait --for=condition=Ready pod/x", "auth can-i list pods",
        "cluster-info", "rollout status deploy/x", "rollout history deploy/x",
    ]
    KUBECTL_MUT = [
        "apply -f m.yaml", "delete ns x", "edit deploy/x", "patch deploy x -p {}",
        "replace -f m.yaml", "scale deploy x --replicas=0", "annotate pod x k=v",
        "label pod x k=v", "rollout restart deploy/x", "drain node-1",
        "cordon node-1", "uncordon node-1", "taint nodes node-1 k=v:NoSchedule",
        "exec -it pod-x -- sh", "cp pod-x:/f /tmp/f", "run tmp --image=busybox",
        "expose deploy x --port=80", "set image deploy/x c=img:2",
    ]

    def test_kubectl_readonly_defers_on_prod(self):
        for tail in self.KUBECTL_RO:
            with self.subTest(tail=tail):
                decision, _ = run_hook(
                    "kubectl --context gke_acme_prod-us %s" % tail)
                self.assertIsNone(decision)

    def test_kubectl_mutating_denies_on_prod(self):
        for tail in self.KUBECTL_MUT:
            with self.subTest(tail=tail):
                decision, _ = run_hook(
                    "kubectl --context gke_acme_prod-us %s" % tail)
                self.assertEqual(decision, "deny")

    def test_helm_sweep(self):
        for tail in ("list -A", "status api", "history api", "get values api"):
            with self.subTest(tail=tail):
                decision, _ = run_hook(
                    "helm --kube-context acme-production %s" % tail)
                self.assertIsNone(decision)
        for tail in ("install api ./chart", "upgrade api ./chart",
                     "uninstall api", "rollback api 1", "test api"):
            with self.subTest(tail=tail):
                decision, _ = run_hook(
                    "helm --kube-context acme-production %s" % tail)
                self.assertEqual(decision, "deny")

    def test_aws_sweep(self):
        for tail in ("ec2 describe-instances", "s3api list-buckets",
                     "s3 ls s3://b", "sts get-caller-identity",
                     "s3api head-object --bucket b --key k"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("aws %s --profile prod" % tail)
                self.assertIsNone(decision)
        for tail in ("s3api put-object --bucket b --key k",
                     "ec2 modify-instance-attribute --instance-id i-1",
                     "s3api delete-bucket --bucket b", "s3 sync . s3://b",
                     "s3 cp f s3://b/f", "s3 mv s3://b/a s3://b/c",
                     "ec2 run-instances --image-id ami-1",
                     "ec2 start-instances --instance-ids i-1",
                     "rds reboot-db-instance --db-instance-identifier d"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("aws %s --profile prod" % tail)
                self.assertEqual(decision, "deny")

    def test_gcloud_sweep(self):
        for tail in ("compute instances list", "compute instances describe vm1",
                     "projects get-iam-policy p", "run services list"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("gcloud %s --project acme-prod" % tail)
                self.assertIsNone(decision)
        for tail in ("compute instances update vm1", "run deploy svc --image i",
                     "projects add-iam-policy-binding p --member m --role r",
                     "projects set-iam-policy p policy.json",
                     "compute ssh vm1", "sql instances restart db1"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("gcloud %s --project acme-prod" % tail)
                self.assertEqual(decision, "deny")

    def test_az_sweep(self):
        for tail in ("vm show -n v -g rg", "vm list", "group list"):
            with self.subTest(tail=tail):
                decision, _ = run_hook(
                    "az %s --subscription acme-prod-sub" % tail)
                self.assertIsNone(decision)
        for tail in ("vm update -n v -g rg", "vm start -n v -g rg",
                     "vm stop -n v -g rg", "vm restart -n v -g rg",
                     "vm deallocate -n v -g rg", "keyvault purge -n kv"):
            with self.subTest(tail=tail):
                decision, _ = run_hook(
                    "az %s --subscription acme-prod-sub" % tail)
                self.assertEqual(decision, "deny")

    def test_terraform_sweep(self):
        for verb in ("fmt", "validate", "show", "output", "providers", "graph"):
            with self.subTest(verb=verb):
                decision, _ = run_hook("TF_WORKSPACE=prod terraform %s" % verb)
                self.assertIsNone(decision)
        for verb in ("apply", "destroy", "import aws_x.y id", "taint aws_x.y",
                     "untaint aws_x.y", "refresh"):
            with self.subTest(verb=verb):
                decision, _ = run_hook("TF_WORKSPACE=prod terraform %s" % verb)
                self.assertEqual(decision, "deny")

    def test_tofu_alias(self):
        decision, _ = run_hook("TF_WORKSPACE=prod tofu apply")
        self.assertEqual(decision, "deny")

    def test_docker_sweep(self):
        for tail in ("images", "inspect c1", "logs c1", "stats", "events",
                     "history img"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("docker --context prod-swarm %s" % tail)
                self.assertIsNone(decision)
        for tail in ("stop c1", "kill c1", "exec c1 sh", "run img",
                     "system prune -f", "rmi img", "restart c1"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("docker --context prod-swarm %s" % tail)
                self.assertEqual(decision, "deny")

    def test_flux_sweep(self):
        for tail in ("get kustomizations", "logs", "check", "tree kustomization app",
                     "export source git app"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("flux %s --context acme-production" % tail)
                self.assertIsNone(decision)
        for tail in ("suspend kustomization app", "resume kustomization app",
                     "reconcile kustomization app", "delete kustomization app",
                     "create source git app --url u"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("flux %s --context acme-production" % tail)
                self.assertEqual(decision, "deny")


class AmbientFixtureTests(unittest.TestCase):
    """Edge cases in the local config-file readers."""

    def test_azure_profile_with_bom(self):
        home = make_home(az_subscription="Acme Production", az_bom=True)
        decision, _ = run_hook("az vm delete -n v -g rg --yes", home=home)
        self.assertEqual(decision, "deny")

    def test_kubeconfig_env_multi_path_uses_first(self):
        home = make_home()
        kc1 = os.path.join(home, "kc-prod")
        with open(kc1, "w", encoding="utf-8") as f:
            f.write(KUBECONFIG_PROD)
        decision, _ = run_hook(
            "kubectl delete pod x", home=home,
            env_extra={"KUBECONFIG": "%s:%s" % (kc1, os.path.join(home, "kc-other"))})
        self.assertEqual(decision, "deny")

    def test_kubeconfig_quoted_current_context(self):
        home = make_home(
            kubeconfig='apiVersion: v1\ncurrent-context: "gke_acme_prod-us"\n')
        decision, _ = run_hook("kubectl delete pod x", home=home)
        self.assertEqual(decision, "deny")

    def test_kubeconfig_prefix_assignment_unresolvable_asks(self):
        decision, _ = run_hook("KUBECONFIG=/nonexistent kubectl delete pod x")
        self.assertEqual(decision, "ask")

    def test_docker_config_without_current_context_defers(self):
        home = make_home()
        ddir = os.path.join(home, ".docker")
        os.makedirs(ddir)
        with open(os.path.join(ddir, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"auths": {}}, f)
        decision, _ = run_hook("docker rm -f c1", home=home)
        self.assertIsNone(decision)

    def test_argocd_ambient_prod_denied(self):
        home = make_home(argocd_context="argocd.prod.acme.io")
        decision, _ = run_hook("argocd app sync api", home=home)
        self.assertEqual(decision, "deny")

    def test_argocd_ambient_unknown_asks(self):
        home = make_home(argocd_context="argocd.internal")
        decision, _ = run_hook("argocd app sync api", home=home)
        self.assertEqual(decision, "ask")


class SpecialCaseTests(unittest.TestCase):
    """Branches for commands that mutate shared local state (kubeconfig
    writers, credential/context switchers) and registry-classified pushes."""

    def test_eksctl_write_kubeconfig_asks(self):
        decision, reason = run_hook(
            "eksctl utils write-kubeconfig --cluster dev-main")
        self.assertEqual(decision, "ask")
        self.assertIn("kubeconfig", reason)

    def test_doctl_kubeconfig_save_asks(self):
        decision, reason = run_hook(
            "doctl kubernetes cluster kubeconfig save c1")
        self.assertEqual(decision, "ask")
        self.assertIn("kubeconfig", reason)

    def test_az_login_and_account_clear_ask(self):
        for cmd in ("az login", "az logout", "az account clear"):
            with self.subTest(cmd=cmd):
                decision, _ = run_hook(cmd)
                self.assertEqual(decision, "ask")

    def test_terraform_login_asks(self):
        decision, _ = run_hook("terraform login")
        self.assertEqual(decision, "ask")

    def test_terraform_state_push_asks(self):
        decision, _ = run_hook("terraform state push errored.tfstate")
        self.assertEqual(decision, "ask")

    def test_gcloud_auth_login_asks_list_defers(self):
        decision, _ = run_hook("gcloud auth login")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("gcloud auth list")
        self.assertIsNone(decision)

    def test_kubectl_config_delete_context_asks(self):
        decision, _ = run_hook("kubectl config delete-context old-ctx")
        self.assertEqual(decision, "ask")

    def test_kubectx_delete_and_previous_ask(self):
        decision, _ = run_hook("kubectx -d old-ctx")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("kubectx -")
        self.assertEqual(decision, "ask")

    def test_helm_push_registry_classified(self):
        decision, _ = run_hook(
            "helm push chart.tgz oci://registry.prod.acme.io/charts")
        self.assertEqual(decision, "deny")
        decision, _ = run_hook(
            "helm push chart.tgz oci://127.0.0.1:5000/charts")
        self.assertIsNone(decision)
        decision, _ = run_hook(
            "helm push chart.tgz oci://ghcr.io/acme/charts")
        self.assertEqual(decision, "ask")

    def test_docker_build_push_tag_classified(self):
        decision, _ = run_hook(
            "docker build --push -t registry.prod.acme.io/app:1 .")
        self.assertEqual(decision, "deny")
        decision, _ = run_hook("docker build --push -t ghcr.io/acme/app:1 .")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("docker build --push -t 127.0.0.1:5000/app:1 .")
        self.assertIsNone(decision)

    def test_gh_repo_env_var_target(self):
        decision, _ = run_hook("GH_REPO=acme/prod-app gh workflow run deploy")
        self.assertEqual(decision, "deny")

    def test_gcloud_configurations_activate_asks(self):
        decision, _ = run_hook("gcloud config configurations activate other")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("gcloud config configurations list")
        self.assertIsNone(decision)


class AliasToolTests(unittest.TestCase):
    """Q1: oc shares kubectl's evaluator; podman/nerdctl/docker-compose share
    docker's. The alias must inherit the full decision matrix, plus the few
    alias-specific verbs (oc login/project, podman --connection)."""

    def test_oc_prod_mutation_denied(self):
        decision, _ = run_hook("oc --context gke_acme_prod-us delete project x")
        self.assertEqual(decision, "deny")

    def test_oc_readonly_defers(self):
        for cmd in ("oc --context gke_acme_prod-us get pods",
                    "oc status", "oc whoami", "oc projects",
                    "oc process -f template.yaml"):
            with self.subTest(cmd=cmd):
                decision, _ = run_hook(cmd)
                self.assertIsNone(decision)

    def test_oc_ambient_mutation_asks(self):
        home = make_home(kubeconfig=KUBECONFIG_KIND)
        decision, _ = run_hook("oc new-app nginx", home=home)
        self.assertEqual(decision, "ask")

    def test_oc_login_asks(self):
        decision, reason = run_hook("oc login https://api.cluster.example:6443")
        self.assertEqual(decision, "ask")
        self.assertIn("kubeconfig", reason)

    def test_oc_project_switch_asks_bare_defers(self):
        decision, _ = run_hook("oc project other-ns")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("oc project")
        self.assertIsNone(decision)

    def test_kubectl_login_verb_stays_guarded(self):
        # kubectl has no `login`; via oc's rule it now asks rather than
        # falling into ambient resolution — still never a silent pass.
        decision, _ = run_hook("kubectl login")
        self.assertEqual(decision, "ask")

    def test_podman_local_defers_remote_denied(self):
        decision, _ = run_hook("podman rm -f c1")
        self.assertIsNone(decision)
        decision, _ = run_hook("podman --connection prod-host rm -f c1")
        self.assertEqual(decision, "deny")

    def test_podman_container_host_env_denied(self):
        decision, _ = run_hook(
            "CONTAINER_HOST=ssh://root@prod-host podman rm -f c1")
        self.assertEqual(decision, "deny")

    def test_podman_push_prod_registry_denied(self):
        decision, _ = run_hook("podman push registry.prod.acme.io/app:1")
        self.assertEqual(decision, "deny")

    def test_nerdctl_push_and_local(self):
        decision, _ = run_hook("nerdctl rm -f c1")
        self.assertIsNone(decision)
        decision, _ = run_hook("nerdctl push registry.prod.acme.io/app:1")
        self.assertEqual(decision, "deny")


class DockerComposeAndMultiTagTests(unittest.TestCase):
    """Q5: every -t on docker build --push is classified, and compose pushes
    (whose registry lives in the compose file) fail closed."""

    def test_multi_tag_push_prod_second_denied(self):
        decision, _ = run_hook(
            "docker build --push -t 127.0.0.1:5000/app:1 "
            "-t registry.prod.acme.io/app:1 .")
        self.assertEqual(decision, "deny")

    def test_multi_tag_push_all_nonprod_defers(self):
        decision, _ = run_hook(
            "docker build --push -t 127.0.0.1:5000/app:1 -t kind-local/app:1 .")
        self.assertIsNone(decision)

    def test_multi_tag_push_unknown_among_nonprod_asks(self):
        decision, reason = run_hook(
            "docker build --push -t 127.0.0.1:5000/app:1 -t ghcr.io/acme/app:1 .")
        self.assertEqual(decision, "ask")
        self.assertIn("ghcr.io/acme/app:1", reason)

    def test_push_without_tags_asks(self):
        decision, _ = run_hook("docker buildx build --push .")
        self.assertEqual(decision, "ask")

    def test_compose_push_asks(self):
        decision, reason = run_hook("docker compose push")
        self.assertEqual(decision, "ask")
        self.assertIn("compose file", reason)

    def test_compose_build_push_asks_plain_build_defers(self):
        decision, _ = run_hook("docker compose build --push")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("docker compose build")
        self.assertIsNone(decision)

    def test_compose_readonly_defers(self):
        for tail in ("ps", "config", "logs", "ls"):
            with self.subTest(tail=tail):
                decision, _ = run_hook("docker compose %s" % tail)
                self.assertIsNone(decision)

    def test_compose_up_local_defers_prod_context_denied(self):
        decision, _ = run_hook("docker compose up -d")
        self.assertIsNone(decision)
        home = make_home(docker_context="prod-swarm")
        decision, _ = run_hook("docker compose up -d", home=home)
        self.assertEqual(decision, "deny")

    def test_standalone_docker_compose_binary(self):
        decision, _ = run_hook("docker-compose push")
        self.assertEqual(decision, "ask")
        decision, _ = run_hook("docker-compose ps")
        self.assertIsNone(decision)


class RobustnessTests(unittest.TestCase):
    """The hook must never crash (PROD_GUARD_DEBUG=1 in run_hook re-raises
    any exception as a nonzero exit) and never emit `allow` (asserted inside
    run_hook on every call), whatever the input shape."""

    GARBAGE = [
        ";;;", "((((", "))))", "&& kubectl", "kubectl |", "| | |",
        "kubectl --context", "kubectl --context=",
        "kubectl üñîçødé delete",
        "a" * 10000,
        "kubectl " + "-x " * 500 + "delete",
        "docker push", "helm push", "gh api", "terraform", "eval", "bash -c",
        "bash -c ''", "xargs", "sudo", "env", "timeout 5",
        "kubectl delete\x0b\x0cpod",
    ]

    def test_garbage_corpus_never_crashes(self):
        for cmd in self.GARBAGE:
            with self.subTest(cmd=cmd[:40]):
                run_hook(cmd)  # run_hook raises on crash or forbidden output

    def test_long_chain_evaluates_all_segments(self):
        chain = " && ".join(["true"] * 50
                            + ["kubectl --context gke_acme_prod-us delete ns x"])
        decision, _ = run_hook(chain)
        self.assertEqual(decision, "deny")


class WiringTests(unittest.TestCase):
    def test_hooks_json_points_at_script(self):
        with open(REPO / "hooks" / "hooks.json", encoding="utf-8") as f:
            hooks = json.load(f)
        entries = hooks["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["matcher"], "Bash")
        cmd = entries[0]["hooks"][0]["command"]
        self.assertIn("scripts/bash-prod-guard.py", cmd)
        self.assertTrue(SCRIPT.exists())

    def test_plugin_and_marketplace_versions_match(self):
        with open(REPO / ".claude-plugin" / "plugin.json", encoding="utf-8") as f:
            plugin = json.load(f)
        with open(REPO / ".claude-plugin" / "marketplace.json", encoding="utf-8") as f:
            market = json.load(f)
        self.assertEqual(plugin["name"], "prod-guard")
        self.assertEqual(market["plugins"][0]["name"], "prod-guard")
        self.assertEqual(plugin["version"], market["plugins"][0]["version"])


if __name__ == "__main__":
    unittest.main()
