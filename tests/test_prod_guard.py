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
              az_subscription=None):
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
        with open(os.path.join(adir, "azureProfile.json"), "w", encoding="utf-8") as f:
            json.dump({"subscriptions": [
                {"name": az_subscription, "isDefault": True}]}, f)
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
    return out["permissionDecision"], out["permissionDecisionReason"]


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
