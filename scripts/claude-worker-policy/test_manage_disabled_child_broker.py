import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock as mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "manage_disabled_child_broker",
    os.path.join(_HERE, "manage-disabled-child-broker.py"),
)
tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(tool)


BROKER_SOURCE = (
    '"""Disabled child-session broker."""\n\n'
    'DENY_REASON_DISABLED = "child_broker_disabled"\n\n\n'
    'def get_status():\n'
    '    return {"prepared": True, "active": False}\n\n\n'
    'def request_child_session(*args, **kwargs):\n'
    '    return {"allowed": False, "reason": DENY_REASON_DISABLED}\n'
)

EXPECTED_OBJECT = {
    "prepared": True,
    "active": False,
    "repoHandshakePrepared": False,
    "paneClaudeExecutionMasterAllowed": False,
    "defaultDecision": "DENY",
    "sideEffectsAllowed": False,
    "workerCreationAllowed": False,
    "nestedDelegationAllowed": False,
    "capabilityAccessAllowed": False,
    "capabilityMintingAllowed": False,
    "gitAuthority": False,
    "scopeAuthority": False,
    "rollbackAuthority": False,
    "approvalAuthority": False,
    "promotionAuthority": False,
    "reviewerWriteAllowed": False,
    "providerFallbackAllowed": False,
    "authorizedCreators": ["codex-desktop-master"],
    "brokerModulePath": "/fixture/claude_child_broker.py",
    "brokerModuleSha256": "placeholder",
    "brokerTestPath": "/fixture/test_claude_child_broker.py",
}

# Mirrors the real verify_worker_policy.py shape closely enough to prove the
# patch actually wires check_claude_child_broker into run_all(spec), rather
# than merely defining it: a Check/LoadError class, CANONICAL_POLICY,
# read_json/sha256_file helpers, check_self_integrity computing SELF-01 from
# the manifest (so it observes whatever the manifest says *right now*), and
# check_canonical_policy computing POLICY-01 -- the exact call the patch must
# insert its own call immediately after.
VERIFIER_TEMPLATE = """#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path

CANONICAL_POLICY = Path({canonical_path!r})
GOLDEN_POLICY = Path({golden_path!r})
GOLDEN_MANIFEST = Path({manifest_path!r})
VERIFIER_PATH = Path(__file__).resolve()

NAME_TO_PATH = {{
    "verify_worker_policy.py": VERIFIER_PATH,
    "claude-worker-policy.golden.json": GOLDEN_POLICY,
}}


class LoadError(Exception):
    pass


class Check:
    __slots__ = ("cid", "target", "expectation", "ok", "observed")

    def __init__(self, cid, target, expectation, ok, observed):
        self.cid, self.target = cid, str(target)
        self.expectation, self.ok, self.observed = expectation, bool(ok), observed


def sha256_file(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return "unreadable"


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise LoadError(str(exc)) from exc


def check_self_integrity(checks):
    if not GOLDEN_MANIFEST.exists():
        raise LoadError("manifest missing")
    ok = True
    for line in GOLDEN_MANIFEST.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition("  ")
        path = NAME_TO_PATH.get(name.strip())
        if path is None or not path.exists():
            continue
        if sha256_file(path) != digest.strip():
            ok = False
    checks.append(Check("SELF-01", GOLDEN_MANIFEST, "hashes match manifest", ok, ok))
    return ok


def check_canonical_policy(checks, spec):
    golden = read_json(GOLDEN_POLICY)
    live = read_json(CANONICAL_POLICY)
    same = live == golden
    checks.append(Check("POLICY-01", CANONICAL_POLICY, "matches golden", same, same))


def run_all(spec):
    checks = []
    integrity_ok = check_self_integrity(checks)
    check_canonical_policy(checks, spec)
    return checks, integrity_ok


def main(argv=None):
    checks, integrity_ok = run_all({{}})
    ok = integrity_ok and all(c.ok for c in checks)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
"""


class FixtureMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)

        self.broker_path = root / "claude_child_broker.py"
        self.broker_path.write_text(BROKER_SOURCE)
        broker_sha256 = tool.sha256_text(BROKER_SOURCE)

        expected_obj = dict(EXPECTED_OBJECT)
        expected_obj["brokerModulePath"] = str(self.broker_path)
        expected_obj["brokerModuleSha256"] = broker_sha256
        expected_obj["brokerTestPath"] = str(root / "test_claude_child_broker.py")
        self.expected_obj = expected_obj

        self.canonical_path = root / "claude-worker-policy.json"
        canonical_data = {"schemaVersion": 8, "someOtherField": "untouched"}
        self.canonical_path.write_text(json.dumps(canonical_data, indent=2))

        self.golden_path = root / "claude-worker-policy.golden.json"
        self.golden_path.write_text(json.dumps(canonical_data, indent=2))

        self.verifier_path = root / "verify_worker_policy.py"
        self.verifier_path.write_text(
            VERIFIER_TEMPLATE.format(
                canonical_path=str(self.canonical_path),
                golden_path=str(self.golden_path),
                manifest_path=str(root / "GOLDEN.sha256"),
            )
        )

        self.manifest_path = root / "GOLDEN.sha256"
        self.manifest_path.write_text(
            f"# fixture manifest\n"
            f"{tool.sha256_file(self.verifier_path)}  verify_worker_policy.py\n"
            f"{tool.sha256_file(self.golden_path)}  claude-worker-policy.golden.json\n"
            f"cccc  some-other-file.json\n"
        )

        self.backup_dir = root / "rollback"

        self.config = {
            "schemaVersion": 3,
            "broker_prerequisite": {
                "path": str(self.broker_path),
                "expected_sha256": broker_sha256,
            },
            "claude_child_broker_object": expected_obj,
            "top_level_key": "claudeChildBroker",
            "must_be_false_fields": [
                "active",
                "repoHandshakePrepared",
                "paneClaudeExecutionMasterAllowed",
                "sideEffectsAllowed",
                "workerCreationAllowed",
                "nestedDelegationAllowed",
                "capabilityAccessAllowed",
                "capabilityMintingAllowed",
                "gitAuthority",
                "scopeAuthority",
                "rollbackAuthority",
                "approvalAuthority",
                "promotionAuthority",
                "reviewerWriteAllowed",
                "providerFallbackAllowed",
            ],
            "must_equal_fields": {"defaultDecision": "DENY"},
            "verifier_patch": {
                "function_marker": "# BEGIN claudeChildBroker verifier check (managed by disabled-child-broker.json, do not hand-edit)",
                "function_end_marker": "# END claudeChildBroker verifier check",
                "function_insert_before": "def run_all(spec):",
                "function_template": (
                    "# BEGIN claudeChildBroker verifier check (managed by disabled-child-broker.json, do not hand-edit)\n"
                    "def check_claude_child_broker(checks, spec):\n"
                    "    expected = {expected_literal}\n"
                    "    cid, target, expectation = \"POLICY-54\", CANONICAL_POLICY, \"claudeChildBroker is present and strictly disabled\"\n"
                    "    try:\n"
                    "        live = read_json(CANONICAL_POLICY)\n"
                    "    except LoadError as exc:\n"
                    "        checks.append(Check(cid, target, expectation, False, f\"canonical policy unreadable: {exc}\"))\n"
                    "        return\n"
                    "    obj = live.get(\"claudeChildBroker\")\n"
                    "    if not isinstance(obj, dict):\n"
                    "        checks.append(Check(cid, target, expectation, False, \"claudeChildBroker missing or not an object\"))\n"
                    "        return\n"
                    "    mismatches = [f\"{k}={obj.get(k)!r} (want {v!r})\" for k, v in expected.items() if obj.get(k) != v]\n"
                    "    broker_path = Path(expected.get(\"brokerModulePath\", \"\"))\n"
                    "    broker_ok = broker_path.exists() and sha256_file(broker_path) == expected.get(\"brokerModuleSha256\")\n"
                    "    if not broker_ok:\n"
                    "        mismatches.append(\"broker module missing or hash mismatch\")\n"
                    "    ok = not mismatches\n"
                    "    checks.append(Check(cid, target, expectation, ok, \"matches expected disabled posture\" if ok else \"; \".join(mismatches)))\n"
                    "# END claudeChildBroker verifier check\n\n\n"
                ),
                "call_anchor": "check_canonical_policy(checks, spec)",
                "call_statement": "check_claude_child_broker(checks, spec)  # managed by disabled-child-broker.json (claudeChildBroker, POLICY-54)",
            },
            "surfaces": {
                "canonical": {
                    "path": str(self.canonical_path),
                    "kind": "json_top_level_key",
                    "expected_prehash_sha256": tool.sha256_text(self.canonical_path.read_text()),
                },
                "golden": {
                    "path": str(self.golden_path),
                    "kind": "json_top_level_key",
                    "expected_prehash_sha256": tool.sha256_text(self.golden_path.read_text()),
                },
                "verifier": {
                    "path": str(self.verifier_path),
                    "kind": "python_patch",
                    "expected_prehash_sha256": tool.sha256_text(self.verifier_path.read_text()),
                },
                "manifest": {
                    "path": str(self.manifest_path),
                    "kind": "manifest",
                    "expected_prehash_sha256": tool.sha256_text(self.manifest_path.read_text()),
                    "updatable_entries": [
                        "verify_worker_policy.py",
                        "claude-worker-policy.golden.json",
                    ],
                },
            },
            "backup_dir": str(self.backup_dir),
            # Minimal stub so tool.main()'s combined check (broker + projection)
            # doesn't KeyError for fixtures that only exercise the broker wave.
            "projection": {
                "marker": "unused-in-broker-wave-fixtures",
                "detection_text": "unused-in-broker-wave-fixtures",
                "targets": {},
                "manifest": {"path": os.path.join(self.tmp.name, "nonexistent-projection-manifest")},
            },
        }


class CheckModeTests(FixtureMixin, unittest.TestCase):
    def test_check_reports_red_when_nothing_integrated_yet(self):
        result = tool.check(self.config)
        self.assertEqual(result["status"], "RED")
        # canonical/golden/verifier haven't been touched yet; "manifest" can
        # already read GREEN at a pristine fixture since it only tracks hash
        # integrity of verifier+golden, not claudeChildBroker presence.
        self.assertFalse(result["surfaces"]["canonical"])
        self.assertFalse(result["surfaces"]["golden"])
        self.assertFalse(result["surfaces"]["verifier"])

    def test_check_makes_zero_writes(self):
        before = {
            name: pathlib.Path(surf["path"]).read_text()
            for name, surf in self.config["surfaces"].items()
        }
        tool.check(self.config)
        after = {
            name: pathlib.Path(surf["path"]).read_text()
            for name, surf in self.config["surfaces"].items()
        }
        self.assertEqual(before, after)
        self.assertFalse(self.backup_dir.exists())

    def test_check_never_spawns_subprocess_or_network(self):
        with mock.patch.object(subprocess, "run") as run, \
                mock.patch("socket.socket") as sock:
            tool.check(self.config)
            run.assert_not_called()
            sock.assert_not_called()

    def test_cli_default_mode_is_check_and_read_only(self):
        config_path = pathlib.Path(self.tmp.name) / "disabled-child-broker.json"
        config_path.write_text(json.dumps(self.config))
        code = tool.main(["--config", str(config_path)])
        self.assertEqual(code, 1)  # RED: nothing integrated yet in a fresh fixture
        self.assertFalse(self.backup_dir.exists())


class HardRefuseTests(FixtureMixin, unittest.TestCase):
    def test_apply_refuses_active_true_and_makes_no_changes(self):
        bad = dict(self.config)
        bad_obj = dict(self.expected_obj)
        bad_obj["active"] = True
        bad["claude_child_broker_object"] = bad_obj
        with self.assertRaises(tool.PolicyRefused):
            tool.apply(bad)
        self.assertFalse(self.backup_dir.exists())
        self.assertNotIn("claudeChildBroker", json.loads(self.canonical_path.read_text()))

    def test_apply_refuses_prehash_mismatch_on_any_surface(self):
        self.canonical_path.write_text(
            json.dumps({"schemaVersion": 8, "someOtherField": "drifted"}, indent=2)
        )
        with self.assertRaises(tool.PrehashMismatch):
            tool.apply(self.config)
        self.assertFalse(self.backup_dir.exists())

    def test_apply_refuses_existing_enabling_object_already_on_disk(self):
        data = json.loads(self.canonical_path.read_text())
        data["claudeChildBroker"] = dict(self.expected_obj, active=True)
        self.canonical_path.write_text(json.dumps(data, indent=2))
        self.config["surfaces"]["canonical"]["expected_prehash_sha256"] = tool.sha256_text(
            self.canonical_path.read_text()
        )
        with self.assertRaises(tool.PolicyRefused):
            tool.apply(self.config)
        self.assertFalse(self.backup_dir.exists())


class ApplyModeTests(FixtureMixin, unittest.TestCase):
    def test_sandbox_apply_is_green_and_integrates_all_four(self):
        result = tool.apply(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertTrue(result["changed"])

        canonical = json.loads(self.canonical_path.read_text())
        self.assertEqual(canonical["claudeChildBroker"], self.expected_obj)
        self.assertEqual(canonical["someOtherField"], "untouched")

        golden = json.loads(self.golden_path.read_text())
        self.assertEqual(golden["claudeChildBroker"], self.expected_obj)

        check_result = tool.check(self.config)
        self.assertEqual(check_result["status"], "GREEN")

    def test_verifier_definition_is_actually_called_from_run_all(self):
        # Before apply: POLICY-54 doesn't exist at all. After apply: the real
        # subprocess run of the patched verifier must exit 0, which is only
        # possible if run_all() actually invokes check_claude_child_broker
        # (not just defines it) and that check passes against what apply()
        # wrote to canonical policy.
        tool.apply(self.config)
        result = subprocess.run(
            [tool.sys.executable, str(self.verifier_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)

        verifier_text = self.verifier_path.read_text()
        call_line_index = verifier_text.index(self.config["verifier_patch"]["call_statement"])
        canonical_call_index = verifier_text.index("check_canonical_policy(checks, spec)")
        self.assertGreater(call_line_index, canonical_call_index)

    def test_verifier_definition_alone_would_fail_without_wiring(self):
        # Guard against the earlier bug: patch only the function, skip the
        # call insertion, and confirm run_all() genuinely does NOT expose a
        # POLICY-54 check unless the call was inserted.
        tool.apply(self.config)
        verifier_text = self.verifier_path.read_text()
        without_call = verifier_text.replace(
            "    " + self.config["verifier_patch"]["call_statement"] + "\n", ""
        )
        self.assertNotEqual(without_call, verifier_text)
        self.assertNotIn("check_claude_child_broker(checks, spec)  #", without_call)

    def test_manifest_is_updated_before_verifier_observes_it(self):
        # The fixture verifier's SELF-01 recomputes hashes of golden+verifier
        # from disk and compares them to the manifest at run time. If apply()
        # ran the verifier before updating the manifest, SELF-01 would fail
        # (manifest would still list the pre-patch hashes) and apply() would
        # raise VerifierFailed instead of returning GREEN.
        result = tool.apply(self.config)
        self.assertEqual(result["status"], "GREEN")
        manifest_text = self.manifest_path.read_text()
        self.assertIn(tool.sha256_file(self.verifier_path), manifest_text)
        self.assertIn(tool.sha256_file(self.golden_path), manifest_text)

    def test_second_apply_is_noop_with_no_duplicate_backup(self):
        tool.apply(self.config)
        backups_after_first = sorted(os.listdir(self.backup_dir))
        self.assertEqual(len(backups_after_first), 1)

        result = tool.apply(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertFalse(result["changed"])

        backups_after_second = sorted(os.listdir(self.backup_dir))
        self.assertEqual(backups_after_first, backups_after_second)

    def test_manifest_update_failure_restores_all_four(self):
        original = {
            name: pathlib.Path(surf["path"]).read_text()
            for name, surf in self.config["surfaces"].items()
        }
        with mock.patch.object(tool, "_update_manifest", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                tool.apply(self.config)
        for name, surf in self.config["surfaces"].items():
            self.assertEqual(pathlib.Path(surf["path"]).read_text(), original[name])

    def test_verifier_failure_restores_all_four_surfaces(self):
        # Make the verifier itself unreadable to the subprocess by pointing
        # its own CANONICAL_POLICY constant at a nonexistent file, forcing a
        # real nonzero exit, after recomputing this surface's prehash.
        broken_template = VERIFIER_TEMPLATE.replace(
            "def main(argv=None):\n    checks, integrity_ok = run_all({{}})\n    ok = integrity_ok and all(c.ok for c in checks)\n    return 0 if ok else 1",
            "def main(argv=None):\n    return 1",
        )
        self.verifier_path.write_text(
            broken_template.format(
                canonical_path=str(self.canonical_path),
                golden_path=str(self.golden_path),
                manifest_path=str(self.manifest_path),
            )
        )
        self.config["surfaces"]["verifier"]["expected_prehash_sha256"] = tool.sha256_text(
            self.verifier_path.read_text()
        )
        original = {
            name: pathlib.Path(surf["path"]).read_text()
            for name, surf in self.config["surfaces"].items()
        }
        with self.assertRaises(tool.VerifierFailed):
            tool.apply(self.config)
        for name, surf in self.config["surfaces"].items():
            self.assertEqual(pathlib.Path(surf["path"]).read_text(), original[name])

    def test_manifest_unrelated_lines_are_unchanged(self):
        tool.apply(self.config)
        lines = self.manifest_path.read_text().splitlines()
        other_line = [line for line in lines if "some-other-file.json" in line][0]
        self.assertTrue(other_line.startswith("cccc"))

    def test_apply_never_uses_network(self):
        with mock.patch("socket.socket") as sock:
            tool.apply(self.config)
            sock.assert_not_called()

    def test_apply_never_writes_broker_prerequisite(self):
        before = self.broker_path.read_text()
        tool.apply(self.config)
        after = self.broker_path.read_text()
        self.assertEqual(before, after)

    def test_apply_refuses_when_broker_prerequisite_hash_mismatches(self):
        self.broker_path.write_text(BROKER_SOURCE + "\n# tampered\n")
        with self.assertRaises(tool.PolicyRefused):
            tool.apply(self.config)
        self.assertFalse(self.backup_dir.exists())


PROVIDER_LOCK_FIXTURE = (
    "# Provider lock (agents)\n\n"
    "17. Item seventeen text, unrelated to the broker.\n"
    "18. The Pane Codex Orkestra Sefi is recorded, not active.\n"
)

MANAGED_FIELDS_FIXTURE = {
    "claudeRefusalBlock": {
        "path": "/fixture/CLAUDE.md",
        "body": [
            "## Claude Invocation Routing",
            "",
            "10. Some earlier item.",
            "11. The Pane Codex Orkestra Sefi is recorded but disabled:",
            "    details continue here.",
        ],
    },
    "launchd": {
        "requiredWatchPaths": [
            "/fixture/AGENTS.md",
            "/fixture/CLAUDE.md",
        ]
    },
}

LIVE_CLAUDE_MD_FIXTURE = (
    "# Claude Code — Global Managed Directives\n\n"
    "<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:BEGIN -->\n"
    "## Claude Invocation Routing\n\n"
    "10. Some earlier item.\n"
    "11. The Pane Codex Orkestra Sefi is recorded but disabled:\n"
    "    details continue here.\n"
    "<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:END -->\n"
)

PLIST_FIXTURE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<plist version="1.0">\n<dict>\n'
    "\t<key>WatchPaths</key>\n\t<array>\n"
    "\t\t<string>/fixture/AGENTS.md</string>\n"
    "\t</array>\n"
    "</dict>\n</plist>\n"
)


class ProjectionFixtureMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)

        self.agents_doc = root / "provider-lock-agents.md"
        self.agents_doc.write_text(PROVIDER_LOCK_FIXTURE)

        self.orch_doc = root / "provider-lock-orchestrator.md"
        self.orch_doc.write_text(PROVIDER_LOCK_FIXTURE.replace("agents", "orchestrator"))

        self.managed_fields = root / "managed-fields.golden.json"
        self.managed_fields.write_text(json.dumps(MANAGED_FIELDS_FIXTURE, indent=2))

        self.live_claude_md = root / "CLAUDE.md"
        self.live_claude_md.write_text(LIVE_CLAUDE_MD_FIXTURE)

        # These live docs start with a lock block that is byte-identical to
        # the golden provider-lock file's *pre-apply* content, mirroring the
        # real repo where AGENTS.md/runpane-orchestrator.md carry the golden
        # provider-lock text verbatim between CLAUDE-WORKER-PROVIDER-LOCK
        # markers.
        self.live_agents_md = root / "AGENTS.md"
        self.live_agents_md.write_text(
            "# Codex AGENTS.md fixture\n\n"
            "<!-- CLAUDE-WORKER-PROVIDER-LOCK:BEGIN -->\n\n"
            + PROVIDER_LOCK_FIXTURE.strip("\n")
            + "\n\n<!-- CLAUDE-WORKER-PROVIDER-LOCK:END -->\n\n"
            "Tail content below the lock block.\n"
        )

        self.live_orchestrator_md = root / "runpane-orchestrator.md"
        self.live_orchestrator_md.write_text(
            "# runpane orchestrator fixture\n\n"
            "<!-- CLAUDE-WORKER-PROVIDER-LOCK:BEGIN -->\n\n"
            + PROVIDER_LOCK_FIXTURE.replace("agents", "orchestrator").strip("\n")
            + "\n\n<!-- CLAUDE-WORKER-PROVIDER-LOCK:END -->\n\n"
            "Tail content below the lock block.\n"
        )

        self.plist_path = root / "com.codex.claude-worker-policy.plist"
        self.plist_path.write_text(PLIST_FIXTURE)

        self.manifest_path = root / "GOLDEN.sha256"
        self.manifest_path.write_text(
            f"# fixture manifest\n"
            f"{tool.sha256_file(self.agents_doc)}  provider-lock-agents.md\n"
            f"{tool.sha256_file(self.orch_doc)}  provider-lock-orchestrator.md\n"
            f"{tool.sha256_file(self.managed_fields)}  managed-fields.golden.json\n"
            f"dddd  some-other-file.json\n"
        )

        self.backup_dir = root / "rollback"

        item_text_template = [
            "{n}. **Claude child-session broker is prepared, not active.**",
            "   activation remains a non-goal.",
        ]
        refusal_body_item_template = [
            "{n}. **Claude child-session broker is prepared, not active.**",
            "    activation remains a non-goal.",
        ]
        self.config = {
            "schemaVersion": 4,
            "projection": {
                "marker": "claude-child-broker-prepared-not-active-projection-m4",
                "detection_text": "Claude child-session broker is prepared, not active",
                "item_text_template": item_text_template,
                "refusal_body_item_template": refusal_body_item_template,
                "watch_path_value": "/fixture/claude_child_broker.py",
                "targets": {
                    "provider_lock_agents": {
                        "kind": "numbered_list_append",
                        "path": str(self.agents_doc),
                        "manifest_name": "provider-lock-agents.md",
                        "expected_prehash_sha256": tool.sha256_text(self.agents_doc.read_text()),
                    },
                    "provider_lock_orchestrator": {
                        "kind": "numbered_list_append",
                        "path": str(self.orch_doc),
                        "manifest_name": "provider-lock-orchestrator.md",
                        "expected_prehash_sha256": tool.sha256_text(self.orch_doc.read_text()),
                    },
                    "managed_fields_refusal": {
                        "kind": "json_body_array_append",
                        "path": str(self.managed_fields),
                        "json_path": ["claudeRefusalBlock", "body"],
                        "manifest_name": "managed-fields.golden.json",
                        "expected_prehash_sha256": tool.sha256_text(self.managed_fields.read_text()),
                    },
                    "managed_fields_watchpaths": {
                        "kind": "json_array_append_unique",
                        "path": str(self.managed_fields),
                        "json_path": ["launchd", "requiredWatchPaths"],
                        "manifest_name": "managed-fields.golden.json",
                        "expected_prehash_sha256": tool.sha256_text(self.managed_fields.read_text()),
                    },
                    "live_claude_md": {
                        "kind": "numbered_list_append_within_markers",
                        "path": str(self.live_claude_md),
                        "begin_marker": "<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:BEGIN -->",
                        "end_marker": "<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:END -->",
                        "expected_prehash_sha256": tool.sha256_text(self.live_claude_md.read_text()),
                    },
                    "live_agents_md": {
                        "kind": "numbered_list_append_within_markers",
                        "path": str(self.live_agents_md),
                        "begin_marker": "<!-- CLAUDE-WORKER-PROVIDER-LOCK:BEGIN -->",
                        "end_marker": "<!-- CLAUDE-WORKER-PROVIDER-LOCK:END -->",
                        "source_path": str(self.agents_doc),
                        "expected_prehash_sha256": tool.sha256_text(self.live_agents_md.read_text()),
                    },
                    "live_runpane_orchestrator_md": {
                        "kind": "numbered_list_append_within_markers",
                        "path": str(self.live_orchestrator_md),
                        "begin_marker": "<!-- CLAUDE-WORKER-PROVIDER-LOCK:BEGIN -->",
                        "end_marker": "<!-- CLAUDE-WORKER-PROVIDER-LOCK:END -->",
                        "source_path": str(self.orch_doc),
                        "expected_prehash_sha256": tool.sha256_text(self.live_orchestrator_md.read_text()),
                    },
                    "launch_agent_plist": {
                        "kind": "plist_watchpath_append",
                        "path": str(self.plist_path),
                        "expected_prehash_sha256": tool.sha256_text(self.plist_path.read_text()),
                    },
                },
                "manifest": {
                    "path": str(self.manifest_path),
                    "expected_prehash_sha256": tool.sha256_text(self.manifest_path.read_text()),
                    "updatable_entries": [
                        "provider-lock-agents.md",
                        "provider-lock-orchestrator.md",
                        "managed-fields.golden.json",
                    ],
                },
                "backup_dir": str(self.backup_dir),
            },
        }


class ProjectionCheckTests(ProjectionFixtureMixin, unittest.TestCase):
    def test_check_reports_red_before_projection(self):
        result = tool.check_projection(self.config)
        self.assertEqual(result["status"], "RED")
        self.assertFalse(result["targets"]["provider_lock_agents"])
        self.assertFalse(result["targets"]["live_agents_md"])
        self.assertFalse(result["targets"]["launch_agent_plist"])

    def test_check_makes_zero_writes(self):
        before = {
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
            "live_claude_md": self.live_claude_md.read_text(),
            "live_agents_md": self.live_agents_md.read_text(),
            "plist": self.plist_path.read_text(),
        }
        tool.check_projection(self.config)
        after = {
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
            "live_claude_md": self.live_claude_md.read_text(),
            "live_agents_md": self.live_agents_md.read_text(),
            "plist": self.plist_path.read_text(),
        }
        self.assertEqual(before, after)
        self.assertFalse(self.backup_dir.exists())

    def test_check_never_spawns_subprocess_or_network(self):
        with mock.patch.object(subprocess, "run") as run, \
                mock.patch("socket.socket") as sock:
            tool.check_projection(self.config)
            run.assert_not_called()
            sock.assert_not_called()


class ProjectionApplyTests(ProjectionFixtureMixin, unittest.TestCase):
    def test_apply_projection_is_green_and_writes_next_sequential_item(self):
        result = tool.apply_projection(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertTrue(result["changed"])

        agents_text = self.agents_doc.read_text()
        self.assertIn("19. **Claude child-session broker", agents_text)
        orch_text = self.orch_doc.read_text()
        self.assertIn("19. **Claude child-session broker", orch_text)

        data = json.loads(self.managed_fields.read_text())
        body_text = "\n".join(data["claudeRefusalBlock"]["body"])
        self.assertIn("12. **Claude child-session broker", body_text)
        self.assertIn("/fixture/claude_child_broker.py", data["launchd"]["requiredWatchPaths"])

        live_claude_text = self.live_claude_md.read_text()
        self.assertIn("12. **Claude child-session broker", live_claude_text)
        self.assertTrue(live_claude_text.index("12. **Claude") < live_claude_text.index("LOCK:END"))

        # The two live docs' lock blocks must be inside the EXISTING
        # CLAUDE-WORKER-PROVIDER-LOCK markers and byte-for-byte identical to
        # the just-updated golden provider-lock file -- no separate marker
        # block left anywhere outside those markers.
        def lock_block(text):
            return text.split("<!-- CLAUDE-WORKER-PROVIDER-LOCK:BEGIN -->", 1)[1].split(
                "<!-- CLAUDE-WORKER-PROVIDER-LOCK:END -->", 1
            )[0].strip("\n")

        live_agents_text = self.live_agents_md.read_text()
        self.assertEqual(lock_block(live_agents_text), agents_text.strip("\n"))
        self.assertEqual(live_agents_text.count("CLAUDE-WORKER-PROVIDER-LOCK:BEGIN"), 1)
        self.assertNotIn(self.config["projection"]["marker"], live_agents_text)

        live_orch_text = self.live_orchestrator_md.read_text()
        self.assertEqual(lock_block(live_orch_text), orch_text.strip("\n"))
        self.assertEqual(live_orch_text.count("CLAUDE-WORKER-PROVIDER-LOCK:BEGIN"), 1)
        self.assertNotIn(self.config["projection"]["marker"], live_orch_text)

        plist_text = self.plist_path.read_text()
        self.assertIn("<string>/fixture/claude_child_broker.py</string>", plist_text)

        check_result = tool.check_projection(self.config)
        self.assertEqual(check_result["status"], "GREEN")

    def test_second_apply_projection_is_noop_no_duplicate_backup(self):
        tool.apply_projection(self.config)
        first = sorted(os.listdir(self.backup_dir))
        self.assertEqual(len(first), 1)

        result = tool.apply_projection(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertFalse(result["changed"])
        second = sorted(os.listdir(self.backup_dir))
        self.assertEqual(first, second)

    def test_apply_projection_refuses_prehash_mismatch_with_zero_writes(self):
        self.agents_doc.write_text(PROVIDER_LOCK_FIXTURE + "\ndrift\n")
        with self.assertRaises(tool.PrehashMismatch):
            tool.apply_projection(self.config)
        self.assertFalse(self.backup_dir.exists())

    def test_apply_projection_refuses_plist_prehash_mismatch_with_zero_writes(self):
        # The plist is exactly as fail-closed as every other target: if it
        # drifted from its recorded baseline, apply_projection refuses
        # before touching anything, including targets that hadn't drifted.
        self.plist_path.write_text(PLIST_FIXTURE.replace("</array>", "\t<string>/tampered</string>\n\t</array>"))
        original = {
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
        }
        with self.assertRaises(tool.PrehashMismatch):
            tool.apply_projection(self.config)
        self.assertFalse(self.backup_dir.exists())
        self.assertEqual(self.agents_doc.read_text(), original["agents_doc"])
        self.assertEqual(self.orch_doc.read_text(), original["orch_doc"])
        self.assertEqual(self.managed_fields.read_text(), original["managed_fields"])

    def test_apply_projection_rollback_restores_all_targets_on_failure(self):
        original = {
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
            "live_claude_md": self.live_claude_md.read_text(),
            "live_agents_md": self.live_agents_md.read_text(),
            "live_orchestrator_md": self.live_orchestrator_md.read_text(),
            "plist": self.plist_path.read_text(),
            "manifest": self.manifest_path.read_text(),
        }
        with mock.patch.object(tool, "_update_projection_manifest", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                tool.apply_projection(self.config)
        after = {
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
            "live_claude_md": self.live_claude_md.read_text(),
            "live_agents_md": self.live_agents_md.read_text(),
            "live_orchestrator_md": self.live_orchestrator_md.read_text(),
            "plist": self.plist_path.read_text(),
            "manifest": self.manifest_path.read_text(),
        }
        self.assertEqual(original, after)

    def test_apply_projection_updates_only_allowed_manifest_entries(self):
        tool.apply_projection(self.config)
        lines = self.manifest_path.read_text().splitlines()
        other_line = [l for l in lines if "some-other-file.json" in l][0]
        self.assertTrue(other_line.startswith("dddd"))

    def test_apply_projection_never_uses_network(self):
        with mock.patch("socket.socket") as sock:
            tool.apply_projection(self.config)
            sock.assert_not_called()

    def test_stale_item_is_updated_in_place_not_duplicate_appended(self):
        # Simulate an earlier projection wave having already appended an
        # item whose text is now stale (e.g. repoHandshakePrepared flipped
        # true with new evidence). A re-apply must rewrite that existing
        # numbered item in place, not append a second duplicate item.
        stale_item = [
            "19. **Claude child-session broker is prepared, not active.**",
            "   stale text from a prior wave.",
        ]
        self.agents_doc.write_text(
            self.agents_doc.read_text().rstrip("\n") + "\n" + "\n".join(stale_item) + "\n"
        )
        self.config["projection"]["targets"]["provider_lock_agents"]["expected_prehash_sha256"] = (
            tool.sha256_text(self.agents_doc.read_text())
        )

        result = tool.apply_projection(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertTrue(result["changed"])

        text = self.agents_doc.read_text()
        self.assertEqual(text.count("Claude child-session broker is prepared, not active"), 1)
        self.assertIn("19. **Claude child-session broker is prepared, not active.**", text)
        self.assertNotIn("stale text from a prior wave.", text)
        self.assertNotIn("20. **Claude child-session broker", text)

        check_result = tool.check_projection(self.config)
        self.assertEqual(check_result["status"], "GREEN")

    def test_stale_item_within_markers_non_source_mode_replaces_in_place(self):
        # Regression for manage-disabled-child-broker.py:566 -- a prior
        # `_write_numbered_within_markers` reused `end` as both the marker
        # string and (via `start, end, number = found`) the item-block end
        # index, so concatenating `end` into the new file text raised
        # TypeError on any *replacement* of an existing stale item inside
        # begin/end markers (append-only writes never hit this path).
        stale_item = [
            "11. **Claude child-session broker is prepared, not active.**",
            "    stale text from a prior wave.",
        ]
        self.live_claude_md.write_text(
            LIVE_CLAUDE_MD_FIXTURE.replace(
                "<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:END -->",
                "\n".join(stale_item) + "\n<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:END -->",
            )
        )
        self.config["projection"]["targets"]["live_claude_md"]["expected_prehash_sha256"] = (
            tool.sha256_text(self.live_claude_md.read_text())
        )

        target = self.config["projection"]["targets"]["live_claude_md"]
        tool._write_numbered_within_markers(self.config, target)

        text = self.live_claude_md.read_text()
        self.assertEqual(text.count("Claude child-session broker is prepared, not active"), 1)
        self.assertIn("11. **Claude child-session broker is prepared, not active.**", text)
        self.assertNotIn("stale text from a prior wave.", text)
        self.assertIn("<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:END -->", text)
        self.assertTrue(
            text.index("11. **Claude child-session broker")
            < text.index("<!-- CLAUDE-WORKER-INVOCATION-ROUTING-LOCK:END -->")
        )

    def test_stale_item_within_markers_source_path_mode_still_works(self):
        # source_path mode takes the early-return golden-splice branch, which
        # never touched the shadowed `end` variable -- confirm it remains
        # unaffected by the fix.
        target = self.config["projection"]["targets"]["live_agents_md"]
        tool._write_numbered_within_markers(self.config, target)
        text = self.live_agents_md.read_text()
        self.assertIn(PROVIDER_LOCK_FIXTURE.strip("\n"), text)
        self.assertEqual(text.count("CLAUDE-WORKER-PROVIDER-LOCK:BEGIN"), 1)

    def test_second_apply_after_upsert_is_still_noop(self):
        stale_item = [
            "19. **Claude child-session broker is prepared, not active.**",
            "   stale text from a prior wave.",
        ]
        self.agents_doc.write_text(
            self.agents_doc.read_text().rstrip("\n") + "\n" + "\n".join(stale_item) + "\n"
        )
        self.config["projection"]["targets"]["provider_lock_agents"]["expected_prehash_sha256"] = (
            tool.sha256_text(self.agents_doc.read_text())
        )

        tool.apply_projection(self.config)
        result = tool.apply_projection(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertFalse(result["changed"])


class RealSnapshotPrehashTests(unittest.TestCase):
    """Regression coverage for the successor package: the recorded
    expected_prehash_sha256 values in the real disabled-child-broker.json
    must match the current on-disk state of every real target (both the
    POLICY-54 surfaces and both projection manifest phases), and the
    fail-closed drift check must still reject a value that doesn't match."""

    def setUp(self):
        self.config = tool.load_config(tool.DEFAULT_CONFIG)

    def _live_targets(self):
        targets = dict(self.config["surfaces"])
        targets["projection_manifest"] = self.config["projection"]["manifest"]
        for name, t in self.config["projection"]["targets"].items():
            if "expected_prehash_sha256" in t:
                targets[f"projection_{name}"] = t
        return targets

    def test_recorded_prehashes_match_current_live_targets(self):
        mismatches = []
        for name, surf in self._live_targets().items():
            path = surf["path"]
            if not os.path.exists(path):
                mismatches.append(f"{name}: missing at {path}")
                continue
            actual = tool.sha256_text(tool._read_text(path))
            if actual != surf["expected_prehash_sha256"]:
                mismatches.append(f"{name}: expected {surf['expected_prehash_sha256']}, found {actual}")
        self.assertEqual(mismatches, [], "; ".join(mismatches))

    def test_both_manifest_phases_share_the_same_live_hash(self):
        # surfaces.manifest and projection.manifest point at the same real
        # GOLDEN.sha256 file; both recorded prehashes must agree with each
        # other and with the file's current hash.
        surf_manifest = self.config["surfaces"]["manifest"]
        proj_manifest = self.config["projection"]["manifest"]
        self.assertEqual(surf_manifest["path"], proj_manifest["path"])
        self.assertEqual(
            surf_manifest["expected_prehash_sha256"],
            proj_manifest["expected_prehash_sha256"],
        )
        actual = tool.sha256_text(tool._read_text(surf_manifest["path"]))
        self.assertEqual(actual, surf_manifest["expected_prehash_sha256"])

    def test_apply_still_fail_closed_refuses_on_injected_drift(self):
        # Prove the successor snapshot doesn't just happen to pass -- a
        # deliberately wrong prehash on a real surface must still be
        # refused before any write, with zero side effects.
        drifted = json.loads(json.dumps(self.config))
        drifted["surfaces"]["canonical"]["expected_prehash_sha256"] = "0" * 64
        with self.assertRaises(tool.PrehashMismatch):
            tool.apply(drifted)

    def test_disabled_posture_and_non_goals_preserved(self):
        obj = self.config["claude_child_broker_object"]
        self.assertFalse(obj["active"])
        self.assertEqual(obj["defaultDecision"], "DENY")
        self.assertEqual(obj["authorizedCreators"], ["codex-desktop-master"])
        for field in self.config["must_be_false_fields"]:
            self.assertFalse(obj[field], f"{field} must stay false")


class ApplyAllFixtureMixin(FixtureMixin, ProjectionFixtureMixin):
    def setUp(self):
        FixtureMixin.setUp(self)
        broker_config = self.config

        ProjectionFixtureMixin.setUp(self)
        projection_config = self.config["projection"]

        # Both waves must share exactly one GOLDEN.sha256 file so apply_all
        # exercises the real shared-manifest path.
        shared_manifest_path = pathlib.Path(broker_config["surfaces"]["manifest"]["path"])
        shared_manifest_path.write_text(
            "# fixture manifest\n"
            f"{tool.sha256_file(pathlib.Path(broker_config['surfaces']['verifier']['path']))}"
            "  verify_worker_policy.py\n"
            f"{tool.sha256_file(pathlib.Path(broker_config['surfaces']['golden']['path']))}"
            "  claude-worker-policy.golden.json\n"
            f"{tool.sha256_file(self.agents_doc)}  provider-lock-agents.md\n"
            f"{tool.sha256_file(self.orch_doc)}  provider-lock-orchestrator.md\n"
            f"{tool.sha256_file(self.managed_fields)}  managed-fields.golden.json\n"
            "eeee  some-other-file.json\n"
        )
        shared_hash = tool.sha256_text(shared_manifest_path.read_text())

        broker_config["surfaces"]["manifest"]["path"] = str(shared_manifest_path)
        broker_config["surfaces"]["manifest"]["expected_prehash_sha256"] = shared_hash
        broker_config["backup_dir"] = str(self.backup_dir)

        projection_config["manifest"]["path"] = str(shared_manifest_path)
        projection_config["manifest"]["expected_prehash_sha256"] = shared_hash

        self.config = dict(broker_config)
        self.config["projection"] = projection_config
        self.manifest_path = shared_manifest_path

        # Isolate every ApplyAll fixture test from the real LaunchAgent by
        # default: an unloaded fake means apply_all() never invokes
        # _default_launchd_ops() or real launchctl unless a test explicitly
        # overrides self.config["launchd_ops"] (or removes the key to
        # exercise the true default-ops path under its own subprocess mock).
        self.launchd_ops = FakeLaunchdOps(initially_loaded=False)
        self.config["launchd_ops"] = self.launchd_ops.as_dict()


class ApplyAllTests(ApplyAllFixtureMixin, unittest.TestCase):
    def test_apply_all_is_green_and_integrates_both_waves_from_one_snapshot(self):
        result = tool.apply_all(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertTrue(result["changed"])

        canonical = json.loads(self.canonical_path.read_text())
        self.assertEqual(canonical["claudeChildBroker"], self.expected_obj)

        agents_text = self.agents_doc.read_text()
        self.assertIn("19. **Claude child-session broker", agents_text)
        plist_text = self.plist_path.read_text()
        self.assertIn("<string>/fixture/claude_child_broker.py</string>", plist_text)

        self.assertEqual(tool.check(self.config)["status"], "GREEN")
        self.assertEqual(tool.check_projection(self.config)["status"], "GREEN")

    def test_apply_all_uses_one_backup_directory_for_the_union(self):
        tool.apply_all(self.config)
        entries = os.listdir(self.backup_dir)
        self.assertEqual(len(entries), 1)
        txn_dir = pathlib.Path(self.backup_dir) / entries[0]
        backed_up_names = set(os.listdir(txn_dir))
        # exactly one backup of the shared manifest, not two
        manifest_backups = [n for n in backed_up_names if "manifest" in n]
        self.assertEqual(len(manifest_backups), 1)

    def test_apply_all_refuses_shared_manifest_hash_inconsistency(self):
        self.config["projection"]["manifest"]["expected_prehash_sha256"] = "0" * 64
        with self.assertRaises(tool.PolicyRefused):
            tool.apply_all(self.config)
        self.assertFalse(os.path.exists(self.backup_dir))

    def test_apply_all_refuses_drift_before_any_side_effect(self):
        self.agents_doc.write_text(PROVIDER_LOCK_FIXTURE + "\ndrift\n")
        original_canonical = self.canonical_path.read_text()
        with self.assertRaises(tool.PrehashMismatch):
            tool.apply_all(self.config)
        self.assertFalse(os.path.exists(self.backup_dir))
        self.assertEqual(self.canonical_path.read_text(), original_canonical)

    def test_apply_all_refuses_enabling_posture_before_any_side_effect(self):
        bad_obj = dict(self.expected_obj, active=True)
        self.config["claude_child_broker_object"] = bad_obj
        with self.assertRaises(tool.PolicyRefused):
            tool.apply_all(self.config)
        self.assertFalse(os.path.exists(self.backup_dir))
        self.assertNotIn("claudeChildBroker", json.loads(self.canonical_path.read_text()))

    def test_apply_all_late_failure_restores_every_union_target(self):
        original = {
            "canonical": self.canonical_path.read_text(),
            "golden": self.golden_path.read_text(),
            "verifier": self.verifier_path.read_text(),
            "manifest": self.manifest_path.read_text(),
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
            "plist": self.plist_path.read_text(),
        }
        with mock.patch.object(tool, "_update_manifest_all", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                tool.apply_all(self.config)
        after = {
            "canonical": self.canonical_path.read_text(),
            "golden": self.golden_path.read_text(),
            "verifier": self.verifier_path.read_text(),
            "manifest": self.manifest_path.read_text(),
            "agents_doc": self.agents_doc.read_text(),
            "orch_doc": self.orch_doc.read_text(),
            "managed_fields": self.managed_fields.read_text(),
            "plist": self.plist_path.read_text(),
        }
        self.assertEqual(original, after)
        # only one backup attempt occurred despite the rollback
        self.assertEqual(len(os.listdir(self.backup_dir)), 1)

    def test_apply_all_runs_verifier_exactly_once_after_final_manifest(self):
        with mock.patch.object(tool, "_run_verifier_readonly", wraps=tool._run_verifier_readonly) as spy:
            tool.apply_all(self.config)
            spy.assert_called_once()
        manifest_text = self.manifest_path.read_text()
        self.assertIn(tool.sha256_file(self.verifier_path), manifest_text)
        self.assertIn(tool.sha256_file(self.agents_doc), manifest_text)

    def test_second_apply_all_is_noop_no_backup_no_write(self):
        tool.apply_all(self.config)
        before = {
            "canonical": self.canonical_path.read_text(),
            "agents_doc": self.agents_doc.read_text(),
        }
        backups_first = sorted(os.listdir(self.backup_dir))

        result = tool.apply_all(self.config)
        self.assertEqual(result["status"], "GREEN")
        self.assertFalse(result["changed"])

        after = {
            "canonical": self.canonical_path.read_text(),
            "agents_doc": self.agents_doc.read_text(),
        }
        self.assertEqual(before, after)
        self.assertEqual(backups_first, sorted(os.listdir(self.backup_dir)))

    def test_apply_and_apply_projection_remain_compatible_after_apply_all_added(self):
        # apply() alone still integrates just the broker wave without
        # touching projection targets.
        broker_only_config = dict(self.config)
        result = tool.apply(broker_only_config)
        self.assertEqual(result["status"], "GREEN")
        self.assertNotIn("19. **Claude child-session broker", self.agents_doc.read_text())


class ApplyAllCliTests(ApplyAllFixtureMixin, unittest.TestCase):
    def _write_config_json(self, path, config=None):
        # launchd_ops holds live callables and is never part of the real
        # on-disk config; CLI tests write the JSON-serializable rest and
        # inject a fake ops factory instead of ever exercising real
        # launchctl via the CLI entrypoint.
        serializable = dict(config if config is not None else self.config)
        serializable.pop("launchd_ops", None)
        path.write_text(json.dumps(serializable))

    def test_apply_all_and_apply_are_mutually_exclusive(self):
        config_path = pathlib.Path(self.tmp.name) / "disabled-child-broker.json"
        self._write_config_json(config_path)
        with self.assertRaises(SystemExit):
            tool.main(["--config", str(config_path), "--apply", "--apply-all"])

    def test_cli_apply_all_integrates_both_waves(self):
        config_path = pathlib.Path(self.tmp.name) / "disabled-child-broker.json"
        self._write_config_json(config_path)
        with mock.patch.object(tool, "_default_launchd_ops", return_value=self.launchd_ops.as_dict()):
            code = tool.main(["--config", str(config_path), "--apply-all"])
        self.assertEqual(code, 0)
        self.assertEqual(tool.check(self.config)["status"], "GREEN")
        self.assertEqual(tool.check_projection(self.config)["status"], "GREEN")

    def test_cli_denies_cleanly_on_launchd_op_failure(self):
        config_path = pathlib.Path(self.tmp.name) / "disabled-child-broker.json"
        self._write_config_json(config_path)
        failing_ops = FakeLaunchdOps(initially_loaded=True, bootout_error=tool.LaunchdOpFailed("cli boot boom"))
        stderr = io.StringIO()
        with mock.patch.object(tool, "_default_launchd_ops", return_value=failing_ops.as_dict()):
            with contextlib.redirect_stderr(stderr):
                code = tool.main(["--config", str(config_path), "--apply-all"])
        self.assertEqual(code, 1)
        self.assertIn("DENY:", stderr.getvalue())
        self.assertIn("cli boot boom", stderr.getvalue())
        self.assertFalse(os.path.exists(self.backup_dir))

    def test_cli_denies_cleanly_on_apply_all_rollback_failure(self):
        config_path = pathlib.Path(self.tmp.name) / "disabled-child-broker.json"
        self._write_config_json(config_path)
        recovery_error = tool.LaunchdOpFailed("cli recovery boom")
        failing_ops = FakeLaunchdOps(initially_loaded=True, bootstrap_error_on_calls={1: recovery_error})
        stderr = io.StringIO()
        with mock.patch.object(tool, "_default_launchd_ops", return_value=failing_ops.as_dict()):
            with mock.patch.object(tool, "_update_manifest_all", side_effect=RuntimeError("cli write boom")):
                with contextlib.redirect_stderr(stderr):
                    code = tool.main(["--config", str(config_path), "--apply-all"])
        self.assertEqual(code, 1)
        self.assertIn("DENY:", stderr.getvalue())
        self.assertIn("cli write boom", stderr.getvalue())
        self.assertIn("cli recovery boom", stderr.getvalue())


class FakeLaunchdOps:
    """Injectable launchctl stand-in. Records every call so tests can assert
    ordering; never touches a real service."""

    def __init__(self, initially_loaded=False, bootout_error=None, bootstrap_error_on_calls=(), event_log=None):
        self.initially_loaded = initially_loaded
        self.bootout_error = bootout_error
        # 1-indexed bootstrap call numbers that should raise bootstrap_error_on_calls[i]
        self.bootstrap_error_on_calls = dict(bootstrap_error_on_calls)
        # Pass a shared list to interleave these calls with other events
        # (e.g. _backup_set) in one strict order assertion.
        self.calls = event_log if event_log is not None else []
        self._bootstrap_calls = 0

    def is_loaded(self):
        self.calls.append("is_loaded")
        return self.initially_loaded

    def bootout(self):
        self.calls.append("bootout")
        if self.bootout_error is not None:
            raise self.bootout_error

    def bootstrap(self, plist_path):
        self._bootstrap_calls += 1
        self.calls.append(f"bootstrap:{plist_path}:{self._bootstrap_calls}")
        error = self.bootstrap_error_on_calls.get(self._bootstrap_calls)
        if error is not None:
            raise error

    def as_dict(self):
        return {"is_loaded": self.is_loaded, "bootout": self.bootout, "bootstrap": self.bootstrap}


class ApplyAllLaunchdQuiescenceTests(ApplyAllFixtureMixin, unittest.TestCase):
    def test_loaded_service_is_booted_out_before_backup_and_bootstrapped_after_success(self):
        events = []
        ops = FakeLaunchdOps(initially_loaded=True, event_log=events)
        self.config["launchd_ops"] = ops.as_dict()

        # Interleave a "backup" marker into the SAME event list so ordering
        # against is_loaded/bootout/bootstrap is one strict assertion, not
        # separately-checked existence facts.
        real_backup_set = tool._backup_set

        def wrapped_backup_set(*args, **kwargs):
            events.append("backup")
            return real_backup_set(*args, **kwargs)

        # subprocess.run is legitimately used by the real read-only verifier
        # invocation inside apply_all -- only assert launchctl itself (argv[0])
        # is never invoked, since the injected fake ops must fully replace it.
        real_run = subprocess.run

        def guarded_run(argv, *args, **kwargs):
            self.assertNotEqual(argv[0], "launchctl")
            return real_run(argv, *args, **kwargs)

        with mock.patch.object(tool, "_backup_set", side_effect=wrapped_backup_set):
            with mock.patch.object(subprocess, "run", side_effect=guarded_run):
                result = tool.apply_all(self.config)

        self.assertEqual(result["status"], "GREEN")
        self.assertTrue(result["service_was_loaded"])
        # is_loaded -> bootout -> backup -> (writes/verifier happen between
        # backup returning and bootstrap being called) -> bootstrap
        self.assertEqual(
            events,
            ["is_loaded", "bootout", "backup", f"bootstrap:{self.plist_path}:1"],
        )
        self.assertTrue(os.path.exists(self.backup_dir))

    def test_fixture_default_injection_never_touches_default_ops_or_real_launchctl(self):
        # Safety regression: the ApplyAllFixtureMixin default injection
        # (an unloaded FakeLaunchdOps) must fully replace launchctl for
        # every ordinary ApplyAll fixture test -- _default_launchd_ops()
        # must never even be constructed, let alone invoke a real command.
        real_run = subprocess.run

        def guarded_run(argv, *args, **kwargs):
            self.assertNotEqual(argv[0], "launchctl")
            return real_run(argv, *args, **kwargs)

        with mock.patch.object(
            tool, "_default_launchd_ops", side_effect=AssertionError("must not construct default ops")
        ) as ctor:
            with mock.patch.object(subprocess, "run", side_effect=guarded_run):
                result = tool.apply_all(self.config)

        ctor.assert_not_called()
        self.assertEqual(result["status"], "GREEN")
        self.assertEqual(self.launchd_ops.calls, ["is_loaded"])  # unloaded: bootout/bootstrap never called

    def test_unloaded_service_is_never_booted_out_or_bootstrapped(self):
        ops = FakeLaunchdOps(initially_loaded=False)
        self.config["launchd_ops"] = ops.as_dict()

        result = tool.apply_all(self.config)

        self.assertEqual(result["status"], "GREEN")
        self.assertFalse(result["service_was_loaded"])
        self.assertEqual(ops.calls, ["is_loaded"])

    def test_bootout_failure_is_fail_closed_zero_backups_zero_writes(self):
        ops = FakeLaunchdOps(initially_loaded=True, bootout_error=RuntimeError("bootout boom"))
        self.config["launchd_ops"] = ops.as_dict()
        original_canonical = self.canonical_path.read_text()

        with self.assertRaises(RuntimeError):
            tool.apply_all(self.config)

        self.assertEqual(ops.calls, ["is_loaded", "bootout"])
        self.assertFalse(os.path.exists(self.backup_dir))
        self.assertEqual(self.canonical_path.read_text(), original_canonical)

    def test_noop_and_refusal_paths_never_touch_launchctl(self):
        ops = FakeLaunchdOps(initially_loaded=True)
        self.config["launchd_ops"] = ops.as_dict()

        # prehash-drift refusal
        self.agents_doc.write_text(PROVIDER_LOCK_FIXTURE + "\ndrift\n")
        with self.assertRaises(tool.PrehashMismatch):
            tool.apply_all(self.config)
        self.assertEqual(ops.calls, [])

        # restore drift, then force the no-op (already-integrated) path
        self.agents_doc.write_text(PROVIDER_LOCK_FIXTURE)
        self.config["projection"]["targets"]["provider_lock_agents"]["expected_prehash_sha256"] = (
            tool.sha256_text(self.agents_doc.read_text())
        )
        with mock.patch.object(tool, "is_apply_all_integrated", return_value=True):
            result = tool.apply_all(self.config)
        self.assertFalse(result["changed"])
        self.assertEqual(ops.calls, [])

    def test_default_ops_never_constructed_or_exercised_when_noop(self):
        # Intentionally un-inject the fixture default to exercise the true
        # default-ops code path -- but subprocess.run is mocked BEFORE the
        # call so that even if the no-op guard were broken, no real command
        # would ever run.
        del self.config["launchd_ops"]
        with mock.patch.object(tool, "is_apply_all_integrated", return_value=True):
            with mock.patch.object(subprocess, "run") as run:
                result = tool.apply_all(self.config)
                run.assert_not_called()
        self.assertFalse(result["changed"])

    def test_write_failure_restores_targets_and_recovers_loaded_service(self):
        ops = FakeLaunchdOps(initially_loaded=True)
        self.config["launchd_ops"] = ops.as_dict()
        original = {
            "canonical": self.canonical_path.read_text(),
            "agents_doc": self.agents_doc.read_text(),
            "plist": self.plist_path.read_text(),
        }

        with mock.patch.object(tool, "_update_manifest_all", side_effect=RuntimeError("write boom")):
            with self.assertRaises(RuntimeError) as ctx:
                tool.apply_all(self.config)
        self.assertEqual(str(ctx.exception), "write boom")

        self.assertEqual(self.canonical_path.read_text(), original["canonical"])
        self.assertEqual(self.agents_doc.read_text(), original["agents_doc"])
        self.assertEqual(self.plist_path.read_text(), original["plist"])
        self.assertEqual(
            ops.calls,
            ["is_loaded", "bootout", f"bootstrap:{self.plist_path}:1"],
        )

    def test_bootstrap_after_success_failure_rolls_back_and_recovers(self):
        first_error = tool.LaunchdOpFailed("bootstrap after success failed")
        ops = FakeLaunchdOps(initially_loaded=True, bootstrap_error_on_calls={1: first_error})
        self.config["launchd_ops"] = ops.as_dict()
        original = {
            "canonical": self.canonical_path.read_text(),
            "agents_doc": self.agents_doc.read_text(),
        }

        with self.assertRaises(tool.LaunchdOpFailed) as ctx:
            tool.apply_all(self.config)
        self.assertIs(ctx.exception, first_error)

        # writes must be rolled back even though they succeeded, because the
        # post-success bootstrap failed
        self.assertEqual(self.canonical_path.read_text(), original["canonical"])
        self.assertEqual(self.agents_doc.read_text(), original["agents_doc"])
        # recovery bootstrap attempted (2nd call) and this one succeeds
        self.assertEqual(len(ops.calls), 4)
        self.assertEqual(ops.calls[0], "is_loaded")
        self.assertEqual(ops.calls[1], "bootout")
        self.assertTrue(ops.calls[2].endswith(":1"))
        self.assertTrue(ops.calls[3].endswith(":2"))

    def test_write_failure_plus_service_recovery_failure_raises_one_compound_error(self):
        recovery_error = tool.LaunchdOpFailed("recovery bootstrap also failed")
        ops = FakeLaunchdOps(initially_loaded=True, bootstrap_error_on_calls={1: recovery_error})
        self.config["launchd_ops"] = ops.as_dict()
        original_exc = RuntimeError("original write boom")

        with mock.patch.object(tool, "_update_manifest_all", side_effect=original_exc):
            with self.assertRaises(tool.ApplyAllRollbackFailure) as ctx:
                tool.apply_all(self.config)

        message = str(ctx.exception)
        self.assertIn("original write boom", message)
        self.assertIn("recovery bootstrap also failed", message)
        self.assertIs(ctx.exception.__cause__, original_exc)

    def test_restore_union_no_early_abort_continues_past_individual_failures(self):
        names_by_path = {"a": "/tmp/fake-a", "b": "/tmp/fake-b", "c": "/tmp/fake-c"}
        backups = {"a": "/tmp/backup-a", "b": "/tmp/backup-b", "c": "/tmp/backup-c"}

        def fake_copy2(src, dst):
            if dst == "/tmp/fake-b":
                raise OSError("disk full")

        with mock.patch.object(shutil, "copy2", side_effect=fake_copy2) as copy2:
            errors = tool._restore_union_no_early_abort(names_by_path, backups)
            self.assertEqual(copy2.call_count, 3)  # a and c still attempted despite b failing

        self.assertEqual(len(errors), 1)
        self.assertIn("b", errors[0])
        self.assertIn("disk full", errors[0])

    def test_recover_apply_all_failure_aggregates_restore_and_service_errors(self):
        original_exc = RuntimeError("original cause")
        ops = FakeLaunchdOps(initially_loaded=True, bootstrap_error_on_calls={1: RuntimeError("svc down")})

        with mock.patch.object(
            tool, "_restore_union_no_early_abort", return_value=["target-x: boom"]
        ):
            with self.assertRaises(tool.ApplyAllRollbackFailure) as ctx:
                tool._recover_apply_all_failure(
                    self.config, {}, {}, True, ops.as_dict(), original_exc
                )

        message = str(ctx.exception)
        self.assertIn("original cause", message)
        self.assertIn("target-x: boom", message)
        self.assertIn("svc down", message)
        self.assertIs(ctx.exception.__cause__, original_exc)

    def test_recover_apply_all_failure_reraises_original_when_recovery_clean(self):
        original_exc = RuntimeError("clean original cause")
        ops = FakeLaunchdOps(initially_loaded=False)

        with self.assertRaises(RuntimeError) as ctx:
            tool._recover_apply_all_failure(self.config, {}, {}, False, ops.as_dict(), original_exc)
        self.assertIs(ctx.exception, original_exc)
        self.assertEqual(ops.calls, [])  # unloaded service: no recovery bootstrap attempted

    def test_backup_set_failure_after_bootout_recovers_service_without_target_restore(self):
        ops = FakeLaunchdOps(initially_loaded=True)
        self.config["launchd_ops"] = ops.as_dict()
        original_canonical = self.canonical_path.read_text()

        with mock.patch.object(tool, "_backup_set", side_effect=RuntimeError("backup boom")):
            with self.assertRaises(RuntimeError) as ctx:
                tool.apply_all(self.config)
        self.assertEqual(str(ctx.exception), "backup boom")

        # zero writes: nothing was ever written because backup itself failed
        self.assertEqual(self.canonical_path.read_text(), original_canonical)
        self.assertFalse(os.path.exists(self.backup_dir))
        # service was booted out, then recovered -- no target restore attempted
        self.assertEqual(
            ops.calls,
            ["is_loaded", "bootout", f"bootstrap:{self.plist_path}:1"],
        )

    def test_recover_apply_all_service_only_raises_compound_on_recovery_failure(self):
        original_exc = RuntimeError("original backup cause")
        ops = FakeLaunchdOps(initially_loaded=True, bootstrap_error_on_calls={1: RuntimeError("svc still down")})

        with self.assertRaises(tool.ApplyAllRollbackFailure) as ctx:
            tool._recover_apply_all_service_only(self.config, True, ops.as_dict(), original_exc)

        message = str(ctx.exception)
        self.assertIn("original backup cause", message)
        self.assertIn("svc still down", message)
        self.assertIs(ctx.exception.__cause__, original_exc)

    def test_recover_apply_all_service_only_reraises_when_unloaded(self):
        original_exc = RuntimeError("clean cause")
        ops = FakeLaunchdOps(initially_loaded=False)

        with self.assertRaises(RuntimeError) as ctx:
            tool._recover_apply_all_service_only(self.config, False, ops.as_dict(), original_exc)
        self.assertIs(ctx.exception, original_exc)
        self.assertEqual(ops.calls, [])


class DefaultLaunchdOpsTests(unittest.TestCase):
    """Direct, fully-mocked coverage of _default_launchd_ops(): every test
    here patches subprocess.run so it NEVER invokes a real launchctl
    command, real or otherwise."""

    def _ops(self):
        return tool._default_launchd_ops()

    @staticmethod
    def _result(code, stderr=""):
        return type("FakeCompletedProcess", (), {"returncode": code, "stdout": "", "stderr": stderr})()

    def test_is_loaded_true_on_exit_0(self):
        ops = self._ops()
        with mock.patch.object(subprocess, "run", return_value=self._result(0)) as run:
            self.assertTrue(ops["is_loaded"]())
            self.assertEqual(run.call_args[0][0][0], "launchctl")

    def test_is_loaded_false_on_exit_113(self):
        ops = self._ops()
        with mock.patch.object(subprocess, "run", return_value=self._result(113)):
            self.assertFalse(ops["is_loaded"]())

    def test_is_loaded_denies_on_unknown_exit(self):
        ops = self._ops()
        with mock.patch.object(subprocess, "run", return_value=self._result(37, "weird")):
            with self.assertRaises(tool.LaunchdOpFailed):
                ops["is_loaded"]()

    def test_bootout_succeeds_immediately_on_exit_0_no_followup_probe(self):
        ops = self._ops()
        with mock.patch.object(subprocess, "run", return_value=self._result(0)) as run:
            ops["bootout"]()
            self.assertEqual(run.call_count, 1)

    def test_bootout_tolerates_nonzero_when_followup_probe_confirms_unloaded(self):
        ops = self._ops()
        results = [self._result(1, "already gone"), self._result(113)]
        with mock.patch.object(subprocess, "run", side_effect=results) as run:
            ops["bootout"]()  # must not raise
            self.assertEqual(run.call_count, 2)

    def test_bootout_denies_when_followup_probe_confirms_still_loaded(self):
        ops = self._ops()
        results = [self._result(1, "denied"), self._result(0)]
        with mock.patch.object(subprocess, "run", side_effect=results):
            with self.assertRaises(tool.LaunchdOpFailed):
                ops["bootout"]()

    def test_bootout_denies_when_followup_probe_itself_unknown(self):
        ops = self._ops()
        results = [self._result(1, "denied"), self._result(99, "??")]
        with mock.patch.object(subprocess, "run", side_effect=results):
            with self.assertRaises(tool.LaunchdOpFailed):
                ops["bootout"]()

    def test_bootstrap_succeeds_immediately_on_exit_0_no_followup_probe(self):
        ops = self._ops()
        with mock.patch.object(subprocess, "run", return_value=self._result(0)) as run:
            ops["bootstrap"]("/fixture/x.plist")
            self.assertEqual(run.call_count, 1)

    def test_bootstrap_tolerates_nonzero_when_followup_probe_confirms_loaded(self):
        ops = self._ops()
        results = [self._result(1, "already loaded"), self._result(0)]
        with mock.patch.object(subprocess, "run", side_effect=results):
            ops["bootstrap"]("/fixture/x.plist")  # must not raise

    def test_bootstrap_denies_when_followup_probe_confirms_still_unloaded(self):
        ops = self._ops()
        results = [self._result(1, "denied"), self._result(113)]
        with mock.patch.object(subprocess, "run", side_effect=results):
            with self.assertRaises(tool.LaunchdOpFailed):
                ops["bootstrap"]("/fixture/x.plist")

    def test_bootstrap_denies_when_followup_probe_itself_unknown(self):
        ops = self._ops()
        results = [self._result(1, "denied"), self._result(55)]
        with mock.patch.object(subprocess, "run", side_effect=results):
            with self.assertRaises(tool.LaunchdOpFailed):
                ops["bootstrap"]("/fixture/x.plist")


class VerifierDiagnosticsTests(unittest.TestCase):
    """_run_verifier_readonly() must surface WHY the verifier rejected the
    change, not just its exit code -- the real verify_worker_policy.py
    prints its [FAIL]/diagnostic detail to stdout, not stderr, so a message
    built from stderr alone is silently empty on a real failure."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.verifier_path = pathlib.Path(self.tmp.name) / "fake_verifier.py"

    def _config(self):
        return {"surfaces": {"verifier": {"path": str(self.verifier_path)}}}

    def test_verifier_failure_preserves_stdout_diagnostics(self):
        self.verifier_path.write_text(
            "import sys\n"
            "print('DIAGNOSTIC-STDOUT: POLICY-99 mismatch detail xyz')\n"
            "sys.exit(1)\n"
        )
        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        self.assertIn("DIAGNOSTIC-STDOUT: POLICY-99 mismatch detail xyz", str(ctx.exception))

    def test_verifier_failure_preserves_stderr_diagnostics(self):
        self.verifier_path.write_text(
            "import sys\n"
            "print('DIAGNOSTIC-STDERR: traceback-like detail', file=sys.stderr)\n"
            "sys.exit(1)\n"
        )
        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        self.assertIn("DIAGNOSTIC-STDERR: traceback-like detail", str(ctx.exception))

    def test_verifier_failure_preserves_both_stdout_and_stderr(self):
        self.verifier_path.write_text(
            "import sys\n"
            "print('OUT-PART: from stdout')\n"
            "print('ERR-PART: from stderr', file=sys.stderr)\n"
            "sys.exit(1)\n"
        )
        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        message = str(ctx.exception)
        self.assertIn("OUT-PART: from stdout", message)
        self.assertIn("ERR-PART: from stderr", message)

    def test_verifier_failure_diagnostics_are_bounded(self):
        self.verifier_path.write_text(
            "print('X' * 200000)\n"
            "import sys; sys.exit(1)\n"
        )
        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        message = str(ctx.exception)
        self.assertLess(len(message), 10000)

    def test_verifier_failure_with_no_output_says_so_explicitly(self):
        self.verifier_path.write_text("import sys\nsys.exit(1)\n")
        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        message = str(ctx.exception)
        self.assertIn("1", message)
        self.assertNotEqual(message.strip().endswith(":"), True)

    def test_verifier_success_is_unaffected(self):
        self.verifier_path.write_text("print('all good')\n")
        tool._run_verifier_readonly(self._config())  # must not raise

    def test_verifier_failure_preserves_fail_line_buried_in_long_stdout(self):
        # Regression for a real live-apply denial: the verifier prints one
        # [FAIL] line near the TOP of its output, followed by thousands of
        # [PASS] lines. A tail-only bound keeps only the end of the output,
        # so the actual failing check silently disappears from the DENY
        # message even though the message looks "full" of real content.
        script_lines = [
            "print('[FAIL] POLICY-99 the real failing check detail xyz')",
        ]
        script_lines += [f"print('[PASS] filler check number {i}')" for i in range(2000)]
        script_lines.append("import sys; sys.exit(1)")
        self.verifier_path.write_text("\n".join(script_lines) + "\n")

        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        message = str(ctx.exception)
        self.assertIn("[FAIL] POLICY-99 the real failing check detail xyz", message)
        self.assertLess(len(message), 10000)  # still bounded overall

    def test_verifier_failure_stderr_stays_tail_only_when_oversized(self):
        # stderr behavior must stay exactly as before: plain tail-bounded,
        # no [FAIL]-line extraction (the verifier's own diagnostics live on
        # stdout; stderr is for unexpected tracebacks/crash noise).
        script_lines = [
            "import sys",
            "print('[FAIL] should not be specially preserved on stderr', file=sys.stderr)",
        ]
        script_lines += [f"print('filler stderr line {i}', file=sys.stderr)" for i in range(2000)]
        script_lines.append("sys.exit(1)")
        self.verifier_path.write_text("\n".join(script_lines) + "\n")

        with self.assertRaises(tool.VerifierFailed) as ctx:
            tool._run_verifier_readonly(self._config())
        message = str(ctx.exception)
        self.assertNotIn("[FAIL] should not be specially preserved on stderr", message)
        self.assertIn("filler stderr line 1999", message)  # tail is preserved
        self.assertLess(len(message), 10000)


if __name__ == "__main__":
    unittest.main()
