import importlib.util
import json
import os
import pathlib
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


if __name__ == "__main__":
    unittest.main()
