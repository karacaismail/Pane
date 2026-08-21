#!/usr/bin/env python3
"""Transactional installer for the disabled Claude child-session broker
posture across the four real global policy surfaces: canonical policy,
golden policy, verifier, and the golden integrity manifest.

The local broker module (claude_child_broker.py) is a READ-ONLY
prerequisite: this package checks its hash but never writes it.

Default mode is `check`: read-only, no writes, no subprocess, no network,
no Git. `--apply` writes canonical, golden and verifier, updates the
manifest, and only then runs the verifier read-only, so the verifier's own
self-integrity check (SELF-01) observes a manifest that already matches
what was written -- all inside one rollback-protected transaction that
restores all four surfaces on any failure. The verifier patch wires a real
POLICY-54-style check into run_all(spec); it is not merely defined and
left uncalled. A second `--apply` on an already-integrated state is a
no-op (no duplicate backups, no writes). An expected object (from this
config, or an existing claudeChildBroker object already on disk) that
encodes an enabling posture is hard refused before any write happens;
everything else relies on exact prehash matching rather than scanning
unrelated file content for markers.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

DEFAULT_CONFIG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "disabled-child-broker.json"
)

SURFACE_ORDER = ["canonical", "golden", "verifier", "manifest"]


class PolicyRefused(Exception):
    """Raised when content encodes an enabling posture; no writes occur."""


class PrehashMismatch(PolicyRefused):
    """Raised when a target surface has drifted from its recorded baseline."""


class VerifierFailed(Exception):
    """Raised when the post-write verifier run rejects the applied change."""


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def load_config(path):
    with open(path, "r") as fh:
        return json.load(fh)


def _read_text(path):
    with open(path, "r") as fh:
        return fh.read()


def _write_text(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def refuse_if_enabling_object(config, obj):
    """Field-by-field check of a claudeChildBroker object (expected, or an
    existing one found on disk). Never scans unrelated file text."""
    if not isinstance(obj, dict):
        return
    for key in config.get("must_be_false_fields", []):
        if obj.get(key) is True:
            raise PolicyRefused(f"refusing: claudeChildBroker.{key} is enabled (True)")
    for key, want in config.get("must_equal_fields", {}).items():
        if key in obj and obj.get(key) != want:
            raise PolicyRefused(
                f"refusing: claudeChildBroker.{key}={obj.get(key)!r} is not the closed value {want!r}"
            )


def render_verifier_function(config):
    obj = config["claude_child_broker_object"]
    template = config["verifier_patch"]["function_template"]
    return template.replace("{expected_literal}", repr(obj))


def _verify_broker_prerequisite(config):
    """Read-only check of the local broker module. Never written here."""
    prereq = config["broker_prerequisite"]
    path = prereq["path"]
    if not os.path.exists(path):
        raise PolicyRefused(f"broker prerequisite missing: {path}")
    actual = sha256_file(path)
    if actual != prereq["expected_sha256"]:
        raise PolicyRefused(
            "broker prerequisite hash mismatch; refusing (this package never "
            "writes the broker module itself)"
        )


def _canonical_state(path, key):
    if not os.path.exists(path):
        return None
    with open(path, "r") as fh:
        data = json.load(fh)
    return data.get(key)


def _verifier_has_patch(path, verifier_patch):
    if not os.path.exists(path):
        return False
    text = _read_text(path)
    call_marker = verifier_patch["call_statement"]
    return verifier_patch["function_marker"] in text and call_marker in text


def _manifest_entry_hash(manifest_text, name):
    for line in manifest_text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith(f"  {name}") or stripped.endswith(f" {name}"):
            return stripped.split()[0]
    return None


def _manifest_reflects_current(config):
    surfaces = config["surfaces"]
    manifest_path = surfaces["manifest"]["path"]
    verifier_path = surfaces["verifier"]["path"]
    golden_path = surfaces["golden"]["path"]
    if not (os.path.exists(manifest_path) and os.path.exists(verifier_path) and os.path.exists(golden_path)):
        return False
    manifest_text = _read_text(manifest_path)
    return (
        _manifest_entry_hash(manifest_text, "verify_worker_policy.py") == sha256_file(verifier_path)
        and _manifest_entry_hash(manifest_text, "claude-worker-policy.golden.json") == sha256_file(golden_path)
    )


def _per_surface_status(config):
    surfaces = config["surfaces"]
    key = config["top_level_key"]
    expected_obj = config["claude_child_broker_object"]
    return {
        "canonical": _canonical_state(surfaces["canonical"]["path"], key) == expected_obj,
        "golden": _canonical_state(surfaces["golden"]["path"], key) == expected_obj,
        "verifier": _verifier_has_patch(surfaces["verifier"]["path"], config["verifier_patch"]),
        "manifest": _manifest_reflects_current(config),
    }


def is_fully_integrated(config):
    return all(_per_surface_status(config).values())


def check(config):
    """Read-only report of whether all four surfaces are integrated. Never
    writes, never runs a subprocess, never touches the network."""
    per_surface = _per_surface_status(config)
    integrated = all(per_surface.values())
    return {
        "status": "GREEN" if integrated else "RED",
        "detail": "all four surfaces integrated" if integrated else "not fully integrated",
        "surfaces": per_surface,
    }


def _backup_all(config):
    surfaces = config["surfaces"]
    backup_dir = config["backup_dir"]
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    txn_dir = os.path.join(backup_dir, f"claudeChildBroker.{stamp}")
    suffix = 0
    while os.path.exists(txn_dir):
        suffix += 1
        txn_dir = os.path.join(backup_dir, f"claudeChildBroker.{stamp}.{suffix}")
    os.makedirs(txn_dir)

    backups = {}
    for name in SURFACE_ORDER:
        src = surfaces[name]["path"]
        dst = os.path.join(txn_dir, name)
        shutil.copy2(src, dst)
        backups[name] = dst
    return txn_dir, backups


def _restore_all(config, backups):
    surfaces = config["surfaces"]
    for name in SURFACE_ORDER:
        shutil.copy2(backups[name], surfaces[name]["path"])


def _write_canonical_or_golden(config, surface_name):
    surfaces = config["surfaces"]
    path = surfaces[surface_name]["path"]
    key = config["top_level_key"]
    with open(path, "r") as fh:
        data = json.load(fh)
    existing = data.get(key)
    if existing is not None:
        refuse_if_enabling_object(config, existing)
    data[key] = config["claude_child_broker_object"]
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def _write_verifier_patch(config):
    surfaces = config["surfaces"]
    path = surfaces["verifier"]["path"]
    patch = config["verifier_patch"]

    content = _read_text(path)

    if patch["function_marker"] not in content:
        anchor = patch["function_insert_before"]
        if anchor not in content:
            raise PolicyRefused(f"verifier function anchor not found: {anchor!r}")
        function_text = render_verifier_function(config)
        content = content.replace(anchor, function_text + anchor, 1)

    if patch["call_statement"] not in content:
        call_anchor = patch["call_anchor"]
        lines = content.split("\n")
        idx = None
        indent = ""
        for i, line in enumerate(lines):
            if line.strip() == call_anchor:
                idx = i
                indent = line[: len(line) - len(line.lstrip())]
                break
        if idx is None:
            raise PolicyRefused(f"verifier call anchor not found: {call_anchor!r}")
        lines.insert(idx + 1, f"{indent}{patch['call_statement']}")
        content = "\n".join(lines)

    _write_text(path, content)


def _update_manifest(config):
    surfaces = config["surfaces"]
    manifest_path = surfaces["manifest"]["path"]
    allowed = set(surfaces["manifest"].get("updatable_entries", []))
    if not os.path.exists(manifest_path) or not allowed:
        return

    hashes = {}
    if "verify_worker_policy.py" in allowed and os.path.exists(surfaces["verifier"]["path"]):
        hashes["verify_worker_policy.py"] = sha256_file(surfaces["verifier"]["path"])
    if "claude-worker-policy.golden.json" in allowed and os.path.exists(surfaces["golden"]["path"]):
        hashes["claude-worker-policy.golden.json"] = sha256_file(surfaces["golden"]["path"])

    lines = _read_text(manifest_path).splitlines(keepends=True)
    new_lines = []
    for line in lines:
        stripped = line.rstrip("\n")
        replaced = False
        for name, digest in hashes.items():
            if stripped.endswith(f"  {name}") or stripped.endswith(f" {name}"):
                new_lines.append(f"{digest}  {name}\n")
                replaced = True
                break
        if not replaced:
            new_lines.append(line)
    _write_text(manifest_path, "".join(new_lines))


def _run_verifier_readonly(config):
    path = config["surfaces"]["verifier"]["path"]
    result = subprocess.run(
        [sys.executable, path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise VerifierFailed(
            f"verifier {path} exited {result.returncode}: {result.stderr.strip()}"
        )


def apply(config):
    """Atomically install the claudeChildBroker disabled posture across the
    four real policy surfaces. Idempotent, prehash-checked, backed up, and
    rolled back in full on any manifest-update or verifier failure.

    Write order inside the single protected transaction: canonical,
    golden, verifier, THEN manifest, THEN the read-only verifier run --
    so the verifier's own self-integrity check observes a manifest that
    already matches what was just written.
    """
    expected_obj = config["claude_child_broker_object"]
    refuse_if_enabling_object(config, expected_obj)

    _verify_broker_prerequisite(config)

    if is_fully_integrated(config):
        return {"status": "GREEN", "detail": "already integrated", "changed": False}

    surfaces = config["surfaces"]
    key = config["top_level_key"]
    for name in SURFACE_ORDER:
        surf = surfaces[name]
        path = surf["path"]
        if not os.path.exists(path):
            raise PolicyRefused(f"{name}: target missing at {path}")
        actual = sha256_text(_read_text(path))
        if actual != surf["expected_prehash_sha256"]:
            raise PrehashMismatch(
                f"{name}: prehash mismatch (expected "
                f"{surf['expected_prehash_sha256']}, found {actual}); refusing"
            )

    # Field-by-field check of any pre-existing claudeChildBroker object,
    # BEFORE any backup or write, so a tampered on-disk object refuses
    # cleanly with zero filesystem side effects.
    for name in ("canonical", "golden"):
        existing = _canonical_state(surfaces[name]["path"], key)
        if existing is not None:
            refuse_if_enabling_object(config, existing)

    txn_dir, backups = _backup_all(config)

    try:
        _write_canonical_or_golden(config, "canonical")
        _write_canonical_or_golden(config, "golden")
        _write_verifier_patch(config)
        _update_manifest(config)
        _run_verifier_readonly(config)
    except Exception:
        _restore_all(config, backups)
        raise

    return {
        "status": "GREEN",
        "detail": "claudeChildBroker disabled posture integrated across all four surfaces",
        "changed": True,
        "backup_dir": txn_dir,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="install the disabled posture across all four surfaces (default is a read-only check)",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)

    try:
        result = apply(config) if args.apply else check(config)
    except (PolicyRefused, VerifierFailed) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
