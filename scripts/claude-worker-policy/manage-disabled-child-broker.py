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
    begin_marker = patch["function_marker"]
    end_marker = patch["function_end_marker"]
    begin_count = content.count(begin_marker)
    end_count = content.count(end_marker)

    if begin_count == 0 and end_count == 0:
        anchor = patch["function_insert_before"]
        if anchor not in content:
            raise PolicyRefused(f"verifier function anchor not found: {anchor!r}")
        function_text = render_verifier_function(config)
        content = content.replace(anchor, function_text + anchor, 1)
    elif begin_count == 1 and end_count == 1:
        begin_idx = content.index(begin_marker)
        end_idx = content.index(end_marker)
        if end_idx < begin_idx:
            raise PolicyRefused(
                "verifier managed function block markers are out of order; refusing"
            )
        # Replace the existing marked block (which may carry a stale
        # expected literal from an earlier config generation) with the
        # current render, in place -- never appending a second block.
        end_idx_after_marker = end_idx + len(end_marker)
        rendered = render_verifier_function(config)
        content = content[:begin_idx] + rendered + content[end_idx_after_marker:]
    else:
        raise PolicyRefused(
            "verifier managed function block markers are malformed: found "
            f"{begin_count} start marker(s) and {end_count} end marker(s) "
            "(expected exactly one matched pair, or neither); refusing"
        )

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


_VERIFIER_DIAGNOSTIC_MAX_CHARS = 4000


def _bounded_diagnostic(text, max_chars=_VERIFIER_DIAGNOSTIC_MAX_CHARS):
    """Tail-truncate to a bounded size so a runaway verifier can't blow up
    the failure message (or, worst case, spray unbounded output into logs)."""
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    return f"...[truncated to last {max_chars} chars]...\n" + text[-max_chars:]


def _bounded_stdout_diagnostic(text, max_chars=_VERIFIER_DIAGNOSTIC_MAX_CHARS):
    """Like _bounded_diagnostic, but a real verifier's own [FAIL] lines are
    the whole point of the message -- a plain tail truncation can bury one
    under thousands of later [PASS] lines. When truncation is needed, every
    "[FAIL]" line is kept in full (itself tail-bounded if pathologically
    numerous/long), with any remaining budget filled by the plain tail for
    surrounding context."""
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text

    fail_lines = [line for line in text.splitlines() if "[FAIL]" in line]
    if not fail_lines:
        return _bounded_diagnostic(text, max_chars)

    fail_block = "\n".join(fail_lines)
    if len(fail_block) > max_chars:
        return f"...[truncated to last {max_chars} chars of [FAIL] lines]...\n" + fail_block[-max_chars:]

    header = f"[FAIL] lines ({len(fail_lines)}):\n"
    remaining = max_chars - len(header) - len(fail_block)
    if remaining <= 0:
        return header + fail_block

    tail_marker = "\n...[tail]...\n"
    tail_budget = remaining - len(tail_marker)
    if tail_budget <= 0:
        return header + fail_block

    return header + fail_block + tail_marker + text[-tail_budget:]


def _run_verifier_readonly(config):
    path = config["surfaces"]["verifier"]["path"]
    result = subprocess.run(
        [sys.executable, path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stdout = _bounded_stdout_diagnostic(result.stdout)
        stderr = _bounded_diagnostic(result.stderr)
        parts = [f"verifier {path} exited {result.returncode}"]
        if stdout:
            parts.append(f"stdout: {stdout}")
        if stderr:
            parts.append(f"stderr: {stderr}")
        if not stdout and not stderr:
            parts.append("(no output on stdout or stderr)")
        raise VerifierFailed(" | ".join(parts))


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


# ------------------------------------------------------------- projection
#
# A second, independent transactional wave. It carries the same
# prepared-not-active broker text into the golden provider-lock docs, the
# managed-fields golden config (refusal body + launchd requiredWatchPaths),
# three live managed-content files, and the real LaunchAgent plist. It
# reuses the same prehash/backup/rollback/idempotency shape as apply()
# above but targets a disjoint set of files and does not require, and does
# not re-touch, the POLICY-54 wave.

_NUMBERED_ITEM_RE = None


def _numbered_item_re():
    global _NUMBERED_ITEM_RE
    if _NUMBERED_ITEM_RE is None:
        import re

        _NUMBERED_ITEM_RE = re.compile(r"^(\d+)\.\s")
    return _NUMBERED_ITEM_RE


def _next_item_number(lines):
    """Highest `N. ` line-start seen, plus one. Never trusts an asserted
    anchor number from config -- always recomputed from live content."""
    pattern = _numbered_item_re()
    highest = 0
    for line in lines:
        m = pattern.match(line.lstrip("﻿"))
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def _find_item_block(lines, detect):
    """Locate the [start, end) line range of the existing numbered item that
    contains `detect`, plus its item number. Returns None if no such item
    exists. Used to update a stale item in place instead of appending a
    duplicate."""
    pattern = _numbered_item_re()
    start = None
    number = None
    for i, line in enumerate(lines):
        m = pattern.match(line.lstrip("﻿"))
        if m:
            if start is not None:
                if any(detect in lines[j] for j in range(start, i)):
                    return start, i, number
                start = None
            start = i
            number = int(m.group(1))
    if start is not None and any(detect in lines[j] for j in range(start, len(lines))):
        end = len(lines)
        while end > start and lines[end - 1].strip() == "":
            end -= 1
        return start, end, number
    return None


def _render_item(config, template_key, n):
    return [line.replace("{n}", str(n)) for line in config["projection"][template_key]]


def _projection_target_present(config, name, target):
    kind = target["kind"]
    path = target["path"]
    if not os.path.exists(path):
        return False
    detect = config["projection"]["detection_text"]

    if kind == "numbered_list_append":
        lines = _read_text(path).splitlines()
        found = _find_item_block(lines, detect)
        if found is None:
            return False
        start, end, number = found
        return lines[start:end] == _render_item(config, "item_text_template", number)

    if kind == "numbered_list_append_within_markers":
        text = _read_text(path)
        if "source_path" in target:
            # Golden-sync mode: integrated iff the live lock block is byte-
            # identical (modulo surrounding whitespace) to the golden file.
            begin, end = target["begin_marker"], target["end_marker"]
            if begin not in text or end not in text:
                return False
            block = text.split(begin, 1)[1].split(end, 1)[0].strip("\n")
            source_path = target["source_path"]
            if not os.path.exists(source_path):
                return False
            golden = _read_text(source_path).strip("\n")
            return block == golden and detect in block
        begin, end = target["begin_marker"], target["end_marker"]
        if begin not in text or end not in text:
            return False
        body = text.split(begin, 1)[1].split(end, 1)[0]
        lines = body.splitlines()
        found = _find_item_block(lines, detect)
        if found is None:
            return False
        start, end, number = found
        return lines[start:end] == _render_item(config, "refusal_body_item_template", number)

    if kind == "json_body_array_append":
        with open(path, "r") as fh:
            data = json.load(fh)
        node = data
        for key in target["json_path"]:
            node = node.get(key, {})
        body = node if isinstance(node, list) else []
        found = _find_item_block(body, detect)
        if found is None:
            return False
        start, end, number = found
        return body[start:end] == _render_item(config, "refusal_body_item_template", number)

    if kind == "json_array_append_unique":
        with open(path, "r") as fh:
            data = json.load(fh)
        node = data
        for key in target["json_path"]:
            node = node.get(key, [])
        return config["projection"]["watch_path_value"] in (node or [])

    if kind == "plist_watchpath_append":
        return config["projection"]["watch_path_value"] in _read_text(path)

    raise PolicyRefused(f"unknown projection target kind: {kind}")


def is_projection_integrated(config):
    targets = config["projection"]["targets"]
    return all(
        _projection_target_present(config, name, target) for name, target in targets.items()
    )


def check_projection(config):
    """Read-only report of the projection wave. Never writes."""
    targets = config["projection"]["targets"]
    per_target = {
        name: _projection_target_present(config, name, target)
        for name, target in targets.items()
    }
    manifest_keys = ("provider_lock_agents", "provider_lock_orchestrator", "managed_fields_refusal")
    manifest_ok = True
    if all(k in targets for k in manifest_keys):
        manifest_path = config["projection"]["manifest"]["path"]
        manifest_ok = False
        if os.path.exists(manifest_path) and all(os.path.exists(targets[k]["path"]) for k in manifest_keys):
            manifest_text = _read_text(manifest_path)
            manifest_ok = all(
                _manifest_entry_hash(manifest_text, name) == sha256_file(targets[key]["path"])
                for key, name in (
                    ("provider_lock_agents", "provider-lock-agents.md"),
                    ("provider_lock_orchestrator", "provider-lock-orchestrator.md"),
                    ("managed_fields_refusal", "managed-fields.golden.json"),
                )
            )
    per_target["manifest"] = manifest_ok

    integrated = all(per_target.values())
    return {
        "status": "GREEN" if integrated else "RED",
        "detail": "all projection targets integrated" if integrated else "projection not fully integrated",
        "targets": per_target,
    }


def _write_numbered_list_append(config, path, template_key):
    detect = config["projection"]["detection_text"]
    lines = _read_text(path).splitlines()
    found = _find_item_block(lines, detect)
    if found is not None:
        start, end, number = found
        lines[start:end] = _render_item(config, template_key, number)
        _write_text(path, "\n".join(lines) + "\n")
        return
    n = _next_item_number(lines)
    new_item = _render_item(config, template_key, n)
    text = _read_text(path)
    if not text.endswith("\n"):
        text += "\n"
    text += "\n".join(new_item) + "\n"
    _write_text(path, text)


def _write_numbered_within_markers(config, target):
    path = target["path"]
    text = _read_text(path)
    begin, end = target["begin_marker"], target["end_marker"]
    if begin not in text or end not in text:
        raise PolicyRefused(f"managed block markers not found in {path}")
    head, rest = text.split(begin, 1)
    body, tail = rest.split(end, 1)

    if "source_path" in target:
        # Golden-sync mode: the golden provider-lock file (already updated
        # with its own new numbered item by this point in the transaction)
        # is spliced in verbatim, so the live lock block stays byte-for-byte
        # identical to golden -- no independent numbering, no drift, and no
        # separate marker block left outside the existing lock markers.
        source_path = target["source_path"]
        if not os.path.exists(source_path):
            raise PolicyRefused(f"projection source missing: {source_path}")
        golden_text = _read_text(source_path).strip("\n")
        new_text = head + begin + "\n\n" + golden_text + "\n\n" + end + tail
        _write_text(path, new_text)
        return

    detect = config["projection"]["detection_text"]
    lines = body.splitlines()
    found = _find_item_block(lines, detect)
    if found is not None:
        item_start, item_end, number = found
        lines[item_start:item_end] = _render_item(config, "refusal_body_item_template", number)
        new_body = "\n".join(lines) + "\n"
        _write_text(path, head + begin + new_body + end + tail)
        return
    n = _next_item_number(lines)
    new_item = _render_item(config, "refusal_body_item_template", n)
    new_body = body.rstrip("\n") + "\n" + "\n".join(new_item) + "\n"
    _write_text(path, head + begin + new_body + end + tail)


def _write_json_body_array_append(config, target):
    path = target["path"]
    with open(path, "r") as fh:
        data = json.load(fh)
    node = data
    for key in target["json_path"][:-1]:
        node = node[key]
    array_key = target["json_path"][-1]
    body = node[array_key]
    detect = config["projection"]["detection_text"]
    found = _find_item_block(body, detect)
    if found is not None:
        start, end, number = found
        body[start:end] = _render_item(config, "refusal_body_item_template", number)
        node[array_key] = body
    else:
        n = _next_item_number(body)
        new_item = _render_item(config, "refusal_body_item_template", n)
        node[array_key] = body + new_item
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def _write_json_array_append_unique(config, target):
    path = target["path"]
    value = config["projection"]["watch_path_value"]
    with open(path, "r") as fh:
        data = json.load(fh)
    node = data
    for key in target["json_path"][:-1]:
        node = node[key]
    array_key = target["json_path"][-1]
    arr = node.get(array_key, [])
    if value not in arr:
        arr = arr + [value]
    node[array_key] = arr
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def _write_plist_watchpath_append(config, target):
    path = target["path"]
    value = config["projection"]["watch_path_value"]
    text = _read_text(path)
    anchor = "<key>WatchPaths</key>"
    if anchor not in text:
        raise PolicyRefused(f"WatchPaths key not found in {path}")
    if f"<string>{value}</string>" in text:
        return
    array_open = text.index("<array>", text.index(anchor))
    close_tag = "</array>"
    close_idx = text.index(close_tag, array_open)
    insertion = f"\t\t<string>{value}</string>\n\t"
    text = text[:close_idx] + insertion + text[close_idx:]
    _write_text(path, text)


_WRITERS = {
    "numbered_list_append": lambda config, target: _write_numbered_list_append(
        config, target["path"], "item_text_template"
    ),
    "numbered_list_append_within_markers": _write_numbered_within_markers,
    "json_body_array_append": _write_json_body_array_append,
    "json_array_append_unique": _write_json_array_append_unique,
    "plist_watchpath_append": _write_plist_watchpath_append,
}


def _backup_set(paths_by_name, backup_dir, txn_label):
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    txn_dir = os.path.join(backup_dir, f"{txn_label}.{stamp}")
    suffix = 0
    while os.path.exists(txn_dir):
        suffix += 1
        txn_dir = os.path.join(backup_dir, f"{txn_label}.{stamp}.{suffix}")
    os.makedirs(txn_dir)
    backups = {}
    for name, path in paths_by_name.items():
        dst = os.path.join(txn_dir, name)
        shutil.copy2(path, dst)
        backups[name] = dst
    return txn_dir, backups


def _restore_set(paths_by_name, backups):
    for name, path in paths_by_name.items():
        shutil.copy2(backups[name], path)


def _update_projection_manifest(config):
    manifest_cfg = config["projection"]["manifest"]
    manifest_path = manifest_cfg["path"]
    allowed = set(manifest_cfg.get("updatable_entries", []))
    if not os.path.exists(manifest_path) or not allowed:
        return
    targets = config["projection"]["targets"]
    name_to_path = {
        "provider-lock-agents.md": targets["provider_lock_agents"]["path"],
        "provider-lock-orchestrator.md": targets["provider_lock_orchestrator"]["path"],
        "managed-fields.golden.json": targets["managed_fields_refusal"]["path"],
    }
    hashes = {
        name: sha256_file(path)
        for name, path in name_to_path.items()
        if name in allowed and os.path.exists(path)
    }
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


def apply_projection(config):
    """Atomically install the projection wave across its (disjoint) target
    set. Idempotent, prehash-checked, backed up as one transaction, and
    rolled back in full on any failure. Does not run the verifier and does
    not touch the POLICY-54 wave's surfaces."""
    if is_projection_integrated(config):
        return {"status": "GREEN", "detail": "projection already integrated", "changed": False}

    targets = config["projection"]["targets"]
    manifest_cfg = config["projection"]["manifest"]

    paths_by_name = {name: t["path"] for name, t in targets.items()}
    paths_by_name["manifest"] = manifest_cfg["path"]

    # De-duplicate: managed-fields.golden.json is targeted twice (refusal
    # body + watchpaths) but must be prehash-checked and backed up once.
    unique_paths = {}
    for name, path in paths_by_name.items():
        unique_paths.setdefault(path, name)

    for path, first_name in unique_paths.items():
        if not os.path.exists(path):
            raise PolicyRefused(f"{first_name}: target missing at {path}")
        actual = sha256_text(_read_text(path))
        expected = None
        for name, t in targets.items():
            if t["path"] == path and "expected_prehash_sha256" in t:
                expected = t["expected_prehash_sha256"]
                break
        if expected is None and path == manifest_cfg["path"]:
            expected = manifest_cfg["expected_prehash_sha256"]
        if expected is not None and actual != expected:
            raise PrehashMismatch(
                f"{first_name}: prehash mismatch (expected {expected}, found {actual}); refusing"
            )

    backup_dir = config["projection"]["backup_dir"]
    names_by_path = {n: p for p, n in unique_paths.items()}
    txn_dir, backups = _backup_set(names_by_path, backup_dir, "projection")

    try:
        for name, target in targets.items():
            writer = _WRITERS[target["kind"]]
            writer(config, target)
        _update_projection_manifest(config)
    except Exception:
        _restore_set(names_by_path, backups)
        raise

    return {
        "status": "GREEN",
        "detail": "projection wave integrated across all targets",
        "changed": True,
        "backup_dir": txn_dir,
    }


# --------------------------------------------------------------- apply-all
#
# A single atomic transaction that applies both the POLICY-54 core wave and
# the projection wave from the same initial snapshot: one preflight over the
# union of every unique target path (shared paths, including GOLDEN.sha256,
# checked once for hash consistency), one backup directory for the union,
# one write pass across every target, one merged final manifest, and one
# verifier run after that final manifest is in place. Any failure restores
# every union target. A second run, once both waves are integrated, is a
# no-op with no backup and no write.


def _apply_all_manifest_hashes(config):
    surfaces = config["surfaces"]
    targets = config["projection"]["targets"]
    hashes = {}
    if os.path.exists(surfaces["verifier"]["path"]):
        hashes["verify_worker_policy.py"] = sha256_file(surfaces["verifier"]["path"])
    if os.path.exists(surfaces["golden"]["path"]):
        hashes["claude-worker-policy.golden.json"] = sha256_file(surfaces["golden"]["path"])
    name_to_path = {
        "provider-lock-agents.md": targets.get("provider_lock_agents", {}).get("path"),
        "provider-lock-orchestrator.md": targets.get("provider_lock_orchestrator", {}).get("path"),
        "managed-fields.golden.json": targets.get("managed_fields_refusal", {}).get("path"),
    }
    for name, path in name_to_path.items():
        if path and os.path.exists(path):
            hashes[name] = sha256_file(path)
    return hashes


def _update_manifest_all(config):
    manifest_path = config["surfaces"]["manifest"]["path"]
    allowed = set(config["surfaces"]["manifest"].get("updatable_entries", []))
    allowed |= set(config["projection"]["manifest"].get("updatable_entries", []))
    if not os.path.exists(manifest_path) or not allowed:
        return

    hashes = {
        name: digest
        for name, digest in _apply_all_manifest_hashes(config).items()
        if name in allowed
    }

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


def _apply_all_union_paths(config):
    """name -> path for every unique target across both waves. Shared paths
    (GOLDEN.sha256) collapse to a single entry keyed by their first-seen
    name, so they are prehash-checked, backed up and restored exactly once."""
    surfaces = config["surfaces"]
    targets = config["projection"]["targets"]
    proj_manifest = config["projection"]["manifest"]

    ordered = []
    for name in SURFACE_ORDER:
        ordered.append((f"broker:{name}", surfaces[name]["path"]))
    for name, t in targets.items():
        ordered.append((f"projection:{name}", t["path"]))
    ordered.append(("projection:manifest", proj_manifest["path"]))

    unique_paths = {}
    for name, path in ordered:
        unique_paths.setdefault(path, name)
    return unique_paths


def _apply_all_expected_prehash(config, path):
    surfaces = config["surfaces"]
    targets = config["projection"]["targets"]
    proj_manifest = config["projection"]["manifest"]

    expected = None
    for surf in surfaces.values():
        if surf["path"] == path and "expected_prehash_sha256" in surf:
            if expected is not None and expected != surf["expected_prehash_sha256"]:
                raise PolicyRefused(
                    f"shared target {path} has inconsistent expected hashes across surfaces; refusing"
                )
            expected = surf["expected_prehash_sha256"]
    for t in targets.values():
        if t["path"] == path and "expected_prehash_sha256" in t:
            if expected is not None and expected != t["expected_prehash_sha256"]:
                raise PolicyRefused(
                    f"shared target {path} has inconsistent expected hashes across surfaces; refusing"
                )
            expected = t["expected_prehash_sha256"]
    if path == proj_manifest["path"] and "expected_prehash_sha256" in proj_manifest:
        if expected is not None and expected != proj_manifest["expected_prehash_sha256"]:
            raise PolicyRefused(
                f"shared target {path} has inconsistent expected hashes across surfaces; refusing"
            )
        expected = proj_manifest["expected_prehash_sha256"]
    return expected


def is_apply_all_integrated(config):
    return is_fully_integrated(config) and is_projection_integrated(config)


# ------------------------------------------------------- launchd quiescence
#
# apply_all() writes a target the LaunchAgent watches (com.codex.claude-
# worker-policy), so a watcher could observe a partially-written union mid-
# transaction. To avoid that, apply_all() boots the service out before the
# backup/write phase (only if it was actually loaded) and bootstraps it back
# in only after everything -- writes, verifier, manifest -- has succeeded.
# An initially-unloaded service is never touched by launchctl and stays
# unloaded on every path, success or failure.

LAUNCHD_LABEL = "com.codex.claude-worker-policy"


class LaunchdOpFailed(Exception):
    """Raised when a launchctl bootout/bootstrap/probe operation fails."""


class ApplyAllRollbackFailure(Exception):
    """Raised when apply_all() fails and restoring the union of targets
    and/or recovering the LaunchAgent service also failed. Aggregates the
    original cause with every restore/recovery error encountered; nothing
    is swallowed."""


def _default_launchd_ops():
    """Real launchctl-backed ops, used only outside of tests. Tests must
    always inject config["launchd_ops"] and never exercise this path.

    `is_loaded` is strict about `launchctl print` exit codes: 0 means loaded,
    113 is launchd's documented "no such service" code and means unloaded,
    and any other exit code is an unknown probe failure that DENYs (raises
    LaunchdOpFailed) rather than guessing. `bootout`/`bootstrap` tolerate a
    nonzero command exit only when a follow-up strict `is_loaded` probe
    proves the operation's desired end state was actually reached (e.g. the
    service was already unloaded when bootout ran); an unknown follow-up
    probe failure still DENYs."""
    uid = os.getuid()
    domain = f"gui/{uid}"

    def is_loaded():
        result = subprocess.run(
            ["launchctl", "print", f"{domain}/{LAUNCHD_LABEL}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True
        if result.returncode == 113:
            return False
        raise LaunchdOpFailed(
            f"launchctl print unknown exit {result.returncode}: {result.stderr.strip()}"
        )

    def bootout():
        result = subprocess.run(
            ["launchctl", "bootout", f"{domain}/{LAUNCHD_LABEL}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        if not is_loaded():
            return  # desired end state (unloaded) reached despite nonzero exit
        raise LaunchdOpFailed(f"launchctl bootout failed: {result.stderr.strip()}")

    def bootstrap(plist_path):
        result = subprocess.run(
            ["launchctl", "bootstrap", domain, plist_path],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        if is_loaded():
            return  # desired end state (loaded) reached despite nonzero exit
        raise LaunchdOpFailed(f"launchctl bootstrap failed: {result.stderr.strip()}")

    return {"is_loaded": is_loaded, "bootout": bootout, "bootstrap": bootstrap}


def _restore_union_no_early_abort(names_by_path, backups):
    """Restore every union target, continuing past individual failures
    instead of aborting on the first one. Returns the list of per-target
    error strings (empty if every restore succeeded)."""
    errors = []
    for name, path in names_by_path.items():
        try:
            shutil.copy2(backups[name], path)
        except Exception as exc:
            errors.append(f"{name} ({path}): {exc}")
    return errors


def _recover_apply_all_failure(config, names_by_path, backups, was_loaded, ops, original_exc):
    """Shared failure path for both a write/verifier failure and a
    bootstrap-after-success failure: restore every union target without
    early abort, then (only if the service was initially loaded) restore
    it using the just-restored plist. Raises one compound failure if any
    restore or the service recovery itself failed; otherwise re-raises the
    original exception unchanged."""
    restore_errors = _restore_union_no_early_abort(names_by_path, backups)

    service_error = None
    if was_loaded:
        plist_path = config["projection"]["targets"]["launch_agent_plist"]["path"]
        try:
            ops["bootstrap"](plist_path)
        except Exception as exc:
            service_error = str(exc)

    if restore_errors or service_error:
        parts = [f"original failure: {original_exc}"]
        if restore_errors:
            parts.append("restore failures: " + "; ".join(restore_errors))
        if service_error:
            parts.append(f"service recovery failure: {service_error}")
        raise ApplyAllRollbackFailure("; ".join(parts)) from original_exc

    raise original_exc


def _recover_apply_all_service_only(config, was_loaded, ops, original_exc):
    """Failure path for a backup-phase failure: no target was ever written
    (the backup itself is what failed), so there is nothing to restore --
    only an initially-loaded service is recovered, using the still-original
    (untouched) plist. Raises one compound failure if that recovery itself
    failed; otherwise re-raises the original exception unchanged."""
    service_error = None
    if was_loaded:
        plist_path = config["projection"]["targets"]["launch_agent_plist"]["path"]
        try:
            ops["bootstrap"](plist_path)
        except Exception as exc:
            service_error = str(exc)

    if service_error:
        raise ApplyAllRollbackFailure(
            f"original failure: {original_exc}; service recovery failure: {service_error}"
        ) from original_exc

    raise original_exc


def apply_all(config):
    """Atomically apply the POLICY-54 core wave and the projection wave from
    one initial snapshot: preflight the union of unique target paths (shared
    paths checked once for consistent expected hashes), hard-refuse drift or
    an enabling posture before any side effect, one backup directory for the
    union, write every target, update the shared manifest to its single
    final merged content, then run the verifier exactly once. If the watched
    LaunchAgent service was loaded, it is booted out before the first backup
    or write and bootstrapped back in only after the whole transaction
    (including that bootstrap) succeeds; an initially-unloaded service is
    never touched. Any write/verifier/bootstrap failure restores every union
    target (without early abort, aggregating errors) and attempts to
    recover an initially-loaded service. Idempotent once both waves are
    integrated -- the no-op and preflight-refusal paths never touch
    launchctl."""
    expected_obj = config["claude_child_broker_object"]
    refuse_if_enabling_object(config, expected_obj)
    _verify_broker_prerequisite(config)

    if is_apply_all_integrated(config):
        return {"status": "GREEN", "detail": "already integrated (broker + projection)", "changed": False}

    surfaces = config["surfaces"]
    key = config["top_level_key"]

    unique_paths = _apply_all_union_paths(config)
    for path, first_name in unique_paths.items():
        if not os.path.exists(path):
            raise PolicyRefused(f"{first_name}: target missing at {path}")
        expected = _apply_all_expected_prehash(config, path)
        if expected is None:
            continue
        actual = sha256_text(_read_text(path))
        if actual != expected:
            raise PrehashMismatch(
                f"{first_name}: prehash mismatch (expected {expected}, found {actual}); refusing"
            )

    for name in ("canonical", "golden"):
        existing = _canonical_state(surfaces[name]["path"], key)
        if existing is not None:
            refuse_if_enabling_object(config, existing)

    ops = config.get("launchd_ops") or _default_launchd_ops()
    was_loaded = ops["is_loaded"]()
    if was_loaded:
        # Fail-closed: a bootout failure means zero backups and zero writes.
        ops["bootout"]()

    names_by_path = {p: n for n, p in unique_paths.items()}
    backup_dir = config["backup_dir"]
    try:
        txn_dir, backups = _backup_set(names_by_path, backup_dir, "applyAll")
    except Exception as exc:
        _recover_apply_all_service_only(config, was_loaded, ops, exc)

    try:
        _write_canonical_or_golden(config, "canonical")
        _write_canonical_or_golden(config, "golden")
        _write_verifier_patch(config)
        for target in config["projection"]["targets"].values():
            writer = _WRITERS[target["kind"]]
            writer(config, target)
        _update_manifest_all(config)
        _run_verifier_readonly(config)
        if was_loaded:
            plist_path = config["projection"]["targets"]["launch_agent_plist"]["path"]
            ops["bootstrap"](plist_path)
    except Exception as exc:
        _recover_apply_all_failure(config, names_by_path, backups, was_loaded, ops, exc)

    return {
        "status": "GREEN",
        "detail": "broker and projection waves integrated atomically from one snapshot",
        "changed": True,
        "backup_dir": txn_dir,
        "service_was_loaded": was_loaded,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="install the POLICY-54 disabled posture across the four core surfaces",
    )
    mode.add_argument(
        "--apply-projection",
        action="store_true",
        help="install the independent projection wave (provider-lock docs, managed-fields, live files, LaunchAgent)",
    )
    mode.add_argument(
        "--apply-all",
        action="store_true",
        help="atomically apply both the POLICY-54 core wave and the projection wave from one snapshot",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)

    try:
        if args.apply:
            result = apply(config)
        elif args.apply_projection:
            result = apply_projection(config)
        elif args.apply_all:
            result = apply_all(config)
        else:
            result = {"broker": check(config), "projection": check_projection(config)}
    except (PolicyRefused, VerifierFailed, LaunchdOpFailed, ApplyAllRollbackFailure) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    if "status" in result:
        return 0 if result["status"] == "GREEN" else 1
    return 0 if result["broker"]["status"] == "GREEN" and result["projection"]["status"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
