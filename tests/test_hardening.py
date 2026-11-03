"""Adversarial offline regression tests for reviewed hardening behavior."""
import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from vuln_verdict import cli, lanes, muse, pipeline, remediate
from vuln_verdict.classifier import load_probs
from vuln_verdict.report import annotate_sarif, write_all
from vuln_verdict.sarif import _uri_to_rel, load_alerts

TINY = os.path.join(ROOT, "examples", "tiny")
SARIF = os.path.join(TINY, "semgrep.sarif")


def tiny():
    with open(SARIF, encoding="utf-8") as f:
        sarif = json.load(f)
    return sarif, load_alerts(sarif, TINY)


def test_absolute_and_file_uri_paths_inside_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "Inside.java"
    source.write_text("class Inside {}\n", encoding="utf-8")
    assert _uri_to_rel(str(source), repo) == "Inside.java"
    assert _uri_to_rel(source.as_uri(), repo) == "Inside.java"


@pytest.mark.parametrize("uri", ["../Outside.java", "%2e%2e/Outside.java", "https://example.com/Outside.java", "bad%00.java"])
def test_unsafe_source_paths_rejected(uri, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError):
        _uri_to_rel(uri, repo)


def test_absolute_and_symlink_source_escapes_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Outside.java").write_text("class Outside {}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        _uri_to_rel(str(outside / "Outside.java"), repo)
    (repo / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        _uri_to_rel("link/Outside.java", repo)


def test_alerts_remain_visible_when_source_context_fails(tmp_path):
    sarif, _ = tiny()
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "../Outside.java"
    alerts = load_alerts(sarif, TINY)
    assert len(alerts) == 6 and alerts[0].error
    state = pipeline.assign_lanes(alerts, {})
    write_all(str(tmp_path), sarif, alerts, state, "unsafe path")
    with open(tmp_path / "annotated.sarif", encoding="utf-8") as f:
        annotated = json.load(f)
    results = [r for run in annotated["runs"] for r in run["results"]]
    assert len(results) == 6
    assert results[0]["properties"]["vulnVerdict"]["contextError"]
    assert all(r["properties"]["vulnVerdict"]["neverSuppressed"] for r in results)
    assert not any("suppressions" in r for r in results)
    assert "context error:" in (tmp_path / "report.md").read_text(encoding="utf-8")


def test_sandbox_writes_reject_absolute_and_parent_paths_before_writing(tmp_path):
    root = tmp_path / "sandbox"
    root.mkdir()
    canary = tmp_path / "canary"
    for path in (str(canary), "../canary"):
        with pytest.raises(ValueError, match="unsafe path"):
            remediate._safe_join(root, path)
    assert not canary.exists()


def test_sandbox_write_rejects_symlink_escape_before_writing(tmp_path):
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe path"):
        remediate._safe_join(root, "link", "canary")
    assert not (outside / "canary").exists()


def test_no_model_invocation_for_unsafe_source_path(tmp_path, monkeypatch):
    sarif, _ = tiny()
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "../Outside.java"
    alerts = load_alerts(sarif, TINY)
    state = pipeline.assign_lanes(alerts, {a.id: 0.5 for a in alerts})
    calls = []
    monkeypatch.setattr(pipeline.audit_mod, "audit", lambda a, p, e="low": calls.append(a.id) or {"verdict": "true_positive"})
    monkeypatch.setattr(pipeline.audit_mod, "confirm_fp", lambda a, p, e="low": calls.append(a.id) or {"verdict": "false_positive"})
    pipeline.run_audits(alerts, state, str(tmp_path), workers=1)
    assert "r0.0" not in calls
    assert "context unavailable" in state["r0.0"]["audit_skip"]


def test_nonzero_semgrep_status_rejected_with_valid_json(monkeypatch, tmp_path):
    completed = SimpleNamespace(returncode=2, stdout=json.dumps({"results": [], "errors": []}), stderr="")
    monkeypatch.setattr(remediate.subprocess, "run", lambda *a, **kw: completed)
    with pytest.raises(RuntimeError, match="exit 2"):
        remediate.semgrep_scan(str(tmp_path), "p/java", "semgrep")


def remediation_run(tmp_path, monkeypatch, patched_results):
    _, alerts = tiny()
    alert = alerts[0]
    source = Path(TINY) / alert.file
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(remediate, "propose", lambda *a, **kw: {"summary": "sandbox change", "caveats": "none"})
    monkeypatch.setattr(remediate, "apply_edits", lambda old, *a: (old + "\n// sandbox only\n", []))

    def scan(root, config, semgrep_bin):
        if Path(root).name == "sandbox_baseline":
            return {alert.file: [(alert.rule_id, alert.line)]}, {}
        return patched_results(alert), {}

    monkeypatch.setattr(remediate, "semgrep_scan", scan)
    records = remediate.remediate_batch([(alert, None)], TINY, str(tmp_path), log=lambda *a: None)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    return alerts, alert, records


def test_new_alert_of_other_rule_blocks_clearance_and_preserves_source(tmp_path, monkeypatch):
    _, alert, records = remediation_run(tmp_path, monkeypatch, lambda a: {os.path.join(a.id, a.file): [("other.rule", 1)]})
    record = records[alert.id]
    assert record["status"] == "fix suggested, unverified"
    assert "other rule" in record["reason"]
    assert record["recheck"]["new_other_rules"] == ["rule"]


def test_successful_remediation_disclosure_and_source_integrity(tmp_path, monkeypatch):
    sarif, _ = tiny()
    alerts, alert, records = remediation_run(tmp_path / "remediation", monkeypatch, lambda a: {})
    assert records[alert.id]["status"] == "fix verified"
    assert records[alert.id]["reason"] == "Semgrep-cleared; not compiled or tested."
    state = pipeline.assign_lanes(alerts, {})
    state[alert.id]["fix"] = records[alert.id]
    write_all(str(tmp_path / "reports"), sarif, alerts, state, "disclosure")
    assert "Semgrep-cleared; not compiled or tested." in (tmp_path / "reports" / "report.md").read_text(encoding="utf-8")
    assert "Semgrep-cleared; not compiled or tested." in (tmp_path / "reports" / "report.html").read_text(encoding="utf-8")
    annotated = annotate_sarif(sarif, alerts, state)
    display = annotated["runs"][0]["results"][0]["properties"]["vulnVerdict"]["fix"]["displayStatus"]
    assert display == "Semgrep-cleared; not compiled or tested."


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, "not-a-number", -0.01, 1.01])
def test_invalid_probabilities_rejected(value, tmp_path):
    _, alerts = tiny()
    path = tmp_path / "probs.jsonl"
    path.write_text(json.dumps({"alert_id": "r0.0", "p_true": value}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_probs(str(path), alerts)


def test_duplicate_probability_assignment_rejected(tmp_path):
    _, alerts = tiny()
    path = tmp_path / "probs.jsonl"
    rows = [{"alert_id": "r0.0", "p_true": 0.8}, {"idx": 0, "p_true_renorm": 0.7}]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate assignment"):
        load_probs(str(path), alerts)


def test_ambiguous_probability_location_rejected(tmp_path):
    _, alerts = tiny()
    duplicate = copy.deepcopy(alerts[0])
    duplicate.id = "duplicate"
    path = tmp_path / "probs.jsonl"
    path.write_text(json.dumps({"file": alerts[0].file, "line": alerts[0].line, "rule_id": alerts[0].rule_id, "p_true": 0.5}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ambiguous"):
        load_probs(str(path), alerts + [duplicate])


@pytest.mark.parametrize("idx", [1.5, -1, 6])
def test_invalid_classifier_indices_rejected(idx, tmp_path):
    _, alerts = tiny()
    path = tmp_path / "probs.jsonl"
    path.write_text(json.dumps({"idx": idx, "p_true_renorm": 0.5}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_probs(str(path), alerts)


@pytest.mark.parametrize("lo,hi", [(float("nan"), 0.98), (0.44, float("inf")), (-0.1, 0.98), (0.5, 0.4), (0.0, 1.1), (True, 0.98)])
def test_invalid_lane_thresholds_rejected(lo, hi):
    with pytest.raises(ValueError):
        lanes.validate_band(lo, hi)


@pytest.mark.parametrize("flag", ["--max-audits", "--max-fixes"])
def test_negative_cli_caps_rejected(flag):
    args = ["triage", SARIF, "--repo", TINY, "--out", "unused", "--probs-file", os.path.join(TINY, "probs_r2_s7.jsonl"), flag, "-1"]
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2


def test_cache_rejects_legacy_rows_and_content_fingerprint_mismatch(tmp_path):
    _, alerts = tiny()
    path = tmp_path / "audits.jsonl"
    rows = [{"alert_id": "r0.0", "data": {"verdict": "true_positive"}},
            {"alert_id": "r0.0", "alert_fingerprint": "wrong", "data": {"verdict": "false_positive"}}]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    assert pipeline._cache(str(path), alerts) == {}
    pipeline._append(str(path), alerts[0], {"verdict": "true_positive"})
    assert pipeline._cache(str(path), alerts) == {"r0.0": {"verdict": "true_positive"}}
    changed = copy.deepcopy(alerts)
    changed[0].message += " changed"
    assert pipeline._cache(str(path), changed) == {}


def test_spend_reservation_and_release_survive_reload(tmp_path, monkeypatch):
    spend = tmp_path / "spend.json"
    monkeypatch.setenv("VV_SPEND_FILE", str(spend))
    monkeypatch.setenv("VV_BUDGET_USD", "1.5")
    monkeypatch.setattr(muse, "_reserved", 0.0)
    muse._reserve(1.0)
    assert json.loads(spend.read_text(encoding="utf-8"))["reserved_usd"] == 1.0
    monkeypatch.setattr(muse, "_reserved", 0.0)
    with pytest.raises(muse.BudgetExceeded):
        muse._reserve(0.6)
    muse._release(1.0)
    assert json.loads(spend.read_text(encoding="utf-8"))["reserved_usd"] == 0.0
    muse._reserve(0.6)
    muse._release(0.6)
    assert json.loads(spend.read_text(encoding="utf-8"))["reserved_usd"] == 0.0


@pytest.mark.parametrize("value", ["-1", "nan", "inf"])
def test_invalid_budgets_rejected(value, monkeypatch):
    monkeypatch.setenv("VV_BUDGET_USD", value)
    with pytest.raises(ValueError):
        muse.budget()


def test_reasoning_tokens_are_subset_of_output_tokens(tmp_path, monkeypatch):
    spend = tmp_path / "spend.json"
    monkeypatch.setenv("VV_SPEND_FILE", str(spend))
    muse._record("test", {"prompt_tokens": 10, "completion_tokens": 100,
                          "completion_tokens_details": {"reasoning_tokens": 80}})
    data = json.loads(spend.read_text(encoding="utf-8"))
    assert data["output_tokens"] == 100
    assert data["reasoning_tokens"] == 80
    assert data["total_usd"] == round(10 * muse.PRICE_IN + 100 * muse.PRICE_OUT, 6)


def test_result_retention_across_multiple_sarif_runs():
    sarif, _ = tiny()
    second = copy.deepcopy(sarif["runs"][0])
    sarif["runs"].append(second)
    alerts = load_alerts(sarif, TINY)
    state = pipeline.assign_lanes(alerts, {})
    annotated = annotate_sarif(sarif, alerts, state)
    assert [len(run["results"]) for run in annotated["runs"]] == [6, 6]
    results = [r for run in annotated["runs"] for r in run["results"]]
    assert len(results) == 12
    assert all(r["properties"]["vulnVerdict"]["neverSuppressed"] for r in results)
    assert not any("suppressions" in r for r in results)
