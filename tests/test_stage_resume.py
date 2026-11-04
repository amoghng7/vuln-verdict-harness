"""Separate CLI invocations must keep fingerprint-valid audit and fix state. Offline."""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from vuln_verdict import cli, pipeline
from vuln_verdict.classifier import load_probs
from vuln_verdict.pipeline import assign_lanes
from vuln_verdict.sarif import load_alerts

TINY = os.path.join(ROOT, "examples", "tiny")
SARIF = os.path.join(TINY, "semgrep.sarif")
PROBS = os.path.join(TINY, "probs_r2_s7.jsonl")
AUDIT = "AUDIT_MARKER_ALPHA"
FIX = "FIX_MARKER_BETA"


def _patch(monkeypatch):
    monkeypatch.setattr(pipeline.audit_mod, "audit",
                        lambda a, p, e="low": {"verdict": "true_positive", "explanation": AUDIT,
                                               "attack_path": "none", "severity": "high"})
    monkeypatch.setattr(pipeline.audit_mod, "confirm_fp",
                        lambda a, p, e="low": {"verdict": "false_positive", "why_safe": AUDIT,
                                               "check": "review", "explanation": AUDIT})

    def batch(items, repo, outdir, semgrep_bin="semgrep", config="p/java", effort="low", log=print):
        return {a.id: {"status": "fix verified", "reason": "Semgrep-cleared; not compiled or tested.",
                       "verification_level": "semgrep", "summary": FIX, "caveats": "none",
                       "patch_path": f"{a.id}.patch"}
                for a, _audit in items}
    monkeypatch.setattr(pipeline.remediate, "remediate_batch", batch)


def _triage(tmp_path, out, extra, repo=TINY, sarif=SARIF):
    dummy = tmp_path / "semgrep"
    dummy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.main(["triage", sarif, "--repo", repo, "--out", str(out), "--probs-file", PROBS,
              "--semgrep-bin", str(dummy), *extra])


def _blobs(out):
    sarif = json.loads((out / "annotated.sarif").read_text(encoding="utf-8"))
    results = [r for run in sarif["runs"] for r in run["results"]]
    return {
        "md": (out / "report.md").read_text(encoding="utf-8"),
        "html": (out / "report.html").read_text(encoding="utf-8"),
        "state": (out / "state.jsonl").read_text(encoding="utf-8"),
        "sarif": sarif,
        "results": results,
    }


def _assert_both(out):
    got = _blobs(out)
    for name in ("md", "html", "state"):
        assert AUDIT in got[name] and FIX in got[name]
    verdict = got["results"][0]["properties"]["vulnVerdict"]
    assert verdict["audit"]["explanation"] == AUDIT
    assert verdict["fix"]["summary"] == FIX
    assert verdict["neverSuppressed"] is True
    assert "suppressions" not in got["results"][0]
    return got


def test_remediation_invocation_keeps_earlier_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("VV_SPEND_FILE", str(tmp_path / "spend.json"))
    monkeypatch.setenv("MODEL_API_KEY", "")
    _patch(monkeypatch)
    out = tmp_path / "out"
    _triage(tmp_path, out, ["--audit"])
    assert AUDIT in (out / "report.md").read_text(encoding="utf-8")
    assert FIX not in (out / "state.jsonl").read_text(encoding="utf-8")
    audit_rows = (out / "audits.jsonl").read_text(encoding="utf-8")
    _triage(tmp_path, out, ["--remediate"])
    _assert_both(out)
    assert audit_rows == (out / "audits.jsonl").read_text(encoding="utf-8")


def test_audit_invocation_keeps_earlier_remediation(tmp_path, monkeypatch):
    monkeypatch.setenv("VV_SPEND_FILE", str(tmp_path / "spend.json"))
    monkeypatch.setenv("MODEL_API_KEY", "")
    _patch(monkeypatch)
    out = tmp_path / "out"
    _triage(tmp_path, out, ["--remediate"])
    assert FIX in (out / "report.md").read_text(encoding="utf-8")
    assert AUDIT not in (out / "state.jsonl").read_text(encoding="utf-8")
    fix_rows = (out / "fixes.jsonl").read_text(encoding="utf-8")
    _triage(tmp_path, out, ["--audit"])
    _assert_both(out)
    assert fix_rows == (out / "fixes.jsonl").read_text(encoding="utf-8")


def test_changed_fingerprint_drops_stale_state(tmp_path, monkeypatch):
    monkeypatch.setenv("VV_SPEND_FILE", str(tmp_path / "spend.json"))
    monkeypatch.setenv("MODEL_API_KEY", "")
    _patch(monkeypatch)
    out = tmp_path / "out"
    _triage(tmp_path, out, ["--audit"])
    cached = (out / "audits.jsonl").read_text(encoding="utf-8")
    sarif = json.loads(open(SARIF, encoding="utf-8").read())
    sarif["runs"][0]["results"][0]["message"]["text"] += " CHANGED"
    changed = tmp_path / "changed.sarif"
    changed.write_text(json.dumps(sarif), encoding="utf-8")
    _triage(tmp_path, out, [], sarif=str(changed))
    assert (out / "audits.jsonl").read_text(encoding="utf-8") == cached
    rows = [json.loads(line) for line in (out / "state.jsonl").read_text(encoding="utf-8").splitlines()]
    by_id = {row["alert"]["id"]: row for row in rows}
    assert "audit" not in by_id["r0.0"]
    assert by_id["r0.1"]["audit"]["explanation"] == AUDIT
    annotated = json.loads((out / "annotated.sarif").read_text(encoding="utf-8"))
    results = [r for run in annotated["runs"] for r in run["results"]]
    assert len(results) == 6
    assert "audit" not in results[0]["properties"]["vulnVerdict"]
    assert results[1]["properties"]["vulnVerdict"]["audit"]["explanation"] == AUDIT
    assert all(r["properties"]["vulnVerdict"]["neverSuppressed"] is True for r in results)
    assert not any("suppressions" in r for r in results)


def test_two_sarif_runs_keep_every_result_across_invocations(tmp_path, monkeypatch):
    monkeypatch.setenv("VV_SPEND_FILE", str(tmp_path / "spend.json"))
    monkeypatch.setenv("MODEL_API_KEY", "")
    _patch(monkeypatch)
    sarif = json.loads(open(SARIF, encoding="utf-8").read())
    sarif["runs"].append(json.loads(json.dumps(sarif["runs"][0])))
    sarif_path = tmp_path / "two.sarif"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    out = tmp_path / "out"
    _triage(tmp_path, out, ["--audit"], sarif=str(sarif_path))
    _triage(tmp_path, out, ["--remediate"], sarif=str(sarif_path))
    got = _assert_both(out)
    assert [len(run["results"]) for run in got["sarif"]["runs"]] == [6, 6]
    assert len(got["results"]) == 12
    assert all(r["properties"]["vulnVerdict"]["neverSuppressed"] is True for r in got["results"])
    assert not any("suppressions" in r for r in got["results"])
    rows = [json.loads(line) for line in got["state"].splitlines()]
    by_id = {row["alert"]["id"]: row for row in rows}
    assert by_id["r0.0"]["audit"]["explanation"] == AUDIT
    assert by_id["r0.0"]["fix"]["summary"] == FIX
    assert by_id["r1.0"]["lane"] == "unclassified"
    assert by_id["r1.0"]["audit"]["explanation"] == AUDIT
    assert "fix" not in by_id["r1.0"]


def test_merge_cached_state_ignores_other_ids_and_keeps_fresh_values(tmp_path):
    alerts = load_alerts(json.loads(open(SARIF, encoding="utf-8").read()), TINY)
    state = assign_lanes(alerts, load_probs(PROBS, alerts))
    fp0 = pipeline._fingerprint(alerts[0])
    rows = [
        {"alert_id": "r9.9", "alert_fingerprint": fp0, "data": {"explanation": "FOREIGN"}},
        {"alert_id": "r0.0", "alert_fingerprint": "stale", "data": {"explanation": "STALE"}},
        {"alert_id": alerts[1].id, "alert_fingerprint": pipeline._fingerprint(alerts[1]),
         "data": {"explanation": "CACHED_AUDIT"}},
    ]
    (tmp_path / "audits.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    (tmp_path / "fixes.jsonl").write_text(json.dumps({
        "alert_id": alerts[1].id, "alert_fingerprint": pipeline._fingerprint(alerts[1]),
        "data": {"summary": "CACHED_FIX", "status": "fix verified"}}) + "\n", encoding="utf-8")
    state[alerts[1].id]["audit"] = {"explanation": "FRESH"}
    pipeline.merge_cached_state(alerts, state, str(tmp_path))
    assert "audit" not in state[alerts[0].id]
    assert state[alerts[1].id]["audit"]["explanation"] == "FRESH"
    assert state[alerts[1].id]["fix"]["summary"] == "CACHED_FIX"
    assert "FOREIGN" not in json.dumps(state)
    assert (tmp_path / "audits.jsonl").read_text(encoding="utf-8").count("FOREIGN") == 1
