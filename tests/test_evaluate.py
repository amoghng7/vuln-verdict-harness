"""Offline evaluation metric and input-validation tests."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from scripts import evaluate
from vuln_verdict.pipeline import assign_lanes
from vuln_verdict.sarif import load_alerts

TINY = os.path.join(ROOT, "examples", "tiny")


def tiny_alerts():
    with open(os.path.join(TINY, "semgrep.sarif"), encoding="utf-8") as f:
        return load_alerts(json.load(f), TINY)


def test_argmax_recalls_and_always_tp_baselines():
    alerts = tiny_alerts()
    labels = {a.id: ("true_positive" if i < 4 else "false_positive") for i, a in enumerate(alerts)}
    probs = {"r0.0": 0.9, "r0.1": 0.2, "r0.3": 0.8, "r0.4": 0.1, "r0.5": 0.9}
    state = assign_lanes(alerts, probs)
    out = evaluate.metrics(alerts, state, labels)
    assert out["classifier_argmax_accuracy"] == 0.5
    assert out["classifier_argmax_TP_recall"] == 0.5
    assert out["classifier_argmax_FP_recall"] == 0.5
    assert out["classifier_argmax_balanced_accuracy"] == 0.5
    assert out["always_TP_baseline_accuracy"] == 0.667
    assert out["always_TP_baseline_balanced_accuracy"] == 0.5


def test_missing_prediction_is_an_argmax_error():
    alerts = tiny_alerts()[:1]
    state = assign_lanes(alerts, {})
    out = evaluate.metrics(alerts, state, {alerts[0].id: "true_positive"})
    assert out["classifier_argmax_accuracy"] == 0.0
    assert out["classifier_argmax_TP_recall"] == 0.0
    assert out["classifier_argmax_balanced_accuracy"] == 0.0
    assert out["always_TP_baseline_accuracy"] == 1.0
    assert out["always_TP_baseline_balanced_accuracy"] == 1.0


def test_semgrep_clearance_metric_and_disclosure():
    alerts = tiny_alerts()[:2]
    state = assign_lanes(alerts, {})
    state[alerts[0].id]["fix"] = {"status": "fix verified"}
    state[alerts[1].id]["fix"] = {"status": "fix suggested, unverified", "reason": "still reported"}
    labels = {a.id: "true_positive" for a in alerts}
    out = evaluate.metrics(alerts, state, labels)["fix"]
    assert out["semgrep_cleared_rate"] == 0.5
    assert out["verification_level"] == "semgrep_only"
    assert "verified_rate" not in out


def test_dev_row_metadata_length_mismatch(tmp_path):
    dev = tmp_path / "dev"
    dev.mkdir()
    (dev / "dev.jsonl").write_text("{}\n", encoding="utf-8")
    (dev / "dev.meta.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="length mismatch"):
        evaluate.dev_alerts(str(tmp_path))


@pytest.mark.parametrize("value", ["-1", "-100"])
def test_negative_evaluation_caps_rejected(value):
    with pytest.raises(evaluate.argparse.ArgumentTypeError, match="non-negative"):
        evaluate._non_negative(value)


def test_evaluation_selection_and_leakage_disclosures():
    assert "dev set influenced model and probability-band selection" in evaluate.__doc__
    assert "real set is not independent" in evaluate.__doc__
    assert "targeted training-data design" in evaluate.__doc__
