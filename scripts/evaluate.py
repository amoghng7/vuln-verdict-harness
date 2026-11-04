#!/usr/bin/env python3
"""Evaluate the harness on private labelled dev and real-world data; outputs go to --out.

The dev set influenced model and probability-band selection. The real set is not independent:
its round-1 failure categories informed targeted training-data design, even though it was excluded
from direct model/band selection scores. No private data is copied into this repository.

  python scripts/evaluate.py --data DATASET_DIR --real-repo PATH/TO/REPO \
      --real-sarif real.sarif --out eval_out [--max-audits 200] [--max-fixes 100] [--no-audit] [--no-fix]

Reports alerts per lane, lane accuracy, Muse audit agreement, classifier recalls and balanced
accuracy, always-TP baselines, and Semgrep clearance by rule on real-set true positives."""
import argparse, collections, json, math, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vuln_verdict import muse, pipeline, remediate
from vuln_verdict.sarif import Alert, load_alerts
from vuln_verdict.report import write_all

LABELS = {"true_positive", "false_positive"}


def _jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _prediction(row, n):
    idx = row["idx"]
    if isinstance(idx, bool) or (isinstance(idx, float) and not idx.is_integer()):
        raise ValueError("prediction idx must be an integer")
    try:
        idx = int(idx)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("prediction idx must be an integer") from None
    if not 0 <= idx < n:
        raise ValueError(f"prediction idx {idx} is outside 0..{n - 1}")
    value = row["p_true_renorm"]
    if isinstance(value, bool):
        raise ValueError("prediction probability must be numeric, not boolean")
    try:
        p = float(value)
    except (TypeError, ValueError):
        raise ValueError("prediction probability must be numeric") from None
    if not math.isfinite(p) or not 0.0 <= p <= 1.0:
        raise ValueError("prediction probability must be finite and in [0, 1]")
    return idx, p


def _label(value):
    if value not in LABELS:
        raise ValueError(f"invalid label: {value!r}")
    return value


def dev_alerts(data):
    rows = _jsonl(os.path.join(data, "dev", "dev.jsonl"))
    meta = _jsonl(os.path.join(data, "dev", "dev.meta.jsonl"))
    if len(rows) != len(meta):
        raise ValueError(f"dev row/metadata length mismatch: {len(rows)} != {len(meta)}")
    preds = _jsonl(os.path.join(data, "round2", "results", "r2_s7", "preds_dev_adapter.jsonl"))
    alerts, probs, labels = [], {}, {}
    for i, (r, m) in enumerate(zip(rows, meta)):
        u = r["messages"][1]["content"]
        get = lambda k: (re.search(rf"^{k}: (.*)$", u, re.M) or [None, ""])[1]
        sev = re.match(r"(\w+) \(rule confidence: (.*)\)", get("Severity"))
        a = Alert(id=f"dev.{i}", run_index=0, result_index=i, rule_id=m["check_id"], rule_short=m["rule"],
                  message=get("Message"), level="", severity=sev.group(1), confidence=sev.group(2), cwe=m["cwe"],
                  file=f"{m['repo']}/{m['file']}", line=m["line"], end_line=m["end_line"], tool="Semgrep",
                  tool_version=get("Tool").split()[-1], code=u.split("```java\n", 1)[1].rsplit("\n```", 1)[0],
                  snippet_truncated="partly elided" in u, snippet_windowed=m.get("snippet_windowed", False))
        alerts.append(a)
        labels[a.id] = _label(m["label"])
    for row in preds:
        idx, p = _prediction(row, len(alerts))
        aid = alerts[idx].id
        if aid in probs:
            raise ValueError(f"duplicate prediction for dev alert {aid}")
        probs[aid] = p
    return alerts, probs, labels


def real_alerts(data, repo, sarif_path):
    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)
    alerts = load_alerts(sarif, repo, scrub=True)
    meta = _jsonl(os.path.join(data, "real", "real.meta.jsonl"))
    preds = _jsonl(os.path.join(data, "round2", "results", "r2_s7", "preds_real_adapter.jsonl"))
    locations = {}
    for a in alerts:
        locations.setdefault((a.file, a.line, a.rule_id), []).append(a.id)
    by_meta = []
    probs, labels = {}, {}
    for i, m in enumerate(meta):
        key = (m["file"], m["line"], m["check_id"])
        matches = locations.get(key, [])
        if len(matches) != 1:
            raise ValueError(f"real metadata row {i} has {len(matches)} matching alerts; expected exactly one")
        aid = matches[0]
        if aid in labels:
            raise ValueError(f"duplicate real metadata assignment for alert {aid}")
        labels[aid] = _label(m["label"])
        by_meta.append(aid)
    if len(labels) != len(alerts):
        raise ValueError(f"real labels cover {len(labels)} of {len(alerts)} alerts")
    for row in preds:
        idx, p = _prediction(row, len(meta))
        aid = by_meta[idx]
        if aid in probs:
            raise ValueError(f"duplicate prediction for real alert {aid}")
        probs[aid] = p
    return sarif, alerts, probs, labels


def _rate(numerator, denominator):
    return round(numerator / denominator, 3) if denominator else None


def metrics(alerts, state, labels):
    L = collections.defaultdict(collections.Counter)
    for a in alerts:
        L[state[a.id]["lane"]][labels.get(a.id, "unlabelled")] += 1
    n1, n3 = sum(L["confident_tp"].values()), sum(L["likely_fp"].values())
    c1, c3 = L["confident_tp"]["true_positive"], L["likely_fp"]["false_positive"]
    labelled = [a for a in alerts if labels.get(a.id) in LABELS]
    tps = [a for a in labelled if labels[a.id] == "true_positive"]
    fps = [a for a in labelled if labels[a.id] == "false_positive"]
    predicted = lambda a: state[a.id].get("classifier_verdict")
    argmax_err = [a for a in labelled if predicted(a) != labels[a.id]]
    tp_recall_value = sum(predicted(a) == "true_positive" for a in tps) / len(tps) if tps else None
    fp_recall_value = sum(predicted(a) == "false_positive" for a in fps) / len(fps) if fps else None
    tp_recall = round(tp_recall_value, 3) if tp_recall_value is not None else None
    fp_recall = round(fp_recall_value, 3) if fp_recall_value is not None else None
    recalls = [x for x in (tp_recall_value, fp_recall_value) if x is not None]
    baseline_recalls = [x for x in (1.0 if tps else None, 0.0 if fps else None) if x is not None]
    out = {"n": len(alerts), "lanes": {k: dict(v) for k, v in L.items()},
           "lane1_precision_TP": _rate(c1, n1),
           "lane3_precision_FP": _rate(c3, n3),
           "auto_lanes_accuracy": _rate(c1 + c3, n1 + n3),
           "coverage_auto": _rate(n1 + n3, len(alerts)),
           "classifier_argmax_accuracy": _rate(len(labelled) - len(argmax_err), len(labelled)),
           "classifier_argmax_TP_recall": tp_recall,
           "classifier_argmax_FP_recall": fp_recall,
           "classifier_argmax_balanced_accuracy": round(sum(recalls) / len(recalls), 3) if recalls else None,
           "always_TP_baseline_accuracy": _rate(len(tps), len(labelled)),
           "always_TP_baseline_balanced_accuracy": round(sum(baseline_recalls) / len(baseline_recalls), 3) if baseline_recalls else None,
           "argmax_errors_routed_to_review": f"{sum(state[a.id]['lane'] == 'needs_review' for a in argmax_err)}/{len(argmax_err)}",
           "real_bugs_in_likely_fp_lane": L["likely_fp"]["true_positive"]}
    au = [a for a in labelled if (state[a.id].get("audit") or {}).get("verdict")]
    if au:
        def acc(xs):
            return f"{sum(state[a.id]['audit']['verdict'] == labels[a.id] for a in xs)}/{len(xs)}" if xs else "0/0"
        out["audit"] = {
            "audited": len(au), "errors": sum(1 for a in labelled if (state[a.id].get("audit") or {}).get("error")),
            "agrees_with_label": acc(au),
            "agrees_with_label_by_lane": {k: acc([a for a in au if state[a.id]["lane"] == k]) for k in ("confident_tp", "needs_review", "likely_fp")},
            "on_label_TP": acc([a for a in au if labels[a.id] == "true_positive"]),
            "on_label_FP": acc([a for a in au if labels[a.id] == "false_positive"]),
            "classifier_argmax_on_same_alerts": f"{sum(predicted(a) == labels[a.id] for a in au)}/{len(au)}",
            "audit_agrees_with_classifier": f"{sum(state[a.id]['audit']['verdict'] == predicted(a) for a in au)}/{len(au)}",
            "needs_review_resolved_correctly_by_audit": acc([a for a in au if state[a.id]["lane"] == "needs_review"]),
            "likely_fp_lane_real_bugs_flagged_by_audit": f"{sum(1 for a in au if state[a.id]['lane'] == 'likely_fp' and labels[a.id] == 'true_positive' and state[a.id]['audit']['verdict'] == 'true_positive')}/{sum(1 for a in au if state[a.id]['lane'] == 'likely_fp' and labels[a.id] == 'true_positive')}",
        }
    fx = [a for a in alerts if state[a.id].get("fix")]
    if fx:
        by = collections.defaultdict(collections.Counter)
        for a in fx:
            by[a.rule_short][state[a.id]["fix"]["status"]] += 1
            by["_category_" + (remediate.category(a) or "none")][state[a.id]["fix"]["status"]] += 1
        tot = collections.Counter(state[a.id]["fix"]["status"] for a in fx)
        out["fix"] = {"attempted_on": len(fx), "status": dict(tot),
                      "semgrep_cleared_rate": _rate(tot["fix verified"], len(fx)),
                      "verification_level": "semgrep_only",
                      "by_rule": {k: dict(v) for k, v in sorted(by.items())},
                      "unverified_reasons": dict(collections.Counter(state[a.id]["fix"].get("reason", "")[:80] for a in fx if state[a.id]["fix"]["status"] != "fix verified"))}
    return out


def _non_negative(value):
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if n < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True); ap.add_argument("--real-repo", required=True)
    ap.add_argument("--real-sarif", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--max-audits", type=_non_negative, default=200); ap.add_argument("--max-fixes", type=_non_negative, default=100)
    ap.add_argument("--no-audit", action="store_true"); ap.add_argument("--no-fix", action="store_true")
    ap.add_argument("--sets", default="dev,real")
    ap.add_argument("--semgrep-bin", default=os.environ.get("SEMGREP_BIN", "semgrep"))
    a = ap.parse_args()
    sets = {x.strip() for x in a.sets.split(",") if x.strip()}
    if not sets or not sets <= {"dev", "real"}:
        ap.error("--sets must contain only dev and/or real")
    res = {}
    s0 = muse.spent() if os.environ.get("MODEL_API_KEY") else None
    if "dev" in sets:
        od = os.path.join(a.out, "dev"); os.makedirs(od, exist_ok=True)
        alerts, probs, labels = dev_alerts(a.data)
        st = pipeline.assign_lanes(alerts, probs)
        if not a.no_audit:
            pipeline.run_audits(alerts, st, od, a.max_audits)
        pipeline.merge_cached_state(alerts, st, od)
        res["dev"] = metrics(alerts, st, labels)
        with open(os.path.join(od, "state.jsonl"), "w", encoding="utf-8") as f:
            for x in alerts:
                f.write(json.dumps({"id": x.id, "label": labels[x.id], **st[x.id]}) + "\n")
    if "real" in sets:
        od = os.path.join(a.out, "real"); os.makedirs(od, exist_ok=True)
        sarif, alerts, probs, labels = real_alerts(a.data, a.real_repo, a.real_sarif)
        st = pipeline.assign_lanes(alerts, probs)
        if not a.no_audit:
            pipeline.run_audits(alerts, st, od, a.max_audits)
        if not a.no_fix:
            tps = {x.id for x in alerts if labels.get(x.id) == "true_positive" and remediate.category(x)}
            pipeline.run_remediation(alerts, st, a.real_repo, od, lanes=("confident_tp", "needs_review", "likely_fp"),
                                     max_fixes=a.max_fixes, require_audit_agree=False, semgrep_bin=a.semgrep_bin, only=tps)
        pipeline.merge_cached_state(alerts, st, od)
        res["real"] = metrics(alerts, st, labels)
        write_all(od, sarif, alerts, st, "real-world set (evaluation)", {"note": "evaluation run; remediation on labelled TPs"})
    if s0 is not None:
        res["muse_spend_this_run_usd"] = round(muse.spent() - s0, 4); res["spend_log_total_usd"] = muse.spent()
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
