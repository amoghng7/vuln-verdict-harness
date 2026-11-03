"""Classifier backends: precomputed probabilities (--probs-file) or a batch run on Modal."""
import json, math, os, subprocess, sys, warnings

from .sarif import classifier_row

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _probability(row, line_no):
    value = row.get("p_true", row.get("p_true_renorm"))
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"probabilities line {line_no}: p_true must be numeric, not boolean")
    try:
        p = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"probabilities line {line_no}: invalid probability {value!r}") from None
    if not math.isfinite(p) or not 0.0 <= p <= 1.0:
        raise ValueError(f"probabilities line {line_no}: p_true must be finite and in [0, 1], got {p!r}")
    return p


def load_probs(path, alerts):
    """Load validated probabilities without silently misassigning alerts.

    Accepted rows: alert_id+p_true, file/line/rule_id+p_true, or idx+p_true_renorm.
    Missing alerts remain unclassified. Malformed probabilities, duplicate assignments and
    ambiguous location keys raise a clear error; unmatched rows emit a warning.
    """
    by_id = {a.id: a for a in alerts}
    by_loc = {}
    for a in alerts:
        by_loc.setdefault((a.file, a.line, a.rule_id), []).append(a.id)
    out = {}
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"probabilities line {line_no}: invalid JSON: {e.msg}") from None
            if not isinstance(row, dict):
                raise ValueError(f"probabilities line {line_no}: expected a JSON object")
            p = _probability(row, line_no)
            if p is None:
                continue
            aid = None
            if row.get("alert_id") in by_id:
                aid = row["alert_id"]
            elif "file" in row:
                key = (row["file"], row.get("line"), row.get("rule_id") or row.get("check_id"))
                matches = by_loc.get(key, [])
                if len(matches) > 1:
                    raise ValueError(f"probabilities line {line_no}: location is ambiguous across {matches}; use alert_id")
                if matches:
                    aid = matches[0]
            elif "idx" in row:
                raw_idx = row["idx"]
                if isinstance(raw_idx, bool) or (isinstance(raw_idx, float) and not raw_idx.is_integer()):
                    raise ValueError(f"probabilities line {line_no}: idx must be an integer")
                try:
                    idx = int(raw_idx)
                except (TypeError, ValueError, OverflowError):
                    raise ValueError(f"probabilities line {line_no}: idx must be an integer") from None
                if not 0 <= idx < len(alerts):
                    raise ValueError(f"probabilities line {line_no}: idx {idx} is outside 0..{len(alerts) - 1}")
                aid = alerts[idx].id
            if aid is None:
                warnings.warn(f"probabilities line {line_no} did not match any alert; row ignored", RuntimeWarning)
                continue
            if aid in out:
                raise ValueError(f"probabilities line {line_no}: duplicate assignment for alert {aid}")
            out[aid] = p
    return out


def run_modal(alerts, workdir, adapter="r2_s7", modal_bin="modal"):
    """Runs modal_app/classifier_modal.py as an ephemeral Modal app (stopped when the call returns)."""
    todo = [a for a in alerts if not a.error]
    inp = os.path.join(workdir, "classifier_input.jsonl")
    outp = os.path.join(workdir, "classifier_probs.jsonl")
    with open(inp, "w", encoding="utf-8") as f:
        for a in todo:
            row = classifier_row(a)
            row["alert_id"] = a.id
            f.write(json.dumps(row) + "\n")
    cmd = [modal_bin, "run", os.path.join(HERE, "modal_app", "classifier_modal.py"),
           "--input", inp, "--out", outp, "--adapter", adapter]
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, check=True)
    return load_probs(outp, alerts), outp
