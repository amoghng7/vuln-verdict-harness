"""Lane assignment with validated probabilities.

The harness NEVER silently drops, suppresses or hides an alert. Invalid scores fail closed with a
clear error instead of accidentally becoming a likely-false-positive decision.
"""
import math

LO, HI = 0.44, 0.98   # needs_review band for adapter r2_s7, chosen on dev + OWASP val only

LANES = {
    "confident_tp": {"rank": 1, "title": "confident true positive", "action": "audit + remediate"},
    "needs_review": {"rank": 2, "title": "needs review", "action": "audit (explain), flag for human"},
    "likely_fp": {"rank": 3, "title": "likely false positive, confirm", "action": "short explanation; human confirms - never auto-suppressed"},
    "unclassified": {"rank": 2, "title": "unclassified (no classifier score)", "action": "treat as needs review"},
}


def validate_band(lo=LO, hi=HI):
    if isinstance(lo, bool) or isinstance(hi, bool) or not all(isinstance(x, (int, float)) for x in (lo, hi)):
        raise ValueError("lane thresholds must be numbers")
    if not math.isfinite(lo) or not math.isfinite(hi) or not 0.0 <= lo <= hi <= 1.0:
        raise ValueError(f"lane thresholds must satisfy 0 <= lo <= hi <= 1; got [{lo}, {hi}]")


def lane_for(p_true, lo=LO, hi=HI):
    validate_band(lo, hi)
    if p_true is None:
        return "unclassified"
    if isinstance(p_true, bool) or not isinstance(p_true, (int, float)) or not math.isfinite(p_true) or not 0.0 <= p_true <= 1.0:
        raise ValueError(f"p_true must be a finite number in [0, 1]; got {p_true!r}")
    if p_true >= hi:
        return "confident_tp"
    if p_true >= lo:
        return "needs_review"
    return "likely_fp"
