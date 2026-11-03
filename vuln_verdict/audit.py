"""Muse Spark audit of one alert (lanes 1-2) and short 'why it looks safe' check (lane 3)."""
from . import muse

AUDIT_SCHEMA = ("audit", {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive"]},
        "explanation": {"type": "string"},
        "attack_path": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "none"]},
    },
    "required": ["verdict", "explanation", "attack_path", "severity"],
})
CONFIRM_SCHEMA = ("confirm", {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive"]},
        "why_safe": {"type": "string"},
        "check": {"type": "string"},
    },
    "required": ["verdict", "why_safe", "check"],
})

AUDIT_SYSTEM = (
    "You are a senior application-security reviewer. Judge ONE static-analysis finding in Java code using only "
    "the code shown (a fine-tuned classifier's opinion is given; you may disagree). Trace source to sink: can an "
    "attacker control the value, is any sanitising correct for this sink, is the flagged API use security-relevant? "
    "Return JSON: verdict (true_positive = real, exploitable weakness of this CWE; else false_positive), "
    "explanation (<=50 words, plain language), attack_path (<=35 words, or 'none'), severity.")
CONFIRM_SYSTEM = (
    "You are a senior application-security reviewer. A classifier thinks this static-analysis finding in Java "
    "code is a false positive. Check it using only the code shown. Return JSON: verdict (true_positive if it IS a "
    "real, exploitable weakness of this CWE, else false_positive), why_safe (<=40 words: why it looks safe, or why "
    "it is not), check (<=20 words: what a human should verify before dismissing it).")


def _finding(a, p_true):
    return (f"Rule: {a.rule_short}\nCWE: {a.cwe}\nSeverity: {a.severity}\nMessage: {a.message[:400]}\n"
            f"Flagged line: {a.line}\nClassifier p(true_positive) = {p_true:.2f}\n\n"
            f"Code (original line numbers, comments removed):\n```java\n{a.code}\n```")


def audit(a, p_true, effort="low"):
    out, cost = muse.chat_json([{"role": "system", "content": AUDIT_SYSTEM}, {"role": "user", "content": _finding(a, p_true)}],
                               tag="harness_audit", schema=AUDIT_SCHEMA, max_tokens=2500, reasoning_effort=effort)
    out["cost_usd"] = round(cost, 5)
    out["kind"] = "audit"
    return out


def confirm_fp(a, p_true, effort="low"):
    out, cost = muse.chat_json([{"role": "system", "content": CONFIRM_SYSTEM}, {"role": "user", "content": _finding(a, p_true)}],
                               tag="harness_confirm", schema=CONFIRM_SCHEMA, max_tokens=2000, reasoning_effort=effort)
    out["cost_usd"] = round(cost, 5)
    out["kind"] = "confirm_fp"
    out["explanation"] = out.get("why_safe", "")
    return out
