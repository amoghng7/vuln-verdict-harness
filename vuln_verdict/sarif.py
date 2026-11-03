"""SARIF 2.1.0 reading (Semgrep output) and alert extraction.

Artifact paths are treated as untrusted input: every readable source must resolve inside the
repository root. Invalid or escaping paths remain visible as alerts with a context error.
"""
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .snippet import format_code

SYSTEM_PROMPT = (
    "You are a security triage assistant. You are given one static-analysis alert and the relevant "
    "Java source code. Decide whether the alert is a real, exploitable vulnerability (true_positive) "
    "or a false alarm (false_positive). Respond with strict JSON only: "
    '{"verdict":"true_positive"} or {"verdict":"false_positive"}.'
)
LEVEL_TO_SEVERITY = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}
CWE_TAG = re.compile(r"^CWE-\d+")
CONF_TAG = re.compile(r"^(HIGH|MEDIUM|LOW) CONFIDENCE$")


@dataclass
class Alert:
    id: str
    run_index: int
    result_index: int
    rule_id: str
    rule_short: str
    message: str
    level: str
    severity: str
    confidence: str
    cwe: str
    file: str
    line: int
    end_line: int
    tool: str
    tool_version: str
    code: str = ""
    snippet_truncated: bool = False
    snippet_windowed: bool = False
    error: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def _rules_by_id(run):
    rules = {}
    drv = run.get("tool", {}).get("driver", {})
    for r in drv.get("rules", []) or []:
        rules[r.get("id")] = r
    for ext in run.get("tool", {}).get("extensions", []) or []:
        for r in ext.get("rules", []) or []:
            rules.setdefault(r.get("id"), r)
    return rules


def _uri_to_rel(uri, repo):
    """Return a canonical repo-relative POSIX path, rejecting paths outside the repo.

    Resolution also follows symlinks, so an in-repo symlink to an external file is rejected.
    The caller catches errors and retains the alert with ``error`` set.
    """
    if not uri:
        raise ValueError("missing artifactLocation.uri")
    if not repo:
        raise ValueError("repository root is required")
    if re.match(r"^[A-Za-z]:[\\/]", uri):
        raw = uri
    else:
        parsed = urlsplit(uri)
        if parsed.scheme and parsed.scheme.lower() != "file":
            raise ValueError(f"unsupported artifact URI scheme: {parsed.scheme}")
        raw = unquote(parsed.path if parsed.scheme else uri)
    if "\x00" in raw:
        raise ValueError("artifact path contains a NUL byte")
    root = Path(repo).resolve()
    candidate = Path(raw)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        rel = resolved.relative_to(root)
    except ValueError:
        raise ValueError(f"artifact path escapes repository: {uri}") from None
    if rel == Path("."):
        raise ValueError("artifact path refers to the repository root, not a file")
    return rel.as_posix()


def load_alerts(sarif, repo, scrub=False):
    """Every SARIF result becomes exactly one Alert, in file order.

    Results whose source cannot be read or whose path is unsafe are kept with ``error`` set;
    nothing is dropped and unsafe paths are never opened.
    """
    alerts = []
    for ri, run in enumerate(sarif.get("runs", [])):
        rules = _rules_by_id(run)
        drv = run.get("tool", {}).get("driver", {})
        tool = drv.get("name", "unknown")
        ver = drv.get("semanticVersion") or drv.get("version") or ""
        for xi, res in enumerate(run.get("results", [])):
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(rid, {})
            props = rule.get("properties", {}) or {}
            tags = props.get("tags", []) or []
            cwe = "; ".join(t for t in tags if CWE_TAG.match(t)) or "unknown"
            conf = next((CONF_TAG.match(t).group(1) for t in tags if CONF_TAG.match(t)), None)
            if not conf:
                conf = {"very-high": "HIGH", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(props.get("precision"), "n/a")
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            loc = ((res.get("locations") or [{}])[0]).get("physicalLocation", {})
            region = loc.get("region", {})
            source_uri = loc.get("artifactLocation", {}).get("uri", "")
            a = Alert(
                id=f"r{ri}.{xi}", run_index=ri, result_index=xi, rule_id=rid, rule_short=rid.split(".")[-1],
                message=(res.get("message") or {}).get("text", ""), level=level,
                severity=LEVEL_TO_SEVERITY.get(level, level.upper()), confidence=conf, cwe=cwe,
                file=source_uri or "<missing>",
                line=int(region.get("startLine", 0) or 0), end_line=int(region.get("endLine", region.get("startLine", 0)) or 0),
                tool=tool, tool_version=ver)
            try:
                a.file = _uri_to_rel(source_uri, repo)
                source = (Path(repo).resolve() / a.file).resolve()
                source.relative_to(Path(repo).resolve())
                raw = source.read_text(encoding="utf-8", errors="replace")
                a.code, a.snippet_truncated, a.snippet_windowed = format_code(raw, a.file, a.line, scrub)
            except Exception as e:
                a.error = f"context unavailable: {type(e).__name__}: {e}"
            alerts.append(a)
    return alerts


def user_prompt(a):
    """Classifier user turn - identical layout to the training / eval datasets."""
    tool = "Semgrep" if a.tool.lower().startswith("semgrep") else a.tool
    return ("Static-analysis alert\n"
            f"Tool: {tool} {a.tool_version}\n"
            f"Rule: {a.rule_id}\n"
            f"Severity: {a.severity} (rule confidence: {a.confidence})\n"
            f"CWE: {a.cwe}\n"
            f"Location: RequestHandler.java:{a.line}\n"
            f"Message: {a.message}\n\n"
            "Code (line-numbered, comments removed" + (", partly elided" if a.snippet_truncated else "") + "):\n"
            f"```java\n{a.code}\n```")


def classifier_row(a):
    return {"messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt(a)}]}
