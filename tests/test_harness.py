"""Offline tests: no GPU, no API key, no Semgrep needed."""
import json, os, re, sys, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from vuln_verdict import lanes, remediate
from vuln_verdict.classifier import load_probs
from vuln_verdict.pipeline import assign_lanes
from vuln_verdict.report import NEVER_DROPPED, annotate_sarif, write_all
from vuln_verdict.sarif import load_alerts, user_prompt, classifier_row
from vuln_verdict.snippet import format_code

TINY = os.path.join(ROOT, "examples", "tiny")
SARIF = os.path.join(TINY, "semgrep.sarif")
PROBS = os.path.join(ROOT, "tests", "fixtures", "tiny_probs.jsonl")


def tiny():
    s = json.load(open(SARIF)); return s, load_alerts(s, TINY)


def test_lane_thresholds():
    assert lanes.lane_for(0.98) == "confident_tp" and lanes.lane_for(0.979) == "needs_review"
    assert lanes.lane_for(0.44) == "needs_review" and lanes.lane_for(0.4399) == "likely_fp"
    assert lanes.lane_for(None) == "unclassified"


def test_alerts_extracted():
    s, al = tiny()
    assert len(al) == sum(len(r["results"]) for r in s["runs"]) == 6
    a = al[0]
    assert a.rule_short == "formatted-sql-string" and a.line == 25 and a.cwe.startswith("CWE-89")
    assert a.file == "src/main/java/com/example/demo/AccountService.java" and not a.error


def test_prompt_layout():
    _, al = tiny()
    u = user_prompt(al[0])
    assert u.startswith("Static-analysis alert\nTool: Semgrep ")
    for k in ("Rule: ", "Severity: ", "CWE: ", "Location: RequestHandler.java:", "Message: ", "```java\n"):
        assert k in u
    code = u.split("```java\n")[1]
    assert re.search(r"(?m)^  25 \| .*executeQuery\(sql\)", code)            # alert line kept, f"{n:>4} | {t}"
    assert "class RequestHandler" in code and "AccountService" not in code  # anonymised class
    assert "//" not in code and "/**" not in code                        # comments stripped
    row = classifier_row(al[0])
    assert row["messages"][0]["role"] == "system" and row["messages"][1]["content"] == u


def test_load_probs_formats(tmp_path):
    _, al = tiny()
    p = tmp_path / "p.jsonl"
    p.write_text("\n".join([json.dumps({"alert_id": "r0.0", "p_true": 0.9}),
                            json.dumps({"file": al[1].file, "line": al[1].line, "rule_id": al[1].rule_id, "p_true": 0.1}),
                            json.dumps({"idx": 2, "p_true_renorm": 0.5})]))
    pr = load_probs(str(p), al)
    assert pr == {"r0.0": 0.9, "r0.1": 0.1, "r0.2": 0.5}


def test_never_drops_alerts(tmp_path):
    s, al = tiny()
    probs = load_probs(PROBS, al)
    del probs["r0.3"]                                   # a missing probability must not drop the alert
    st = assign_lanes(al, probs)
    assert st["r0.3"]["lane"] == "unclassified" and st["r0.5"]["lane"] == "likely_fp"
    write_all(str(tmp_path), s, al, st, "t")
    out = json.load(open(tmp_path / "annotated.sarif"))
    res = [r for run in out["runs"] for r in run["results"]]
    assert len(res) == 6
    assert all(r["properties"]["vulnVerdict"]["neverSuppressed"] for r in res)
    assert not any("suppressions" in r for r in res)
    md = (tmp_path / "report.md").read_text()
    assert NEVER_DROPPED in md
    assert md.count("AccountService.java:") >= 6           # every alert listed, incl. likely-FP + unclassified
    assert "AccountService.java:60" in md                   # the likely-FP one is visible


def test_apply_edits_and_imports():
    src = "package a;\nimport java.sql.Statement;\n\nclass X {\n  void f() {\n    int a = 1;\n  }\n  void g() {\n    int a = 1;\n  }\n}\n"
    new, probs = remediate.apply_edits(src, [{"find": "int a = 1;", "replace": "int a = 2;"}], ["java.sql.PreparedStatement", "java.lang.String"], 9)
    assert not probs
    assert new.split("\n")[9] == "    int a = 2;" and new.split("\n")[6] == "    int a = 1;"   # edit nearest the alert line
    assert "import java.sql.PreparedStatement;" in new and "import java.lang.String" not in new
    _, probs = remediate.apply_edits(src, [{"find": "nope", "replace": "x"}], [], 1)
    assert probs
    new2, probs = remediate.apply_edits(src, [{"find": "int a = 1;\n  }\n  void g", "replace": "int a = 3;\n  }\n  void g"}], [], 6)
    assert not probs and "int a = 3;" in new2


def test_line_map_and_parse_checks():
    old = "a\nb\nc\nd\n"; new = "a\nX\nY\nc\nd\n"
    m = remediate.line_map(old, new)
    assert m[1] == 1 and m[4] == 3 and m[5] == 4 and 2 not in m
    assert remediate.braces_balanced("class X { void f() { String s = \"{\"; } }")
    assert not remediate.braces_balanced("class X { void f() { }")


def test_category():
    _, al = tiny()
    cats = [remediate.category(a) for a in al]
    assert cats[:5] == ["sqli", "crypto", "crypto", "crypto", "xxe"]


def test_cli_probs_file(tmp_path):
    r = subprocess.run([sys.executable, "-m", "vuln_verdict", "triage", SARIF, "--repo", TINY, "--out", str(tmp_path),
                        "--probs-file", PROBS], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "MODEL_API_KEY": ""})
    assert r.returncode == 0, r.stderr
    summ = json.loads(r.stdout[r.stdout.index("{"):])
    assert summ["alerts"] == 6 and sum(summ["lanes"].values()) == 6
    for f in ("annotated.sarif", "report.md", "report.html"):
        assert (tmp_path / f).exists()


def test_audit_priority_under_cap(tmp_path, monkeypatch):
    from vuln_verdict import pipeline, audit as audit_mod
    _, al = tiny()
    st = assign_lanes(al, load_probs(PROBS, al))
    calls = []
    monkeypatch.setattr(audit_mod, "audit", lambda a, p, e="low": calls.append(a.id) or {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(audit_mod, "confirm_fp", lambda a, p, e="low": calls.append(a.id) or {"verdict": "false_positive", "why_safe": "y"})
    pipeline.run_audits(al, st, str(tmp_path), max_audits=3, workers=1)
    assert calls[0] == "r0.3" and "r0.5" in calls          # needs-review first, likely-FP before confident TPs
    skipped = [a.id for a in al if st[a.id].get("audit_skip")]
    assert len(skipped) == 3
    write_all(str(tmp_path), json.load(open(SARIF)), al, st, "t")
    assert (tmp_path / "report.md").read_text().count("not audited") == 3
