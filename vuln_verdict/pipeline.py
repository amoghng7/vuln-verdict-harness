"""Triage pipeline: classifier lanes -> Muse audit -> verifiable remediation -> annotated outputs.

Audits and fixes are cached with an alert-content fingerprint, preventing alert IDs such as r0.0 from
reusing results belonging to a different SARIF file in the same output directory. Both caches are
merged back into alert state before every report write, including a later invocation of only one stage.
"""
import concurrent.futures as cf, hashlib, json, os, sys

from . import audit as audit_mod, muse, remediate
from .lanes import LO, HI, lane_for
from .report import write_all


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def _fingerprint(a):
    payload = json.dumps({"file": a.file, "line": a.line, "end_line": a.end_line, "rule_id": a.rule_id,
                          "message": a.message, "code": a.code}, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _cache(path, alerts):
    by_id = {a.id: a for a in alerts}
    d = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                a = by_id.get(row.get("alert_id"))
                if a is not None and row.get("alert_fingerprint") == _fingerprint(a):
                    d[a.id] = row["data"]
    return d


def _append(path, a, data):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"alert_id": a.id, "alert_fingerprint": _fingerprint(a), "data": data}) + "\n")


def merge_cached_state(alerts, state, outdir):
    """Load fingerprint-valid audit and fix caches into `state` before a report write.

    Entries already set in this process are kept. A later invocation that runs only one
    stage still writes the other stage's cached result. Mismatched fingerprints and other
    alert IDs are ignored, and cache files are not deleted or rewritten here.
    """
    for key, name in (("audit", "audits.jsonl"), ("fix", "fixes.jsonl")):
        cached = _cache(os.path.join(outdir, name), alerts)
        for aid, data in cached.items():
            if aid in state:
                state[aid].setdefault(key, data)
    return state


def assign_lanes(alerts, probs, lo=LO, hi=HI):
    state = {}
    for a in alerts:
        p = probs.get(a.id)
        state[a.id] = {"lane": lane_for(p, lo, hi), "p_true": p,
                       "classifier_verdict": None if p is None else ("true_positive" if p >= 0.5 else "false_positive")}
    return state


def run_audits(alerts, state, outdir, max_audits=200, confirm_fp=True, effort="low", workers=4, only=None):
    """Audit by priority while retaining every alert, including cap/context skips."""
    cpath = os.path.join(outdir, "audits.jsonl"); cache = _cache(cpath, alerts)
    order = {"needs_review": 0, "unclassified": 0, "likely_fp": 1, "confident_tp": 2}
    todo = [a for a in alerts if not a.error and (only is None or a.id in only)
            and (state[a.id]["lane"] != "likely_fp" or confirm_fp)]
    todo.sort(key=lambda a: (order[state[a.id]["lane"]], state[a.id]["p_true"] if state[a.id]["p_true"] is not None else 0))
    for a in todo:
        if a.id in cache: state[a.id]["audit"] = cache[a.id]
    fresh = [a for a in todo if a.id not in cache][:max(0, max_audits - sum(1 for a in todo if a.id in cache))]

    def one(a):
        p = state[a.id]["p_true"]; p = 0.5 if p is None else p
        try:
            return a, (audit_mod.confirm_fp(a, p, effort) if state[a.id]["lane"] == "likely_fp" else audit_mod.audit(a, p, effort))
        except muse.BudgetExceeded as e:
            return a, {"error": f"budget stop: {e}", "_nocache": True}
        except Exception as e:
            return a, {"error": f"{type(e).__name__}: {e}"[:300], "_nocache": True}
    done = 0
    with cf.ThreadPoolExecutor(workers) as ex:
        for a, r in ex.map(one, fresh):
            state[a.id]["audit"] = {k: v for k, v in r.items() if k != "_nocache"}
            if not r.get("_nocache"): _append(cpath, a, r)
            done += 1
            if done % 10 == 0: log(f"  audits {done}/{len(fresh)}  spend ${muse.spent():.2f}")
    todo_ids = {a.id for a in todo}
    for a in alerts:
        if a.id not in todo_ids or "audit" not in state[a.id]:
            state[a.id].setdefault("audit_skip", "not audited (cap or context error)" if not a.error else a.error)
    return state


def run_remediation(alerts, state, repo, outdir, lanes=("confident_tp",), max_fixes=30, require_audit_agree=True,
                    semgrep_bin="semgrep", config="p/java", effort="low", only=None, chunk=8):
    fpath = os.path.join(outdir, "fixes.jsonl"); cache = _cache(fpath, alerts)
    cand = []
    for a in alerts:
        st = state[a.id]
        if a.id in cache:
            st["fix"] = cache[a.id]; continue
        if only is not None and a.id not in only:
            st["fix_skip"] = "not selected"; continue
        if st["lane"] not in lanes:
            st["fix_skip"] = f"lane {st['lane']} is not remediated automatically"; continue
        if not remediate.category(a):
            st["fix_skip"] = "rule type not in the verifiable set (SQLi, XXE, weak crypto, redirect, path)"; continue
        if require_audit_agree and (st.get("audit") or {}).get("verdict") == "false_positive":
            st["fix_skip"] = "Muse audit judged it a false positive"; continue
        if a.error:
            st["fix_skip"] = a.error; continue
        cand.append(a)
    used = sum(1 for a in alerts if a.id in cache)
    budget_left = max(0, max_fixes - used)
    for a in cand[budget_left:]:
        state[a.id]["fix_skip"] = "remediation cap reached"
    cand = cand[:budget_left]
    for i in range(0, len(cand), chunk):
        part = cand[i:i + chunk]
        batch_name = f"batch{used + i:03d}"
        log(f"  remediation {i + 1}-{i + len(part)} of {len(cand)}  spend ${muse.spent():.2f}")
        recs = remediate.remediate_batch([(a, state[a.id].get("audit")) for a in part], repo,
                                         os.path.join(outdir, "remediation", batch_name),
                                         semgrep_bin, config, effort, log)
        for a in part:
            r = recs.get(a.id, {"status": "no fix attempted", "reason": "missing"})
            if r.get("patch_path"):
                r["patch_path"] = os.path.relpath(os.path.join(outdir, "remediation", batch_name, r["patch_path"]), outdir)
            state[a.id]["fix"] = r
            if not str(r.get("reason", "")).startswith("budget"): _append(fpath, a, r)
    return state


def finish(outdir, sarif, alerts, state, title, meta=None, stage=""):
    merge_cached_state(alerts, state, outdir)
    write_all(outdir, sarif, alerts, state, title, meta)
    log(f"[{stage}] wrote {outdir}/annotated.sarif, report.md, report.html")
