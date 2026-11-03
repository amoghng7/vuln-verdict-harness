"""Annotated SARIF + Markdown + HTML report. Every input result appears in every output."""
import copy, html, json, os, collections

from .lanes import LANES

NEVER_DROPPED = ("vuln-verdict never silently drops, suppresses or hides an alert. Every Semgrep result is kept in "
                 "the annotated SARIF and listed in this report. 'Likely false positive' alerts are only "
                 "de-prioritised and must be confirmed by a human: the classifier has missed real bugs at high "
                 "false-positive confidence.")
FIX_CAVEAT = ("Verification level: Semgrep only. 'Fix verified' means the alert disappeared, no new alert of any rule "
              "appeared in the re-scan, and parse checks passed. It does not mean the project compiles, tests pass, "
              "or the change is semantically correct.")


def _fix_display(status):
    return "Semgrep-cleared; not compiled or tested." if status == "fix verified" else status


def annotate_sarif(sarif, alerts, state):
    out = copy.deepcopy(sarif)
    by = {a.id: a for a in alerts}
    for ri, run in enumerate(out.get("runs", [])):
        for xi, res in enumerate(run.get("results", [])):
            aid = f"r{ri}.{xi}"; st = state.get(aid, {})
            vv = {"lane": st.get("lane"), "laneTitle": LANES[st.get("lane", "unclassified")]["title"],
                  "laneAction": LANES[st.get("lane", "unclassified")]["action"],
                  "pTrue": st.get("p_true"), "classifierVerdict": st.get("classifier_verdict"),
                  "neverSuppressed": True}
            if by[aid].error: vv["contextError"] = by[aid].error
            au = st.get("audit")
            if au:
                vv["audit"] = {k: au.get(k) for k in ("kind", "verdict", "explanation", "attack_path", "severity", "check", "error") if au.get(k) is not None}
                if au.get("verdict") and st.get("classifier_verdict"):
                    vv["audit"]["agreesWithClassifier"] = au["verdict"] == st["classifier_verdict"]
            elif st.get("audit_skip"):
                vv["audit"] = {"status": st["audit_skip"]}
            fx = st.get("fix") or {}
            status = fx.get("status", "no fix attempted")
            vv["fix"] = {"status": status, "displayStatus": _fix_display(status),
                         "verificationLevel": fx.get("verification_level", "none"),
                         "reason": fx.get("reason", st.get("fix_skip", "")),
                         "patch": fx.get("patch_path"), "summary": fx.get("summary"), "caveats": fx.get("caveats")}
            props = res.setdefault("properties", {})
            props["vulnVerdict"] = vv
            if st.get("p_true") is not None:
                res["rank"] = round(100 * st["p_true"], 1)
        run.setdefault("properties", {})["vulnVerdict"] = {"note": NEVER_DROPPED, "fixCaveat": FIX_CAVEAT,
                                                            "summary": summary(alerts, state)}
    return out


def summary(alerts, state):
    lanes = collections.Counter(state[a.id].get("lane") for a in alerts)
    fixes = collections.Counter((state[a.id].get("fix") or {}).get("status", "no fix attempted") for a in alerts)
    aud = [state[a.id]["audit"] for a in alerts if (state[a.id].get("audit") or {}).get("verdict")]
    agree = sum(1 for a in alerts if (state[a.id].get("audit") or {}).get("verdict") == state[a.id].get("classifier_verdict") and state[a.id].get("audit"))
    return {"alerts": len(alerts), "lanes": dict(lanes), "audited": len(aud), "audit_agrees_with_classifier": agree,
            "fix_status": dict(fixes)}


def _row_md(a, st):
    au = st.get("audit") or {}; fx = st.get("fix") or {}
    p = st.get("p_true")
    lines = [f"#### `{a.rule_short}` - {a.file}:{a.line}",
             f"- p_true: **{p:.3f}**" if p is not None else "- p_true: n/a (unclassified)",
             f"- {a.severity}, {a.cwe}", f"- Semgrep: {a.message[:240]}"]
    if a.error: lines.append(f"- context error: {a.error}")
    if au.get("verdict"):
        tag = "agrees" if au["verdict"] == st.get("classifier_verdict") else "DISAGREES"
        lines.append(f"- Muse audit ({tag} with classifier): **{au['verdict']}**" + (f", severity {au['severity']}" if au.get("severity") else ""))
        lines.append(f"  - {au.get('explanation', '')}")
        if au.get("attack_path") and au.get("attack_path", "").lower() != "none": lines.append(f"  - attack path: {au['attack_path']}")
        if au.get("check"): lines.append(f"  - before dismissing, check: {au['check']}")
    elif au.get("error"):
        lines.append(f"- audit not available: {au['error']}")
    elif st.get("audit_skip"):
        lines.append(f"- Muse audit: {st['audit_skip']}")
    if fx:
        lines.append(f"- fix: **{_fix_display(fx.get('status'))}**" + (f" - {fx.get('reason')}" if fx.get("reason") else ""))
        if fx.get("patch_path"): lines.append(f"  - patch: `{fx['patch_path']}` - {fx.get('summary', '')}")
        if fx.get("caveats") and fx["caveats"].lower() != "none": lines.append(f"  - caveats: {fx['caveats']}")
    elif st.get("fix_skip"):
        lines.append(f"- fix: no fix attempted ({st['fix_skip']})")
    return "\n".join(lines)


def markdown(alerts, state, title, meta=None):
    s = summary(alerts, state)
    out = [f"# vuln-verdict triage report: {title}", "", f"> {NEVER_DROPPED}", "", f"> {FIX_CAVEAT}", ""]
    if meta: out += [f"- {k}: {v}" for k, v in meta.items()] + [""]
    out += ["| Lane | Meaning | Alerts |", "|---|---|---|"]
    for k in ("confident_tp", "needs_review", "likely_fp", "unclassified"):
        if s["lanes"].get(k): out.append(f"| {LANES[k]['title']} | {LANES[k]['action']} | {s['lanes'][k]} |")
    out += ["", f"Total alerts: {s['alerts']} (all listed below). Audited by Muse: {s['audited']}. "
            "Fix status: " + ", ".join(f"{_fix_display(k)}: {v}" for k, v in sorted(s["fix_status"].items())), ""]
    for k in ("confident_tp", "needs_review", "unclassified", "likely_fp"):
        al = [a for a in alerts if state[a.id].get("lane") == k]
        if not al: continue
        al.sort(key=lambda a: -(state[a.id].get("p_true") or 0))
        out += [f"## {LANES[k]['title']} ({len(al)}) - {LANES[k]['action']}", ""]
        for a in al: out += [_row_md(a, state[a.id]), ""]
    return "\n".join(out)


def html_report(md_text, title):
    """Tiny dependency-free Markdown->HTML (headings, lists, tables, bold, code)."""
    import re
    def inline(t):
        t = html.escape(t)
        t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    out, in_tbl, in_ul = [], False, 0
    for line in md_text.split("\n"):
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-") for c in cells): continue
            if not in_tbl: out.append("<table>"); in_tbl = True; tag = "th"
            else: tag = "td"
            out.append("<tr>" + "".join(f"<{tag}>{inline(c)}</{tag}>" for c in cells) + "</tr>"); continue
        if in_tbl: out.append("</table>"); in_tbl = False
        m = re.match(r"^( *)- (.*)", line)
        if m:
            depth = len(m.group(1)) // 2 + 1
            while in_ul < depth: out.append("<ul>"); in_ul += 1
            while in_ul > depth: out.append("</ul>"); in_ul -= 1
            out.append(f"<li>{inline(m.group(2))}</li>"); continue
        while in_ul: out.append("</ul>"); in_ul -= 1
        h = re.match(r"^(#+) (.*)", line)
        if h: out.append(f"<h{len(h.group(1))}>{inline(h.group(2))}</h{len(h.group(1))}>")
        elif line.startswith("> "): out.append(f"<blockquote>{inline(line[2:])}</blockquote>")
        elif line.strip(): out.append(f"<p>{inline(line)}</p>")
    if in_tbl: out.append("</table>")
    while in_ul: out.append("</ul>"); in_ul -= 1
    css = ("body{font-family:system-ui,sans-serif;max-width:1000px;margin:2em auto;padding:0 1em;line-height:1.45}"
           "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px}code{background:#f3f3f3;padding:1px 3px}"
           "blockquote{border-left:4px solid #d33;margin:1em 0;padding:.5em 1em;background:#fff5f5}h4{margin-bottom:.2em}")
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{css}</style></head><body>{''.join(out)}</body></html>"


def write_all(outdir, sarif, alerts, state, title, meta=None):
    os.makedirs(outdir, exist_ok=True)
    annotated = annotate_sarif(sarif, alerts, state)
    before = [len(run.get("results", [])) for run in sarif.get("runs", [])]
    after = [len(run.get("results", [])) for run in annotated.get("runs", [])]
    assert before == after, "annotated SARIF changed the number or distribution of results"
    with open(os.path.join(outdir, "annotated.sarif"), "w", encoding="utf-8") as f:
        json.dump(annotated, f, indent=1)
    md = markdown(alerts, state, title, meta)
    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as f:
        f.write(md)
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(html_report(md, f"vuln-verdict: {title}"))
    with open(os.path.join(outdir, "state.jsonl"), "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps({"alert": {k: v for k, v in a.to_dict().items() if k != "code"}, **state[a.id]}) + "\n")
