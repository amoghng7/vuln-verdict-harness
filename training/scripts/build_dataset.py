#!/usr/bin/env python3
"""Build the vuln-verdict first-pass fine-tuning dataset from OWASP Benchmark (Java) + Semgrep.

Reproduce:  python3 out/scripts/build_dataset.py            (from /workspace/vuln-verdict-data)
Options:    --rescan   re-run semgrep even if raw JSON exists
            --root DIR base dir (default: parent of out/)
Needs: git, semgrep (looked up in ROOT/.venv/bin, then PATH). Stdlib only otherwise.
"""
import argparse, collections, csv, hashlib, json, os, random, re, shutil, subprocess, sys, time

SEED = 20261030
MAX_SNIPPET_LINES = 60
SEMGREP_CONFIGS = ["p/java"]  # p/owasp-top-ten was also tried: added 0 extra findings on this corpus
REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava"

# Semgrep rule -> OWASP Benchmark category it speaks to. Alerts whose category != the test case's
# category carry no ground truth (Benchmark only labels the one seeded flaw per file) and are skipped.
RULE_CATEGORY = {
    "httpservlet-path-traversal": "pathtraver",
    "tainted-cmd-from-http-request": "cmdi",
    "no-direct-response-writer": "xss",
    "tainted-sql-from-http-request": "sqli",
    "tainted-ldapi-from-http-request": "ldapi",
    "tainted-xpath-from-http-request": "xpathi",
    "tainted-session-from-http-request": "trustbound",
    "des-is-deprecated": "crypto",       # rule says CWE-326; Benchmark files it under CWE-327
    "desede-is-deprecated": "crypto",
    "use-of-md5": "hash",
    "use-of-sha1": "hash",
}

SYSTEM_PROMPT = (
    "You are a security triage assistant. You are given one static-analysis alert and the relevant "
    "Java source code. Decide whether the alert is a real, exploitable vulnerability (true_positive) "
    "or a false alarm (false_positive). Respond with strict JSON only: "
    '{"verdict":"true_positive"} or {"verdict":"false_positive"}.'
)

# String literals that read as answer hints or category names -> neutral replacements.
LITERAL_MAP = {
    "safe": "alpha", "moresafe": "beta", "alsosafe": "gamma", " SafeStuff": " stuff",
    "safe!": "constant_value", "This should never happen": "value_one",
    "This_should_always_happen": "value_two",
}
LEAKY_LITERAL = re.compile(
    r"safe|vuln|never happen|always happen|benchmark|test ?case|cmdi|sqli|xss|pathtrav|ldapi|xpathi|"
    r"crypto|hash|weakrand|trustbound|securecookie|owasp", re.I)


def sh(cmd, **kw):
    print("+", " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, check=True, **kw)


def strip_comments(src):
    """Remove // and /* */ comments, preserving newlines and string/char literals."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i); j = n if j < 0 else j
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2); j = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, j)); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def neutral_literal(s):
    if s in LITERAL_MAP:
        return LITERAL_MAP[s]
    if LEAKY_LITERAL.search(s):
        return "msg_" + hashlib.sha1(s.encode()).hexdigest()[:6]
    return None


def anonymise(code, test_id):
    code = code.replace(test_id, "RequestHandler")
    code = re.sub(r"BenchmarkTest\d{5}", "RequestHandler", code)
    code = code.replace("org.owasp.benchmark", "com.example.app")
    def lit(m):
        body = m.group(1)
        r = neutral_literal(body)
        return m.group(0) if r is None else '"' + r + '"'
    code = re.sub(r'"((?:[^"\\\n]|\\.)*)"', lit, code)
    return re.sub(r"[Bb]enchmark", "app", code)  # e.g. local var `benchmarkprops`


def match_brace(text, open_idx):
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1; continue
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: return i
        i += 1
    return n - 1


def extract_snippet(raw, test_id, alert_line):
    """Class body minus doGet (whose @WebServlet/forward URL leaks the category) and boilerplate.
    Returns list of (orig_line_no, text) after comment stripping and anonymisation."""
    src = strip_comments(raw)
    lines = src.split("\n")
    keep = [True] * len(lines)
    # drop everything before the class declaration (package, imports, @WebServlet annotation)
    cls = next(i for i, l in enumerate(lines) if re.search(r"\bclass\s+" + test_id + r"\b", l))
    for i in range(cls): keep[i] = False
    # drop doGet method (and its @Override)
    m = re.search(r"public void doGet\s*\(", src)
    if m:
        ob = src.index("{", m.end()); cb = match_brace(src, ob)
        s_line = src.count("\n", 0, m.start()); e_line = src.count("\n", 0, cb)
        for i in range(s_line, e_line + 1): keep[i] = False
        if s_line > 0 and lines[s_line - 1].strip() == "@Override": keep[s_line - 1] = False
    out = []
    for i, l in enumerate(lines):
        if not keep[i] or not l.strip() or "serialVersionUID" in l: continue
        out.append((i + 1, anonymise(l.rstrip(), test_id)))
    # join formatter continuation lines (e.g. `org.owasp\n.esapi\n.ESAPI`) to save lines, keep 1st line no.
    joined = []
    for n, t in out:
        st = t.strip()
        if joined and (st[:1] in ".+)?:" or st.startswith("&&") or st.startswith("||")
                       or joined[-1][1].rstrip()[-1:] in "(=,+" ) and not st.startswith("@"):
            joined[-1] = (joined[-1][0], joined[-1][1].rstrip() + ("" if st[:1] in ".)" or joined[-1][1].rstrip()[-1:] == "(" else " ") + st)
        else:
            joined.append((n, t))
    out = joined
    truncated = windowed = False
    if len(out) > MAX_SNIPPET_LINES:
        truncated = True
        # 1st choice: elide the oldest lines of the request-input parsing at the top of doPost
        # (everything before the first use of the propagated variable `bar`), which is long
        # boilerplate; the propagator + sink that decide the label are kept intact.
        sig = next((k for k, (_, t) in enumerate(out) if "void doPost(" in t), None)
        if sig is not None:
            body = next((k for k in range(sig, len(out)) if out[k][1].rstrip().endswith("{")), sig) + 1
            first_bar = next((k for k in range(body, len(out)) if re.search(r"\bbar\b", out[k][1])), body)
            k = min(len(out) - MAX_SNIPPET_LINES + 1, max(0, first_bar - body - 1))
            if k > 0:
                ind = out[body][1][: len(out[body][1]) - len(out[body][1].lstrip())]
                out = out[:body] + [(None, ind + "...")] + out[body + k:]
    if len(out) > MAX_SNIPPET_LINES:
        # 2nd choice: elide the tail of doPost after the sink (output formatting / error handling)
        sig = next((k for k, (_, t) in enumerate(out) if "void doPost(" in t), None)
        a_idx = next((k for k, (n, _) in enumerate(out) if n is not None and n >= alert_line), None)
        if sig is not None and a_idx is not None and a_idx > sig:
            sig_ind = len(out[sig][1]) - len(out[sig][1].lstrip())
            end = next((k for k in range(a_idx, len(out)) if out[k][1].strip() == "}" and len(out[k][1]) - len(out[k][1].lstrip()) == sig_ind), None)
            start = a_idx + 6
            if end is not None and end - start > 1:
                k = min(len(out) - MAX_SNIPPET_LINES + 1, end - start)
                ind = out[start][1][: len(out[start][1]) - len(out[start][1].lstrip())]
                out = out[:start] + [(None, ind + "...")] + out[start + k:]
    if len(out) > MAX_SNIPPET_LINES:
        # last resort: window around the alert line
        windowed = True
        idx = min(range(len(out)), key=lambda k: abs((out[k][0] or 0) - alert_line))
        start = max(0, min(idx - MAX_SNIPPET_LINES // 2, len(out) - MAX_SNIPPET_LINES))
        out = out[start:start + MAX_SNIPPET_LINES]
    return out, truncated, windowed


def dedent(block):
    ind = min((len(t) - len(t.lstrip()) for _, t in block if t.strip()), default=0)
    return [(n, t[ind:]) for n, t in block]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    ap.add_argument("--rescan", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    root = a.root; out = os.path.join(root, "out"); raw = os.path.join(out, "raw")
    os.makedirs(raw, exist_ok=True)
    repo = os.path.join(root, "BenchmarkJava")
    if not os.path.isdir(repo):
        sh(["git", "clone", "--depth", "1", REPO_URL, repo])
    commit = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    tdir = os.path.join(repo, "src/main/java/org/owasp/benchmark/testcode")
    sg_json = os.path.join(raw, "semgrep_p-java.json")
    if a.rescan or not os.path.exists(sg_json):
        semgrep = os.path.join(root, ".venv/bin/semgrep")
        semgrep = semgrep if os.path.exists(semgrep) else shutil.which("semgrep")
        cmd = [semgrep, "scan", "--json", "--metrics=off", "--jobs", "8", "--timeout", "30", "-o", sg_json]
        for c in SEMGREP_CONFIGS: cmd += ["--config", c]
        sh(cmd + [tdir])
    sg = json.load(open(sg_json))
    sg_version = sg.get("version", "?")

    exp_csv = next(os.path.join(repo, f) for f in sorted(os.listdir(repo)) if f.startswith("expectedresults-") and f.endswith(".csv"))
    expected = {}
    for r in csv.reader(open(exp_csv)):
        if not r or r[0].startswith("#"): continue
        expected[r[0].strip()] = {"category": r[1].strip(), "real": r[2].strip() == "true", "cwe": int(r[3])}

    stats = collections.Counter()
    stats["semgrep_results_raw"] = len(sg["results"]); stats["semgrep_errors"] = len(sg["errors"])
    stats["benchmark_cases"] = len(expected)
    # one example per (test case, rule); keep earliest line, record count
    alerts = {}
    for r in sg["results"]:
        tid = re.search(r"BenchmarkTest\d{5}", r["path"]).group()
        rule = r["check_id"].split(".")[-1]
        key = (tid, r["check_id"])
        if key in alerts:
            alerts[key]["n"] += 1
            if r["start"]["line"] < alerts[key]["line"]: alerts[key]["line"] = r["start"]["line"]
            stats["dup_alerts_same_rule_same_case_merged"] += 1
            continue
        md = r["extra"].get("metadata", {})
        alerts[key] = {"tid": tid, "check_id": r["check_id"], "rule": rule, "line": r["start"]["line"],
                       "message": r["extra"]["message"], "severity": r["extra"]["severity"],
                       "confidence": md.get("confidence"), "likelihood": md.get("likelihood"),
                       "cwe": md.get("cwe", []), "n": 1}

    alerted_cases = {k[0] for k in alerts}
    stats["cases_with_any_alert"] = len(alerted_cases)
    stats["cases_with_no_alert_skipped"] = len(expected) - len(alerted_cases)
    skipped_no_alert = collections.Counter(
        (v["category"], "real" if v["real"] else "safe") for k, v in expected.items() if k not in alerted_cases)

    examples, mismatch = [], collections.Counter()
    for (tid, _), al in sorted(alerts.items()):
        e = expected[tid]
        rcat = RULE_CATEGORY.get(al["rule"])
        if rcat != e["category"]:
            mismatch[(al["rule"], e["category"])] += 1
            stats["alerts_skipped_category_mismatch"] += 1
            continue
        label = "true_positive" if e["real"] else "false_positive"
        rawsrc = open(os.path.join(tdir, tid + ".java"), encoding="utf-8").read()
        snip, trunc, windowed = extract_snippet(rawsrc, tid, al["line"])
        stats["snippets_fallback_windowed"] += windowed
        snip = dedent(snip)
        stats["snippets_shortened_to_60_lines"] += trunc
        code = "\n".join((f"{n:>4} | {t}" if n else f"     | {t}") for n, t in snip)
        cwe = "; ".join(al["cwe"]) if al["cwe"] else "unknown"
        user = (
            "Static-analysis alert\n"
            f"Tool: Semgrep {sg_version}\n"
            f"Rule: {al['check_id']}\n"
            f"Severity: {al['severity']} (rule confidence: {al['confidence'] or 'n/a'})\n"
            f"CWE: {cwe}\n"
            f"Location: RequestHandler.java:{al['line']}\n"
            f"Message: {al['message']}\n\n"
            "Code (line-numbered, comments removed" + (", partly elided" if trunc else "") + "):\n"
            f"```java\n{code}\n```"
        )
        norm = re.sub(r"\s+", " ", "\n".join(t for _, t in snip)).strip()
        examples.append({
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                          {"role": "user", "content": user},
                          {"role": "assistant", "content": json.dumps({"verdict": label}, separators=(",", ":"))}],
            "_meta": {"test_id": tid, "category": e["category"], "cwe": e["cwe"], "label": label,
                      "rule": al["rule"], "confidence": al["confidence"], "n_alerts_merged": al["n"],
                      "code_hash": hashlib.sha1(norm.encode()).hexdigest()},
        })

    # ---- leakage audit: string literals strongly associated with one label ----
    lit_lab = collections.defaultdict(collections.Counter)
    for ex in examples:
        for s in set(re.findall(r'"((?:[^"\\\n]|\\.)*)"', ex["messages"][1]["content"])):
            lit_lab[s][ex["_meta"]["label"]] += 1
    leaky = sorted([(s, dict(c)) for s, c in lit_lab.items() if sum(c.values()) >= 20 and max(c.values()) / sum(c.values()) >= 0.95],
                   key=lambda x: -sum(x[1].values()))
    leftover = [s for s in lit_lab if LEAKY_LITERAL.search(s)]
    id_leak = sum("BenchmarkTest" in ex["messages"][1]["content"] or "owasp" in ex["messages"][1]["content"].lower() for ex in examples)

    # ---- grouping: same test case, or identical normalised code -> same split ----
    parent = {}
    def find(x):
        while parent.setdefault(x, x) != x: x = parent[x]
        return x
    def union(a_, b_): parent[find(a_)] = find(b_)
    by_hash = {}
    for ex in examples:
        m = ex["_meta"]; union("t:" + m["test_id"], "t:" + m["test_id"])
        h = m["code_hash"]
        if h in by_hash: union("t:" + m["test_id"], "t:" + by_hash[h]); stats["exact_dup_code_pairs_grouped"] += 1
        else: by_hash[h] = m["test_id"]
    groups = collections.defaultdict(list)
    for ex in examples: groups[find("t:" + ex["_meta"]["test_id"])].append(ex)
    # label conflicts inside duplicate groups
    stats["dup_groups_with_conflicting_labels"] = sum(len({e["_meta"]["label"] for e in g}) > 1 for g in groups.values())

    # ---- stratified group split ----
    rng = random.Random(SEED)
    strata = collections.defaultdict(list)
    for gid in sorted(groups):
        g = groups[gid]; m = g[0]["_meta"]
        strata[(m["category"], m["label"])].append(gid)
    split_of = {}
    for key in sorted(strata):
        gids = strata[key]; rng.shuffle(gids)
        total = sum(len(groups[g]) for g in gids); acc = 0
        for g in gids:
            frac = acc / total
            split_of[g] = "train" if frac < 0.70 else ("val" if frac < 0.85 else "test")
            acc += len(groups[g])
    splits = {"train": [], "val": [], "test": []}
    for gid, g in groups.items(): splits[split_of[gid]].extend(g)
    for s in splits: rng.shuffle(splits[s])

    def write(path, rows, meta=False):
        with open(path, "w") as f:
            for ex in rows:
                obj = ex if meta else {"messages": ex["messages"]}
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        return os.path.getsize(path)

    sizes = {}
    for s, rows in splits.items():
        sizes[f"{s}.jsonl"] = write(os.path.join(out, f"{s}.jsonl"), rows)
        write(os.path.join(raw, f"{s}.meta.jsonl"), rows, meta=True)  # with _meta for analysis; NOT for upload
    # smoke subset: 200 from train, stratified-ish, 100 per label where possible
    tr = splits["train"]; srng = random.Random(SEED + 1)
    tp = [e for e in tr if e["_meta"]["label"] == "true_positive"]; fp = [e for e in tr if e["_meta"]["label"] == "false_positive"]
    srng.shuffle(tp); srng.shuffle(fp)
    nfp = min(100, len(fp)); smoke = fp[:nfp] + tp[:200 - nfp]; srng.shuffle(smoke)
    sizes["smoke_train.jsonl"] = write(os.path.join(out, "smoke_train.jsonl"), smoke)

    # ---- stats ----
    def tok(ex): return sum(len(m["content"]) for m in ex["messages"]) / 4
    per_split = {}
    for s, rows in list(splits.items()) + [("smoke_train", smoke)]:
        lc = collections.Counter(e["_meta"]["label"] for e in rows)
        toks = sorted(tok(e) for e in rows)
        per_split[s] = {"n": len(rows), "labels": dict(lc),
                        "tp_share": round(lc["true_positive"] / max(1, len(rows)), 3),
                        "by_category": {c: dict(collections.Counter(e["_meta"]["label"] for e in rows if e["_meta"]["category"] == c))
                                        for c in sorted({e["_meta"]["category"] for e in rows})},
                        "approx_tokens_total": int(sum(toks)),
                        "approx_tokens_mean": int(sum(toks) / max(1, len(toks))),
                        "approx_tokens_p50": int(toks[len(toks) // 2]) if toks else 0,
                        "approx_tokens_max": int(toks[-1]) if toks else 0}
    # sanity: no test_id / code_hash crosses splits
    def ids(s, k): return {e["_meta"][k] for e in splits[s]}
    cross = {k: sum(len(ids(a1, k) & ids(b1, k)) for a1, b1 in [("train", "val"), ("train", "test"), ("val", "test")]) for k in ("test_id", "code_hash")}

    summary = {
        "seed": SEED, "semgrep_version": sg_version, "semgrep_configs": SEMGREP_CONFIGS,
        "benchmark_commit": commit, "expected_results_file": os.path.basename(exp_csv),
        "counts": dict(stats), "examples_total": len(examples),
        "labels_total": dict(collections.Counter(e["_meta"]["label"] for e in examples)),
        "per_split": per_split, "file_bytes": sizes,
        "fireworks_upload_bytes_train_plus_val": sizes["train.jsonl"] + sizes["val.jsonl"],
        "skipped_category_mismatch": {f"{r} on {c} case": n for (r, c), n in mismatch.most_common()},
        "skipped_no_alert_by_category": {f"{c}/{l}": n for (c, l), n in sorted(skipped_no_alert.items())},
        "rule_label_table": {r: dict(collections.Counter(e["_meta"]["label"] for e in examples if e["_meta"]["rule"] == r))
                             for r in sorted({e["_meta"]["rule"] for e in examples})},
        "confidence_label_table": {str(c): dict(collections.Counter(e["_meta"]["label"] for e in examples if e["_meta"]["confidence"] == c))
                                   for c in sorted({str(e["_meta"]["confidence"]) for e in examples})},
        "leakage_audit": {"examples_containing_BenchmarkTest_or_owasp": id_leak,
                          "leftover_leaky_literals": leftover,
                          "literals_>=95pct_one_label_(n>=20)": leaky[:30]},
        "cross_split_overlap": cross,
        "runtime_seconds": round(time.time() - t0, 1),
    }
    json.dump(summary, open(os.path.join(out, "stats.json"), "w"), indent=2)
    print(json.dumps({k: summary[k] for k in ("examples_total", "labels_total", "counts", "cross_split_overlap")}, indent=1))
    for s, v in per_split.items(): print(s, v["n"], v["labels"], "tp_share", v["tp_share"], "tok_mean", v["approx_tokens_mean"], "max", v["approx_tokens_max"])
    print("leaky literals:", leaky[:15]); print("leftover:", leftover)


if __name__ == "__main__":
    main()
