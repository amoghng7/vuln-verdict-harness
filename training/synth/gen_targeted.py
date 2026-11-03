"""Round-2 TARGETED synthetic training data (new scenario families, prefix U-, seed 31337).

Families target abstract failure patterns observed in round 1 (method-parameter / DTO / DB-stored taint, quote-stripping
sanitizers, non-HTML responses, unseen rules: formatted-sql-string, XXE, ECB / static IV, unencrypted socket).
No code from the user's repo is used; generated snippets are additionally rejected if they resemble any user-repo or
dev-set snippet (5-gram Jaccard >= 0.5).

One generator call produces a contrastive PAIR (TP + FP sharing domain / style; the deciding detail differs).
Each snippet is then judged INDEPENDENTLY by the same blind judge as round 1 (pipeline.judge); only agreeing snippets kept.
Alert header = real Semgrep 1.183.0 rule id / severity / confidence / CWE / message (semgrep_rules.json);
class anonymised to RequestHandler like the OWASP and real sets.
Usage: export MODEL_API_KEY=...; python3 gen_targeted.py --pairs N [--pilot K] [--finalize-only]
"""
import argparse, collections, hashlib, json, os, random, re, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline, metaapi

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "targeted")
SEED = 31337
RULES = json.load(open(os.path.join(HERE, "semgrep_rules.json")))
DOMAINS = ["school district student information system", "veterinary clinic", "parking enforcement", "energy utility billing",
           "museum ticketing", "court case management", "gym membership", "recruiting / applicant tracking",
           "freight brokerage", "dental practice scheduling", "hotel property management", "charity donations",
           "agriculture co-op marketplace", "news publishing CMS", "city bike sharing", "laboratory sample tracking"]
FRAMEWORKS = ["plain Java Servlet (HttpServlet) with a DAO class", "Spring MVC @Controller calling a @Service",
              "Spring Boot @RestController with a DTO and JdbcTemplate repository", "legacy JSP-era servlet with helper utility class",
              "JAX-RS resource calling a service layer", "plain Java service + DAO (no web layer shown)",
              "background job / message consumer processing records", "Jakarta Servlet filter + utility class"]

# family -> (weight, [rule keys], [(tp_variant, desc)], [(fp_variant, desc)])
FAM = {
 "sql_param": (14, ["formatted-sql-string"], [
   ("dao_param", "a DAO/repository method receives a String argument (passed down from a controller or DTO that the snippet shows comes from the client) and concatenates it into SQL executed with java.sql.Statement or JdbcTemplate.query"),
   ("dto_field", "a DTO field bound from a request body/form (e.g. a search filter's name or sort field) is concatenated into a WHERE or ORDER BY clause in the service/DAO"),
   ("second_order", "second-order: a value a user saved earlier (read back from a DB row/entity, e.g. display name, saved search, tag) is concatenated into another SQL statement"),
  ], [
   ("const_fragments", "the SQL text is built with String.format/concatenation only from constants (static final table/column names, ? placeholders) and all client values are bound through PreparedStatement setters or JdbcTemplate args"),
   ("allowlist_map", "a sort/column value from a DTO is mapped through a fixed Map/enum/switch allowlist so only constant SQL fragments are concatenated"),
   ("typed_param", "the concatenated method parameter is a long/int/UUID (or parsed with Long.parseLong / UUID.fromString first), so no SQL syntax can be injected"),
  ]),
 "sql_request": (6, ["tainted-sql-from-http-request"], [
   ("via_service", "a request parameter is passed through a service method parameter (shown) and concatenated into SQL there"),
  ], [
   ("bound_only", "a request parameter is used only as a bound ? parameter of a PreparedStatement while the SQL text concatenates constant fragments (e.g. a static final schema name)"),
  ]),
 "sql_sanitizer": (14, ["formatted-sql-string", "tainted-sql-from-http-request"], [
   ("strip_quote_numeric", "a helper (shown) strips single quotes, but the value is placed in an UNQUOTED numeric context (WHERE id = + value), so input like `1 OR 1=1` changes the query"),
   ("keyword_blacklist", "a helper (shown) only removes ';', '--' or case-sensitive keywords like DROP/UNION; the value is concatenated inside quotes and quotes are not handled"),
   ("double_quote_mysql_backslash", "a helper (shown) doubles single quotes but leaves backslashes, and the code targets MySQL (com.mysql.cj.jdbc driver URL shown) where backslash escapes are active, so `\\'` breaks out"),
  ], [
   ("strip_quote_quoted", "a helper (shown) removes EVERY single quote and the value is always placed inside single quotes in a statement for an H2 or PostgreSQL database (JDBC URL shown; standard strings, no backslash escapes), so the value cannot leave the string literal"),
   ("double_quote_standard", "a helper (shown) doubles every single quote (replace(\"'\", \"''\")) and the value is always inside single quotes on an H2/PostgreSQL/Oracle database (JDBC URL shown)"),
   ("regex_fullmatch", "a helper (shown) accepts the value only if it fully matches ^[A-Za-z0-9_]{1,32}$ and otherwise throws, before it is concatenated"),
  ]),
 "xss_flow": (18, ["no-direct-response-writer"], [
   ("stored_db", "a user-editable value loaded from the database (comment, bio, review, note) is written into an HTML response via response.getWriter() without HTML encoding"),
   ("dto_service", "a value returned by a DTO/service method, which the snippet shows originates from request input, is written into an HTML response without encoding"),
   ("attr_partial_encoder", "an encoding helper (shown) escapes only < and >, but the value is written inside a double-quoted HTML attribute, so a \" breaks out into an event handler"),
   ("encoded_wrong_var", "an HTML encoding helper (shown) is applied, but to a different variable than the one actually written to the response"),
  ], [
   ("json_ct", "the response content type is application/json and the body is produced by Jackson ObjectMapper or Gson serialisation of a DTO/map containing the value"),
   ("boolean_numeric", "the written value is a boolean / int / long / count computed server-side (e.g. whether a record exists), never a request string"),
   ("full_encoder", "the value goes through an encoding helper (shown) that escapes & < > \" and ' before being written into HTML element text"),
   ("constant_body", "only server constants / fixed template text are written; the request value is used just to choose between constant messages"),
  ]),
 "redirect": (7, ["unvalidated-redirect"], [
   ("stored_return_url", "a return URL saved earlier from the request into the session, a cookie or a DB row is later passed to sendRedirect without validation"),
   ("dto_param", "a redirect URL arriving through a DTO / service method parameter is passed to sendRedirect without validation"),
  ], [
   ("map_lookup", "the redirect target is looked up by key in a fixed Map of internal destinations; unknown keys fall back to a constant"),
   ("relative_only", "the URL is parsed with java.net.URI and accepted only when it has no scheme and no host and its path starts with a single '/' (not '//' or '/\\\\'); otherwise a constant default is used"),
  ]),
 "path": (7, ["httpservlet-path-traversal"], [
   ("stored_filename", "a file name that a user supplied earlier (stored original upload name in a DB row or DTO) is joined to a base directory and read without normalisation"),
   ("service_param", "a request value passed through a service method parameter is used in new File(baseDir, name) and streamed back"),
  ], [
   ("getfilename", "the name is reduced with Paths.get(name).getFileName() or org.apache.commons.io.FilenameUtils.getName before joining to the base directory"),
   ("canonical_check", "the joined path is canonicalised (getCanonicalPath / toRealPath / normalize) and checked with startsWith(base + File.separator) before access"),
  ]),
 "xxe": (10, ["documentbuilderfactory-disallow-doctype-decl-missing", "saxparserfactory-disallow-doctype-decl-missing"], [
   ("default_param", "the parser factory is created with default settings and parses XML passed in as a method parameter / uploaded stream / message body"),
   ("partial_hardening", "only setExpandEntityReferences(false) or setXIncludeAware(false) is set, DOCTYPEs and external entities stay enabled, and client XML is parsed"),
  ], [
   ("helper_disallow", "the factory comes from a helper method (shown) that sets http://apache.org/xml/features/disallow-doctype-decl to true on that same instance before parsing"),
   ("bundled_resource", "the parser only reads a bundled classpath resource / file generated by the application itself, never client-supplied XML"),
   ("external_disabled", "external-general-entities and external-parameter-entities are disabled, load-external-dtd is false and FEATURE_SECURE_PROCESSING is set on the same factory before parsing client XML"),
  ]),
 "crypto_ecb": (7, ["ecb-cipher", "use-of-aes-ecb"], [
   ("aes_ecb_pii", "AES/ECB/PKCS5Padding is used to encrypt multi-block sensitive data (PII, tokens, card data) that is stored or sent"),
  ], [
   ("rsa_ecb_oaep", "the matched string is RSA/ECB/OAEPWithSHA-256AndMGF1Padding used for RSA key wrapping; for RSA the ECB label is a naming artifact (single block), so ECB weaknesses do not apply. Use rule ecb-cipher"),
  ]),
 "static_iv": (7, ["no-static-initialization-vector"], [
   ("const_iv", "a static final constant byte[] IV is used with AES/CBC or AES/GCM to encrypt many different records"),
  ], [
   ("iv_overwritten", "a byte[] IV is declared with an initialiser, but it is filled with SecureRandom.nextBytes before every encryption and prepended to the ciphertext"),
  ]),
 "socket": (10, ["unencrypted-socket"], [
   ("remote_secret", "a plain java.net.Socket connects to a remote, configurable host and sends credentials, session tokens or personal data"),
  ], [
   ("loopback_health", "a plain Socket connects to 127.0.0.1 / localhost (a local sidecar or agent) and only sends a constant health-check line"),
   ("reachability_probe", "a plain Socket is used only to test TCP reachability of a host/port (connect with timeout, then close); no application data is sent or received"),
  ]),
}
DIFF = ["easy", "medium", "hard"]
STYLE = ("Imitate everyday business code written by different teams: layered controller/service/DAO, DTOs, helper utility "
         "classes, some legacy style, some modern Java 17.")

PAIR_ITEM = {"type": "object", "properties": {"class_name": {"type": "string"}, "code": {"type": "string"},
             "flagged_line": {"type": "string"}, "rationale": {"type": "string"}},
             "required": ["class_name", "code", "flagged_line", "rationale"]}
PAIR_SCHEMA = ("alert_pair", {"type": "object", "properties": {"tp": PAIR_ITEM, "fp": PAIR_ITEM}, "required": ["tp", "fp"]})


def build_specs(n, seed=SEED):
    rng = random.Random(seed)
    fams = list(FAM); w = [FAM[f][0] for f in fams]
    specs, seen, tries = [], set(), 0
    while len(specs) < n and tries < n * 50:
        tries += 1
        f = rng.choices(fams, weights=w)[0]
        _, rules, tps, fps = FAM[f]
        tp = rng.choice(tps); fp = rng.choice(fps); rule = rng.choice(rules)
        if f == "crypto_ecb" and fp[0] == "rsa_ecb_oaep":
            rule = "ecb-cipher"
        dom, fw, diff = rng.choice(DOMAINS), rng.choice(FRAMEWORKS), rng.choices(DIFF, weights=[2, 3, 3])[0]
        if f == "sql_request" or (rule == "tainted-sql-from-http-request"):
            fw = rng.choice([x for x in FRAMEWORKS if "Servlet" in x or "servlet" in x])
        key = (f, tp[0], fp[0], rule, dom, fw, diff)
        if key in seen:
            continue
        seen.add(key)
        sid = f"U-{f}-{tp[0]}-{fp[0]}-" + hashlib.sha1(repr(key + (seed,)).encode()).hexdigest()[:8]
        specs.append({"scenario_id": sid, "set": "U", "family": f, "rule_key": rule, "tp_variant": tp[0], "tp_desc": tp[1],
                      "fp_variant": fp[0], "fp_desc": fp[1], "domain": dom, "framework": fw, "difficulty": diff})
    return specs


def gen_messages(s):
    r = RULES[s["rule_key"]]
    sys_p = ("You write realistic Java source snippets for a benchmark that teaches triage of Semgrep findings. Ground truth "
             "must be unambiguous to an expert who sees only the snippet. " + STYLE)
    user = f"""Create a CONTRASTIVE PAIR of Java snippets on which this Semgrep rule fires at one sink line:
Rule: {r['check_id']}
Rule message: {r['message']}

Both snippets: domain "{s['domain']}", style "{s['framework']}", difficulty {s['difficulty']} (hard = the deciding detail is subtle but visible). Make them look alike (similar size and structure) but with DIFFERENT class/method/variable names.
- "tp": a REAL, exploitable finding. Scenario: {s['tp_desc']}.
- "fp": NOT exploitable (false alarm; the rule still matches). Scenario: {s['fp_desc']}.

Each item:
- `code`: 18-55 lines of Java starting at the main class declaration (no package/imports; fully-qualified names where library identity matters). Show every helper/DTO/DAO method that decides the outcome (nested static classes or extra methods are fine). The data source (request, DTO, DB row, parameter) must be visible.
- NO comments. No identifiers or strings that reveal the answer (no safe/unsafe/vulnerable/insecure/sanitized/tainted/attacker/exploit/malicious/bypass/evil/xss/sqli).
- `class_name`: the main class name. `flagged_line`: copy EXACTLY one line of `code` (the sink the rule matches).
- `rationale`: <=35 words."""
    return [{"role": "system", "content": sys_p}, {"role": "user", "content": user}]


def fmt(s, item, label, rng):
    r = RULES[s["rule_key"]]
    code = pipeline.strip_comments(item["code"].replace("\t", "    ")).rstrip()
    cls = re.sub(r"\W", "", item.get("class_name") or "")
    m = re.search(r"\bclass\s+([A-Za-z_]\w*)", code)
    if m and (not cls or cls not in code):
        cls = m.group(1)
    if cls and cls != "RequestHandler":
        code = re.sub(rf"\b{re.escape(cls)}\b", "RequestHandler", code)
    fl_raw = pipeline.strip_comments(item["flagged_line"])
    if cls:
        fl_raw = re.sub(rf"\b{re.escape(cls)}\b", "RequestHandler", fl_raw)
    lines = [l for l in code.split("\n") if not re.match(r"\s*(package|import)\s+[\w.*]+;\s*$", l)]
    while lines and not lines[0].strip():
        lines.pop(0)
    start = rng.randint(10, 45)
    fl = re.sub(r"\s+", " ", fl_raw.strip())
    numbered, flagged = [], None
    for k, t in enumerate(lines):
        if not t.strip():
            continue
        numbered.append((start + k, t.rstrip()))
        if flagged is None and fl and re.sub(r"\s+", " ", t.strip()) == fl:
            flagged = start + k
    if flagged is None:
        for k, t in enumerate(lines):
            tt = re.sub(r"\s+", " ", t.strip())
            if fl and tt and (fl in tt or (len(tt) > 12 and tt in fl)):
                flagged = start + k; break
    if flagged is None or not (12 <= len(numbered) <= 70):
        return None, f"format(flag={flagged is not None},lines={len(numbered)})"
    ind = min(len(t) - len(t.lstrip()) for _, t in numbered)
    body = [t[ind:] for _, t in numbered]
    user = ("Static-analysis alert\n"
            f"Tool: Semgrep {pipeline.SEMGREP_VERSION}\n"
            f"Rule: {r['check_id']}\n"
            f"Severity: {r['severity']} (rule confidence: {r['confidence'] or 'n/a'})\n"
            f"CWE: {r['cwe'] or 'unknown'}\n"
            f"Location: RequestHandler.java:{flagged}\n"
            f"Message: {r['message']}\n\n"
            "Code (line-numbered, comments removed):\n```java\n" +
            "\n".join(f"{n:>4} | {b}" for (n, _), b in zip(numbered, body)) + "\n```")
    return {"user": user, "code_body": "\n".join(body), "rule": r["check_id"], "line": flagged, "n_lines": len(numbered),
            "label": label}, None


def judge(user_msg):
    content, _ = metaapi.chat([{"role": "system", "content": pipeline.JUDGE_SYSTEM}, {"role": "user", "content": user_msg}],
                              tag="judge_U", max_tokens=4000, reasoning_effort=JUDGE_EFFORT, schema=pipeline.JUDGE_SCHEMA)
    j = json.loads(content)
    return j["verdict"], j.get("analysis", "")


GEN_EFFORT, JUDGE_EFFORT = "minimal", "low"


def process(s, seed):
    rng = random.Random(seed)
    rec = {"spec": s, "items": {}}
    try:
        content, _ = metaapi.chat(gen_messages(s), tag="gen_U", max_tokens=7000, reasoning_effort=GEN_EFFORT,
                                  schema=PAIR_SCHEMA, temperature=1.0)
        g = json.loads(content)
    except metaapi.BudgetExceeded as e:
        rec["status"] = "budget"; rec["err"] = str(e); return rec
    except Exception as e:
        rec["status"] = "gen_error"; rec["err"] = str(e)[:300]; return rec
    rec["gen"] = g; rec["status"] = "done"
    for side, label in (("tp", "true_positive"), ("fp", "false_positive")):
        it = {"label": label}
        rec["items"][side] = it
        item = g.get(side) or {}
        leaks = pipeline.leak_tokens(pipeline.strip_comments(item.get("code", "")))
        if leaks:
            it["status"] = "leak"; it["leaks"] = leaks; continue
        ex, why = fmt(s, item, label, rng)
        if ex is None:
            it["status"] = "format"; it["err"] = why; continue
        it["ex"] = ex
        try:
            v, an = judge(ex["user"])
        except metaapi.BudgetExceeded as e:
            it["status"] = "budget"; rec["status"] = "budget"; continue
        except Exception as e:
            it["status"] = "judge_error"; it["err"] = str(e)[:200]; continue
        it["judge_verdict"], it["judge_analysis"] = v, an
        it["status"] = "agree" if v == label else "disagree"
    return rec


def run(specs, raw, workers):
    done = set()
    if os.path.exists(raw):
        for l in open(raw):
            r = json.loads(l)
            if r.get("status") == "done":
                done.add(r["spec"]["scenario_id"])
    todo = [s for s in specs if s["scenario_id"] not in done]
    print(f"[run] {len(specs)} specs, {len(done)} done, {len(todo)} todo; spent ${metaapi.spent():.3f}", flush=True)
    stop = threading.Event(); lock = threading.Lock(); n = 0
    with open(raw, "a") as f, ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(lambda s=s, k=k: None if stop.is_set() else process(s, SEED * 1009 + k)) for k, s in enumerate(todo)]
        for fu in as_completed(futs):
            r = fu.result()
            if r is None:
                continue
            if r["status"] == "budget":
                stop.set()
            with lock:
                f.write(json.dumps(r) + "\n"); f.flush(); n += 1
                if n % 20 == 0:
                    print(f"[run] {n}/{len(todo)} spent ${metaapi.spent():.3f}", flush=True)
    print(f"[run] finished; spent ${metaapi.spent():.3f}", flush=True)


CODE_RE = re.compile(r"^\s*\d*\s\| ?(.*)$")


def code_of_user(u):
    c = u.split("```java\n", 1)[1].rsplit("```", 1)[0]
    return "\n".join(m.group(1) for l in c.split("\n") if (m := re.match(r"^\s*\d*\s*\| ?(.*)$", l)))


def exclusion_sets():
    H, SH_strict, SH_user = set(), [], []
    D = os.path.dirname(HERE)
    for p in ["out/train.jsonl", "out/val.jsonl", "out/test.jsonl", "synth/stress.jsonl", "synth/synth_train.jsonl"]:
        for l in open(os.path.join(D, p)):
            c = code_of_user(json.loads(l)["messages"][1]["content"])
            H.add(pipeline.norm_hash(c))
            if "stress" in p or "synth_train" in p:
                SH_strict.append(pipeline.shingles(c))
    for p in ["real/real.jsonl", "dev/dev.jsonl"]:
        fp = os.path.join(D, p)
        if os.path.exists(fp):
            for l in open(fp):
                c = code_of_user(json.loads(l)["messages"][1]["content"])
                H.add(pipeline.norm_hash(c)); SH_user.append(pipeline.shingles(c))
    return H, SH_strict, SH_user


def finalize(raw):
    recs = {}
    for l in open(raw):
        r = json.loads(l); recs[r["spec"]["scenario_id"]] = r
    H, SH_strict, SH_user = exclusion_sets()
    jac = lambda a, b: len(a & b) / max(1, len(a | b))
    st = collections.Counter(); per = collections.defaultdict(collections.Counter)
    kept, own_h, own_sh = [], set(), []
    drops = collections.Counter(); maxj_user = 0.0
    for sid in sorted(recs):
        r = recs[sid]
        for side, it in r.get("items", {}).items():
            st[it.get("status")] += 1
            if it.get("status") in ("agree", "disagree"):
                per[f"{r['spec']['family']}/{r['spec'][side + '_variant']}/{it['label']}"][it["status"]] += 1
            if it.get("status") != "agree":
                continue
            c = it["ex"]["code_body"]; h = pipeline.norm_hash(c); sh = pipeline.shingles(c)
            if h in H or h in own_h:
                drops["exact"] += 1; continue
            ju = max([jac(sh, o) for o in SH_user] or [0])
            maxj_user = max(maxj_user, ju) if ju < 0.5 else maxj_user
            if ju >= 0.5:
                drops["near_user_or_dev"] += 1; continue
            if any(jac(sh, o) >= 0.85 for o in SH_strict):
                drops["near_prior_synth"] += 1; continue
            if any(jac(sh, o) >= 0.85 for o, osid in own_sh if osid != sid):
                drops["near_self"] += 1; continue
            own_h.add(h); own_sh.append((sh, sid))
            kept.append((r, side, it, h))
    with open(os.path.join(OUT, "targeted.jsonl"), "w") as fc, open(os.path.join(OUT, "targeted.meta.jsonl"), "w") as fm:
        for r, side, it, h in kept:
            s = r["spec"]
            fc.write(json.dumps({"messages": [{"role": "system", "content": pipeline.SYSTEM_PROMPT},
                                              {"role": "user", "content": it["ex"]["user"]},
                                              {"role": "assistant", "content": json.dumps({"verdict": it["label"]}, separators=(",", ":"))}]}) + "\n")
            fm.write(json.dumps({"scenario_id": s["scenario_id"] + "-" + side, "pair_id": s["scenario_id"], "family": s["family"],
                                 "variant": s[side + "_variant"], "label": it["label"], "rule": it["ex"]["rule"],
                                 "difficulty": s["difficulty"], "domain": s["domain"], "framework": s["framework"],
                                 "line": it["ex"]["line"], "n_lines": it["ex"]["n_lines"], "code_hash": h,
                                 "generator_rationale": r["gen"][side].get("rationale"),
                                 "judge_analysis": it.get("judge_analysis")}) + "\n")
    lab = collections.Counter(it["label"] for _, _, it, _ in kept)
    fam = collections.Counter(f"{r['spec']['family']}/{it['label'][:2]}" for r, _, it, _ in kept)
    rep = {"pairs": len(recs), "item_status": dict(st), "kept": len(kept), "kept_labels": dict(lab), "dedup_drops": dict(drops),
           "max_jaccard_vs_user_and_dev_kept": round(maxj_user, 3), "kept_by_family_label": dict(sorted(fam.items())),
           "judge_by_variant": {k: dict(v) for k, v in sorted(per.items())}, "spent_total_usd": metaapi.spent()}
    json.dump(rep, open(os.path.join(OUT, "targeted_report.json"), "w"), indent=1)
    return rep


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", type=int, default=400)
    ap.add_argument("--pilot", type=int, default=0)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--finalize-only", action="store_true")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    specs = build_specs(a.pairs)
    raw = os.path.join(OUT, "raw_targeted.jsonl")
    if a.pilot:
        specs = specs[:a.pilot]
    if not a.finalize_only:
        run(specs, raw, a.workers)
    rep = finalize(raw)
    print(json.dumps({k: v for k, v in rep.items() if k != "judge_by_variant"}, indent=1))
