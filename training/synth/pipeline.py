"""Shared synthetic-example pipeline: scenario catalogue -> Muse Spark generator -> independent Muse Spark judge
-> leak/format filters -> normalised-code dedup -> chat JSONL (same format as out/train.jsonl) + metadata sidecar."""
import hashlib, json, os, random, re, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import metaapi

HERE = os.path.dirname(os.path.abspath(__file__))
SYSTEM_PROMPT = ("You are a security triage assistant. You are given one static-analysis alert and the relevant Java "
                 "source code. Decide whether the alert is a real, exploitable vulnerability (true_positive) or a false "
                 "alarm (false_positive). Respond with strict JSON only: {\"verdict\":\"true_positive\"} or "
                 "{\"verdict\":\"false_positive\"}.")
SEMGREP_VERSION = "1.183.0"

CWE = {
    "sqli": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "xss": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "pathtraver": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "cmdi": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "deser": "CWE-502: Deserialization of Untrusted Data",
    "ssrf": "CWE-918: Server-Side Request Forgery (SSRF)",
    "hardcoded": "CWE-798: Use of Hard-coded Credentials",
    "crypto": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "xxe": "CWE-611: Improper Restriction of XML External Entity Reference",
    "redirect": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
    "logi": "CWE-117: Improper Output Neutralization for Logs",
}

# (variant_key, intended_label, description). Shared by stress and train; combos/ids are made disjoint per set.
VARIANTS = {
 "sqli": [
  ("concat_stmt", "true_positive", "request value concatenated into a JDBC Statement.executeQuery/executeUpdate string"),
  ("jpa_native_concat", "true_positive", "JPA EntityManager.createNativeQuery / @Query(nativeQuery=true) built by string concatenation or String.format with user input"),
  ("jdbctemplate_concat", "true_positive", "Spring JdbcTemplate.query/queryForList with a SQL string built from user input (e.g. dynamic ORDER BY or WHERE)"),
  ("orderby_bypass", "true_positive", "dynamic ORDER BY / column name where a validation check exists but is bypassable (e.g. startsWith / contains / case-insensitive check)"),
  ("prepared_ok", "false_positive", "PreparedStatement with ? placeholders and setString/setInt; the rule fires on string building of the constant SQL text"),
  ("named_param_ok", "false_positive", "JPA/Hibernate named parameters (:name) or NamedParameterJdbcTemplate with a MapSqlParameterSource"),
  ("derived_query_ok", "false_positive", "Spring Data repository derived query / @Query with bound parameters; concatenation only joins constant fragments"),
  ("allowlist_ok", "false_positive", "dynamic column/table name chosen from a fixed Map/enum/switch allowlist, user value never reaches SQL text"),
  ("numeric_ok", "false_positive", "user input parsed to int/long/UUID before concatenation, so no injection is possible"),
 ],
 "xss": [
  ("writer_raw", "true_positive", "servlet writes request parameter/header into response.getWriter() HTML without encoding"),
  ("thymeleaf_utext", "true_positive", "Spring MVC model attribute from user input rendered via th:utext or returned as @ResponseBody text/html string"),
  ("wrong_context", "true_positive", "an encoder is present but wrong for the context (e.g. HTML-encoding into a JavaScript string or an unquoted attribute, or URL-encoding into HTML)"),
  ("encode_wrong_var", "true_positive", "encoder applied to a different variable / to a copy, while the raw value is the one written"),
  ("encoder_ok", "false_positive", "OWASP Java Encoder Encode.forHtml / StringEscapeUtils.escapeHtml4 / HtmlUtils.htmlEscape applied before writing"),
  ("json_ok", "false_positive", "response content type is application/json produced by Jackson ObjectMapper, or text/plain, not rendered as HTML"),
  ("thymeleaf_text_ok", "false_positive", "Thymeleaf th:text auto-escaping / JAX-RS returning a DTO; the rule fires on a raw-string-looking helper"),
  ("constant_ok", "false_positive", "value written is a server-side constant or a number/enum not derived from the request"),
 ],
 "pathtraver": [
  ("raw_join", "true_positive", "new File(baseDir, userFilename) or Paths.get(base, input) read/served without any check"),
  ("startswith_noncanon", "true_positive", "startsWith(baseDir) check on the non-normalised/non-canonical path (bypassable with ../)"),
  ("blacklist_bypass", "true_positive", "replace(\"../\", \"\") single-pass filter or checks only for '..' in one encoding"),
  ("zip_slip", "true_positive", "ZipEntry name used to build output file without normalisation check"),
  ("canonical_ok", "false_positive", "getCanonicalPath()/toRealPath()/normalize() then startsWith(base) check before access"),
  ("allowlist_ok", "false_positive", "filename looked up in a fixed allowlist/Map or must match ^[a-zA-Z0-9_-]+\\.pdf$ regex with matches()"),
  ("id_lookup_ok", "false_positive", "user supplies a numeric id/UUID, path built from a DB record or UUID.fromString, not raw input"),
  ("getname_ok", "false_positive", "Paths.get(input).getFileName() / FilenameUtils.getName strips directories before joining"),
 ],
 "cmdi": [
  ("shell_concat", "true_positive", "Runtime.exec(\"sh -c ...\" + input) or ProcessBuilder(\"bash\",\"-c\", cmd+input)"),
  ("exec_string_args", "true_positive", "Runtime.exec(String) with user-controlled argument that allows option injection or command splitting in a shell"),
  ("bypassable_check", "true_positive", "validation that checks for ';' only, or a regex without anchors, before passing to a shell"),
  ("array_args_ok", "false_positive", "ProcessBuilder with a String[]/List argv (no shell) and a fixed executable, user value is a validated single argument"),
  ("enum_ok", "false_positive", "command chosen from an enum/switch of fixed commands; user input only selects which"),
  ("constant_ok", "false_positive", "command built only from configuration constants / static final values, not request data"),
  ("regex_ok", "false_positive", "argument must fully match a strict anchored regex like ^[0-9]{1,5}$ before use, no shell"),
 ],
 "deser": [
  ("ois_request", "true_positive", "ObjectInputStream.readObject on request body / cookie / socket bytes with no filter"),
  ("xstream_jackson_poly", "true_positive", "XStream.fromXML on user input without allowlist, or Jackson enableDefaultTyping / @JsonTypeInfo(use=CLASS) on untrusted JSON"),
  ("snakeyaml_load", "true_positive", "SnakeYAML new Yaml().load(userInput) with default constructor (older API)"),
  ("filter_ok", "false_positive", "ObjectInputStream with ObjectInputFilter allowlisting a few DTO classes, or a look-ahead subclass overriding resolveClass"),
  ("trusted_source_ok", "false_positive", "readObject on a classpath resource / file written by the app itself in a private directory, not attacker-controlled"),
  ("safe_parser_ok", "false_positive", "Jackson readValue into a concrete final DTO class without default typing, or SnakeYAML with SafeConstructor"),
 ],
 "ssrf": [
  ("raw_url", "true_positive", "new URL(userUrl).openConnection() / RestTemplate.getForObject(userUrl) / HttpClient with user URL"),
  ("weak_host_check", "true_positive", "host check via contains()/endsWith(\"example.com\") or startsWith on the URL string (bypassable)"),
  ("redirect_follow", "true_positive", "allowlisted host but path/query from user and client follows redirects, or URL built by concatenating user host"),
  ("host_allowlist_ok", "false_positive", "URI parsed, scheme must be https and host must equal an entry in a Set allowlist before request"),
  ("fixed_base_ok", "false_positive", "fixed base URL constant; user value is only a URL-encoded path segment/query value (UriComponentsBuilder encode)"),
  ("config_ok", "false_positive", "URL comes from server-side configuration / @Value property, not from the request"),
 ],
 "hardcoded": [
  ("prod_password", "true_positive", "real-looking database/LDAP password or API secret hardcoded in production code and used to connect"),
  ("jwt_secret", "true_positive", "hardcoded JWT/HMAC signing key or AES key literal used in production code"),
  ("aws_key", "true_positive", "real-looking cloud access key id + secret literal in a client builder (random-looking, NOT the AWS documentation EXAMPLE keys)"),
  ("env_lookup_ok", "false_positive", "variable named password/secret but value comes from System.getenv / @Value / vault lookup; literal is only the env var name"),
  ("placeholder_ok", "false_positive", "literal is an empty string / placeholder like \"changeme\" used only to detect unset config and throw"),
  ("test_constant_ok", "false_positive", "test-only code (JUnit test class or embedded test DB fixture) with a dummy password"),
  ("non_secret_ok", "false_positive", "constant is a parameter/field name, header name, or message key like PASSWORD_PARAM = \"password\""),
 ],
 "crypto": [
  ("md5_password", "true_positive", "MD5 or SHA-1 used to hash passwords or as a token/signature/MAC for authentication"),
  ("des_ecb", "true_positive", "DES/3DES or AES/ECB used to encrypt sensitive data at rest or in transit"),
  ("sha1_sig", "true_positive", "SHA-1 used for integrity of security-relevant data (e.g. download verification, signed URL)"),
  ("checksum_ok", "false_positive", "MD5/SHA-1 used only as a non-security checksum, ETag, cache key, or dedup fingerprint"),
  ("legacy_interop_ok", "false_positive", "MD5 used for a protocol-mandated non-security purpose (e.g. Content-MD5 header, partition bucketing, UUID v3)"),
  ("strong_ok", "false_positive", "rule fires on getInstance with a variable, but the algorithm resolves to AES/GCM/NoPadding or SHA-256 constant"),
 ],
 "xxe": [
  ("dbf_default", "true_positive", "DocumentBuilderFactory/SAXParserFactory parsing uploaded/requested XML with default settings"),
  ("partial_hardening", "true_positive", "only some features set (e.g. setExpandEntityReferences(false) only, or feature set on a different factory instance)"),
  ("unmarshaller_xif", "true_positive", "JAXB Unmarshaller over an XMLInputFactory/XMLStreamReader without disabling external entities"),
  ("disallow_doctype_ok", "false_positive", "disallow-doctype-decl true (or ACCESS_EXTERNAL_DTD/SCHEMA empty and FEATURE_SECURE_PROCESSING) set on the same factory before parsing"),
  ("trusted_resource_ok", "false_positive", "parses a bundled classpath config resource, not user-supplied XML"),
  ("hardened_helper_ok", "false_positive", "factory obtained from a hardened helper method shown in the snippet that sets the required features"),
 ],
 "redirect": [
  ("raw_redirect", "true_positive", "response.sendRedirect(request.getParameter(\"next\")) or Spring \"redirect:\" + url"),
  ("weak_check", "true_positive", "check like url.startsWith(\"/\") (allows //evil.com) or contains(\"mycompany.com\")"),
  ("relative_ok", "false_positive", "only relative paths accepted: URI parsed, must have no scheme/host and path starts with single '/' and not '//'"),
  ("allowlist_ok", "false_positive", "redirect target chosen from a Map of known keys or host compared exactly with allowlist"),
  ("constant_ok", "false_positive", "redirect target is a constant or built from server-side route names"),
 ],
 "logi": [
  ("raw_log", "true_positive", "logger.info(\"...\" + request param) with plain-text log appender and no CR/LF neutralisation"),
  ("partial_strip", "true_positive", "only \\n stripped but \\r left, or sanitisation applied to a different variable"),
  ("encoded_ok", "false_positive", "value has CR/LF replaced/escaped (replaceAll(\"[\\r\\n]\", \"_\")) or Encode.forJava before logging"),
  ("structured_ok", "false_positive", "structured JSON logging (logstash encoder / kv args) where values are JSON-escaped, or value is a parsed number/UUID"),
  ("constant_ok", "false_positive", "logged value is server-generated (request id from UUID.randomUUID, enum, counter)"),
 ],
}

TWISTS_TP = [
    "straightforward data flow",
    "taint flows through a collection (List/Map) or a Java stream pipeline before the sink",
    "taint flows through a builder/StringBuilder/String.format/helper method before the sink",
    "a validation step exists but is bypassable",
    "the code looks innocent and well-structured (good naming, logging, error handling) but is still exploitable",
    "the input arrives via a header, cookie, path variable or JSON body field rather than a query param",
]
TWISTS_FP = [
    "straightforward protection",
    "the neutralising helper/sanitizer is a separate method shown in the snippet",
    "the alert is on dead code or a branch whose value is always a constant",
    "test-only code (JUnit test class or test fixture)",
    "framework-provided protection (Spring Data, @Valid with @Pattern regex, typed path variable, JPA parameter binding)",
    "user data passes through a collection/stream, but is replaced by a constant or validated value before the sink",
]
FRAMEWORKS = ["plain Java Servlet (HttpServlet)", "Spring MVC @Controller", "Spring Boot @RestController",
              "JAX-RS (Jakarta REST) resource", "Android Activity/ContentProvider/Service (Java)",
              "plain Java service/DAO class", "Spring @Service with repository", "Jakarta EE / Jakarta Servlet filter",
              "scheduled batch job / CLI tool", "Micronaut or Quarkus controller (Java)"]
DIFFICULTY = ["easy", "medium", "hard"]

GEN_SCHEMA = ("synthetic_alert", {
    "type": "object",
    "properties": {
        "file_name": {"type": "string"},
        "rule_id": {"type": "string"},
        "severity": {"type": "string", "enum": ["ERROR", "WARNING", "INFO"]},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "message": {"type": "string"},
        "code": {"type": "string"},
        "flagged_line": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["file_name", "rule_id", "severity", "confidence", "message", "code", "flagged_line", "rationale"],
})
JUDGE_SCHEMA = ("triage", {
    "type": "object",
    "properties": {"analysis": {"type": "string"},
                   "verdict": {"type": "string", "enum": ["true_positive", "false_positive"]}},
    "required": ["analysis", "verdict"],
})

JUDGE_SYSTEM = ("You are a senior application-security engineer reviewing static-analysis findings for a Java codebase. "
                "Trace the data flow from sources to the flagged sink using ONLY the code shown. Consider whether an "
                "attacker can actually control the value, whether neutralisation/validation is correct and complete for "
                "the sink's context, whether the code is reachable production code, and whether the flagged API use is "
                "actually security-relevant. A finding is true_positive if the flagged code is a real, exploitable "
                "weakness of the reported CWE as shown; otherwise false_positive. Give a short analysis (<=80 words), "
                "then the verdict.")


def build_scenarios(n, set_name, seed, domains, prompt_style):
    """Balanced scenario specs: round-robin over categories, alternate labels, random framework/twist/domain."""
    rng = random.Random(seed)
    cats = list(VARIANTS)
    specs, seen = [], set()
    i = 0
    while len(specs) < n:
        cat = cats[i % len(cats)]
        label = "true_positive" if (i // len(cats)) % 2 == 0 else "false_positive"
        i += 1
        var = rng.choice([v for v in VARIANTS[cat] if v[1] == label])
        twist = rng.choice(TWISTS_TP if label == "true_positive" else TWISTS_FP)
        fw = rng.choice(FRAMEWORKS)
        dom = rng.choice(domains)
        diff = rng.choices(DIFFICULTY, weights=[2, 3, 3])[0]
        key = (cat, var[0], twist, fw, dom, diff)
        if key in seen:
            continue
        seen.add(key)
        sid = f"{set_name}-{cat}-{var[0]}-" + hashlib.sha1(repr(key + (set_name, seed)).encode()).hexdigest()[:8]
        specs.append({"scenario_id": sid, "set": set_name, "category": cat, "variant": var[0], "intended_label": label,
                      "variant_desc": var[2], "twist": twist, "framework": fw, "domain": dom, "difficulty": diff,
                      "prompt_style": prompt_style, "cwe": CWE[cat]})
    return specs


def gen_messages(spec, style_note):
    label_txt = ("a REAL, exploitable vulnerability (the alert is a TRUE POSITIVE)" if spec["intended_label"] == "true_positive"
                 else "NOT exploitable (the alert is a FALSE POSITIVE, the scanner over-approximates)")
    sys_p = ("You write realistic Java source snippets and matching Semgrep alerts to build a benchmark for triaging "
             "static-analysis findings. Precision matters: the ground truth you are asked for must be unambiguously "
             "correct to an expert who sees only the snippet. " + style_note)
    user = f"""Create ONE example.

Category: {spec['cwe']}
Scenario: {spec['variant_desc']}
Twist: {spec['twist']}
Ground truth required: {label_txt}
Framework/style: {spec['framework']}
Application domain: {spec['domain']}
Difficulty: {spec['difficulty']} (hard = an expert must read carefully; the deciding detail is subtle but visible)

Requirements:
- `code`: 15-60 lines of compilable-looking Java (no Kotlin). Start at the class declaration (omit package and imports; use fully-qualified names where a library's identity matters, e.g. org.owasp.encoder.Encode). Include any helper method that decides the outcome. Realistic class/method/variable names for the domain.
- NO comments at all. Do not use words that reveal the answer in identifiers or strings (no safe/unsafe/vulnerable/insecure/sanitized/tainted/attacker/exploit/malicious/bypass/check-passed). Real library APIs (e.g. SafeConstructor) are fine.
- A Semgrep-OSS-style alert: `rule_id` like java.lang.security.audit.<topic>.<rule-name>.<rule-name> or java.spring.security.<...> or com.example.security.<...>; `message` 1-3 sentences in Semgrep's style describing the pattern matched (it must NOT state the verdict); `severity` and `confidence` plausible (scanners often say HIGH confidence even on false positives).
- `flagged_line`: copy EXACTLY one line of `code` (the sink line the rule matches).
- `file_name`: e.g. InvoiceExportController.java (matches the class).
- The rule must plausibly fire on this code regardless of the ground truth.
- `rationale`: <=40 words, why the ground truth holds."""
    return [{"role": "system", "content": sys_p}, {"role": "user", "content": user}]


# ---------------------------------------------------------------------------------------------------------------
_STR = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def strip_comments(code):
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c in "\"'":
            m = _STR.match(code, i)
            if m:
                out.append(m.group(0)); i = m.end(); continue
        if code.startswith("//", i):
            j = code.find("\n", i); i = n if j < 0 else j; continue
        if code.startswith("/*", i):
            j = code.find("*/", i + 2); seg = code[i:(n if j < 0 else j + 2)]
            out.append("\n" * seg.count("\n")); i = n if j < 0 else j + 2; continue
        out.append(c); i += 1
    return "".join(out)


BANNED = {"vulnerable", "vulnerability", "vuln", "insecure", "unsafe", "exploit", "exploitable", "malicious", "attacker",
          "tainted", "taint", "safe", "safely", "sanitized", "unsanitized", "noncompliant", "bypass", "evil", "pwned",
          "truepositive", "falsepositive", "xss", "sqli", "injectable"}
ALLOWED_IDENTS = {"SafeConstructor", "SafeHtml", "SafeUrl", "safeFileName"}  # real APIs; safeFileName not used


def leak_tokens(code):
    hits = []
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code):
        if ident in ALLOWED_IDENTS:
            continue
        parts = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", ident)
        for p in parts:
            if p.lower() in BANNED:
                hits.append(ident)
    for s in _STR.findall(code):
        for w in re.findall(r"[A-Za-z]+", s):
            if w.lower() in BANNED:
                hits.append(s[:30])
    return sorted(set(hits))


def format_example(spec, g, rng):
    code = strip_comments(g["code"].replace("\t", "    ")).rstrip()
    lines = code.split("\n")
    # drop package/import lines if model included them
    lines = [l for l in lines if not re.match(r"\s*(package|import)\s+[\w.*]+;\s*$", l)]
    while lines and not lines[0].strip():
        lines.pop(0)
    start = rng.randint(8, 40)
    numbered, flagged_no = [], None
    fl = re.sub(r"\s+", " ", strip_comments(g["flagged_line"]).strip())
    for k, t in enumerate(lines):
        n = start + k
        if not t.strip():
            continue  # blank / comment-only lines removed, numbers keep gaps (same as OWASP build)
        numbered.append(f"{n:>4} | {t.rstrip()}")
        if flagged_no is None and fl and re.sub(r"\s+", " ", t.strip()) == fl:
            flagged_no = n
    if flagged_no is None:  # fall back to containment
        for k, t in enumerate(lines):
            if fl and t.strip() and (fl in re.sub(r"\s+", " ", t) or re.sub(r"\s+", " ", t.strip()) in fl):
                flagged_no = start + k; break
    nlines = len(numbered)
    if flagged_no is None or not (12 <= nlines <= 70):
        return None, f"format(flag={flagged_no is not None},lines={nlines})"
    # dedent
    body = [l.split(" | ", 1)[1] for l in numbered]
    ind = min(len(b) - len(b.lstrip()) for b in body if b.strip())
    numbered = [l.split(" | ", 1)[0] + " | " + l.split(" | ", 1)[1][ind:] for l in numbered]
    rule = re.sub(r"\s+", "", g["rule_id"])
    fname = re.sub(r"[^\w.]", "", g["file_name"]) or "App.java"
    if not fname.endswith(".java"):
        fname += ".java"
    user = ("Static-analysis alert\n"
            f"Tool: Semgrep {SEMGREP_VERSION}\n"
            f"Rule: {rule}\n"
            f"Severity: {g['severity']} (rule confidence: {g['confidence']})\n"
            f"CWE: {spec['cwe']}\n"
            f"Location: {fname}:{flagged_no}\n"
            f"Message: {' '.join(g['message'].split())}\n\n"
            "Code (line-numbered, comments removed):\n"
            "```java\n" + "\n".join(numbered) + "\n```")
    return {"user": user, "code_body": "\n".join(body), "rule": rule, "file": fname, "line": flagged_no,
            "n_lines": nlines}, None


def norm_hash(code_body):
    s = _STR.sub('"S"', code_body)
    s = re.sub(r"\b\d+\b", "0", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return hashlib.sha1(s.encode()).hexdigest()


def shingles(code_body, k=5):
    toks = re.findall(r"[A-Za-z_]\w*|\S", _STR.sub('"S"', code_body))
    return {" ".join(toks[i:i + k]) for i in range(max(1, len(toks) - k + 1))}


JUDGE_EFFORT = "medium"
GEN_EFFORT = "low"


def judge(user_msg):
    content, _ = metaapi.chat([{"role": "system", "content": JUDGE_SYSTEM},
                               {"role": "user", "content": user_msg}],
                              tag="judge", max_tokens=6000, reasoning_effort=JUDGE_EFFORT, schema=JUDGE_SCHEMA)
    j = json.loads(content)
    return j["verdict"], j.get("analysis", "")


def process(spec, style_note, seed):
    rng = random.Random(seed)
    rec = {"spec": spec}
    try:
        content, _ = metaapi.chat(gen_messages(spec, style_note), tag=f"gen_{spec['set']}", max_tokens=8000,
                                  reasoning_effort=GEN_EFFORT, schema=GEN_SCHEMA, temperature=1.0)
        g = json.loads(content)
    except metaapi.BudgetExceeded as e:
        rec["status"] = "budget"; rec["err"] = str(e); return rec
    except Exception as e:
        rec["status"] = "gen_error"; rec["err"] = str(e)[:300]; return rec
    rec["gen"] = g
    leaks = leak_tokens(strip_comments(g.get("code", "")))
    if leaks:
        rec["status"] = "leak"; rec["leaks"] = leaks; return rec
    ex, why = format_example(spec, g, rng)
    if ex is None:
        rec["status"] = "format"; rec["err"] = why; return rec
    rec["ex"] = ex
    try:
        v, analysis = judge(ex["user"])
    except metaapi.BudgetExceeded as e:
        rec["status"] = "budget"; rec["err"] = str(e); return rec
    except Exception as e:
        rec["status"] = "judge_error"; rec["err"] = str(e)[:300]; return rec
    rec["judge_verdict"], rec["judge_analysis"] = v, analysis
    rec["status"] = "agree" if v == spec["intended_label"] else "disagree"
    return rec


def run(specs, style_note, raw_path, workers=16, seed=0):
    """Resumable: scenario_ids already in raw_path are skipped."""
    done = set()
    if os.path.exists(raw_path):
        for l in open(raw_path):
            r = json.loads(l)
            if r.get("status") not in ("budget", "gen_error", "judge_error"):
                done.add(r["spec"]["scenario_id"])
    todo = [s for s in specs if s["scenario_id"] not in done]
    print(f"[run] {len(specs)} specs, {len(done)} done, {len(todo)} to do; spent so far ${metaapi.spent():.3f}", flush=True)
    lock = threading.Lock()
    stop = threading.Event()
    n = 0
    with open(raw_path, "a") as f, ThreadPoolExecutor(workers) as ex:
        futs = {}
        for k, s in enumerate(todo):
            futs[ex.submit(lambda s=s, k=k: None if stop.is_set() else process(s, style_note, seed * 100003 + k))] = s
        for fu in as_completed(futs):
            r = fu.result()
            if r is None:
                continue
            if r["status"] == "budget":
                stop.set()
            with lock:
                f.write(json.dumps(r) + "\n"); f.flush()
                n += 1
                if n % 25 == 0:
                    print(f"[run] {n}/{len(todo)} spent ${metaapi.spent():.3f}", flush=True)
    print(f"[run] finished; spent ${metaapi.spent():.3f}", flush=True)


def finalize(raw_path, out_chat, out_meta, exclude_hashes=(), exclude_shingles=(), jaccard=0.85, report_path=None):
    """Keep judge-agreeing examples, dedupe (exact normalised hash + near-dup shingle Jaccard), write chat+sidecar."""
    import collections
    recs = [json.loads(l) for l in open(raw_path)]
    last = {}
    for r in recs:  # last record per scenario wins (resumes)
        last[r["spec"]["scenario_id"]] = r
    recs = list(last.values())
    stat = collections.Counter(r["status"] for r in recs)
    per = collections.defaultdict(lambda: collections.Counter())
    for r in recs:
        if r["status"] in ("agree", "disagree"):
            per[(r["spec"]["category"], r["spec"]["variant"], r["spec"]["intended_label"])][r["status"]] += 1
    kept, hashes, sh_list = [], set(exclude_hashes), []
    ex_sh = list(exclude_shingles)
    dup_exact = dup_near = dup_cross = 0
    for r in sorted(recs, key=lambda r: r["spec"]["scenario_id"]):
        if r["status"] != "agree":
            continue
        h = norm_hash(r["ex"]["code_body"])
        if h in hashes:
            dup_exact += 1; continue
        sh = shingles(r["ex"]["code_body"])
        def jac(a, b):
            return len(a & b) / max(1, len(a | b))
        if any(jac(sh, o) >= jaccard for o in ex_sh):
            dup_cross += 1; continue
        if any(jac(sh, o) >= jaccard for o in sh_list):
            dup_near += 1; continue
        hashes.add(h); sh_list.append(sh)
        kept.append((r, h))
    with open(out_chat, "w") as fc, open(out_meta, "w") as fm:
        for r, h in kept:
            s = r["spec"]
            fc.write(json.dumps({"messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": r["ex"]["user"]},
                {"role": "assistant", "content": json.dumps({"verdict": s["intended_label"]}, separators=(",", ":"))}]}) + "\n")
            fm.write(json.dumps({"scenario_id": s["scenario_id"], "category": s["category"], "variant": s["variant"],
                                 "difficulty": s["difficulty"], "intended_label": s["intended_label"],
                                 "twist": s["twist"], "framework": s["framework"], "domain": s["domain"],
                                 "rule": r["ex"]["rule"], "file": r["ex"]["file"], "line": r["ex"]["line"],
                                 "n_lines": r["ex"]["n_lines"], "code_hash": h,
                                 "generator_rationale": r["gen"].get("rationale"),
                                 "judge_analysis": r.get("judge_analysis")}) + "\n")
    cat_stats = collections.defaultdict(collections.Counter)
    for (c, v, l), cnt in per.items():
        cat_stats[c]["agree"] += cnt["agree"]; cat_stats[c]["disagree"] += cnt["disagree"]
    lab = collections.Counter(r["spec"]["intended_label"] for r, _ in kept)
    catk = collections.Counter(r["spec"]["category"] for r, _ in kept)
    rep = {"raw_records": len(recs), "status": dict(stat), "kept": len(kept), "kept_labels": dict(lab),
           "kept_by_category": dict(catk), "dedup_exact": dup_exact, "dedup_near": dup_near,
           "dedup_cross_set": dup_cross,
           "judge_disagreement_by_category": {c: {"agree": v["agree"], "disagree": v["disagree"],
                                                  "disagree_rate": round(v["disagree"] / max(1, v["agree"] + v["disagree"]), 3)}
                                              for c, v in sorted(cat_stats.items())},
           "judge_disagreement_by_scenario": {f"{c}/{v}/{l}": {"agree": cnt["agree"], "disagree": cnt["disagree"],
                                                               "disagree_rate": round(cnt["disagree"] / max(1, cnt["agree"] + cnt["disagree"]), 3)}
                                              for (c, v, l), cnt in sorted(per.items())}}
    if report_path:
        json.dump(rep, open(report_path, "w"), indent=2)
    return rep, kept
