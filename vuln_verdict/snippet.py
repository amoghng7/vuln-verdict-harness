"""Code-context formatting for classifier prompts.

Vendored from the vuln-verdict dataset builders (out/scripts/build_dataset.py for the OWASP/real-set layout,
dev/scripts/build_dev.py for the generic fallback) so prompts at inference time have the same layout the
classifier was trained and evaluated on: comments stripped, blank lines dropped, the alerted class renamed to
`RequestHandler`, original line numbers right-aligned in a 4-char column (`  33 | code`), elided spans shown as
`     | ...`, and files longer than MAX_SNIPPET_LINES (60) cut to a window around the alert line.
"""
import hashlib, re

MAX_SNIPPET_LINES = 60

LITERAL_MAP = {
    "safe": "alpha", "moresafe": "beta", "alsosafe": "gamma", " SafeStuff": " stuff",
    "safe!": "constant_value", "This should never happen": "value_one",
    "This_should_always_happen": "value_two",
}
LEAKY_LITERAL = re.compile(
    r"safe|vuln|never happen|always happen|benchmark|test ?case|cmdi|sqli|xss|pathtrav|ldapi|xpathi|"
    r"crypto|hash|weakrand|trustbound|securecookie|owasp", re.I)


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


def anonymise(code, cls):
    code = code.replace(cls, "RequestHandler")
    code = re.sub(r"BenchmarkTest\d{5}", "RequestHandler", code)
    code = code.replace("org.owasp.benchmark", "com.example.app")

    def lit(m):
        r = neutral_literal(m.group(1))
        return m.group(0) if r is None else '"' + r + '"'
    code = re.sub(r'"((?:[^"\\\n]|\\.)*)"', lit, code)
    return re.sub(r"[Bb]enchmark", "app", code)


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


def extract_snippet(raw, cls, alert_line):
    """Dataset-builder layout (used for OWASP train/val/test and the real-world eval set).
    Raises StopIteration if `class <cls>` is not declared in the file."""
    src = strip_comments(raw)
    lines = src.split("\n")
    keep = [True] * len(lines)
    c0 = next(i for i, l in enumerate(lines) if re.search(r"\bclass\s+" + re.escape(cls) + r"\b", l))
    for i in range(c0): keep[i] = False
    m = re.search(r"public void doGet\s*\(", src)
    if m:
        ob = src.index("{", m.end()); cb = match_brace(src, ob)
        s_line = src.count("\n", 0, m.start()); e_line = src.count("\n", 0, cb)
        if not (s_line <= alert_line - 1 <= e_line):  # never elide the alerted line itself
            for i in range(s_line, e_line + 1): keep[i] = False
            if s_line > 0 and lines[s_line - 1].strip() == "@Override": keep[s_line - 1] = False
    out = []
    for i, l in enumerate(lines):
        if not keep[i] or not l.strip() or "serialVersionUID" in l: continue
        out.append((i + 1, anonymise(l.rstrip(), cls)))
    joined = []
    for n, t in out:
        st = t.strip()
        if joined and (st[:1] in ".+)?:" or st.startswith("&&") or st.startswith("||")
                       or joined[-1][1].rstrip()[-1:] in "(=,+") and not st.startswith("@"):
            joined[-1] = (joined[-1][0], joined[-1][1].rstrip() + ("" if st[:1] in ".)" or joined[-1][1].rstrip()[-1:] == "(" else " ") + st)
        else:
            joined.append((n, t))
    out = joined
    truncated = windowed = False
    if len(out) > MAX_SNIPPET_LINES:
        truncated = True
        sig = next((k for k, (_, t) in enumerate(out) if "void doPost(" in t), None)
        if sig is not None:
            body = next((k for k in range(sig, len(out)) if out[k][1].rstrip().endswith("{")), sig) + 1
            first_bar = next((k for k in range(body, len(out)) if re.search(r"\bbar\b", out[k][1])), body)
            k = min(len(out) - MAX_SNIPPET_LINES + 1, max(0, first_bar - body - 1))
            if k > 0:
                ind = out[body][1][: len(out[body][1]) - len(out[body][1].lstrip())]
                out = out[:body] + [(None, ind + "...")] + out[body + k:]
    if len(out) > MAX_SNIPPET_LINES:
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
        windowed = True
        idx = min(range(len(out)), key=lambda k: abs((out[k][0] or 0) - alert_line))
        start = max(0, min(idx - MAX_SNIPPET_LINES // 2, len(out) - MAX_SNIPPET_LINES))
        out = out[start:start + MAX_SNIPPET_LINES]
    return out, truncated, windowed


_MDECL = re.compile(r'^\s*(public|private|protected|static|final|synchronized|\s)*[\w<>\[\],.?\s]+\s+(\w+)\s*\(')


def generic_snippet(raw, cls, line):
    """Fallback layout from the dev-set builder (files whose primary type is not `class <FileName>`)."""
    src = strip_comments(raw); lines = src.split("\n")
    c0 = next((i for i, l in enumerate(lines) if re.search(r"\b(class|interface|enum|record)\s+" + re.escape(cls) + r"\b", l)), 0)
    out = [(i + 1, re.sub(r'\b' + re.escape(cls) + r'\b', 'RequestHandler', l.rstrip())) for i, l in enumerate(lines)
           if i >= c0 and l.strip() and 'serialVersionUID' not in l]
    if not any(n == line for n, _ in out):  # alert above the type declaration (e.g. annotations): start at file top
        out = [(i + 1, l.rstrip()) for i, l in enumerate(lines) if l.strip()]
    windowed = False
    if len(out) > MAX_SNIPPET_LINES:
        windowed = True
        idx = min(range(len(out)), key=lambda k: abs(out[k][0] - line))
        s = idx
        while s > 0 and not (_MDECL.match(out[s][1]) and not re.match(r'\s*(if|for|while|switch|catch|return|new|else|throw)\b', out[s][1])): s -= 1
        if idx - s > MAX_SNIPPET_LINES - 12: s = idx - MAX_SNIPPET_LINES // 2
        s = max(0, s - 2); s = min(s, len(out) - MAX_SNIPPET_LINES)
        out = [out[0]] + [(None, "    ...")] + out[s:s + MAX_SNIPPET_LINES - 2] if s > 1 else out[s:s + MAX_SNIPPET_LINES]
    return out, windowed, windowed


def dedent(block):
    ind = min((len(t) - len(t.lstrip()) for _, t in block if t.strip()), default=0)
    return [(n, t[ind:]) for n, t in block]


# Optional evaluation-only scrubbing (used for the real-world eval set built from a deliberately vulnerable repo):
# identifiers / literals whose names announce the (in)security of the code are replaced by neutral ids.
SCRUB_IDENT = re.compile(r'(?i)vulnerab|insecure|unsafe|untrusted|injection|ssrf|exfiltration|xxe|weak|predictable|hardcoded|bypass|redos|traversal|novalidation|nocontentvalidation|withoutalgorithmvalidation|demonstrate|^getsecureuser$|^rendersecurecontent$')
SCRUB_LIT = re.compile(r'(?i)ssrf|malicious|attacker|evil|vuln|exploit|intentional')


def _neutral(tok):
    h = hashlib.sha1(tok.encode()).hexdigest()[:6]
    if tok.isupper(): return 'CONST_' + h
    if tok[0].isupper(): return 'Type_' + h
    return 'fn_' + h


def scrub(lines):
    out = []
    for n, t in lines:
        parts = re.split(r'("(?:[^"\\\n]|\\.)*")', t)
        for k, p in enumerate(parts):
            if k % 2:
                if SCRUB_LIT.search(p[1:-1]): parts[k] = '"msg_' + hashlib.sha1(p[1:-1].encode()).hexdigest()[:6] + '"'
            else:
                parts[k] = re.sub(r'[A-Za-z_]\w*', lambda m: _neutral(m.group()) if SCRUB_IDENT.search(m.group()) else m.group(), p)
        out.append((n, ''.join(parts)))
    return out


def format_code(raw, path, line, do_scrub=False):
    """Returns (code_block_text, truncated, windowed). Same layout as the training prompts."""
    cls = path.replace("\\", "/").split("/")[-1].rsplit(".", 1)[0]
    try:
        snip, trunc, windowed = extract_snippet(raw, cls, line)
    except StopIteration:
        snip, trunc, windowed = generic_snippet(raw, cls, line)
    snip = dedent(snip)
    if do_scrub:
        snip = scrub(snip)
    code = "\n".join((f"{n:>4} | {t}" if n else f"     | {t}") for n, t in snip)
    return code, trunc, windowed
