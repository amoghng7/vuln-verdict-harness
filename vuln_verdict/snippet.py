"""Code-context formatting for classifier prompts.

Vendored from the vuln-verdict dataset builders (out/scripts/build_dataset.py for the OWASP/real-set layout,
dev/scripts/build_dev.py for the generic fallback) so prompts at inference time have the same layout the
classifier was trained and evaluated on: comments stripped, blank lines dropped, the alerted class renamed to
`RequestHandler`, original line numbers right-aligned in a 4-char column (`  33 | code`), elided spans shown as
`     | ...`, and files longer than MAX_SNIPPET_LINES (60) cut to a window around the alert line.

Class, package, and benchmark-identifier renaming is token-exact. It does not rewrite string literals,
character literals, text blocks, or comments. `neutral_literal()` still scrubs ordinary single-line strings.
"""
import hashlib, re

MAX_SNIPPET_LINES = 60
_BENCH_TEST = re.compile(r"BenchmarkTest\d{5}")
_BENCH_SUB = re.compile(r"[Bb]enchmark")

LITERAL_MAP = {
    "safe": "alpha", "moresafe": "beta", "alsosafe": "gamma", " SafeStuff": " stuff",
    "safe!": "constant_value", "This should never happen": "value_one",
    "This_should_always_happen": "value_two",
}
LEAKY_LITERAL = re.compile(
    r"safe|vuln|never happen|always happen|benchmark|test ?case|cmdi|sqli|xss|pathtrav|ldapi|xpathi|"
    r"crypto|hash|weakrand|trustbound|securecookie|owasp", re.I)


def _ident_start(c):
    return c.isascii() and (c.isalpha() or c in "_$")


def _ident_part(c):
    return c.isascii() and (c.isalnum() or c in "_$")


def _match_char_literal(src, i):
    """Return the end offset of a confident character literal, or None."""
    n = len(src)
    if i + 2 >= n or src[i] != "'":
        return None
    if src[i + 1] == "\\":
        e = src[i + 2]
        if e in "btnfr\"'\\":
            end = i + 4
        elif e == "u":
            h = i + 3
            while h < n and src[h] == "u":
                h += 1
            if h + 4 > n or any(src[h + k] not in "0123456789abcdefABCDEF" for k in range(4)):
                return None
            end = h + 5
        elif e in "01234567":
            h = i + 3
            count = 1
            while h < n and count < 3 and src[h] in "01234567":
                h += 1
                count += 1
            end = h + 1
        else:
            return None
        if end <= n and src[end - 1] == "'":
            return end
        return None
    if src[i + 1] not in "'\\\n\r" and src[i + 2] == "'":
        return i + 3
    return None


def java_tokens(src):
    """Cover `src` with lexical tokens.

    Kinds: ws, comment, string, char, text, ident, other, opaque.
    An unclosed string, character literal, or text block becomes one opaque token through
    the end of the source so later identifier renaming cannot corrupt it.
    """
    i, n = 0, len(src)
    tokens = []
    while i < n:
        c = src[i]
        if c in " \t\r\n\f":
            j = i + 1
            while j < n and src[j] in " \t\r\n\f":
                j += 1
            tokens.append(("ws", i, j)); i = j; continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            tokens.append(("comment", i, j)); i = j; continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                tokens.append(("comment", i, n)); i = n
            else:
                tokens.append(("comment", i, j + 2)); i = j + 2
            continue
        if src.startswith('"""', i):
            k = i + 3
            while k < n and src[k] in " \t\f":
                k += 1
            if k < n and src[k] in "\r\n":
                if src[k] == "\r" and k + 1 < n and src[k + 1] == "\n":
                    body = k + 2
                else:
                    body = k + 1
                j, closed = body, False
                while j < n:
                    if src[j] == "\\":
                        j += 2 if j + 1 < n else 1
                        continue
                    if src.startswith('"""', j):
                        tokens.append(("text", i, j + 3)); i = j + 3; closed = True
                        break
                    j += 1
                if not closed:
                    tokens.append(("opaque", i, n))
                    break
                continue
        if c == '"':
            j, closed = i + 1, False
            while j < n:
                if src[j] == "\\":
                    if j + 1 >= n:
                        break
                    j += 2
                    continue
                if src[j] == '"':
                    tokens.append(("string", i, j + 1)); i = j + 1; closed = True
                    break
                if src[j] in "\r\n":
                    break
                j += 1
            if not closed:
                tokens.append(("opaque", i, n))
                break
            continue
        if c == "'":
            end = _match_char_literal(src, i)
            if end is None:
                tokens.append(("opaque", i, n))
                break
            tokens.append(("char", i, end)); i = end; continue
        if _ident_start(c):
            j = i + 1
            while j < n and _ident_part(src[j]):
                j += 1
            tokens.append(("ident", i, j)); i = j; continue
        tokens.append(("other", i, i + 1)); i += 1
    return tokens


def strip_comments(src):
    """Remove // and /* */ comments, preserving newlines and string/char/text literals."""
    out = []
    for kind, a, b in java_tokens(src):
        if kind == "comment":
            out.append("\n" * src.count("\n", a, b))
        else:
            out.append(src[a:b])
    return "".join(out)


def neutral_literal(s):
    if s in LITERAL_MAP:
        return LITERAL_MAP[s]
    if LEAKY_LITERAL.search(s):
        return "msg_" + hashlib.sha1(s.encode()).hexdigest()[:6]
    return None


def _neutralise_string(token):
    """Apply neutral_literal to one ordinary single-line string token, quotes included."""
    if len(token) < 2 or token[0] != '"' or token[-1] != '"' or "\n" in token or "\r" in token:
        return token
    replaced = neutral_literal(token[1:-1])
    return token if replaced is None else '"' + replaced + '"'


def _class_token(text, cls):
    """Return the renamed identifier, or None when this token is not a class/type rename."""
    if _BENCH_TEST.fullmatch(text):
        return "RequestHandler"
    if cls and text == cls:
        return "RequestHandler"
    return None


def _tok_text(code, tok):
    return code[tok[1]:tok[2]]


def _package_sequence(code, cls, tokens, i):
    """True when tokens[i:i+5] are the contiguous identifier sequence org.owasp.benchmark.

    A class or BenchmarkTest rename wins over the package rewrite, matching the historical
    order. Spaces or comments between the parts do not match.
    """
    if i + 4 >= len(tokens):
        return False
    parts = tokens[i:i + 5]
    if [p[0] for p in parts] != ["ident", "other", "ident", "other", "ident"]:
        return False
    if any(parts[k][1] != parts[k - 1][2] for k in range(1, 5)):
        return False
    words = [_tok_text(code, p) for p in parts]
    if words != ["org", ".", "owasp", ".", "benchmark"]:
        return False
    return all(_class_token(word, cls) is None for word in ("org", "owasp", "benchmark"))


def anonymise(code, cls):
    """Rename the alerted type and the historical package/benchmark identifiers.

    Walks tokens from `java_tokens`. String literals, character literals, text blocks, and
    comments are never rewritten as a side effect. Ordinary single-line strings still pass
    through `neutral_literal`. An opaque tail is copied unchanged.
    """
    tokens = java_tokens(code)
    pieces, i, n = [], 0, len(tokens)
    while i < n:
        if _package_sequence(code, cls, tokens, i):
            pieces.append("com.example.app")
            i += 5
            continue
        kind, a, b = tokens[i]
        text = code[a:b]
        if kind == "ident":
            renamed = _class_token(text, cls)
            pieces.append(_BENCH_SUB.sub("app", text) if renamed is None else renamed)
        elif kind == "string":
            pieces.append(_neutralise_string(text))
        else:
            pieces.append(text)
        i += 1
    return "".join(pieces)


def _rename_type_idents(src, cls):
    """Exact class-identifier rename used by the fallback snippet. No literal scrubbing."""
    if not cls:
        return src
    out = []
    for kind, a, b in java_tokens(src):
        text = src[a:b]
        out.append("RequestHandler" if kind == "ident" and text == cls else text)
    return "".join(out)


def match_brace(text, open_idx):
    depth, n = 0, len(text)
    for kind, a, b in java_tokens(text):
        if b <= open_idx:
            continue
        if kind in ("string", "char", "text", "comment", "opaque"):
            continue
        for i in range(max(a, open_idx), b):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i
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
    renamed = anonymise(src, cls).split("\n")
    out = []
    for i, l in enumerate(lines):
        if not keep[i] or not l.strip() or "serialVersionUID" in l: continue
        out.append((i + 1, renamed[i].rstrip()))
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
    """Fallback layout from the dev-set builder (files whose primary type is not `class <FileName>`).

    Renames only exact type identifiers. It does not apply package rewriting or neutral_literal.
    """
    src = strip_comments(raw); lines = src.split("\n")
    c0 = next((i for i, l in enumerate(lines) if re.search(r"\b(class|interface|enum|record)\s+" + re.escape(cls) + r"\b", l)), 0)
    renamed = _rename_type_idents(src, cls).split("\n")
    out = [(i + 1, renamed[i].rstrip()) for i, l in enumerate(lines)
           if i >= c0 and l.strip() and "serialVersionUID" not in l]
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
