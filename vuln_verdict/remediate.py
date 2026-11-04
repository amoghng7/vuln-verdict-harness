"""Remediation with sandboxed edits and a Semgrep re-check.

Flow per alert: Muse proposes search/replace edits -> the harness writes a patch and applies it to a
COPY inside a path-contained sandbox -> Semgrep rescans baseline and patched copies. ``fix verified``
means Semgrep-cleared only: the target alert is gone, no new alert of any rule appeared, and parse
checks pass. It does not mean the project compiles, tests pass, or the fix is semantically ideal.
"""
import difflib, hashlib, json, os, re, shutil, subprocess
from pathlib import Path

from . import muse
from .snippet import java_tokens

CATEGORIES = {
    "sqli": "SQL injection: replace string-built SQL with a parameterised query (PreparedStatement with ? placeholders "
            "and setString/setInt..., or the equivalent bind-parameter API already used by the code, e.g. JdbcTemplate args, "
            "Query.setParameter). Identifiers that cannot be bound (ORDER BY column, table) must be checked against a fixed allow-list.",
    "xxe": "XXE: harden the XML parser factory right after it is created, before parsing: "
           "DocumentBuilderFactory/SAXParserFactory/XMLInputFactory -> setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) "
           "(XMLInputFactory: setProperty(XMLInputFactory.SUPPORT_DTD, false)); TransformerFactory/SchemaFactory -> "
           "setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\") and ACCESS_EXTERNAL_STYLESHEET/SCHEMA \"\".",
    "crypto": "Weak crypto: first determine the purpose. For password storage, do NOT use a fast SHA-256/SHA-512 digest; "
              "use a password KDF such as Argon2id, bcrypt, scrypt or PBKDF2 with per-password salt and appropriate cost. "
              "For non-password integrity, use SHA-256/SHA-512 or HMAC as appropriate; preserve signature/MAC semantics. "
              "DES/3DES/RC4/ECB/CBC-without-MAC/static IV -> AES/GCM/NoPadding with a fresh random 12-byte IV from SecureRandom "
              "(prepend the IV to ciphertext and read it back when decrypting); RSA keys -> at least 2048 bits. Keep method signatures.",
    "redirect": "Open redirect: only redirect to a relative path on this site or to a host on a fixed allow-list; otherwise redirect to a safe default.",
    "path": "Path traversal: resolve the path against a fixed base directory, normalise it, and reject it unless it still starts with the base directory "
            "(or keep only the file name via java.nio.file.Paths.get(x).getFileName()).",
}


def category(a):
    r, c = a.rule_short.lower(), a.cwe
    if "CWE-89" in c or "sql" in r: return "sqli"
    if "CWE-611" in c or "xxe" in a.rule_id or "doctype" in r or "dtds" in r: return "xxe"
    if any(x in c for x in ("CWE-327", "CWE-328", "CWE-326", "CWE-329")) or any(
            x in r for x in ("md5", "sha1", "des-", "desede", "ecb", "rc4", "static-iv", "weak-rsa", "padding-oracle")): return "crypto"
    if "CWE-601" in c or "redirect" in r: return "redirect"
    if "CWE-22" in c or "path-traversal" in r: return "path"
    return None


EDIT_SCHEMA = ("patch", {
    "type": "object",
    "properties": {
        "edits": {"type": "array", "items": {"type": "object", "properties": {
            "find": {"type": "string"}, "replace": {"type": "string"}}, "required": ["find", "replace"]}},
        "add_imports": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
        "caveats": {"type": "string"},
    },
    "required": ["edits", "add_imports", "summary", "caveats"],
})
FIX_SYSTEM = (
    "You fix ONE security finding in a Java file with the smallest correct change. Output JSON: edits = list of "
    "{find, replace}; each find is an exact, contiguous, verbatim substring of the CURRENT file (copy whole lines, keep "
    "indentation, WITHOUT the line-number prefixes) and must be unique enough to locate; replace is the new text. "
    "add_imports = fully-qualified class names to import (empty if none). summary <= 25 words. caveats <= 25 words "
    "(behaviour changes, e.g. existing stored hashes, callers to update; or 'none'). Do not reformat unrelated code, "
    "do not change public method signatures, keep it compiling.")


def _numbered(lines, lo, hi):
    return "\n".join(f"{i + 1:>4}| {lines[i]}" for i in range(lo, hi))


def _context(text, line, radius=45, whole_max=180):
    lines = text.split("\n")
    if len(lines) <= whole_max:
        return _numbered(lines, 0, len(lines))
    lo, hi = max(0, line - 1 - radius), min(len(lines), line + radius)
    head_end = 0
    for i, l in enumerate(lines[:lo]):
        if re.match(r"\s*(package|import)\b", l): head_end = i + 1
    parts = []
    if head_end and lo > 0:
        parts += [_numbered(lines, 0, head_end), "    | ..."]
    parts.append(_numbered(lines, lo, hi))
    if hi < len(lines): parts.append("    | ...")
    return "\n".join(parts)


def propose(a, text, audit=None, effort="low"):
    cat = category(a)
    user = (f"Finding: {a.rule_short} ({a.cwe}) at line {a.line} of {os.path.basename(a.file)}\n"
            f"Semgrep message: {a.message[:300]}\n"
            + (f"Reviewer note: {audit.get('explanation', '')[:300]}\n" if audit else "")
            + f"Fix guidance: {CATEGORIES[cat]}\n\nFile (line-numbered excerpt):\n```java\n{_context(text, a.line)}\n```")
    out, cost = muse.chat_json([{"role": "system", "content": FIX_SYSTEM}, {"role": "user", "content": user}],
                               tag="harness_fix", schema=EDIT_SCHEMA, max_tokens=5000, reasoning_effort=effort)
    out["cost_usd"] = round(cost, 5)
    return out


def apply_edits(text, edits, add_imports, near_line):
    """Applies search/replace edits; returns (new_text, problems)."""
    problems = []
    for e in edits:
        f, rpl = e.get("find", ""), e.get("replace", "")
        f = re.sub(r"(?m)^\s*\d+\s*\| ?", "", f) if re.match(r"\s*\d+\s*\|", f) else f
        if not f:
            problems.append("empty find"); continue
        idxs = [m.start() for m in re.finditer(re.escape(f), text)]
        if not idxs:
            fl = [l.strip() for l in f.strip("\n").split("\n")]
            tl = text.split("\n")
            cand = [i for i in range(len(tl) - len(fl) + 1) if [l.strip() for l in tl[i:i + len(fl)]] == fl]
            if not cand:
                problems.append(f"find text not in file: {f[:60]!r}"); continue
            i = min(cand, key=lambda k: abs(k + 1 - near_line))
            start = sum(len(l) + 1 for l in tl[:i]); end = start + sum(len(l) + 1 for l in tl[i:i + len(fl)]) - 1
            text = text[:start] + rpl.strip("\n") + text[end:]
            continue
        pos = min(idxs, key=lambda p: abs(text.count("\n", 0, p) + 1 - near_line))
        text = text[:pos] + rpl + text[pos + len(f):]
    imps = [i.strip().rstrip(";") for i in (add_imports or []) if re.match(r"^[\w.]+\*?$", i.strip().rstrip(";"))]
    def imported(i):
        pkg = i.rsplit(".", 1)[0]
        return (re.search(r"(?m)^\s*import\s+" + re.escape(i) + r"\s*;", text)
                or re.search(r"(?m)^\s*import\s+" + re.escape(pkg) + r"\.\*\s*;", text)
                or (pkg == "java.lang"))
    missing = [i for i in imps if "." in i and not imported(i)]
    if missing:
        block = "".join(f"import {i};\n" for i in missing)
        ms = list(re.finditer(r"(?m)^\s*import\s+[\w.*]+\s*;[^\n]*\n", text))
        if ms:
            p = ms[-1].end()
        else:
            m = re.search(r"(?m)^\s*package\s+[\w.]+\s*;[^\n]*\n", text); p = m.end() if m else 0
        text = text[:p] + block + text[p:]
    return text, problems


def unified_diff(old, new, rel):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}"))


def line_map(old, new):
    """new line no -> old line no for unchanged lines (None for inserted/changed lines)."""
    sm = difflib.SequenceMatcher(None, old.split("\n"), new.split("\n"), autojunk=False)
    m = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1): m[j1 + k + 1] = i1 + k + 1
    return m


def braces_balanced(text):
    """Check delimiter ordering as well as counts outside comments and literals.

    Text blocks, strings, and character literals are skipped. An unclosed literal is
    not treated as balanced, because its tail was not classified confidently.
    """
    pairs, stack = {")": "(", "]": "[", "}": "{"}, []
    for kind, a, b in java_tokens(text):
        if kind in ("string", "char", "text", "comment"):
            continue
        if kind == "opaque":
            return False
        for c in text[a:b]:
            if c in "([{":
                stack.append(c)
            elif c in pairs:
                if not stack or stack.pop() != pairs[c]:
                    return False
    return not stack


def javalang_ok(text):
    try:
        import javalang
    except ImportError:
        return None
    try:
        javalang.parse.parse(text); return True
    except Exception:
        return False


def _safe_join(root, *parts):
    """Join and resolve a path, rejecting traversal outside root."""
    base = Path(root).resolve()
    candidate = base.joinpath(*[str(p) for p in parts]).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError(f"unsafe path outside sandbox: {os.path.join(*[str(p) for p in parts])}") from None
    return candidate


def semgrep_scan(root, config, semgrep_bin, timeout=300):
    cmd = [semgrep_bin, "scan", "--config", config, "--json", "--metrics=off", "--quiet", "--no-git-ignore", str(root)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=root, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"semgrep timed out after {timeout}s") from None
    try:
        d = json.loads(p.stdout)
    except Exception:
        raise RuntimeError(f"semgrep failed (exit {p.returncode}): {(p.stderr or p.stdout)[-300:]}")
    if p.returncode != 0:
        raise RuntimeError(f"semgrep failed (exit {p.returncode}): {(p.stderr or json.dumps(d.get('errors', [])))[-300:]}")
    res, errs = {}, {}
    for r in d.get("results", []):
        res.setdefault(os.path.relpath(os.path.join(root, r["path"]), root), []).append((r["check_id"], r["start"]["line"]))
    for e in d.get("errors", []):
        pth = e.get("path") or (e.get("spans") or [{}])[0].get("file")
        if pth:
            errs.setdefault(os.path.relpath(os.path.join(root, pth), root), []).append(e.get("type", "error"))
    return res, errs


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def remediate_batch(items, repo, outdir, semgrep_bin="semgrep", config="p/java", effort="low", log=print):
    """items: list of (alert, audit_dict_or_None). Returns {alert_id: fix_record}."""
    repo = os.path.abspath(repo)
    sand = _safe_join(outdir, "sandbox"); base = _safe_join(outdir, "sandbox_baseline")
    pdir = _safe_join(outdir, "patches")
    for d in (sand, base): shutil.rmtree(d, ignore_errors=True)
    pdir.mkdir(parents=True, exist_ok=True)
    orig_hash = {}
    recs, pending = {}, []
    for a, au in items:
        src = _safe_join(repo, a.file)
        orig_hash[src] = _sha(src)
        old = src.read_text(encoding="utf-8", errors="replace")
        try:
            prop = propose(a, old, au, effort)
        except muse.BudgetExceeded as e:
            recs[a.id] = {"status": "no fix attempted", "reason": f"budget: {e}"}; continue
        except Exception as e:
            recs[a.id] = {"status": "no fix attempted", "reason": f"model error: {e}"[:300]}; continue
        new, problems = apply_edits(old, prop.get("edits", []), prop.get("add_imports", []), a.line)
        rec = {"category": category(a), "summary": prop.get("summary", ""), "caveats": prop.get("caveats", ""),
               "cost_usd": prop.get("cost_usd", 0), "edit_problems": problems,
               "verification_level": "semgrep_only"}
        if new == old:
            rec.update(status="no fix attempted", reason="model edits could not be applied" if problems else "empty patch")
            recs[a.id] = rec; continue
        diff = unified_diff(old, new, a.file)
        ppath = _safe_join(pdir, a.id + ".patch")
        ppath.write_text(diff, encoding="utf-8")
        rec.update(patch_path=os.path.relpath(ppath, outdir), diff_lines=sum(1 for l in diff.splitlines() if l[:1] in "+-" and l[:3] not in ("+++", "---")))
        tgt = _safe_join(sand, a.id, a.file)
        tgt.parent.mkdir(parents=True, exist_ok=True)
        tgt.write_text(new, encoding="utf-8")
        bt = _safe_join(base, a.file)
        if not bt.exists():
            bt.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(src, bt)
        recs[a.id] = rec; pending.append((a, old, new))
        log(f"  patch {a.id} {a.rule_short} {a.file}:{a.line} ({len(problems)} edit problems)")
    if pending:
        log("  semgrep re-check (baseline + patched copies)...")
        b_res, b_err = semgrep_scan(base, config, semgrep_bin)
        p_res, p_err = semgrep_scan(sand, config, semgrep_bin)
        for a, old, new in pending:
            rec = recs[a.id]
            key = os.path.join(a.id, a.file)
            before = [l for r, l in b_res.get(a.file, []) if r == a.rule_id]
            after_all = p_res.get(key, [])
            after = [l for r, l in after_all if r == a.rule_id]
            lm = line_map(old, new)
            mapped = [lm.get(l) for l in after]
            still = a.line in mapped
            new_same = [l for l, m in zip(after, mapped) if m is None or m not in before]
            other_before = {(r, l) for r, l in b_res.get(a.file, [])}
            new_other = sorted({r.split(".")[-1] for r, l in after_all if r != a.rule_id and (r, lm.get(l)) not in other_before})
            perr = len(p_err.get(key, [])) > len(b_err.get(a.file, []))
            bal = braces_balanced(new)
            jl_old, jl_new = javalang_ok(old), javalang_ok(new)
            parse_ok = not perr and bal and not (jl_old and jl_new is False)
            rec["recheck"] = {"baseline_reproduced": a.line in before, "alert_still_present": still,
                              "new_same_rule_lines": new_same, "new_other_rules": new_other,
                              "semgrep_parse_error": perr, "braces_balanced": bal,
                              "javalang_original": jl_old, "javalang_patched": jl_new}
            reasons = []
            if a.line not in before: reasons.append("baseline re-scan did not reproduce the alert")
            if still: reasons.append("alert still reported")
            if new_same: reasons.append(f"new {a.rule_short} alert(s) at {new_same}")
            if new_other: reasons.append(f"new alert(s) of other rule(s): {', '.join(new_other)}")
            if not parse_ok: reasons.append("patched file fails parse checks")
            if rec["edit_problems"]: reasons.append("some edits did not apply")
            if reasons:
                rec.update(status="fix suggested, unverified", reason="; ".join(reasons))
            else:
                rec.update(status="fix verified",
                           reason="Semgrep-cleared; not compiled or tested.")
    for src, h in orig_hash.items():
        if _sha(src) != h:
            raise RuntimeError(f"original file modified: {src}")
    return recs
