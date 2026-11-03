"""Build the dev (model-selection) set in the exact chat format. NEVER train on this."""
import json, re, sys, hashlib, collections
sys.path.insert(0, '/workspace/vuln-verdict-data/out/scripts'); sys.path.insert(0, '/workspace/vuln-verdict-data/dev/scripts')
import build_dataset as B
from labels_src import L
from collect import alerts, ROOT
MAXL = B.MAX_SNIPPET_LINES
IDENT = re.compile(r'(?i)vulnerab|vul|insecure|unsafe|untrusted|injection|ssrf|xxe|weak|hardcoded|bypass|traversal|seccode|safecode|(?:^|_)sec(?:$|_)|(?<=[a-z])Sec$|(?:^|_)safe(?:$|_)|sqli|crlf')
LIT = re.compile(r'(?i)ssrf|malicious|attacker|evil|vuln|exploit|intentional|safecode|seccode|/sec\b|security code|xxe|sqli|injection|bypass|joychou')
def neutral(tok):
    h = hashlib.sha1(tok.encode()).hexdigest()[:6]
    if tok.isupper(): return 'CONST_' + h
    if tok[0].isupper(): return 'Type_' + h
    return 'fn_' + h
def scrub(lines):
    out, ren = [], set()
    for n, t in lines:
        parts = re.split(r'("(?:[^"\\\n]|\\.)*")', t)
        for k, p in enumerate(parts):
            if k % 2:
                if LIT.search(p[1:-1]): parts[k] = '"msg_' + hashlib.sha1(p[1:-1].encode()).hexdigest()[:6] + '"'; ren.add('LIT:' + p)
            else:
                def f(m):
                    w = m.group()
                    if IDENT.search(w) and w not in ('SecurityUtil','adminSecurePort','getAdminSecurePort','INLINE_SAFE_TYPES'): ren.add(w); return neutral(w)
                    return w
                parts[k] = re.sub(r'[A-Za-z_]\w*', f, p)
        out.append((n, ''.join(parts)))
    return out, ren
MDECL = re.compile(r'^\s*(public|private|protected|static|final|synchronized|\s)*[\w<>\[\],.?\s]+\s+(\w+)\s*\(')
def snippet(raw, cls, line):
    src = B.strip_comments(raw); lines = src.split("\n")
    c0 = next((i for i, l in enumerate(lines) if re.search(r"\b(class|interface|enum)\s+" + re.escape(cls) + r"\b", l)), 0)
    out = [(i + 1, re.sub(r'\b' + re.escape(cls) + r'\b', 'RequestHandler', l.rstrip()).replace('org.cysecurity.cspf.jvl', 'com.example.app')) for i, l in enumerate(lines)
           if i >= c0 and l.strip() and 'serialVersionUID' not in l]
    windowed = False
    if len(out) > MAXL:
        windowed = True
        idx = min(range(len(out)), key=lambda k: abs(out[k][0] - line))
        # start at the enclosing method declaration if the method start is within reach
        s = idx
        while s > 0 and not (MDECL.match(out[s][1]) and not re.match(r'\s*(if|for|while|switch|catch|return|new|else|throw)\b', out[s][1])): s -= 1
        if idx - s > MAXL - 12: s = idx - MAXL // 2
        s = max(0, s - 2); s = min(s, len(out) - MAXL)
        out = [out[0]] + [(None, "    ...")] + out[s:s + MAXL - 2] if s > 1 else out[s:s + MAXL]
    return out, windowed, windowed
rows, meta, renamed = [], [], collections.Counter()
for i, (rp, r, ver) in enumerate(alerts()):
    path = r['path']; cls = path.split('/')[-1][:-5]; line = r['start']['line']
    raw = open(ROOT + rp + '/' + path, encoding='utf-8', errors='replace').read()
    snip, trunc, windowed = snippet(raw, cls, line)
    snip, ren = scrub(B.dedent(snip)); renamed.update(ren)
    code = "\n".join((f"{n:>4} | {t}" if n else f"     | {t}") for n, t in snip)
    md = r['extra'].get('metadata', {}); cwe = "; ".join(md.get('cwe', [])) or "unknown"
    user = ("Static-analysis alert\n" f"Tool: Semgrep {ver}\n" f"Rule: {r['check_id']}\n"
            f"Severity: {r['extra']['severity']} (rule confidence: {md.get('confidence') or 'n/a'})\n"
            f"CWE: {cwe}\n" f"Location: RequestHandler.java:{line}\n" f"Message: {r['extra']['message']}\n\n"
            "Code (line-numbered, comments removed" + (", partly elided" if trunc else "") + "):\n" f"```java\n{code}\n```")
    lab = L[i]; rule = r['check_id'].split('.')[-1]
    rows.append({"messages": [{"role": "system", "content": B.SYSTEM_PROMPT}, {"role": "user", "content": user},
                 {"role": "assistant", "content": json.dumps({"verdict": lab['label']}, separators=(",", ":"))}]})
    meta.append({"idx": i, "repo": rp, "file": path, "line": line, "end_line": r['end']['line'], "rule": rule, "check_id": r['check_id'],
                 "cwe": cwe, "label": lab['label'], "label_confidence": lab['confidence'], "rationale": lab['rationale'],
                 "rule_seen_in_training": rule in B.RULE_CATEGORY, "snippet_windowed": bool(windowed)})
D = '/workspace/vuln-verdict-data/dev/'
with open(D + 'dev.jsonl', 'w') as f:
    for x in rows: f.write(json.dumps(x) + "\n")
with open(D + 'dev.meta.jsonl', 'w') as f:
    for x in meta: f.write(json.dumps(x) + "\n")
with open(D + 'labels.jsonl', 'w') as f:
    for m in meta: f.write(json.dumps({k: m[k] for k in ('idx','repo','file','line','rule','label','label_confidence','rationale')}) + "\n")
bad = re.compile(r'(?i)vulnerab|intentional|owasp|insecure|unsafe|exploit|attacker|xxe|ssrf|injection|vuln|seccode|safecode|joychou|cysecurity')
hits = collections.Counter()
for x in rows:
    body = x['messages'][1]['content'].split('```java', 1)[1]
    for m in bad.findall(body): hits[m.lower()] += 1
cls_hits = sum(1 for x, m in zip(rows, meta) if re.search(r'\b' + m['file'].split('/')[-1][:-5] + r'\b', x['messages'][1]['content']))
print("rows", len(rows), "leak hits", dict(hits), "class-name hits", cls_hits)
print(sorted(renamed))
print(collections.Counter((m['label'], m['label_confidence']) for m in meta), "windowed", sum(m['snippet_windowed'] for m in meta))
