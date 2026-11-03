"""Collect Semgrep p/java alerts from the dev repos (public, shallow clones) into one ordered list."""
import json
REPOS = ["java-sec-code", "JavaVulnerableLab", "roller", "jspwiki", "Openfire", "RuoYi"]
ROOT = "/workspace/real-world/"
def alerts():
    out = []
    for rp in REPOS:
        d = json.load(open(f"/workspace/vuln-verdict-data/dev/raw/semgrep_{rp}.json"))
        for r in sorted(d["results"], key=lambda x: (x["path"], x["start"]["line"])):
            out.append((rp, r, d.get("version")))
    return out
