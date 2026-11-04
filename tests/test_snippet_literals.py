"""Token-aware Java anonymization. Offline: no API, GPU, or Semgrep."""
import hashlib, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from vuln_verdict.audit import _finding
from vuln_verdict.sarif import classifier_row, load_alerts, user_prompt
from vuln_verdict.snippet import (
    MAX_SNIPPET_LINES, anonymise, extract_snippet, format_code, generic_snippet, match_brace, neutral_literal,
)

MD5_SOURCE = """\
package com.yt.md5;
import org.owasp.benchmark.helpers.Thing;
import org.owasp.esapi.ESAPI;
/** comment mentions MD5 and should be stripped from the snippet */
public class MD5 {
    private static final long serialVersionUID = 1L;
    MD5 next;
    char tick = '\\'';
    char slash = '\\\\';
    char letter = 'M';
    public MD5(String seed) {}
    // MD5 in a comment must not be renamed
    public String GetMD5Code(MD5 other) {
        String sql = "SELECT id, balance FROM accounts WHERE owner = 'alice'";
        String table = "accounts";
        String column = "password";
        String path = "/var/data/MD5/users.txt";
        String quoted = "say \\"MD5\\"";
        String web = "http://example.test/MD5";
        String win = "C:\\\\temp\\\\MD5";
        String neutral = "safe";
        String leak = "known sqli sample";
        String block = \"\"\"
            MessageDigest.getInstance("MD5")
            class MD5
            \"\"\";
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-1");
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("AES/GCM/NoPadding");
        int benchmarkprops = 1;
        return new MD5(sql).GetMD5Code(other);
    }
}
"""


def _text(pairs):
    return "\n".join(t for _, t in pairs)


def _alert_line():
    return next(i for i, line in enumerate(MD5_SOURCE.splitlines(), 1) if 'getInstance("MD5")' in line and "block" not in line)


def test_anonymise_renames_type_uses_and_keeps_literals():
    out = anonymise(MD5_SOURCE, "MD5")
    assert "class RequestHandler" in out
    assert "public RequestHandler(String seed)" in out
    assert "RequestHandler next;" in out
    assert "GetMD5Code(RequestHandler other)" in out
    assert "new RequestHandler(sql)" in out
    assert "GetMD5Code" in out and "GetRequestHandlerCode" not in out
    assert 'MessageDigest.getInstance("MD5")' in out
    assert 'MessageDigest.getInstance("SHA-1")' in out
    assert 'MessageDigest.getInstance("SHA-256")' in out
    assert 'Cipher.getInstance("AES/GCM/NoPadding")' in out
    assert "SELECT id, balance FROM accounts WHERE owner = 'alice'" in out
    assert '"accounts"' in out and '"password"' in out
    assert '"/var/data/MD5/users.txt"' in out
    assert 'say \\"MD5\\"' in out
    assert "http://example.test/MD5" in out
    assert "C:\\\\temp\\\\MD5" in out
    assert "char tick = '\\'';" in out
    assert "char slash = '\\\\';" in out
    assert "char letter = 'M';" in out
    assert "// MD5 in a comment must not be renamed" in out
    assert '"""' in out and "class MD5" in out  # text block keeps the class name
    assert "com.example.app.helpers.Thing" in out
    assert "org.owasp.esapi.ESAPI" in out
    assert "appprops" in out and "benchmarkprops" not in out
    assert '"safe"' not in out and '"alpha"' in out
    leaked = neutral_literal("known sqli sample")
    assert leaked == "msg_" + hashlib.sha1(b"known sqli sample").hexdigest()[:6]
    assert '"' + leaked + '"' in out


def test_benchmark_test_identifier_is_exact():
    out = anonymise('class BenchmarkTest00042 { BenchmarkTest00042 x; String s = "BenchmarkTest00042"; }', "Other")
    assert out.startswith("class RequestHandler { RequestHandler x;")
    # The literal matches the existing benchmark scrub, so it is neutralised rather than renamed.
    assert '"RequestHandler"' not in out
    assert '"' + neutral_literal("BenchmarkTest00042") + '"' in out
    longer = anonymise("class NotBenchmarkTest00042 {}", "Other")
    assert "RequestHandler" not in longer and "NotappTest00042" in longer


def test_package_rewrite_does_not_edit_string_or_longer_identifier():
    src = 'import org.owasp.benchmark.helpers.Thing;\nString s = "see org.owasp.benchmark.helpers";\nimport org.owasp.benchmarkprops.Other;\n'
    out = anonymise(src, "MD5")
    assert "import com.example.app.helpers.Thing;" in out
    assert "import org.owasp.appprops.Other;" in out
    assert "com.example.appprops" not in out
    body = "see org.owasp.benchmark.helpers"
    assert '"' + neutral_literal(body) + '"' in out
    assert "com.example.app" not in out.splitlines()[1]


def test_unclosed_literal_is_preserved():
    src = 'class MD5 { String s = "MD5; GetMD5Code();'
    out = anonymise(src, "MD5")
    assert out.startswith("class RequestHandler")
    assert '"MD5; GetMD5Code();' in out
    assert anonymise('"MD5 class MD5', "MD5") == '"MD5 class MD5'


def test_extract_and_generic_keep_md5_literal_and_line_numbers():
    alert = _alert_line()
    extracted, truncated, windowed = extract_snippet(MD5_SOURCE, "MD5", alert)
    text = _text(extracted)
    assert not truncated and not windowed
    assert 'getInstance("MD5")' in text and "GetRequestHandlerCode" not in text
    assert "GetMD5Code" in text and "class RequestHandler" in text and "new RequestHandler" in text
    assert "SHA-1" in text and "SHA-256" in text and "AES/GCM/NoPadding" in text
    assert "SELECT id, balance FROM accounts" in text
    assert '"/var/data/MD5/users.txt"' in text
    assert "should be stripped" not in text and "MD5 in a comment must not be renamed" not in text
    assert "http://example.test/MD5" in text
    assert "class MD5" in text  # survives only inside the text block
    assert '"alpha"' in text and '"safe"' not in text
    by_num = {n: t for n, t in extracted}
    assert alert in by_num and 'getInstance("MD5")' in by_num[alert]
    raw_lines = MD5_SOURCE.splitlines()
    for n, t in extracted:
        assert n is not None and 1 <= n <= len(raw_lines)
        if "marker" in raw_lines[n - 1]:
            assert raw_lines[n - 1].strip() in t or t in raw_lines[n - 1]
    assert not any(n == next(i for i, line in enumerate(raw_lines, 1) if "serialVersionUID" in line) for n, _ in extracted)

    generic, g_trunc, g_window = generic_snippet(MD5_SOURCE, "MD5", alert)
    gtext = _text(generic)
    assert 'getInstance("MD5")' in gtext and "GetMD5Code" in gtext and "class RequestHandler" in gtext
    assert '"safe"' in gtext and '"alpha"' not in gtext  # fallback does not neutralise literals
    assert "benchmarkprops" in gtext and "com.example.app" not in gtext  # no package or benchmark rewrite
    assert any(n == alert and 'getInstance("MD5")' in t for n, t in generic)
    assert not g_trunc and not g_window


def test_window_keeps_original_line_numbers():
    lines = ["public class MD5 {"]
    lines += [f"    int marker{n} = {n};" for n in range(2, 40)]
    lines.append('    void use() { MessageDigest.getInstance("MD5"); }')
    lines += [f"    int marker{n} = {n};" for n in range(len(lines) + 1, len(lines) + 50)]
    lines.append("}")
    src = "\n".join(lines) + "\n"
    alert = next(i for i, line in enumerate(lines, 1) if "getInstance" in line)
    out, _trunc, windowed = extract_snippet(src, "MD5", alert)
    assert windowed and len(out) <= MAX_SNIPPET_LINES
    assert any(n == alert and 'getInstance("MD5")' in t for n, t in out)
    for n, t in out:
        if n is None:
            continue
        assert f"marker{n}" in t or n in (1, alert, len(lines))
    generic, _, g_window = generic_snippet(src, "MD5", alert)
    assert g_window and len(generic) <= MAX_SNIPPET_LINES
    assert any(n == alert and 'getInstance("MD5")' in t for n, t in generic)
    for n, t in generic:
        if n is None or n in (1, alert, len(lines)):
            continue
        assert f"marker{n}" in t


def test_match_brace_skips_text_block_and_string():
    src = '{ String s = """\n}\n"""; }'
    assert match_brace(src, 0) == src.rindex("}")
    quoted = '{ String s = "{"; }'
    assert match_brace(quoted, 0) == quoted.rindex("}")


def test_prompt_keeps_md5_literal_and_source_bytes(tmp_path):
    name = "MD5.java"
    path = tmp_path / name
    path.write_bytes(MD5_SOURCE.encode())
    before = path.read_bytes()
    alert_line = _alert_line()
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {
        "name": "Semgrep OSS", "semanticVersion": "1.183.0",
        "rules": [{"id": "java.lang.security.audit.crypto.use-of-md5.use-of-md5",
                   "properties": {"tags": ["CWE-328", "HIGH CONFIDENCE"]}}]}},
        "results": [{"ruleId": "java.lang.security.audit.crypto.use-of-md5.use-of-md5",
                     "level": "warning", "message": {"text": "Detected MD5 hash algorithm"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": name},
                                    "region": {"startLine": alert_line, "endLine": alert_line}}}]}]}]}
    alerts = load_alerts(sarif, tmp_path)
    assert path.read_bytes() == before and not alerts[0].error
    prompt = user_prompt(alerts[0])
    finding = _finding(alerts[0], 0.18)
    row = classifier_row(alerts[0])
    for blob in (prompt, finding, row["messages"][1]["content"]):
        assert 'MessageDigest.getInstance("MD5")' in blob
        assert 'getInstance("RequestHandler")' not in blob
        assert "GetMD5Code" in blob and "GetRequestHandlerCode" not in blob
    code, _trunc, _window = format_code(before.decode(), name, alert_line)
    assert 'getInstance("MD5")' in code
    assert path.read_bytes() == before
