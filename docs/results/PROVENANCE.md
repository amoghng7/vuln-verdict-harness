# vuln-verdict dataset v0 — provenance

Built 2026-10-30 (IST) by `scripts/build_dataset.py` (rerun: `cd /workspace/vuln-verdict-data && python3 out/scripts/build_dataset.py`; add `--rescan` to re-run Semgrep). Deterministic: seed 20261030.

## Sources and licences
| Source | Version | Licence | Use |
|---|---|---|---|
| OWASP Benchmark Java — https://github.com/OWASP-Benchmark/BenchmarkJava | shallow clone, commit `f40c618c5a709afce350ef06ed2899c85cf586e9`, `expectedresults-1.2.csv` | **GPL-2.0** | code snippets in every example + ground-truth labels |
| Semgrep CLI (OSS engine) | 1.183.0, installed with pip into `/workspace/vuln-verdict-data/.venv` | LGPL-2.1 (engine) | produced the alerts |
| Semgrep registry ruleset `p/java` | fetched 2026-10-30 | Semgrep Rules License v1.0 | rule ids + rule messages are quoted in the user turn |

**Licence caveat:** every example contains GPL-2.0 code from OWASP Benchmark (modified: comments removed, identifiers renamed). Treat the JSONL files as GPL-2.0 derivative data: keep this notice and source link if redistributed. Whether model weights trained on it count as derivative works is legally unsettled; mention it in the hackathon write-up. Rule messages are quoted from the Semgrep Rules License v1.0 rules, which limits commercial redistribution of the rules themselves; the quoted messages are short, but keep that in mind if you publish the dataset.

## Pipeline
1. Ran `semgrep scan --config p/java --json --metrics=off` over `src/main/java/org/owasp/benchmark/testcode` (2,740 files). Result: 1,909 findings, 0 errors, in 1,515 files. The registry was reachable. `p/owasp-top-ten` was also run with `p/java` and gave **0** extra findings, so only `p/java` is used. Raw output: `raw/semgrep_p-java.json`.
2. Merged repeat alerts from the same rule on the same test case into one alert (151 merged) and kept the earliest line. Result: one example per (test case, rule).
3. **Category-matched join.** OWASP Benchmark labels only the single seeded flaw in each file, by category/CWE. An alert counts only when the rule's category matches the test case's category. The mapping is in `RULE_CATEGORY`: DES/DESede rules (Semgrep calls them CWE-326) map to Benchmark `crypto` (CWE-327), and MD5/SHA1 map to `hash` (CWE-328). **146 alerts were skipped** because no ground truth exists for them: `no-direct-response-writer` (XSS) firing on trustbound (90), sqli (29), and xpathi (27) cases. Labelling those from the case's `real vulnerability` column would have been wrong.
4. Label: `true_positive` if the case is a real vulnerability, `false_positive` if it is safe. **1,225 test cases had no alert and were skipped.** That includes all weakrand (493) and securecookie (67) cases, because `p/java` has no rule that fired on them. See `stats.json → skipped_no_alert_by_category`.
5. Snippet: the test-case class without the package/imports/`@WebServlet` annotation, without `doGet` (its forward URL `/pathtraver-00/...` names the category), and without `serialVersionUID`. Comments and blank lines are stripped. Formatter continuation lines are joined, and lines keep their original line numbers. When a snippet ran over 60 lines (220 examples), the top of the request-parsing boilerplate in `doPost` is replaced by `...`, and then, if still too long, the output/error tail after the sink is replaced too. The propagator and sink are always kept (0 fell back to blind windowing). An earlier blind ±30-line window cut out the deciding helper method and gave identical code with opposite labels, so it was replaced.
6. Anonymisation: `BenchmarkTestNNNNN` → `RequestHandler` (class name, cookie/header/parameter names), `org.owasp.benchmark` → `com.example.app`, and any remaining `benchmark` → `app`. String literals that hint at the answer or category were neutralised with a fixed map (`"safe"`, `"moresafe"`, `"safe!"`, `"This should never happen"`, `"This_should_always_happen"` …) or with `msg_<sha1[:6]>` (any literal matching safe/vuln/test case/category names). Distinct values stay distinct, so the program logic is unchanged. The ESAPI library package `org.owasp.esapi` is kept because it is a real library and the sanitiser call is genuine signal. Check: 0 examples contain `BenchmarkTest` or `benchmark`.
7. Format: chat JSONL `{"messages":[system,user,assistant]}`. The assistant turn is strict JSON `{"verdict":"true_positive"|"false_positive"}` with no rationale. Metadata (test id, category, rule, hash) is only in `raw/*.meta.jsonl`. **Do not upload the meta files.**
8. Split: union-find groups of (same test case) ∪ (identical normalised snippet; 127 duplicate pairs grouped). The split is stratified by (category, label), 70/15/15 by example count, seed 20261030. Checked: 0 test ids and 0 code hashes cross splits, and 0 duplicate groups have conflicting labels.
9. `smoke_train.jsonl`: 200 examples drawn only from train, 100 TP / 100 FP.

## needs_review
Not included. OWASP ground truth is binary, so a needs_review class can't be derived honestly from it. The only available proxy is Semgrep's own rule `confidence` metadata (HIGH: 583 TP / 143 FP; MEDIUM: 517 TP / 369 FP). That describes the scanner, not the case. It could serve as an input feature or for abstention thresholds at inference time, but it is not a label.

## Known limitations / leakage risks
- **Synthetic, templated data.** Benchmark cases are generated from a small set of source × propagator × sink templates. Near-identical code appears across splits; only exact duplicates are grouped. **Test scores will be optimistic** and will not carry over to real-world code. Use a real-code eval (e.g. CVE-fix datasets, your own repos) before claiming anything.
- **Rule-id shortcut:** every crypto (DES/DESede) and hash (MD5/SHA1) alert is `true_positive` (351/1,612 = 22%), because Semgrep only flags algorithms that Benchmark also counts as weak. The model can learn "rule id → TP" for these. Consider dropping them or reporting metrics without them.
- **Template-constant shortcuts** (code logic, not label text, so kept): e.g. the neutralised dead-branch constant `value_one` is TP in 202/206 examples, and `"bob"` is FP in 86/88. These are the actual data-flow reasons, but they are template-specific.
- Line-number gaps show where comments/blank lines were removed. Comment placement is template-driven, so this is a weak structural signal, but not a label string.
- Class imbalance: 68% TP overall. The smoke set is balanced 50/50.
- Only the Semgrep `p/java` rules are used: 9 of 11 Benchmark categories, no weakrand or securecookie.
