# vuln-verdict — real-world test on a private deliberately-vulnerable multi-project Java repo (EVALUATION ONLY)

> Scrubbed for publication: the repository's name, file paths, file names, class names, identifiers and code snippets have been removed. The eval data itself (`real.jsonl`, labels, raw Semgrep output, builder scripts) is not part of this repo.

Never train on this data. The source repo was read-only; nothing was pushed or modified.
Run: 2026-10-31 ~19:37–19:41 IST. Modal ≈ 13 A100-80GB minutes (3 containers, ~100 s inference each) ≈ $0.6–0.8 est.
Meta API: 0 calls (spend.json unchanged at $18.77).

## 1. Semgrep
`semgrep 1.183.0 scan --config p/java --json --metrics=off` over the 57 non-test Java files (default .semgrepignore skips the 8 `test/` harnesses).
**105 alerts, 0 errors, 20 distinct rules, 20 files.** Semgrep works: every alert lands on genuinely risky code; only ~7 are debatable/false.

| rule | n | CWE | seen in training? |
|---|---|---|---|
| formatted-sql-string | 35 | 89 | no (training used tainted-sql only) |
| documentbuilderfactory-disallow-doctype-decl-missing | 18 | 611 | no |
| no-direct-response-writer | 12 | 79 | yes |
| use-of-md5 | 7 | 328 | yes |
| saxparserfactory-disallow-doctype-decl-missing | 7 | 611 | no |
| use-of-sha1 | 4 | 328 | yes |
| ecb-cipher 4, use-of-aes-ecb 3, des-is-deprecated 2, desede-is-deprecated 1, no-static-IV 1, cbc-padding-oracle 1, use-of-rc4 1, weak-rsa-key 1 | 14 | 327/326/329 | des/desede only |
| unvalidated-redirect | 2 | 601 | no |
| httpservlet-path-traversal | 2 | 22 | yes |
| tainted-session, unencrypted-socket, weak-ssl-context, transformerfactory-dtds | 1 each | | session only |

Only 29/105 alerts come from rules the model was trained on. Alerts are concentrated in a handful of files (the top four files hold 55 of the 105 alerts).
Coverage gap: Semgrep's p/java misses much of what the repo documents (deserialization, ReDoS, JWT, SSRF, hardcoded passwords, command injection in several files). It only flagged 20 of 57 files.

## 2. Eval set
`real.jsonl` (105 rows, identical system prompt and user layout to out/test.jsonl, built with `build_dataset.extract_snippet`: comments removed, class renamed to RequestHandler, the same literal scrubbing, a 60-line window).
Additional scrubbing for this deliberately vulnerable repo: 52 self-describing identifiers (names that announce the weakness) were renamed to neutral ids and 3 literals were scrubbed. Real JDK API names (`SecureRandom`, `TrustManager`) and ordinary-sounding helper names were kept.
Leak audit: no "vulnerab/intentional/injection/xxe/ssrf/insecure/unsafe/attacker" text and no original class names in any code block. Sidecar: `real.meta.jsonl` (file, line, rule, label, confidence, rationale, seen-rule flag).
97/105 snippets are windowed, because these are big multi-method classes rather than servlets.

## 3. Ground truth
Source A: the author's annotations (`INTENTIONAL VULNERABILITY` and CWE headers in or around the method).
Source B: my manual review of every alert, including helper methods in other files and the DB dialect.
- high: A names this weakness and B agrees, or the code is unambiguous and A does not contradict it.
- medium: B only, or B overrides A.
- low: debatable.

| label | high | medium | low |
|---|---|---|---|
| true_positive (98) | 91 | 6 | 1 |
| false_positive (7) | 1 | 6 | 0 |

The false positives:
- #27: the response writes only a boolean.
- #28: User-Agent echoed in an `application/json` response.
- #47: a plaintext socket to localhost that sends a constant.
- #17, #42, #43, #44: **the author says these are vulnerable; my review says they are not.** The value sits inside `'...'` after a sanitizer that strips every `'`, and the DB is H2, which has no backslash escapes, so the literal cannot be closed. This would flip on MySQL for the two-field login query (#44). The sanitizer body lives in another file, so the model cannot see it.

**Caveat: with only 7 FPs, the set is 93% positive. "Always true_positive" scores 0.933.** The FP numbers rest on 7 examples, so treat them as anecdotal.

## 4. Results (n=105)
| model | acc | TP prec | TP recall | FP correctly rejected | high-conf acc (n=92) | seen rules (29) | unseen rules (76) |
|---|---|---|---|---|---|---|---|
| always-TP baseline | 0.933 | 0.933 | 1.00 | 0/7 | 0.989 | 0.931 | 0.934 |
| base (no adapter) | 0.886 | 0.978 | 0.898 | **5/7** | 0.902 | 0.793 | 0.921 |
| full (old adapter) | **0.952** | 0.951 | **1.00** | 2/7 | **0.989** | 0.931 | 0.961 |
| synth_mix75 | 0.876 | 0.929 | 0.939 | 0/7 | 0.946 | 0.862 | 0.882 |
| synth_all | 0.819 | 0.944 | 0.857 | 2/7 | 0.902 | 0.759 | 0.842 |

Confusion matrices (tp/fp/fn/tn): base 88/2/10/5 · full 98/5/0/2 · mix75 92/7/6/0 · synth_all 84/5/14/2.
Invalid outputs: 0 for every model. Forced-choice accuracy matches greedy.

Per category, accuracy for base / full / mix75 / synth_all:
| category | n | base | full | mix75 | synth_all |
|---|---|---|---|---|---|
| sqli | 35 | .94 | .94 | .77 | .74 |
| xxe | 26 | .96 | 1 | 1 | 1 |
| crypto | 14 | .86 | 1 | 1 | .93 |
| xss | 12 | .92 | .83 | .75 | .42 |
| hash | 11 | .55 | 1 | 1 | 1 |
| redirect | 2 | .5 | 1 | 1 | .5 |
| transport | 2 | 1 | .5 | .5 | .5 |
Full per-rule numbers are in `metrics_real.json` (not published).

### Error patterns
- **synth_mix75 / synth_all, SQLi with no visible HTTP source:** #58–61 (ORDER BY column, table name, LIKE and UPDATE clauses built from plain method parameters) were called FP. synth_all also missed #54. The synthetic and OWASP data taught "SQL is tainted only if you see `request.getParameter`", but library and service code receives taint through parameters. This is the biggest real-world gap.
- **synth_all, stored XSS:** 7 of the 8 XSS alerts that write DB or user-object data unescaped (#20–24, #29, #30) were called FP with p_true < 0.07. It over-learned "no request taint ⇒ safe". It also missed open redirect #48 and static IV #5.
- **mix75, near-total TP bias on this distribution:** it rejected 0/7 FPs, and sanitizer-wrapped SQL (#17, #42–44) got p≈0.95 TP. Same failure on the boolean output (#27) and the localhost socket (#47).
- **full:** essentially always TP here (recall 1.0, 2/7 FPs rejected: #17, #44). It is wrong on #27, #28, #42, #43, #47.
- **base:** the most discriminating on FPs (5/7) but under-calls weak hashing (MD5/SHA-1 4/11 wrong) and #5, #14, #48, #58, #101.

### OWASP vs real gap
| model | OWASP test | stress | real |
|---|---|---|---|
| full | 0.906 | 0.641 | 0.952 (≈ always-TP) |
| mix75 | 0.983 | 0.887 | 0.876 (below always-TP, 0/7 FP) |
| base | 0.521 | 0.829 | 0.886 |

On real code, mix75's lead over full disappears. The real distribution, where most alerts are true and taint arrives through method parameters or the DB, is unlike the OWASP/synthetic one. 76/105 alerts are from rules the model never saw. XXE and crypto/hash generalise well to unseen rules for the adapters.

## 5. Recommendation (steps 2–4 not started)
1. Targeted new synthetic scenarios, all new and never drawn from this repo:
   - (a) SQL, XSS and redirect where taint arrives through method parameters or DB/stored data (TP), contrasted with genuinely constant or allowlisted inputs (FP).
   - (b) Quote-stripping and escaping sanitizers, with both exploitable and non-exploitable dialect variants, plus a context line showing the helper body.
   - (c) Non-HTML sinks (JSON content type, booleans or numbers written) as FP.
   - (d) formatted-sql-string, XXE-factory, ECB/static-IV and unencrypted-socket rule ids, so these rules are seen in training.
2. `needs_review` from p_true_renorm: most real errors sit at 0.2–0.6 for base/full. mix75's errors on #58–61 have p_true 0.22–0.35, so a 0.2–0.8 band would catch them; its #17/#42–44 errors (≈0.95) would not be caught.
3. 2 epochs plus 3-seed averaging, with model selection on a mix that includes a real-world-like dev set built from a different public repo, not this one, to avoid tuning to the test.

The underlying files (raw Semgrep output, review dump, builder/label scripts, labels, eval set, predictions, metrics) stay private because they contain the source repo's paths and code.
