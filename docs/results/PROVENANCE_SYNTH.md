# Synthetic data provenance (vuln-verdict)

Generated 2026-10-31 (IST) with the **Meta Model API** (`muse-spark-1.3`, Standard mode, `POST https://api.meta.ai/v1/chat/completions`, JSON-schema constrained output). No other provider was used.

## Terms gate
Meta Model API Terms of Service (https://dev.meta.ai/legal/terms-of-service, last updated Oct 9, 2026), §10.1(ix): the bar on using Outputs "to train, fine-tune, distill … any … model … that competes with Meta's models or services", together with the explicit carve-out that "using Services or Outputs solely for evaluation, benchmarking, or quality assessment of your own systems does not constitute a prohibited use." Interpretation: the stress set is evaluation-only (carve-out). The training data fine-tunes Meta's own Apache-2.0 Muse Glimmer into a narrow Java-alert triage classifier for a Meta hackathon, which we read as non-competing. "Competes" is undefined, so this is a judgment call and not legal advice. Saved copy: /workspace/tos.txt.

## Two disjoint sets
| | Stress set (eval only, never trained on) | Synthetic train set |
|---|---|---|
| Files | `stress.jsonl` + `stress.meta.jsonl` | `synth_train.jsonl` + `synth_train.meta.jsonl` |
| Script / seed | `gen_stress.py`, seed 7101, scenario prefix `S-` | `gen_train.py`, seed 9203, prefix `T-` |
| Domains | 12 domains (list A: hospital, banking, airline, …) | 16 different domains (list B: e-commerce, streaming, IoT, …), disjoint from A |
| Style prompt | "experienced enterprise Java team" | mix of legacy / modern Java 17 / Android / microservice |
| Generator effort | `reasoning_effort=low`, T=1.0 | `minimal` (budget) |
| Judge effort | `medium` | `low` (budget) |
| Requested | 360 | 1500 |
| Kept | **345** (FP 175 / TP 170) | **1435** (FP 735 / TP 700) |

## Design
- 11 categories, each with Semgrep-style CWEs: sqli, xss, pathtraver, cmdi, deser, ssrf, hardcoded, crypto, xxe, redirect, logi. Each category has 5–9 named TP/FP *variants*, plus a "twist" for the tricky cases:
  - TP twists: bypassable validation, taint through builders/collections/streams, header/cookie/JSON sources, innocent-looking code.
  - FP twists: a separate sanitizer method, framework protection, dead/constant branches, test-only code, values replaced by constants.
- Assignment is round-robin over categories with alternating labels, which balances the sets about 50/50 overall and per category.
- Output uses exactly the same chat format as `out/train.jsonl`:
  - The system prompt is the same string as `pipeline.SYSTEM_PROMPT`.
  - The user message keeps the Tool/Rule/Severity/CWE/Location/Message block and shows the code line-numbered with comments removed and numbering gaps kept.
  - The assistant turn is `{"verdict":"…"}`.
  - Metadata lives only in the `.meta.jsonl` sidecar.
- Leak prevention:
  - Comments are stripped.
  - Examples containing label-revealing tokens are rejected (vulnerable, safe, sanitized, taint, bypass, …).
  - Imports are removed and the start line is randomised.

## Label verification and filtering
- A second, independent **judge** call (different system prompt: "senior AppSec reviewer, trace source→sink") sees only the alert and code, never the intended label. It returns {analysis, verdict}. Only examples where the judge agrees are kept.
- Dedup:
  - Exact match on a normalised-code SHA-1, which normalises strings, numbers, case and whitespace.
  - Near-duplicates: 5-token shingle Jaccard ≥ 0.85, applied within each set and train→stress.
  - Train records were also excluded against every stress hash and shingle set.
  - Removed: 0 exact, 0 near-duplicates.
  - Post-hoc check: the max Jaccard of any synthetic-train example vs any stress example is 0.43 (p99 0.34). Stress vs the real OWASP test split has a max of 0.10.

### Drop rates
| Set | judged | judge disagree | other drops |
|---|---|---|---|
| Stress | 358 | 13 (3.6%) | 2 judge errors (bad JSON) |
| Train | 1498 | 63 (4.2%) | 2 leak-filter |

Judge disagreement by category:
- **Stress:**
  - ssrf 18.2%
  - hardcoded 12.5% (all 4 were `aws_key` TP specs where the generator used AWS's public documentation EXAMPLE keys, so the judge correctly called them placeholders; the train prompt was tightened afterwards)
  - logi, pathtraver, redirect about 3%
  - all others 0%
- **Train:**
  - ssrf 10.9%, xxe 8.8%, redirect 8.2%, logi 5.9%, cmdi 3.6%
  - all others 2.2% or less

Per-scenario breakdowns are in `stress_report.json` and `train_report.json`.

Most disagreements were real generator mistakes, e.g. a "TP" SSRF spec that ended up with an effective host-prefix check. The judge filter removes these, but it cannot catch mistakes that the generator and judge share.

## Human check
`stress_spotcheck.md` holds 30 random stress examples (rng seed 1). I hand-checked 15 of them: all 15 labels were correct, with one borderline case (SHA-1 secret-suffix "MAC" labelled TP).

## Training mixes (seeded)
- `train_mix75.jsonl`: all 1137 real + 380 synthetic, about 75:25. The synthetic part is stratified by category × label (190 TP / 190 FP), seed 4242. Indices are in `train_mix75.synth_idx.json`.
- `train_all.jsonl`: 1137 real + all 1435 synthetic (2572 total).

## Cost (from `spend.json`, token usage of every response)
- Total **$18.77** over 3735 calls: 2.52M input tokens and 3.67M output tokens, of which 2.59M were reasoning tokens.
- Prices: $1.25/M input, $4.25/M output. Cached input is billed at the full rate, so the figure is conservative.
- Breakdown:
  - stress generation $4.17
  - train generation $7.16
  - judge (both sets) $7.40
  - pilots and probe about $0.04
- Hard abort was set at $20.

## Caveats
- The generator and judge are the same model family, so the agreement filter checks consistency, not ground truth. Labels have not been verified by humans beyond the 15-example spot check.
- The train set used lower reasoning effort than the stress set for both generator and judge.
- The code is synthetic, self-contained, single-file Java: the whole source→sink flow is visible. It is not real-world code.
