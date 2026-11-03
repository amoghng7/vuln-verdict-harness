# vuln-verdict - historical Round 2 results (31 Oct 2026)

**This is the historical round-2 record, not a rerun under the 3 Nov hardening changes.** Adapter paths below are
private author-held artifacts and are not distributed with this repository.

## TL;DR
- **Final model: `r2_s7`** (QLoRA on Muse Glimmer 30B, seed 7, 2 epochs).
  - Private adapter: Modal Volume `vuln-verdict-outputs:/r2_s7/adapter`; the author-held local copy was `round2/results/r2_s7/adapter/`.
  - Training data: real train 1137 + mix75 synthetic 380 + new targeted 378 = 1895 rows (synthetic share 40.0%).
- Selected on **dev + OWASP val only**, by mean of dev balanced accuracy and val accuracy:

  | Model | Selection score |
  |---|---|
  | r2_s7 | 0.938 |
  | r2_s42 | 0.928 |
  | mix75 | 0.861 |
  | full | 0.746 |
  | base | 0.667 |

  The real set was excluded from direct selection and band-choice scores. However, its round-1 failure categories
  informed targeted synthetic training-data design, so it is not an independent test set; real-set claims are optimistic.
- In this historical comparison, r2_s7 scored 0.924 on that non-independent real set, between full (0.952) and mix75
  (0.876). This is not evidence of generalization to unfamiliar repositories.
- With the needs_review band, every remaining error on dev and val went to review. On the real set, all 6 FP errors
  were routed to review.

## Per-set accuracy
Accuracy is forced choice (argmax of p_true). "FP rej" is the share of false positives correctly rejected.

| Model | dev (82) | dev high+med (77) | val (241) | test (234) | stress (345) | real (105) | real FP rej |
|---|---|---|---|---|---|---|---|
| base | 0.829 | 0.870 | 0.506 | 0.521 | 0.835 | 0.867 | 4/7 |
| full (old best on OWASP and real) | 0.585 | 0.558 | 0.917 | 0.906 | 0.643 | 0.952 | 2/7 |
| mix75 (old best on stress and test) | 0.744 | 0.766 | 0.979 | 0.983 | 0.884 | 0.876 | 0/7 |
| r2_s42 | 0.878 | 0.896 | 0.979 | 0.979 | 0.977 | 0.914 | 2/7 |
| **r2_s7 (final)** | **0.890** | 0.883 | **0.988** | 0.974 | **0.988** | 0.924 | 1/7 |

- Always-TP gives **0.933 accuracy and 0.5 balanced accuracy** on the real set (98 TP / 7 FP), so real-set accuracy
  alone hardly separates the models and the seven-FP sample severely limits FP conclusions.
- On dev, r2_s7 rejects 31/40 FP and keeps 42/42 TP (historical balanced accuracy 0.887).
- Greedy-decode accuracy matched forced choice within ±0.01 in this run (dev 0.878, real 0.933). There were 0 invalid outputs.

## Seed variance (r2, 2 seeds; mean ± population SD)

| Set | Mean ± SD | Seed 42 | Seed 7 |
|---|---|---|---|
| dev | 0.884 ± 0.006 | 0.878 | 0.890 |
| val | 0.983 ± 0.004 | 0.979 | 0.988 |
| test | 0.976 ± 0.002 | 0.979 | 0.974 |
| stress | 0.983 ± 0.006 | 0.977 | 0.988 |
| real | 0.919 ± 0.005 | 0.914 | 0.924 |

The gap between seeds (≤1.1 pt) is smaller than the gaps between models. I ran 2 seeds rather than 3 to keep Modal spend low.

## needs_review band (step 3)
- **Rule:** an alert is `needs_review` when lo ≤ p_true ≤ hi.
- **How lo/hi were chosen:** for each model, separately, on dev + val only. The search maximised the mean of dev and val accuracy on auto-decided alerts, subject to coverage ≥ 75% on each set (0.01 grid).
- **Bands:**
  - final r2_s7: [0.44, 0.98]. It is asymmetric because the model's remaining errors are over-confident TP calls on false positives.
  - full: [0.21, 0.54].
  - base: [0.23, 0.44].

Columns: coverage = share auto-decided; acc(auto) = accuracy on auto-decided alerts; acc(abstain) = correct auto-decisions / all alerts; errors routed = argmax errors that land in review.

**r2_s7, band [0.44, 0.98]**

| Set | Coverage | Acc (auto) | Acc (abstain) | Errors routed | n_review |
|---|---|---|---|---|---|
| dev | 0.756 | 1.000 | 0.756 | 9/9 | 20 |
| val | 0.934 | 1.000 | 0.934 | 3/3 | 16 |
| test | 0.932 | 0.995 | 0.927 | 5/6 | 16 |
| stress | 0.835 | 0.997 | 0.832 | 3/4 | 57 |
| real | 0.714 | 0.973 | 0.695 | 6/8 (all 6 FP errors) | 30 |

**full, band [0.21, 0.54]**

| Set | Coverage | Acc (auto) | Acc (abstain) | Errors routed |
|---|---|---|---|---|
| dev | 0.890 | 0.575 | 0.512 | 3/34 |
| val | 0.842 | 0.980 | 0.826 | 16/20 |
| test | 0.799 | 0.973 | 0.778 | 17/22 |
| stress | 0.577 | 0.673 | 0.388 | 58/123 |
| real | 0.981 | 0.951 | 0.933 | 0/5 |

**base, band [0.23, 0.44]**

| Set | Coverage | Acc (auto) | Acc (abstain) | Errors routed |
|---|---|---|---|---|
| dev | 0.866 | 0.845 | 0.732 | 3/14 |
| val | 0.751 | 0.580 | 0.436 | 43/119 |
| test | 0.726 | 0.612 | 0.444 | 46/112 |
| stress | 0.904 | 0.894 | 0.809 | 24/57 |
| real | 0.924 | 0.907 | 0.838 | 5/14 |

The 2 real-set errors that are not routed are TP alerts called FP with high confidence: no-static-initialization-vector (p = 0.04) and formatted-sql-string (p = 0.27).

**`predict.py`.** Usage: `modal run predict.py --input alerts.jsonl --out preds.jsonl [--adapter r2_s7] [--lo 0.44 --hi 0.98]`.
- Input is dataset-format JSONL, or `{"user": ...}` rows.
- Output fields: verdict, decision (verdict or needs_review), p_true, lp_true, lp_false, and gold when present.
- It reuses the training prompt code and the forced-choice logprobs.
- **Verified on 31 Oct, 21:31 IST** with `modal run predict.py --input dev/dev.jsonl --out round2/predict_dev_check.jsonl`. It ran end to end on 1× A100: 82 alerts, 60 auto-decided and 22 needs_review. Accuracy was 0.878 on all 82 alerts (argmax) and 1.000 on the auto-decided ones.
  - The eval-harness numbers were 0.890, with 20 needs_review.
  - Against the eval harness, mean |Δp_true| is 0.007 and max is 0.12. That drift comes from batched left-padding numerics (bs 8).
  - The verdict changes on one alert: idx 77, a gold FP, where p moves from 0.438 to 0.500. That alert flips to TP, but it falls inside the band, so it is routed to review and is not an auto error. The needs_review membership also changes for one alert: idx 3, where p = 0.980 vs 0.982.
  - To reproduce the eval numbers exactly, use bs = 1.

## Data built this round
**Dev set** (`dev/`; never trained on): 82 Semgrep 1.183.0 p/java alerts from 6 public repos.

| Repo | Alerts |
|---|---|
| java-sec-code | 25 |
| JavaVulnerableLab | 18 |
| Openfire | 13 |
| JSPWiki | 12 |
| Roller | 11 |
| RuoYi | 3 |

- Labels: TP 42 / FP 40. Confidence: high 56, medium 21, low 5.
- Same chat format as the existing sets; I hashed identifiers and literals that give away the label.
- Labelling method: a manual pass reading the full source, then a self second-opinion pass.
  - The second pass marked 22 items `uncertain` and gives the alternative reading for each.
  - **It was not an independent annotator.** No Meta budget was left for an LLM second opinion.
- 5 of r2_s7's 9 dev errors are items marked uncertain. The other 4 are Roller escaped-output XSS false positives that I labelled high confidence.

**Targeted synthetic data** (`synth/targeted/`):
- Contents:
  - 240 contrastive TP/FP pairs across 10 new scenario families: sql_param, sql_request, sql_sanitizer, xss_flow, xxe, socket, path, redirect, static_iv, crypto_ecb.
  - Two-call judge agreement: 446 kept, 27 disagreed, 1 judge error.
  - Deduplicated against train, stress, synth, real and dev. The highest Jaccard similarity to any real or dev alert is 0.12.
  - None of the user's repo code was copied.
- A stratified subset of 378 was used (TP 181 / FP 197), which keeps the synthetic share at ≤ 40%.
- **Leakage disclosure:** I designed these families after seeing the round-1 failure categories on the user's repo (SQL/XSS/static-IV/socket false positives). The repo's code was not used, but the user's real set is no longer a fully independent test. Treat its numbers as optimistic.

## Spend
- **Meta:**
  - $18.7717 → $21.8138, so **+$3.04** this round (`synth/spend.json` is the source of truth).
  - Within the $4 cap (≤ $22.8 total) and below the $22 abort.
  - No Meta calls after the targeted generation.
- **Modal** (A100-80GB at $2.50/h), estimated from run timings:

  | Item | Time | Cost |
  |---|---|---|
  | 2 training runs | 1.49 h + 1.39 h (incl. eval) | ≈ $7.2 |
  | dev/val evals for full, base, mix75 | ~15 min | ≈ $0.6 |
  | predict.py check run | | ≈ $0.2 |
  | **Total** | | **≈ $8**, under the ~$12 limit |

  All apps were stopped at the end.

## Remaining weaknesses
1. **Escaped-output XSS:** the model still calls TP on output that is already escaped (escapeXml, escapeHTML), when the escaping is out of view or uses a custom helper. This covers 4 high-confidence dev errors and 2 real-set FP.
2. **Formatted-SQL false positives:** these are near-coin-flips on the user's repo (p = 0.50–0.56). The band catches them, but the model does not resolve them.
3. **Small FP samples:** only 7 FP on the user's real set and 40 on dev, so FP-rejection estimates have wide error bars (±15 pt or more). The dev labels rest on a single annotator.
4. **Too many reviews on hard sets:** the band routes 24–29% of dev and real alerts to review.
5. **Two seeds only:** variance is estimated from 2 seeds.

## Historical recommendation and limits
- The historical dev/OWASP selection favored **r2_s7 + needs_review band [0.44, 0.98]** through `predict.py`.
  - On the OWASP sets in this run it auto-decided about 93% of alerts at ≥ 99.5% accuracy.
  - On the single, non-independent real repository it sent 30/105 alerts to review and reached 0.973 auto-lane accuracy.
    Do not generalize that rate to unfamiliar real-world code.
- Before claiming broader performance, label a larger, independent real-world FP sample and evaluate on untouched
  repositories. The next data to add is escaped-output / sanitizer-helper XSS.
