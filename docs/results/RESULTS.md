# vuln-verdict: synthetic data and stress-test results (2026-10-31 IST)

## Step 0: terms gate (PASSED, with caveat)
Meta Model API Terms of Service, https://dev.meta.ai/legal/terms-of-service (last updated Oct 9, 2026), §10.1. You may not:
> "(ix) use or facilitate the use of the Services (including by taking Actions), or the Outputs of the Services, to train, fine-tune, distill, or otherwise improve or create any artificial intelligence or machine learning model or other product or service that competes with Meta's models or services, or systematically collect Outputs or other data to build training datasets for use in developing competing models or services, without Meta's prior written authorization. For the avoidance of doubt, using Services or Outputs solely for evaluation, benchmarking, or quality assessment of your own systems does not constitute a prohibited use under this Section"

The Acceptable Use Policy (https://dev.meta.ai/legal/acceptable-use-policy) has no output or training clause.
- **Stress set:** evaluation-only, so it falls under the explicit carve-out.
- **Training data:** used to fine-tune Meta's own Apache-2.0 Muse Glimmer into a narrow Java-alert triage classifier for a Meta hackathon. We read this as not "competing". "Competes" is undefined, so this is a judgment call and not legal advice.

## Spend
- **Meta API: $18.77** (from `spend.json`, the source of truth) over 3,735 calls.
  - Generation: stress $4.17, train $7.16. Judge: $7.40. Pilots and probe: ~$0.04.
  - The cap was $25 and the hard abort was set at $20. No further API calls were made.
- **Modal:** estimated at **~$7–8**, from about 2.75 h of A100-80GB time at $2.50/h plus some CPU and memory. This is an estimate from app timestamps, not a bill. It includes:
  - the stress eval: 9 min
  - the first mix75/all attempts: 34 min each. The mix75 adapter was saved; the all-synth run was cancelled mid-training when the local client was killed.
  - re-eval attempts that were cancelled: 2 × 10 min
  - the deployed and spawned jobs: about 68 container-min
- All Modal apps are now stopped (`modal app list` shows no running or deployed apps).

## Datasets
- **Stress set:** 345 kept (FP 175 / TP 170) out of 360 generated. 11 CWE categories with 27–33 examples each. Disjoint domains, seeds and style from the train set.
- **Synthetic train:** 1,435 kept (FP 735 / TP 700) out of 1,500 generated.
- **Mixes:**
  - mix75: 1137 real + 380 synthetic, stratified 190/190.
  - all: 1137 real + 1435 synthetic.
- **Drop rates (judge disagreement):**
  - Stress: 13/358 (3.6%), plus 2 judge errors. By category: ssrf 18.2%, hardcoded 12.5% (all `aws_key`, because the generator used AWS's public documentation EXAMPLE keys), logi/pathtraver/redirect about 3%, all others 0%.
  - Train: 63/1498 (4.2%), plus 2 leak-filter drops. By category: ssrf 10.9%, xxe 8.8%, redirect 8.2%, logi 5.9%, cmdi 3.6%, all others 2.2% or less.
- **Dedup:** 0 exact and 0 near-duplicates removed. Max shingle-Jaccard of synthetic train vs stress is 0.43.
- **Spot check:** 15 stress examples hand-checked; all 15 labels correct, 1 borderline. Details in `stress_spotcheck.md`.

## Results

### Stress set (n=345, synthetic, never trained on)

| model | acc | TP prec | TP recall | confusion |
|---|---|---|---|---|
| base | 0.829 | 0.974 | 0.671 | tp114 fp3 fn56 tn172 |
| old adapter (real only) | 0.641 | 0.631 | 0.653 | tp111 fp65 fn59 tn110 |
| mix75 (1137 real + 380 synth) | 0.887 | 0.978 | 0.788 | tp134 fp3 fn36 tn172 |
| all (1137 real + 1435 synth) | 0.991 | 0.988 | 0.994 | tp169 fp2 fn1 tn173 |

### OWASP real test (n=234)

| model | acc | TP prec | TP recall | confusion |
|---|---|---|---|---|
| base | 0.521 | 0.738 | 0.472 | tp76 fp27 fn85 tn46 |
| old adapter (real only) | 0.906 | 0.966 | 0.894 | tp144 fp5 fn17 tn68 |
| mix75 (1137 real + 380 synth) | 0.983 | 0.976 | 1.000 | tp161 fp4 fn0 tn69 |
| all (1137 real + 1435 synth) | 0.974 | 0.970 | 0.994 | tp160 fp5 fn1 tn68 |

### OWASP real val (n=241)

| model | acc | TP prec | TP recall | confusion |
|---|---|---|---|---|
| base | 0.523 | 0.740 | 0.467 | tp77 fp27 fn88 tn49 |
| old adapter (real only) | 0.917 | 0.974 | 0.903 | tp149 fp4 fn16 tn72 |
| mix75 (1137 real + 380 synth) | 0.979 | 0.976 | 0.994 | tp164 fp4 fn1 tn72 |
| all (1137 real + 1435 synth) | 0.975 | 0.970 | 0.994 | tp164 fp5 fn1 tn71 |

### Stress breakdowns (accuracy)

| category | n | base | old | mix75 | all |
|---|---|---|---|---|---|
| cmdi | 33 | 0.758 | 0.606 | 0.939 | 1.000 |
| crypto | 33 | 1.000 | 0.667 | 1.000 | 1.000 |
| deser | 33 | 0.970 | 0.606 | 0.970 | 0.970 |
| hardcoded | 28 | 1.000 | 0.607 | 0.929 | 1.000 |
| logi | 31 | 0.548 | 0.516 | 0.806 | 1.000 |
| pathtraver | 32 | 0.906 | 0.625 | 0.969 | 0.969 |
| redirect | 31 | 0.645 | 0.903 | 0.806 | 1.000 |
| sqli | 33 | 0.697 | 0.606 | 0.727 | 1.000 |
| ssrf | 27 | 0.852 | 0.593 | 0.889 | 1.000 |
| xss | 32 | 0.812 | 0.531 | 0.906 | 0.969 |
| xxe | 32 | 0.938 | 0.781 | 0.812 | 1.000 |

| intended_label | n | base | old | mix75 | all |
|---|---|---|---|---|---|
| false_positive | 175 | 0.983 | 0.629 | 0.983 | 0.989 |
| true_positive | 170 | 0.671 | 0.653 | 0.788 | 0.994 |

| difficulty | n | base | old | mix75 | all |
|---|---|---|---|---|---|
| easy | 83 | 0.855 | 0.687 | 0.904 | 1.000 |
| hard | 123 | 0.780 | 0.553 | 0.854 | 0.984 |
| medium | 139 | 0.856 | 0.691 | 0.906 | 0.993 |

| twist | n | base | old | mix75 | all |
|---|---|---|---|---|---|
| a validation step exists but is bypassable | 26 | 0.654 | 0.423 | 0.577 | 0.962 |
| framework-provided protection (Spring Data, @Valid with @Pattern regex | 26 | 1.000 | 0.538 | 1.000 | 1.000 |
| straightforward data flow | 34 | 0.706 | 0.735 | 0.794 | 1.000 |
| straightforward protection | 36 | 1.000 | 0.528 | 0.972 | 1.000 |
| taint flows through a builder/StringBuilder/String.format/helper metho | 24 | 0.583 | 0.708 | 0.833 | 1.000 |
| taint flows through a collection (List/Map) or a Java stream pipeline  | 25 | 0.680 | 0.600 | 0.880 | 1.000 |
| test-only code (JUnit test class or test fixture) | 23 | 1.000 | 0.652 | 1.000 | 1.000 |
| the alert is on dead code or a branch whose value is always a constant | 30 | 0.933 | 0.700 | 0.933 | 0.967 |
| the code looks innocent and well-structured (good naming, logging, err | 24 | 0.625 | 0.625 | 0.792 | 1.000 |
| the input arrives via a header, cookie, path variable or JSON body fie | 37 | 0.730 | 0.757 | 0.838 | 1.000 |
| the neutralising helper/sanitizer is a separate method shown in the sn | 37 | 0.973 | 0.730 | 1.000 | 0.973 |
| user data passes through a collection/stream, but is replaced by a con | 23 | 1.000 | 0.609 | 1.000 | 1.000 |

| overall | 345 | 0.829 | 0.641 | 0.887 | 0.991 |

Paired McNemar tests (exact):
- Real test, old vs mix75: mix75 fixes 18 examples and breaks 0 (p≈1e-5).
- Real val: 17 fixed, 2 broken (p≈0.0007).
- mix75 vs all on real test: 2 vs 0 (p=0.5, no difference).
- Stress, base vs mix75: 40 fixed, 20 broken (p≈0.013).

## Interpretation
1. **The old adapter was overfit to OWASP-Benchmark templates.** On the stress set it scores 0.641, well below the *untuned base* (0.829). It gains no TP recall over base (0.653 vs 0.671) and loses most FP-recognition ability: FP accuracy 0.629 vs 0.983, with 65 false alarms vs 3. Its 90.6% on test reflects template matching more than security reasoning.
2. **Mixing in synthetic data fixed this and also improved the real-data scores.** mix75 scores 0.887 on stress (above base, mainly TP recall 0.67→0.79), and on real OWASP data reaches 0.983 test and 0.979 val, vs 0.906 and 0.917 for the old adapter.
3. **The all-synthetic run's 0.991 on stress is inflated and should not be used to pick a winner.** Stress and synthetic-train come from the same generator and judge (muse-spark), so for a synthetic-heavy model the stress set is close to in-distribution. On the independent real test/val sets, all ≈ mix75 (0.974 vs 0.983; 0.975 vs 0.979; not significant).
4. **Best config: `synth_mix75`.** It is best or tied on the real held-out data, which is the only fully independent signal, and it is a smaller deviation from the real distribution. Synthetic data clearly helped.

## Files
- `synth/`: `stress.jsonl` + `stress.meta.jsonl`, `synth_train.jsonl` + `.meta.jsonl`, `train_mix75.jsonl` (+ `train_mix75.synth_idx.json`), `train_all.jsonl`, `stress_report.json`, `train_report.json`, `stress_spotcheck.md`, `PROVENANCE_SYNTH.md`, `spend.json`, `results_tables.md`, and the scripts `pipeline.py`, `metaapi.py`, `gen_stress.py`, `gen_train.py`, `stress_breakdown.py`, `make_results.py`.
- `out/results/full/`: the old adapter, untouched. Adds `eval_summary_stress.json` and `preds_stress_{base,adapter}.jsonl`.
- `out/results/synth_mix75/` and `out/results/synth_all/`: adapters, eval JSONs, preds and train_metrics. The same files are on the Modal volume `vuln-verdict-outputs`.
- `modal/train_modal.py`: adds `--eval-file`, `--no-base`, `--summary-name` and a `train` entrypoint. The original is backed up as `train_modal.py.bak_pre_synth`. `modal/spawn_jobs.py` and `modal/poll_jobs.py` handle server-side spawn and polling.

## Caveats
- The stress set is synthetic: self-contained single-file Java written by the same model family that judged it and generated the training data. It is not real-world code, and it favours synthetic-trained models (see point 3).
- Labels come from generator–judge agreement within one model family, with only 15 human-checked. Shared blind spots would get through.
- The train set used lower reasoning effort than the stress set (generator minimal vs low; judge low vs medium) to fit the budget.
- Each configuration was trained once (one seed). Real test/val are small (234/241) and come from OWASP Benchmark, so near-ceiling scores still say little about real-repo alerts.
- The synthetic-heavy adapters' training loss went near 0, which suggests the synthetic examples are easy for the model to learn.
- Modal cost is an estimate from app timestamps; check the Modal dashboard for the actual bill.
