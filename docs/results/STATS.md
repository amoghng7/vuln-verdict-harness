# vuln-verdict v0 — stats (full machine-readable version: stats.json)

| split | n | true_positive | false_positive | TP share | ~tokens total (chars/4) | mean | max | file size |
|---|---|---|---|---|---|---|---|---|
| train | 1137 | 774 | 363 | 68.1% | 918k | 807 | 1211 | 3.9 MB |
| val | 241 | 165 | 76 | 68.5% | 196k | 812 | 1180 | 0.83 MB |
| test | 234 | 161 | 73 | 68.8% | 187k | 800 | 1205 | 0.80 MB |
| smoke_train | 200 | 100 | 100 | 50.0% | 161k | 803 | 1208 | 0.68 MB |
| **total (excl. smoke)** | **1612** | **1100** | **512** | 68.2% | 1.30M | | | 5.5 MB |

Fireworks-ready upload (train + val): ~4.7 MB, ~1.1M tokens per epoch. No example exceeds ~1.3k tokens, so a 2k context is enough.

Funnel: 2,740 Benchmark cases → 1,909 Semgrep findings in 1,515 files → 1,758 (case, rule) alerts after merging repeats → minus 146 category-mismatched alerts → **1,612 examples**. 1,225 cases had no alert (all weakrand/securecookie included).

Per-rule labels: DES 130/0, DESede 130/0, MD5 28/0, SHA1 61/0 (TP/FP: always TP), path-traversal 120/106, XSS writer 202/108, cmdi 112/96, sqli 234/143, ldapi 26/28, trust-boundary 43/18, xpath 14/13.
