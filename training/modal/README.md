# vuln-verdict QLoRA on Modal

Model: meta-models/Muse-Glimmer-30B (Apache-2.0, not gated, no HF token needed). GPU: 1x A100-80GB ($2.50/h).
Setup: `python3 -m venv .venv-modal && .venv-modal/bin/pip install modal` ; export MODAL_TOKEN_ID/MODAL_TOKEN_SECRET.

- `modal run train_modal.py::download`  (once; weights cached in Volume muse-glimmer-hf-cache)
- `modal run train_modal.py::smoke`     (200 ex, 40-min function timeout)
- `modal run --detach train_modal.py::full`  (train.jsonl 1 epoch + eval val/test, base vs adapter; 3-h timeout)
- `modal run train_modal.py::evaluate --run-name full --splits val,test`  (standalone re-eval; 90-min timeout)

Progress: `modal app logs <app-id>`, `modal app list`. Stop: `modal app stop <app-id>`.
Results: `modal volume ls vuln-verdict-outputs full` ; `modal volume get vuln-verdict-outputs full/adapter ./adapter_full`
  eval_summary.json, eval_<split>_<base|adapter>.json, preds_<split>_<variant>.jsonl (p_true_renorm, lp_true/lp_false,
  verdict_token_logprob for calibration), train_metrics.json.
Prompt: chat template + " to=user<|message|>" forced (skips reasoning channel); base = same 4-bit NF4 weights with adapter disabled.
