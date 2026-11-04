#!/usr/bin/env bash
# Run (with bash) the real fine-tuned classifier (Muse Glimmer 30B + r2_s7 LoRA) on your own Modal account.
#   scripts/run_real_model.sh fetch      download base model + public adapter into your Modal volumes (CPU, once)
#   scripts/run_real_model.sh classify   classify examples/tiny on an A100-80GB and compare with the bundled probabilities
# Needs: pip install -r requirements-modal.txt, then `modal setup`. No Hugging Face token is needed for public repos.
# Env: OUT (default out/real_tiny), VV_HF_VOLUME, VV_ADAPTER_VOLUME, VV_BASE_MODEL_REVISION, PYTHON.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"
cd "$HERE"
case "${1:-}" in
  fetch)
    modal run modal_app/fetch_weights.py ;;
  classify)
    OUT="${OUT:-out/real_tiny}"
    rm -rf "$OUT"
    # Classifier only: no Muse Spark audit or remediation unless you add --audit/--remediate with MODEL_API_KEY.
    MODEL_API_KEY= "$PY" -m vuln_verdict triage examples/tiny/semgrep.sarif --repo examples/tiny --out "$OUT" \
      --modal --title "tiny example (real model)"
    "$PY" - "$OUT/classifier_probs.jsonl" examples/tiny/probs_r2_s7.jsonl <<'PYEOF'
import json, sys
new = {r["alert_id"]: r["p_true"] for r in map(json.loads, open(sys.argv[1])) if r.get("alert_id")}
ref = {r["alert_id"]: r["p_true"] for r in map(json.loads, open(sys.argv[2])) if r.get("alert_id")}
print(f"{'alert':8} {'p_true (your run)':>18} {'bundled':>10} {'|diff|':>8}")
for k in sorted(set(new) | set(ref)):
    a, b = new.get(k), ref.get(k)
    d = f"{abs(a - b):.4f}" if a is not None and b is not None else "-"
    fa = f"{a:.4f}" if a is not None else "-"; fb = f"{b:.4f}" if b is not None else "-"
    print(f"{k:8} {fa:>18} {fb:>10} {d:>8}")
print("Small differences (batching, GPU, library versions) are expected; lanes use the band [0.44, 0.98].")
PYEOF
    ;;
  *) echo "usage: $0 fetch|classify" >&2; exit 2 ;;
esac
