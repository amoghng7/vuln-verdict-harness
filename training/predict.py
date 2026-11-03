"""
vuln-verdict batch inference (Modal, 1x A100-80GB).

Input : JSONL, one alert per line in the dataset chat format: {"messages":[{"role":"system",...},{"role":"user",...}, ...]}
        (an assistant/gold turn, if present, is ignored for prediction and only used to report accuracy),
        or {"user": "<the alert text exactly as in the dataset user turn>"} (the standard system prompt is added).
Output: JSONL, one line per alert: {"idx", "verdict", "decision", "p_true", "lp_true", "lp_false", "gold"?}
        verdict  = forced-choice argmax (true_positive / false_positive)
        decision = verdict, or "needs_review" when LO <= p_true <= HI

Usage (from this directory):
  export PATH=/workspace/.venv-modal/bin:$PATH; export MODEL_API_KEY=...
  modal run predict.py --input alerts.jsonl --out preds.jsonl [--adapter r2_s42] [--lo 0.2 --hi 0.8]
  (--adapter base  -> no adapter; adapters live in Volume vuln-verdict-outputs:/<run>/adapter)
"""
import json, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "modal"), "/root/modal", "/root"):
    if _p not in sys.path: sys.path.insert(0, _p)
try:
    import train_modal as T
except ModuleNotFoundError:
    print("DEBUG /root:", os.listdir("/root") if os.path.isdir("/root") else None, "sys.path:", sys.path, flush=True); raise  # reuses the exact training/eval prompt construction and model loading

DEFAULT_ADAPTER = "r2_s7"    # final round-2 model (see RESULTS_ROUND2.md)
DEFAULT_LO, DEFAULT_HI = 0.44, 0.98 # needs_review band, chosen on dev+val only (RESULTS_ROUND2.md)
sys.path.insert(0, "/workspace/vuln-verdict-data/out/scripts")
PRED_IMAGE = T.image.add_local_dir(os.path.join(_HERE, "modal"), "/root/modal", ignore=["*.pyc", "__pycache__", "*.json", "*.log"])  # ship train_modal.py into the container


@T.app.function(image=PRED_IMAGE, gpu=T.GPU, volumes=T.VOLS, memory=65536, timeout=60 * 60, retries=0)
def predict_batch(rows: list, adapter: str = DEFAULT_ADAPTER, lo: float = DEFAULT_LO, hi: float = DEFAULT_HI, bs: int = 8):
    import torch
    model, tok = T._load_model(adapter_dir=None if adapter == "base" else f"/vol/outputs/{adapter}/adapter")
    model.eval(); tok.padding_side = "left"
    true_id = tok(T.VERDICT_PREFIX + "true", add_special_tokens=False).input_ids[-1]
    false_id = tok(T.VERDICT_PREFIX + "false", add_special_tokens=False).input_ids[-1]
    out = []
    for i in range(0, len(rows), bs):
        batch = rows[i:i + bs]
        prompts = [T._build_prompt(tok, r["messages"]) + T.VERDICT_PREFIX for r in batch]
        enc = tok(prompts, return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
        with torch.no_grad():
            try:
                lg = model(**enc, logits_to_keep=1).logits[:, -1, :].float()
            except TypeError:
                lg = model(**enc).logits[:, -1, :].float()
        lp = torch.log_softmax(lg, -1)
        for j, r in enumerate(batch):
            lt, lf = float(lp[j, true_id]), float(lp[j, false_id])
            p = float(torch.sigmoid(torch.tensor(lt - lf)))
            verdict = "true_positive" if lt >= lf else "false_positive"
            rec = {"idx": i + j, "verdict": verdict, "decision": "needs_review" if lo <= p <= hi else verdict,
                   "p_true": p, "lp_true": lt, "lp_false": lf}
            if len(r["messages"]) > 2:
                try: rec["gold"] = json.loads(r["messages"][2]["content"])["verdict"]
                except Exception: pass
            out.append(rec)
    return out


def _normalise(row):
    if "messages" in row:
        return {"messages": row["messages"][:3]}
    from build_dataset import SYSTEM_PROMPT
    return {"messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": row["user"]}]}


@T.app.local_entrypoint()
def main(input: str, out: str = "preds.jsonl", adapter: str = DEFAULT_ADAPTER, lo: float = DEFAULT_LO, hi: float = DEFAULT_HI):
    rows = [_normalise(json.loads(l)) for l in open(input) if l.strip()]
    preds = predict_batch.remote(rows, adapter, lo, hi)
    with open(out, "w") as f:
        for p in preds: f.write(json.dumps(p) + "\n")
    n = len(preds); rev = sum(p["decision"] == "needs_review" for p in preds)
    print(f"{n} alerts -> {n-rev} auto-decided, {rev} needs_review; written to {out}")
    g = [p for p in preds if "gold" in p]
    if g:
        auto = [p for p in g if p["decision"] != "needs_review"]
        print(f"accuracy(all, argmax)={sum(p['verdict']==p['gold'] for p in g)/len(g):.3f}  "
              f"accuracy(auto-decided)={sum(p['decision']==p['gold'] for p in auto)/max(1,len(auto)):.3f}")
