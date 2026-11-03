"""Batch classifier on Modal (1x A100-80GB): Muse Glimmer 30B (4-bit NF4) + LoRA adapter.

Set VV_BASE_MODEL_REVISION to an immutable Hugging Face commit for reproducible inference. Adapter and
HF cache volume names are configurable through VV_ADAPTER_VOLUME and VV_HF_VOLUME. The app is ephemeral
and stops when the local Modal call returns.
"""
import json, os, re, time
import modal

MODEL_ID = os.environ.get("VV_BASE_MODEL", "meta-models/Muse-Glimmer-30B")
MODEL_REVISION = os.environ.get("VV_BASE_MODEL_REVISION") or None
GPU = os.environ.get("VV_GPU", "A100-80GB")
FORCED_PREFIX = " to=user<|message|>"
VERDICT_PREFIX = '{"verdict":"'

app = modal.App("vuln-verdict-harness-classifier")
hf_vol = modal.Volume.from_name(os.environ.get("VV_HF_VOLUME", "muse-glimmer-hf-cache"))
out_vol = modal.Volume.from_name(os.environ.get("VV_ADAPTER_VOLUME", "vuln-verdict-outputs"))
image = (
    modal.Image.debian_slim(python_version="3.12")
    .uv_pip_install("torch==2.15.0", "transformers==5.22.1", "peft==0.21.2", "bitsandbytes==0.50.2",
                    "accelerate==1.15.0", "huggingface_hub[hf_xet]", "numpy")
    .env({"HF_HOME": "/vol/hf", "TOKENIZERS_PARALLELISM": "false", "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True",
          "VV_BASE_MODEL": MODEL_ID, "VV_BASE_MODEL_REVISION": MODEL_REVISION or ""})
)


@app.function(image=image, gpu=GPU, volumes={"/vol/hf": hf_vol, "/vol/outputs": out_vol}, memory=65536,
              timeout=60 * 60, retries=0)
def classify(rows: list, adapter: str = "r2_s7", bs: int = 8):
    import torch, transformers
    from transformers import AutoConfig, AutoTokenizer, BitsAndBytesConfig
    if bs < 1:
        raise ValueError("batch size must be positive")
    if adapter != "base" and (adapter in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", adapter)):
        raise ValueError("adapter name must be a safe directory name containing only letters, digits, dot, underscore and hyphen")
    t0 = time.time()
    source = {"revision": MODEL_REVISION} if MODEL_REVISION else {}
    tok = AutoTokenizer.from_pretrained(MODEL_ID, **source)
    cls = getattr(transformers, AutoConfig.from_pretrained(MODEL_ID, **source).architectures[0])
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16)
    model = cls.from_pretrained(MODEL_ID, quantization_config=bnb, dtype=torch.bfloat16, device_map={"": 0},
                                attn_implementation="sdpa", **source)
    if adapter != "base":
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, f"/vol/outputs/{adapter}/adapter")
    model.eval(); tok.padding_side = "left"
    print(f"[load] {time.time()-t0:.0f}s; model={MODEL_ID}; revision={MODEL_REVISION or 'unspecified'}", flush=True)
    true_id = tok(VERDICT_PREFIX + "true", add_special_tokens=False).input_ids[-1]
    false_id = tok(VERDICT_PREFIX + "false", add_special_tokens=False).input_ids[-1]
    out = []
    for i in range(0, len(rows), bs):
        batch = rows[i:i + bs]
        prompts = [tok.apply_chat_template(r["messages"][:2], tokenize=False, add_generation_prompt=True)
                   + FORCED_PREFIX + VERDICT_PREFIX for r in batch]
        enc = tok(prompts, return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
        with torch.no_grad():
            try:
                lg = model(**enc, logits_to_keep=1).logits[:, -1, :].float()
            except TypeError:
                lg = model(**enc).logits[:, -1, :].float()
        lp = torch.log_softmax(lg, -1)
        for j, r in enumerate(batch):
            lt, lf = float(lp[j, true_id]), float(lp[j, false_id])
            out.append({"alert_id": r.get("alert_id"), "p_true": float(torch.sigmoid(torch.tensor(lt - lf))),
                        "lp_true": lt, "lp_false": lf})
    print(f"[done] {len(out)} rows in {time.time()-t0:.0f}s", flush=True)
    return out


@app.local_entrypoint()
def main(input: str, out: str, adapter: str = "r2_s7"):
    with open(input, encoding="utf-8") as f:
        rows = [json.loads(l) for l in f if l.strip()]
    preds = classify.remote(rows, adapter)
    with open(out, "w", encoding="utf-8") as f:
        for p in preds:
            f.write(json.dumps(p) + "\n")
    print(f"wrote {len(preds)} probabilities to {out}")
