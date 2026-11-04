"""Download the base model and the published LoRA adapter into your own Modal volumes (CPU only, no GPU).

  modal run modal_app/fetch_weights.py

The base model goes into the HF cache volume (VV_HF_VOLUME) and the adapter into
VV_ADAPTER_VOLUME at /<adapter>/adapter, which is where classifier_modal.py looks for them.
Both repos are public, so no Hugging Face token is needed. If HF_TOKEN is set locally it is passed
to the remote function as a Modal secret (never written to disk or printed).
"""
import os
import modal

MODEL_ID = os.environ.get("VV_BASE_MODEL", "meta-models/Muse-Glimmer-30B")
MODEL_REVISION = os.environ.get("VV_BASE_MODEL_REVISION") or None
ADAPTER_REPO = os.environ.get("VV_ADAPTER_REPO", "amoghng7/vuln-verdict-muse-glimmer-30b-lora")

app = modal.App("vuln-verdict-harness-fetch")
hf_vol = modal.Volume.from_name(os.environ.get("VV_HF_VOLUME", "muse-glimmer-hf-cache"), create_if_missing=True)
out_vol = modal.Volume.from_name(os.environ.get("VV_ADAPTER_VOLUME", "vuln-verdict-outputs"), create_if_missing=True)
image = (modal.Image.debian_slim(python_version="3.12").uv_pip_install("huggingface_hub[hf_xet]")
         .env({"HF_HOME": "/vol/hf"}))
secrets = [modal.Secret.from_dict({"HF_TOKEN": os.environ["HF_TOKEN"]})] if os.environ.get("HF_TOKEN") else []


@app.function(image=image, volumes={"/vol/hf": hf_vol, "/vol/outputs": out_vol}, secrets=secrets,
              timeout=60 * 60, retries=0)
def fetch(adapter: str = "r2_s7"):
    from huggingface_hub import snapshot_download
    print(f"downloading {MODEL_ID} ({MODEL_REVISION or 'main'}) into the HF cache volume", flush=True)
    snapshot_download(MODEL_ID, revision=MODEL_REVISION)
    hf_vol.commit()
    dest = f"/vol/outputs/{adapter}/adapter"
    # Repo root is run r2_s7; seed42/ is the seed-variance run.
    sub = [] if adapter == "r2_s7" else ["seed42/*"]
    tmp = snapshot_download(ADAPTER_REPO, allow_patterns=sub or ["*.json", "*.safetensors", "*.jinja"],
                            ignore_patterns=[] if sub else ["seed42/*"], local_dir=f"/vol/outputs/_dl_{adapter}")
    import shutil
    src = os.path.join(tmp, "seed42") if sub else tmp
    os.makedirs(dest, exist_ok=True)
    for f in os.listdir(src):
        if f.endswith((".json", ".safetensors", ".jinja")):
            shutil.copy2(os.path.join(src, f), os.path.join(dest, f))
    shutil.rmtree(tmp, ignore_errors=True)
    out_vol.commit()
    print(f"adapter {ADAPTER_REPO} -> {dest}: {sorted(os.listdir(dest))}", flush=True)


@app.local_entrypoint()
def main(adapter: str = "r2_s7"):
    if adapter not in {"r2_s7", "r2_s42"}:
        raise SystemExit("adapter must be r2_s7 (repo root) or r2_s42 (seed42/)")
    fetch.remote(adapter)
