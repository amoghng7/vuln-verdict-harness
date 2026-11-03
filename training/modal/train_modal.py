"""
vuln-verdict: QLoRA SFT of meta-models/Muse-Glimmer-30B on Modal (1x A100-80GB, $2.50/h).

Entrypoints:
  modal run train_modal.py::download            # one-time: cache HF weights in a Volume (CPU only)
  modal run train_modal.py::smoke               # smoke: train on smoke_train.jsonl + tiny eval (40 min hard timeout)
  modal run --detach train_modal.py::full       # full: train on train.jsonl, then eval val+test (base vs adapter)
  modal run train_modal.py::evaluate --run-name full --splits val,test   # standalone eval of a saved adapter

Volumes:
  vuln-verdict-data     /data/{smoke_train,train,val,test}.jsonl
  muse-glimmer-hf-cache HF cache with the bf16 checkpoint (~60 GB)
  vuln-verdict-outputs  /outputs/<run>/adapter, train_metrics.json, eval_*.json, preds_*.jsonl
"""
import json
import os
import time

import modal

MODEL_ID = "meta-models/Muse-Glimmer-30B"
GPU = "A100-80GB"
APP_NAME = "vuln-verdict-qlora"

app = modal.App(APP_NAME)

data_vol = modal.Volume.from_name("vuln-verdict-data")
hf_vol = modal.Volume.from_name("muse-glimmer-hf-cache")
out_vol = modal.Volume.from_name("vuln-verdict-outputs")
VOLS = {"/vol/data": data_vol, "/vol/hf": hf_vol, "/vol/outputs": out_vol}

image = (
    modal.Image.debian_slim(python_version="3.12")
    .uv_pip_install(
        "torch==2.15.0",
        "transformers==5.22.1",
        "peft==0.21.2",
        "bitsandbytes==0.50.2",
        "accelerate==1.15.0",
        "huggingface_hub[hf_xet]",
        "numpy",
    )
    .env({"HF_HOME": "/vol/hf", "HF_XET_HIGH_PERFORMANCE": "1", "TOKENIZERS_PARALLELISM": "false",
          "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True"})
)

FORCED_PREFIX = " to=user<|message|>"  # assistant channel header; skips the reasoning channel
VERDICT_PREFIX = '{"verdict":"'
CRYPTO_RULE_MARKERS = ("audit.crypto.des-is-deprecated", "audit.crypto.desede-is-deprecated",
                       "audit.crypto.use-of-md5", "audit.crypto.use-of-sha1")


# ----------------------------------------------------------------------------------------------
# helpers (run inside containers)
# ----------------------------------------------------------------------------------------------
def _read_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def _build_prompt(tok, msgs):
    p = tok.apply_chat_template(msgs[:2], tokenize=False, add_generation_prompt=True)
    return p + FORCED_PREFIX


def _rule_of(row):
    for line in row["messages"][1]["content"].splitlines():
        if line.startswith("Rule: "):
            return line[6:].strip()
    return ""


def _label_of(row):
    return json.loads(row["messages"][2]["content"])["verdict"]


def _load_model(adapter_dir=None, for_training=False):
    import torch
    import transformers
    from transformers import AutoConfig, AutoTokenizer, BitsAndBytesConfig

    t0 = time.time()
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    cfg = AutoConfig.from_pretrained(MODEL_ID)
    cls = getattr(transformers, cfg.architectures[0])
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    model = cls.from_pretrained(MODEL_ID, quantization_config=bnb, dtype=torch.bfloat16,
                                device_map={"": 0}, attn_implementation="sdpa")
    print(f"[load] base loaded in {time.time()-t0:.0f}s; mem={torch.cuda.memory_allocated()/2**30:.1f} GiB", flush=True)
    if adapter_dir:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter_dir, is_trainable=for_training)
        print(f"[load] adapter loaded from {adapter_dir}", flush=True)
    return model, tok


def _metrics(rows, preds):
    tp = fp = fn = tn = correct = invalid = forced_correct = 0
    nc_total = nc_correct = 0
    for r, p in zip(rows, preds):
        gold = _label_of(r)
        pred = p["pred"]
        ok = pred == gold
        correct += ok
        invalid += pred is None
        forced_correct += p["forced_pred"] == gold
        if pred == "true_positive" and gold == "true_positive": tp += 1
        elif pred == "true_positive" and gold != "true_positive": fp += 1
        elif pred != "true_positive" and gold == "true_positive": fn += 1
        else: tn += 1
        if not any(m in _rule_of(r) for m in CRYPTO_RULE_MARKERS):
            nc_total += 1
            nc_correct += ok
    n = len(rows)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "n": n, "accuracy": correct / n, "tp_precision": prec, "tp_recall": rec, "tp_f1": f1,
        "invalid_outputs": invalid, "forced_choice_accuracy": forced_correct / n,
        "n_noncrypto": nc_total, "accuracy_noncrypto": nc_correct / nc_total if nc_total else None,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def _run_eval(model, tok, rows, bs=8, max_new_tokens=16):
    """Greedy decode + forced-choice verdict-token logprobs. Returns per-example predictions."""
    import torch

    model.eval()
    tok.padding_side = "left"
    true_id = tok(VERDICT_PREFIX + "true", add_special_tokens=False).input_ids[-1]
    false_id = tok(VERDICT_PREFIX + "false", add_special_tokens=False).input_ids[-1]
    stop_ids = [tok.convert_tokens_to_ids(t) for t in ("<|eot|>", "<|eom|>", "<|end_of_text|>")]
    pad_id = tok.convert_tokens_to_ids("<|finetune_right_pad|>")
    preds = []
    for i in range(0, len(rows), bs):
        batch = rows[i:i + bs]
        prompts = [_build_prompt(tok, r["messages"]) for r in batch]
        enc = tok(prompts, return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
        with torch.no_grad():
            out = model.generate(**enc, max_new_tokens=max_new_tokens, do_sample=False, temperature=None,
                                 top_p=None, top_k=None, output_logits=True, return_dict_in_generate=True,
                                 eos_token_id=stop_ids, pad_token_id=pad_id)
            gen = out.sequences[:, enc.input_ids.shape[1]:]
            logits = torch.stack(out.logits, dim=1).float()  # [B, T, V]
            # forced choice: prompt + '{"verdict":"' -> next-token logprob of true vs false
            enc2 = tok([p + VERDICT_PREFIX for p in prompts], return_tensors="pt", padding=True,
                       add_special_tokens=False).to("cuda")
            try:
                lg2 = model(**enc2, logits_to_keep=1).logits[:, -1, :].float()
            except TypeError:
                lg2 = model(**enc2).logits[:, -1, :].float()
            lp2 = torch.log_softmax(lg2, dim=-1)
        for j, r in enumerate(batch):
            text = tok.decode(gen[j], skip_special_tokens=True).strip()
            pred = None
            try:
                v = json.loads(text).get("verdict")
                if v in ("true_positive", "false_positive"):
                    pred = v
            except Exception:
                pass
            # logprob of the generated verdict token (greedy path)
            gen_lp = None
            for t in range(gen.shape[1]):
                tid = int(gen[j, t])
                if tid in (true_id, false_id):
                    gen_lp = float(torch.log_softmax(logits[j, t], -1)[tid])
                    break
            lt, lf = float(lp2[j, true_id]), float(lp2[j, false_id])
            m = max(lt, lf)
            p_true = float(torch.exp(torch.tensor(lt - m)) / (torch.exp(torch.tensor(lt - m)) + torch.exp(torch.tensor(lf - m))))
            preds.append({"idx": i + j, "gold": _label_of(r), "rule": _rule_of(r), "raw": text, "pred": pred,
                          "verdict_token_logprob": gen_lp, "lp_true": lt, "lp_false": lf, "p_true_renorm": p_true,
                          "forced_pred": "true_positive" if lt >= lf else "false_positive"})
        print(f"[eval] {min(i+bs, len(rows))}/{len(rows)}", flush=True)
    return preds


def _eval_splits(model, tok, run_dir, splits, limit=None, do_base=True, extra_sets=None, summary_name="eval_summary.json"):
    """splits: names of /vol/data/data/<split>.jsonl; extra_sets: {name: rows} passed in directly (e.g. --eval-file)."""
    results = {}
    sets = [(s, None) for s in splits if s] + list((extra_sets or {}).items())
    for split, given_rows in sets:
        rows = given_rows if given_rows is not None else _read_jsonl(f"/vol/data/data/{split}.jsonl")
        if limit:
            rows = rows[:limit]
        variants = [("adapter", None)]
        if do_base:
            variants.append(("base", "disable"))
        for name, mode in variants:
            t0 = time.time()
            if mode == "disable":
                with model.disable_adapter():
                    preds = _run_eval(model, tok, rows)
            else:
                preds = _run_eval(model, tok, rows)
            met = _metrics(rows, preds)
            met["seconds"] = time.time() - t0
            results[f"{split}/{name}"] = met
            with open(f"{run_dir}/preds_{split}_{name}.jsonl", "w") as f:
                for p in preds:
                    f.write(json.dumps(p) + "\n")
            with open(f"{run_dir}/eval_{split}_{name}.json", "w") as f:
                json.dump(met, f, indent=2)
            print(f"[eval] {split}/{name}: {json.dumps(met)}", flush=True)
            out_vol.commit()
    summ = f"{run_dir}/{summary_name}"
    prev = {}
    if os.path.exists(summ) and summary_name != "eval_summary.json":
        prev = json.load(open(summ))
    prev.update(results)
    with open(summ, "w") as f:
        json.dump(prev, f, indent=2)
    out_vol.commit()
    return results


def _train_impl(run_name, train_file, eval_splits, eval_limit, max_steps=-1, extra_sets=None, do_base=True, epochs=1, seed=42):
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import Trainer, TrainingArguments, TrainerCallback

    t_start = time.time()
    run_dir = f"/vol/outputs/{run_name}"
    if run_name != "full" and os.path.exists(f"{run_dir}/adapter"):
        raise RuntimeError(f"refusing to overwrite existing adapter in {run_dir}")
    os.makedirs(run_dir, exist_ok=True)
    model, tok = _load_model()
    t_loaded = time.time()

    # ---- data: loss on assistant tokens only ----
    eot = "<|eot|>"
    rows = _read_jsonl(f"/vol/data/data/{train_file}")
    feats, lens = [], []
    for r in rows:
        p_ids = tok(_build_prompt(tok, r["messages"]), add_special_tokens=False).input_ids
        a_ids = tok(r["messages"][2]["content"] + eot, add_special_tokens=False).input_ids
        ids = (p_ids + a_ids)[:2048]
        labels = ([-100] * len(p_ids) + a_ids)[:2048]
        feats.append({"input_ids": ids, "labels": labels})
        lens.append(len(ids))
    print(f"[data] {len(feats)} examples, max_len={max(lens)}, mean_len={sum(lens)/len(lens):.0f}", flush=True)
    pad_id = tok.convert_tokens_to_ids("<|finetune_right_pad|>")

    def collate(batch):
        L = max(len(b["input_ids"]) for b in batch)
        ids = torch.full((len(batch), L), pad_id, dtype=torch.long)
        lab = torch.full((len(batch), L), -100, dtype=torch.long)
        att = torch.zeros((len(batch), L), dtype=torch.long)
        for i, b in enumerate(batch):
            n = len(b["input_ids"])
            ids[i, :n] = torch.tensor(b["input_ids"])
            lab[i, :n] = torch.tensor(b["labels"])
            att[i, :n] = 1
        return {"input_ids": ids, "labels": lab, "attention_mask": att}

    # ---- LoRA on language-model linears only (vision tower untouched) ----
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()
    from transformers import set_seed
    set_seed(seed)  # LoRA init depends on the seed too
    lcfg = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
        target_modules=r".*language_model.*\.(q_proj|k_proj|v_proj|o_proj|gate_proj|up_proj|down_proj)$",
    )
    model = get_peft_model(model, lcfg)
    model.print_trainable_parameters()

    per_dev, accum = 2, 8  # effective batch 16
    steps_per_epoch = -(-len(feats) // (per_dev * accum))
    log = []

    class LogCb(TrainerCallback):
        def on_log(self, args, state, control, logs=None, **kw):
            if logs:
                logs = dict(logs, step=state.global_step, elapsed_s=round(time.time() - t_start))
                log.append(logs)
                print(f"[train] {json.dumps(logs)}", flush=True)

    targs = TrainingArguments(
        output_dir=f"/tmp/{run_name}", per_device_train_batch_size=per_dev, gradient_accumulation_steps=accum,
        learning_rate=2e-4, num_train_epochs=epochs, max_steps=max_steps, lr_scheduler_type="cosine",
        warmup_steps=max(1, int(0.05 * steps_per_epoch * epochs)), bf16=True, logging_steps=1, save_strategy="no",
        report_to="none", optim="paged_adamw_8bit", remove_unused_columns=False, gradient_checkpointing=False,
        dataloader_num_workers=0, seed=seed, data_seed=seed, weight_decay=0.0, max_grad_norm=1.0,
    )
    trainer = Trainer(model=model, args=targs, train_dataset=feats, data_collator=collate, callbacks=[LogCb()])
    res = trainer.train()
    t_trained = time.time()
    adapter_dir = f"{run_dir}/adapter"
    model.save_pretrained(adapter_dir)
    tok.save_pretrained(adapter_dir)
    losses = [l["loss"] for l in log if "loss" in l]
    tm = {"run": run_name, "epochs": epochs, "seed": seed, "model": MODEL_ID, "gpu": GPU, "train_file": train_file, "n_train": len(feats),
          "steps": res.global_step, "train_loss_mean": res.training_loss, "first_loss": losses[0] if losses else None,
          "last_loss": losses[-1] if losses else None, "load_s": t_loaded - t_start,
          "train_s": t_trained - t_loaded, "peak_mem_gib": torch.cuda.max_memory_allocated() / 2**30, "log": log}
    with open(f"{run_dir}/train_metrics.json", "w") as f:
        json.dump(tm, f, indent=2)
    out_vol.commit()
    print(f"[train] done: {json.dumps({k: v for k, v in tm.items() if k != 'log'})}", flush=True)

    # ---- eval with the in-memory adapter (base = same 4-bit weights, adapter disabled) ----
    model.gradient_checkpointing_disable()
    model.config.use_cache = True
    results = _eval_splits(model, tok, run_dir, eval_splits, limit=eval_limit, do_base=do_base, extra_sets=extra_sets)
    tm["eval_s"] = time.time() - t_trained
    tm["total_s"] = time.time() - t_start
    with open(f"{run_dir}/train_metrics.json", "w") as f:
        json.dump(tm, f, indent=2)
    out_vol.commit()
    return {"train": {k: v for k, v in tm.items() if k != "log"}, "eval": results}


# ----------------------------------------------------------------------------------------------
# Modal functions (every one has a hard timeout; retries disabled)
# ----------------------------------------------------------------------------------------------
@app.function(image=image, volumes=VOLS, cpu=8, memory=16384, timeout=60 * 60, retries=0)
def download_weights():
    from huggingface_hub import snapshot_download
    t0 = time.time()
    p = snapshot_download(MODEL_ID)  # public, ungated (Apache-2.0); no token needed
    hf_vol.commit()
    return {"path": p, "seconds": time.time() - t0}


@app.function(image=image, gpu=GPU, volumes=VOLS, memory=65536, timeout=40 * 60, retries=0)
def train_smoke():
    return _train_impl("smoke", "smoke_train.jsonl", eval_splits=["val"], eval_limit=16)


@app.function(image=image, gpu=GPU, volumes=VOLS, memory=65536, timeout=3 * 60 * 60, retries=0)
def train_full():
    return _train_impl("full", "train.jsonl", eval_splits=["val", "test"], eval_limit=None)


@app.function(image=image, gpu=GPU, volumes=VOLS, memory=65536, timeout=90 * 60, retries=0)
def eval_adapter(run_name: str = "full", splits: str = "val,test", limit: int = 0, extra_sets: dict = None,
                 do_base: bool = True, summary_name: str = "eval_summary.json"):
    run_dir = f"/vol/outputs/{run_name}"
    model, tok = _load_model(adapter_dir=f"{run_dir}/adapter")
    return _eval_splits(model, tok, run_dir, [s for s in splits.split(",") if s], limit=limit or None,
                        do_base=do_base, extra_sets=extra_sets, summary_name=summary_name)


@app.function(image=image, gpu=GPU, volumes=VOLS, memory=65536, timeout=3 * 60 * 60, retries=0)
def train_custom(run_name: str, train_file: str, eval_splits: str = "val,test", extra_sets: dict = None,
                 do_base: bool = False, epochs: int = 1, seed: int = 42):
    if run_name in ("full", "smoke"):
        raise ValueError("use a new run name; the original runs are never overwritten")
    return _train_impl(run_name, train_file, eval_splits=[s for s in eval_splits.split(",") if s], eval_limit=None,
                       extra_sets=extra_sets, do_base=do_base, epochs=epochs, seed=seed)


def _read_eval_file(path):
    """--eval-file: a local chat-format JSONL; evaluated under split name = file stem (e.g. stress)."""
    if not path:
        return None
    name = os.path.splitext(os.path.basename(path))[0]
    return {name: _read_jsonl(path)}


@app.local_entrypoint()
def download():
    print(download_weights.remote())


@app.local_entrypoint()
def smoke():
    print(json.dumps(train_smoke.remote(), indent=2))


@app.local_entrypoint()
def full():
    print(json.dumps(train_full.remote(), indent=2))


@app.local_entrypoint()
def evaluate(run_name: str = "full", splits: str = "val,test", limit: int = 0, eval_file: str = "",
             no_base: bool = False, summary_name: str = ""):
    """e.g. modal run train_modal.py::evaluate --run-name full --splits "" --eval-file ../synth/stress.jsonl
    (writes eval_summary_<stem>.json so the original eval_summary.json is not replaced)."""
    extra = _read_eval_file(eval_file)
    if not summary_name:
        summary_name = "eval_summary.json" if not extra else f"eval_summary_{list(extra)[0]}.json"
    print(json.dumps(eval_adapter.remote(run_name, splits, limit, extra, not no_base, summary_name), indent=2))


@app.local_entrypoint()
def train(run_name: str, train_file: str, eval_splits: str = "val,test", eval_file: str = "", with_base: bool = False):
    """Same recipe as ::full on /vol/data/data/<train_file>, new run dir; e.g.
    modal run --detach train_modal.py::train --run-name synth_mix75 --train-file train_mix75.jsonl --eval-file ../synth/stress.jsonl"""
    print(json.dumps(train_custom.remote(run_name, train_file, eval_splits, _read_eval_file(eval_file), with_base), indent=2))
