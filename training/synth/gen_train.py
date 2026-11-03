"""Synthetic TRAINING data (~1,500 target): same pipeline/format as the stress set, but disjoint scenario seeds,
a disjoint application-domain list, a different generator style prompt, and dedup against the stress set
(exact normalised-code hash + 5-gram Jaccard >= 0.85) so nothing leaks into training.
Usage: export MODEL_API_KEY=...; python3 gen_train.py [--n 1500] [--finalize-only]"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline, metaapi

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 9203
DOMAINS = ["e-commerce checkout", "video streaming platform", "IoT device fleet management", "food delivery app",
           "travel expense reporting", "online exam proctoring", "library catalogue", "crypto wallet backend",
           "CRM for small businesses", "fitness tracking app", "ticketing / event booking", "document e-signature",
           "warehouse inventory", "car rental", "government tax filing", "chat/messaging backend"]
STYLE = ("Imitate a mix of codebases: legacy pre-Java-8 style, modern Java 17 records/var/streams, Android-style, "
         "and microservice style; vary naming conventions and method decomposition.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1500)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--finalize-only", action="store_true")
    ap.add_argument("--gen-effort", default="minimal")
    ap.add_argument("--judge-effort", default="low")
    a = ap.parse_args()
    pipeline.GEN_EFFORT, pipeline.JUDGE_EFFORT = a.gen_effort, a.judge_effort
    specs = pipeline.build_scenarios(a.n, "T", SEED, DOMAINS, "train-B")
    stress_ids = {json.loads(l)["scenario_id"] for l in open(os.path.join(HERE, "stress.meta.jsonl"))}
    assert not stress_ids & {s["scenario_id"] for s in specs}
    raw = os.path.join(HERE, "raw_train.jsonl")
    if not a.finalize_only:
        pipeline.run(specs, STYLE, raw, workers=a.workers, seed=SEED)
    # exclusion set = every stress example that passed formatting (kept or not), so no stress code leaks
    ex_h, ex_sh = set(), []
    for l in open(os.path.join(HERE, "raw_stress.jsonl")):
        r = json.loads(l)
        if "ex" in r:
            ex_h.add(pipeline.norm_hash(r["ex"]["code_body"])); ex_sh.append(pipeline.shingles(r["ex"]["code_body"]))
    rep, kept = pipeline.finalize(raw, os.path.join(HERE, "synth_train.jsonl"), os.path.join(HERE, "synth_train.meta.jsonl"),
                                  exclude_hashes=ex_h, exclude_shingles=ex_sh,
                                  report_path=os.path.join(HERE, "train_report.json"))
    print(json.dumps({k: v for k, v in rep.items() if k != "judge_disagreement_by_scenario"}, indent=1))
