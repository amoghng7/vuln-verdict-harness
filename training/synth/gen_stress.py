"""Stress-test set (NEVER used for training): ~300 judge-verified synthetic Semgrep-alert triage examples.
Usage: export MODEL_API_KEY=...; python3 gen_stress.py [--n 380] [--pilot 8] [--finalize-only]"""
import argparse, json, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline, metaapi

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 7101
# Domain list A (train uses a disjoint list B)
DOMAINS = ["hospital patient portal", "retail banking", "airline booking", "university LMS", "insurance claims",
           "logistics/shipment tracking", "municipal permits portal", "online pharmacy", "HR payroll",
           "telecom customer care", "real-estate listings", "stock brokerage back office"]
STYLE = ("Write code the way an experienced enterprise Java team would; vary structure (fields, constructors, "
         "private helpers, early returns, Optional, try-with-resources).")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=380)
    ap.add_argument("--pilot", type=int, default=0)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--finalize-only", action="store_true")
    a = ap.parse_args()
    specs = pipeline.build_scenarios(a.n, "S", SEED, DOMAINS, "stress-A")
    raw = os.path.join(HERE, "raw_stress.jsonl")
    if a.pilot:
        specs = specs[:a.pilot]; raw = os.path.join(HERE, "raw_pilot.jsonl")
    if not a.finalize_only:
        pipeline.run(specs, STYLE, raw, workers=a.workers, seed=SEED)
    if a.pilot:
        sys.exit(0)
    rep, kept = pipeline.finalize(raw, os.path.join(HERE, "stress.jsonl"), os.path.join(HERE, "stress.meta.jsonl"),
                                  report_path=os.path.join(HERE, "stress_report.json"))
    print(json.dumps({k: v for k, v in rep.items() if k != "judge_disagreement_by_scenario"}, indent=1))
    # 30 random kept examples for human review
    rng = random.Random(1)
    pick = rng.sample(kept, min(30, len(kept)))
    with open(os.path.join(HERE, "stress_spotcheck.md"), "w") as f:
        f.write("# Stress set spot-check (30 random kept examples)\n\nIntended label = generator label, confirmed by an independent judge call. Review for wrong labels.\n\n")
        for i, (r, h) in enumerate(pick, 1):
            s = r["spec"]
            f.write(f"## {i}. {s['scenario_id']} — **{s['intended_label']}** ({s['category']}/{s['variant']}, {s['difficulty']})\n")
            f.write(f"- twist: {s['twist']} | framework: {s['framework']}\n- generator rationale: {r['gen'].get('rationale')}\n- judge: {r.get('judge_analysis')}\n\n")
            f.write(r["ex"]["user"].split("\n\n", 1)[0].replace("Static-analysis alert\n", "") + "\n\n")
            f.write("```java\n" + r["ex"]["user"].split("```java\n", 1)[1] + "\n\n")
