"""vuln-verdict CLI.

  python -m vuln_verdict triage results.sarif --repo PATH --out OUTDIR (--probs-file P.jsonl | --modal)
         [--audit] [--remediate] [--max-audits N] [--max-fixes N] [--semgrep-bin semgrep] [--semgrep-config p/java]

Every SARIF result is retained. A fix marked verified is Semgrep-cleared only unless compilation and
project tests are separately run; it is not a claim of semantic correctness.
"""
import argparse, json, os, shutil, sys

from . import classifier, muse, pipeline
from .lanes import LO, HI, LANES, validate_band
from .sarif import load_alerts


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vuln-verdict")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="triage a SARIF 2.1.0 file")
    t.add_argument("sarif"); t.add_argument("--repo", required=True); t.add_argument("--out", required=True)
    g = t.add_mutually_exclusive_group(required=True)
    g.add_argument("--probs-file", help="precomputed classifier probabilities (JSONL); no GPU needed")
    g.add_argument("--modal", action="store_true", help="run the classifier as an ephemeral Modal app (stops afterwards)")
    t.add_argument("--adapter", default="r2_s7")
    t.add_argument("--lo", type=float, default=LO); t.add_argument("--hi", type=float, default=HI)
    t.add_argument("--audit", action="store_true", help="Muse Spark audit (needs MODEL_API_KEY)")
    t.add_argument("--no-confirm-fp", action="store_true", help="skip the short explanation for likely-FP alerts")
    t.add_argument("--remediate", action="store_true", help="propose + Semgrep-check fixes (needs --audit or runs on lane only)")
    t.add_argument("--remediate-lanes", default="confident_tp", help="comma list, e.g. confident_tp,needs_review")
    t.add_argument("--max-audits", type=int, default=100); t.add_argument("--max-fixes", type=int, default=30)
    t.add_argument("--effort", default="low", help="Muse reasoning effort")
    t.add_argument("--semgrep-bin", default=os.environ.get("SEMGREP_BIN", "semgrep"))
    t.add_argument("--semgrep-config", default="p/java")
    t.add_argument("--scrub", action="store_true", help="evaluation only: neutralise self-describing identifiers in prompts")
    t.add_argument("--title", default=None)
    a = ap.parse_args(argv)

    try:
        validate_band(a.lo, a.hi)
        if a.max_audits < 0 or a.max_fixes < 0:
            raise ValueError("--max-audits and --max-fixes must be non-negative")
        remediation_lanes = tuple(x.strip() for x in a.remediate_lanes.split(",") if x.strip())
        unknown = sorted(set(remediation_lanes) - set(LANES))
        if unknown:
            raise ValueError(f"unknown remediation lane(s): {', '.join(unknown)}")
    except ValueError as e:
        ap.error(str(e))

    with open(a.sarif, encoding="utf-8") as f:
        sarif = json.load(f)
    if sarif.get("version") != "2.1.0":
        print(f"warning: SARIF version {sarif.get('version')!r}, expected 2.1.0", file=sys.stderr)
    os.makedirs(a.out, exist_ok=True)
    alerts = load_alerts(sarif, a.repo, scrub=a.scrub)
    title = a.title or os.path.basename(os.path.abspath(a.repo))
    pipeline.log(f"{len(alerts)} alerts loaded ({sum(bool(x.error) for x in alerts)} without code context)")
    if a.probs_file:
        probs = classifier.load_probs(a.probs_file, alerts)
    else:
        probs, path = classifier.run_modal(alerts, a.out, a.adapter)
    state = pipeline.assign_lanes(alerts, probs, a.lo, a.hi)
    meta = {"SARIF": os.path.abspath(a.sarif), "classifier": f"adapter {a.adapter}, band [{a.lo}, {a.hi})",
            "probabilities": a.probs_file or "Modal batch run"}
    pipeline.finish(a.out, sarif, alerts, state, title, meta, "lanes")
    if a.audit:
        s0 = muse.spent()
        pipeline.run_audits(alerts, state, a.out, a.max_audits, not a.no_confirm_fp, a.effort)
        meta["Muse audit spend (USD)"] = f"{muse.spent() - s0:.3f}"
        pipeline.finish(a.out, sarif, alerts, state, title, meta, "audit")
    if a.remediate:
        if not shutil.which(a.semgrep_bin) and not os.path.exists(a.semgrep_bin):
            sys.exit(f"semgrep not found: {a.semgrep_bin}")
        s0 = muse.spent()
        pipeline.run_remediation(alerts, state, a.repo, a.out, remediation_lanes, a.max_fixes,
                                 True, a.semgrep_bin, a.semgrep_config, a.effort)
        meta["Muse remediation spend (USD)"] = f"{muse.spent() - s0:.3f}"
        pipeline.finish(a.out, sarif, alerts, state, title, meta, "remediation")
    from .report import summary
    print(json.dumps(summary(alerts, state), indent=1))


if __name__ == "__main__":
    main()
