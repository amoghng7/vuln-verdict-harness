#!/usr/bin/env bash
# One-command demo.
#   scripts/demo.sh                      -> tiny bundled example only
#   scripts/demo.sh /path/to/java/repo   -> tiny example + Semgrep p/java on a COPY of that repo, then triage
# Env:
#   OUT=demo_out            output dir (default ./demo_out)
#   PROBS=file.jsonl        precomputed probabilities for the repo (file/line/rule_id or alert_id keyed);
#                           if unset, the classifier runs as an ephemeral Modal app (--modal), which stops afterwards
#   SEMGREP_BIN=semgrep     Semgrep executable
#   MODEL_API_KEY           enables the Muse Spark audit + remediation (otherwise lanes/report only)
#   MAX_AUDITS=150 MAX_FIXES=10 REMEDIATE_LANES=confident_tp
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python}"
OUT="$(mkdir -p "${OUT:-demo_out}" && cd "${OUT:-demo_out}" && pwd)"
SEMGREP_BIN="${SEMGREP_BIN:-semgrep}"; export SEMGREP_BIN
EXTRA=()
if [ -n "${MODEL_API_KEY:-}" ]; then
  EXTRA=(--audit --remediate --max-audits "${MAX_AUDITS:-150}" --max-fixes "${MAX_FIXES:-10}" --remediate-lanes "${REMEDIATE_LANES:-confident_tp}")
else
  echo "MODEL_API_KEY not set: running lanes + report only (no Muse audit / remediation)"
fi

echo "== 1/2 tiny example (examples/tiny, bundled SARIF + bundled probabilities)"
(cd "$HERE" && "$PY" -m vuln_verdict triage examples/tiny/semgrep.sarif --repo examples/tiny \
   --probs-file examples/tiny/probs_r2_s7.jsonl --out "$OUT/tiny" --title "tiny example" "${EXTRA[@]}")

if [ $# -ge 1 ]; then
  SRC="$(cd "$1" && pwd)"; WORK="$OUT/repo_copy"
  echo "== 2/2 $SRC (copied to $WORK; the original is never modified)"
  rm -rf "$WORK"; mkdir -p "$WORK"; (cd "$SRC" && tar --exclude=.git --exclude=target --exclude=build -cf - .) | (cd "$WORK" && tar -xf -)
  rm -f "$OUT/repo.sarif"
  "$SEMGREP_BIN" scan --config p/java --sarif --quiet --metrics=off --no-git-ignore -o "$OUT/repo.sarif" "$WORK"
  if [ -n "${PROBS:-}" ]; then CLS=(--probs-file "$PROBS"); else CLS=(--modal); fi
  (cd "$HERE" && "$PY" -m vuln_verdict triage "$OUT/repo.sarif" --repo "$WORK" --out "$OUT/repo" \
     --title "$(basename "$SRC")" "${CLS[@]}" "${EXTRA[@]}")
fi
echo "Reports: $OUT/*/report.html  (annotated SARIF: $OUT/*/annotated.sarif)"
