# Dev set (model selection only - NEVER train on it)
82 Semgrep 1.183.0 `p/java` alerts from 6 public repos (shallow clones, not the user's repo, not the stress set):
java-sec-code (25), JavaVulnerableLab (18), Apache Roller (11), Apache JSPWiki (12), Openfire (13), RuoYi (3).
Format identical to out/test.jsonl (class anonymised to RequestHandler, comments stripped, vulnerability-announcing
identifiers/literals hashed; 60-line window around the alert). Labels: TP 42 / FP 40.
Label confidence: high 56, medium 21, low 5. `dev_hm` = high+medium (77 rows).
Labelling: one careful manual pass reading the full source (incl. out-of-snippet callers), then a second
self-review pass with a per-rule checklist; 22 items marked `uncertain` in `second_opinion` (alternative reading given).
No independent second annotator / LLM judge was used (Meta budget was exhausted by step 2; $22 abort guard).
Files: dev.jsonl, dev.meta.jsonl, labels.jsonl, scripts/{collect,labels_src,build_dev}.py, raw/semgrep_*.json
