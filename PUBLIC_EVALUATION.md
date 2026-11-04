# Public live evaluations

Two live runs are recorded here. They are separate from each other and from the historical
numbers in `EVAL.md`. Do not add their metrics together, and do not replace the historical
private **83/87** Semgrep-clearance figure with either run.

Labels and semantic patch reviews were AI-assisted. They are not independent human ground
truth. The repositories are intentionally vulnerable and true-positive heavy. These runs do
not support a production-performance claim.

Semgrep clearance means the stricter re-check passed: the original alert was gone, no new
alert of any rule appeared, and the harness parse checks passed. It does not mean the project
was compiled, tested, or semantically correct. Nothing in either run was compiled or executed
as a Java project.

The resolved Semgrep `p/java` rule-pack revision is unknown for both runs. Semgrep OSS
**1.183.0** was the engine reported by the scans.

## Run A — three public repositories, 111 alerts

Projects: dvja `597ece1ab79ffffea7289d49b0c443bb2ebcbd16` (2 alerts), VeraDemo
`d2d1a34119a6eba955a24ab2b7935fe94c1c7286` (23 alerts), JavaSecLab
`dfa7a8dacae1de698a812053bca08ec1d373e88b` (86 alerts). Reviewed labels: **91 TP / 20 FP**.

The preserved launch script set `VV_BASE_MODEL_REVISION=cec94fcfd6512f2cfe708138c32533b346ea4f69`,
and the Modal load lines report `meta-models/Muse-Glimmer-30B` at that revision. The harness
commit and the `requests` pin for this run were not recorded. They are unknown.

| measure | result |
|---|---|
| Classifier accuracy | 82.0%, the same as always predicting TP |
| Balanced accuracy | 61.7% |
| TP recall | 93.4% |
| FP recall | 30.0% |
| Errors routed to needs-review | 9 of 20 |
| Labelled TPs placed in likely-FP | 6 |
| Muse agreement with the reviewed labels | 101/111 = 91.0% |

Remediation proposed 51 patches. **46** were strictly Semgrep-cleared and **5** stayed
unverified. Among the 46 cleared patches, semantic review called **42** plausible, **one** a
material behavior or security concern, and **three** incorrect. Across all 51 proposals the
same review called **44** plausible, **four** concerns, and **three** incorrect.

Meta spend for this run was **162** calls and an estimated **$0.790062**. Original source
hashes were unchanged. The preserved Modal app lists show the classifier apps stopped.

Two nonfatal Modal messages, `Timed out waiting for final app logs`, occurred for dvja and
JavaSecLab. VeraDemo did not log that timeout. The triage outputs were written, and the app
lists show those apps stopped.

## Run B — three-project live run, 41 alerts

Projects: software-system (28 alerts), jdbc-admin (12), and ontobrowser (1). Reviewed labels:
**30 TP / 11 FP**.

The preserved scorecard records harness `HEAD` `38030a86a5234ac941f7919f0f9633a2e18b4076`.
That tree pins `requests==2.32.3`. Modal load lines say `revision=unspecified`, so this run
did not record the base-model revision that Run A observed.

| measure | result |
|---|---|
| Argmax accuracy | 0.732, the same as always predicting TP |
| Balanced accuracy | 0.644 |
| Lane-1 precision | 0.900 |
| Lane-3 precision | 0.500 |
| Muse agreement with the reviewed labels | 29/41 = 0.707 |
| Labelled TPs placed in likely-FP | 4 |

Remediation: **15** Semgrep-cleared, **13** suggested but unverified, **13** not attempted.
Nothing was compiled or tested.

The run log contains three `Timed out waiting for final app logs` lines, one per project.
Outputs were written. This directory did not keep a Modal app list, so stopped apps are not
confirmed for Run B.

### PRE-FIX classifier and audit evidence

Run B used the snippet anonymizer that replaced the class name `MD5` inside literals and
longer identifiers. The preserved audit of `MD5.java` said `getInstance` used the literal
`"RequestHandler"`, treated that call as throwing, and called a real MD5 password hash a
false positive. The ontobrowser crypto proposal is in the same pre-fix run. Those
observations stay pre-fix evidence. The anonymization correction is not a new accuracy
measurement.

The same run showed reachability limits and path-traversal audits that lacked the later
upload or source use. This change does not add caller tracing or cross-file data flow.

## Observed base revision and adapter checksums

Run A and an earlier validation load observed base revision
`cec94fcfd6512f2cfe708138c32533b346ea4f69`. That observation is not a new default pin in the
harness. Run B's load line left the revision unspecified.

Checksums below were computed from the adapter files fetched during validation. They are
observed values. They have not been compared with a separately reviewed adapter artifact, so
the adapter-identity item in `SUBMISSION.md` stays open.

| file | sha256 |
|---|---|
| `README.md` | `3283b0022fa09da1c3b448e21f2a0af738ff5abc20a4af836a072e96856a1082` |
| `adapter_config.json` | `937d98df4d4d2de5e7da40432449e5047aca77503fc8884db3ec2d824bf848ca` |
| `adapter_model.safetensors` | `b1e122899cd71e6b619f5adb21f9a3aae08a4b0975415ff350837e286726cdb3` |
| `chat_template.jinja` | `cfc67e5f349f37690dfd31ed1f18bc4442a9dd32fe39a648f993cb4eb3cae678` |
| `tokenizer.json` | `c9dbee66967b58f31a7c27f723c3760da3526ccd0427578e8905b0abb0031c4d` |
| `tokenizer_config.json` | `4dda8d9709954d7b3f1d917319f9b915f1b995f77fbbd8fb9379e56842d84f1b` |

## Isolated Java validation — NOT RUN

No container runtime (`docker`, `podman`, `nerdctl`, `singularity`, `apptainer`) and no
`java`, `javac`, `mvn`, or `gradle` were on `PATH`. The preserved projects were not built or
tested on the host. Compilation and tests, had they run, would still not prove semantic
correctness.

## Limits that remain

- Fresh public Semgrep clearance does not replace historical private 83/87.
- Likely-FP is still not suppression. Run A put six labelled true positives there, and Run B put four.
- Dead-method reachability and missing upload or source context are unsolved.
- Judge access, private reproduction of the historical sets, and an independent adapter comparison are unfinished. See `SUBMISSION.md`.
- Exact harness commit and dependency versions are recorded only where the preserved evidence states them. Run A's harness commit is unknown.
