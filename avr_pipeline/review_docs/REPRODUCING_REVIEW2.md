# Reproduce the corrected review-2 study

Run commands from `avr_pipeline` using Python 3.12.14. The current declaration is `review/study-protocol.validated.json`; models are in `review/validated-cohort.json`. `review/study-protocol.json` describes the older validator study. The [study note](VALIDATED_STUDY.md) explains the version boundaries and access-driven model replacement.

## Set up and verify

```text
python -m venv .venv
python -m pip install -r requirements-lock.txt
python -m pytest review_tests -q
python review/smoke.py
python review/prepare_inputs.py
```

Use the new environment's interpreter after creating it (`.venv/bin/python` on Linux; `.venv\Scripts\python.exe` on Windows), or activate it first. `prepare_inputs.py` clones four pinned benchmarks separately and refuses edited inputs. Baseline SARIF and manifests are committed under `review_results/baseline-*`: synthetic 29, PyGoat 62, VAmPI 3 and flask-webgoat 7 findings. Do not scan the surrounding pipeline repository as the synthetic subject.

Set `CODEQL_BIN` and `CODEQL_PACK_ROOT` for CodeQL 2.27.4 and `codeql/python-queries@1.9.0`, or set `AVR_TOOL_ROOT` to a separately provisioned directory holding `.review-work/codeql-cli`, `.review-work/packs`, ZAP and target environments. Target dependencies are locked in `requirements-vampi.lock`, `requirements-django.lock` and `requirements-lessons.lock`. `AVR_VAMPI_PYTHON` and `AVR_PYGOAT_PYTHON` can select explicit target interpreters. Each run records its actual lint environment and distribution hash.

On the measured Windows host, Application Control blocked the compiled isort extension and prevented Pylint from importing. A separate environment using the official **pure Python isort 9.0.2 build** passes preflight without changing Windows policy. Build from the official sdist using `python -m pip install --force-reinstall --no-binary=isort isort==9.0.2`, keeping the optional compiled build hook disabled. Source/build hashes and packages are in `review_results/pipeline-pure-environment.json`. Fatal linter crashes interrupt a run; they are not counted as bad model patches.

## Hosted and local execution

Keep `GEMINI_API_KEY` in the environment. On the measured machine it is a Windows user variable and must be loaded into shells started before it was configured. The older `OPENAI_API_KEY` alias is read only by the Gemini provider and sent only to Google's endpoint. Keys are not printed, committed or uploaded to CI. This study authorizes free/local access only; no paid fallback is configured.

```text
python review/continue_study.py --snapshot . --protocol review/study-protocol.validated.json --cohort review/validated-cohort.json --models gemma-4-26b-a4b-it --tag fresh-study --execute --fresh-interrupted --resume-safe-interrupted
```

Use a fresh tag. Omit `--execute` to inspect the plan. Restrict queues with `--datasets` and `--conditions`; completed uniquely matched cells are reused. The shared request ledger enforces the configured request/input budget across hosted processes. Daily limits are not bypassed. Three consecutive unavailable cells defer the model for that invocation. `--wait-for-quota` waits for a provider-reported reset delay.

Gemma returned an observed free-tier input limit of 16,000 actual tokens per minute. Its later queues use `AVR_INPUT_BUDGET_PER_MINUTE=24000` **estimated** units and `AVR_REQUEST_BUDGET_PER_MINUTE=12`; the estimator charges request characters divided by two, plus 128. Across 1,582 observed replies, this estimate was at least 1.949 times actual prompt-token usage, leaving a margin below the returned limit. This empirical calibration is not a tokenizer guarantee; provider delays are still honored. Earlier transport settings remain visible, and timing is not presented as a controlled model comparison. The model, prompts, reply cap, library and gates did not change with pacing.

The current declared continuation version preserves acknowledged rejected replies, their exact refinement prompts/feedback and the remaining original allowance. Each carried reply links to hashed original evidence, so it cannot be silently changed or counted as a new generation. Earlier completed findings remain intact. The declaration explicitly lists compatible earlier implementations; undeclared source changes cannot resume an existing trial. Changed source/prompts or invalid evidence stop before another request. Do not edit saved source, reset consumed attempts or retry completed poor scores. Token-limit and malformed generations consume attempts; API outages do not provide a reply and remain recorded service interruptions. Older zero-reply-only continuation declarations remain archived separately.

Transient Windows file locks can also interrupt JSON evidence saves. The current worker retries identical bytes for up to 30 seconds, records its I/O-adapter hash and retains retry events. This does not change the model, patch or gate policy. Historical trials with failed evidence saves are excluded by `review/evidence_io.py` and listed in `evidence-storage-audit.json`; their pending JSON remains available. Start those trials fresh, since a lost saved response makes the consumed attempt count uncertain. The lock holder is not known, and Windows security settings are unchanged.

The four local models use official Q4_K_M weights and a pinned llama.cpp CPU runtime. Revisions/checksums are in `review/local-study-assets.json`. Loopback ports are 18081 (0.5B), 18080 (1.5B), 18082 (3B) and 18083 (7B). Reply caps are 8,192; context is 16,384, CPU threads 4 and GPU layers 0. Current manifests record a 3,600-second local HTTP wait. Earlier 180-second local runs are retained under `review_results/local-timeout180-pilots` and excluded from the primary matrix, independently of scores.

On a fresh Linux amd64 checkout, provision and execute one cell with:

```text
python review/ci_local_study.py --model qwen2.5-coder-7b-instruct-q4km --dataset flask-webgoat --condition A --repetition 1
```

This downloads checksum-verified assets and installs target environments. CI jobs use isolated machines; do not start two same-port servers on one host. Public standard GitHub workflows execute these cells without provider secrets, paid runners or expanded cache limits. Lossless evidence archives are capped at 1 MiB each and retained for one day; collect promptly. Runtime clones, databases and weights are excluded. The collector verifies hashes and extraction paths and retains different attempts instead of overwriting them:

```text
python review/collect_github_study.py --run WORKFLOW_ID --use-git-credential --watch
```

The explicit credential option reads an existing local GitHub sign-in for read-only collection and never logs it. Keep workflow IDs and failure/retry records. A plan or queued job is not a result.

## Conditions, comparison and analysis

A, B, no_guidance and no_examples form the full rules/examples factorial. C and simple use one attempt without inline gates; gated conditions use up to three attempts. A_strict blocks every new ordinary-test failure, including tests expecting old vulnerable behavior. The frozen exact-ID reporting policy distinguishes those known assertions from unlisted regressions; it does not change the strict gate. Unsupported classes receive no invented guidance. VAmPI's CWE-1333 alerts cannot identify the effect of absent entries.

The tool-agent baseline can read files, make exact replacements, view git diff, and invoke owner-defined pytest/CodeQL commands. It cannot execute arbitrary model shell text or edit verification tests. Its 21-turn cap matches seven findings times A's maximum three attempts, with the same 8,192 reply cap and final oracle. Strategy, tool compute and gates differ and are reported. The current three-repetition comparator uses local Qwen 7B. Interrupted hosted attempts and timeout-limited comparators remain historical evidence.

```text
python review/build_validated_report.py
python review/study_progress.py
```

The builder recomputes `review_results/validated-analysis/` and `review_docs/VALIDATED_RESULTS.md` from actual artifacts. Outputs include finding/CWE outcomes, combined CSV, configuration as run, exact matched McNemar tests, risk differences, odds-ratio boundaries, Holm adjustments, factorial effects, strict-gate audits and whole-repetition bootstrap intervals. Intervals are withheld below three matched repetitions. Findings can share functions, so finding-level tests are exploratory. Missing scans/tests and partial duplicate-group identities stay null. A source-local missing-function import after a working baseline counts as a startup regression in derived analysis; unresolved setup errors remain unmeasured. Original manifests/logs are unchanged.

Install `requirements-figures.lock` in a separate environment and run `python review/plot_validated_study.py` for PNG/SVG figures. The plots read the report's frozen status snapshot rather than a changing live counter; plotted data and file hashes are saved alongside them. Missing conditions remain blank.

`python review/export_public_summary.py` writes allowlisted aggregate tables and figures under `public_results/review2`, omitting raw prompts/responses, test logs, worker metadata and local machine paths. It rejects credential patterns and prohibited raw-message fields. The raw corpus remains available locally; publishing that corpus requires the user's separate choice after the publication review.

## Paired dynamic measurement and Linux container

```text
python review/model_dast.py --dataset flask-webgoat --baseline benchmarks/flask-webgoat --run review_results/COMPLETED_MODEL_RUN --out review_results/fresh-dast-pair
docker build -t avr-review -f Dockerfile .
docker run --rm avr-review python review/container_check.py
```

DAST accepts completed model manifests matching the pinned input and excludes `oracle_validation`. It logs in with fixture credentials and checks an identical outer session gateway before/after. Active SQL/XSS rules 40012 and 40018 use fixed routes and bounded durations; authenticated rule traffic is required. The gateway is measurement containment, not a native authorization fix. Alert types/instances, route coverage and behavioral assertions remain separate. It is not a full crawl. `review/replay_run.py` reconstructs accepted responses and verifies saved diffs without API access; CI packages also retain `model.patch` for source reconstruction.

The Dockerfile pins its base-image digest, CodeQL 2.27.4 and ZAP 2.17.0 checksums, includes Java and uses locked pipeline/target packages. Linux CI has built the image, executed ZAP's version check and rescanned the unchanged flask-webgoat baseline: 7 retained alerts, zero removed and zero new. Evidence is in `review_results/linux-container-validation-2026-11-09.json`. Ubuntu/Windows framework tests and smoke checks passed. This verifies the supplied Linux path, not every OS/architecture.

Historical `12f7847` runs require that checkout and exact saved configuration. Never resume them using the current validator. The current primary core is `bb43ccd`. Healthy `a4922a2` executions are explicitly compatible with the continuation correction: normal behavior is unchanged, while interrupted requests retain their consumed allowance and feedback. The shorter-timeout `f116a31` implementation is compatible for hosted Gemini-provider results only, because its changed local method is not invoked. Original fingerprints, prior manifests, continuation evidence and equivalence checks remain visible.

Independent human sign-off and Zenodo author/publication details are deferred to the professor at the user's request. No expert review, original reviewer provenance or DOI is claimed. Manuscript edits remain deferred. The [manuscript comparison](MANUSCRIPT_CORRELATION.md) explains why this cohort does not reproduce the original model-specific results.
