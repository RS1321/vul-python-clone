# Reproduce the review-2 study

Run commands from `avr_pipeline`, using Python 3.12.14. Keep credentials in the environment; the Windows `OPENAI_API_KEY` alias is used only by the Gemini provider. Paid routes are not authorized for this study.

```text
python -m pip install -r requirements-lock.txt
python -m pytest review_tests -q
python review/smoke.py
python review/prepare_inputs.py
python review/run_matrix.py --dataset synthetic pygoat vampi flask-webgoat --cohort review/free-cohort.json --tag review2
```

The last command writes a **plan**. Add `--execute` to execute it. Each result has its own pinned source clone. `--tag r2` and `--tag r3` now select those repetition IDs; `--repetition-ids 1 2 3` is explicit. `--resume-interrupted` resumes interrupted runs, while complete/running directories are preserved. `--limit` labels a pilot, excluded from full-study comparisons.

Set `CODEQL_BIN` to the installed platform executable and `CODEQL_PACK_ROOT` to the downloaded query packs, including `codeql/python-queries@1.9.0`. Alternatively `AVR_TOOL_ROOT` can point to a separately provisioned workspace holding `.review-work/codeql-cli`, `.review-work/packs`, ZAP 2.17.0 and dedicated application environments. No scanners, weights or credentials are committed.

The PyGoat and VAmPI behavioral wrappers use the separately pinned fixture environments. Set `AVR_PYGOAT_PYTHON` and `AVR_VAMPI_PYTHON`, or provision `.review-work/pygoat-env` and `.review-work/vampi-env` beneath `AVR_TOOL_ROOT`. Their transitive dependency snapshots are `requirements-django.lock`, `requirements-vampi.lock`; embedded lesson dependencies are in `requirements-lessons.lock`. Pipeline packages are in `requirements-lock.txt`. These are exact-version environment snapshots, not wheel hashes or guarantees that an old intentionally vulnerable benchmark is safe to deploy.

The local Qwen endpoints are loopback-only ports 18080 (1.5B) and 18081 (0.5B), using the previously documented pinned weights/runtime. Start them before selecting the local cohort members. Hosted availability and quotas can change; a preflight success is not a quota guarantee. Use `AVR_TRANSPORT_RETRIES=4` for short provider-supplied rate-limit waits. The current matrix defaults to a shared request limit of 12/minute (`--requests-per-minute`), with optional `AVR_INPUT_BUDGET_PER_MINUTE` token pacing. Daily-quota exhaustion defers the remaining cells for that model; three consecutive provider-unavailable cells also defer that model for the invocation. Deferred cells are not failures or completed results. Timing comparisons must account for pacing/transport settings.

```text
python review/aggregate_effects.py
python review/agent_baseline.py --repo benchmarks/flask-webgoat --sarif review_results/baseline-flask-webgoat/scan.sarif --out review_results/fresh-tool-agent-run --model gemini-3.5-flash-lite --max-turns 21
python review/model_dast.py --dataset flask-webgoat --baseline benchmarks/flask-webgoat --run review_results/COMPLETED_MODEL_RUN --out review_results/fresh-dast-pair
```

The agent baseline has read, exact replacement, git-diff, pytest and CodeQL tools; it cannot execute arbitrary model-written shell text or change tests. For 7 findings, its default cap is 21 model turns, matching A's maximum 3 attempts per finding; every reply has the same 8,192 cap. Tool-use strategy and validation policy differ by design and are recorded. Scans/tests have fixed owner-supplied commands. A completed comparator result is necessary before comparing performance; implementation/smoke tests are not baseline experiment results.

The DAST runner accepts completed model manifests, validates the baseline commit, and excludes `oracle_validation`. It starts fresh loopback copies, logs in with real fixture credentials, and verifies an outer measurement session gate. Only fixed SQL/XSS routes are exposed to active rules 40012 and 40018. The gateway is identical before/after and is not an application fix. Compare traffic evidence and authentication counts as well as alerts. The old synthetic model source remains in the original local runtime workspace; exported historical results omit runtime clones. A fresh run recreates its own source clone.

`configuration-as-run.json`, per-run `finding-outcomes.json`/CSV, `outcomes-by-cwe.json`, `matched-statistics.json`, `factorial-effects.json` and `repeat-effects.json` are generated from actual artifacts. `paired-effects.json` retains the earlier report-compatible effect fields. Classification lists exact test IDs and rationales; unlisted new failures count as regressions. A_strict blocks **all** new test failures regardless of that reporting classification.

The CI definition runs checks and an offline smoke on Ubuntu and Windows. It does not spend API quota or claim to run CodeQL in the smoke. Core Ubuntu and Windows CI checks have passed (see `review_results/review2-validation.json`). The Docker build and Linux scanner/application execution remain unverified. The Linux amd64 Dockerfile pins CodeQL 2.27.4 and its official release SHA256. It refuses an archive with the wrong checksum. ZAP is provisioned separately for DAST. No DOI has been minted; see `RELEASE_STATUS.md`.


The 42-run controlled factorial and additional hosted-model cells use code commit `12f7847`. The later target-environment validator correction is separately audited in `review_results/validation-environment-audit/audit.json`. Current code automatically probes provisioned PyGoat/VAmPI environments for lint imports; `--validation-python` can select an owner-provisioned interpreter explicitly. The environment distribution hash is recorded. Use a fresh study tag for this corrected implementation; existing runs cannot silently be reused or resumed under changed code.

To continue an interrupted controlled run after a quota reset, check out `12f7847` in a separate worktree, use the original pinned source/SARIF and output directory, and pass the saved `pytest_args`, model, condition, repetition, reply cap and context profile from its manifest together with `--resume --rescan`. Use the original absolute pytest paths when resuming on this machine. Cross-machine execution should use fresh run directories. The guidance bytes must still match the saved hash.

`python review/replay_run.py --run SAVED_RUN --baseline PINNED_INPUT --out FRESH_OUTPUT` reconstructs accepted patches without API access and verifies every saved diff. The synthetic patch used for DAST was reproduced this way and matched the retained runtime source byte for byte.

Install `requirements-figures.lock` and run `python review/plot_study.py` to regenerate the PNG/SVG and plotted-data JSON. `configuration-as-run.csv`, `strict-gate-audit.json` and `review_docs/DELIVERY_STATUS.md` supplement the main result tables.
