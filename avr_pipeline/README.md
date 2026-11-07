# Local vulnerability repair replication

This revision addresses implementation and execution concerns in the supplied reviewer comments. All changes are local. Upstream repositories have not been modified. Results produced here belong to a new revision of the pipeline; they do not establish that the original paper's measurements have been reproduced.

Read `continuation/results/CODE_REVIEW_RESPONSE.md` for the continued code-only work and current comparison status. `review_results/REVIEW_RESPONSE.md` retains the earlier study and comment-by-comment status. The user deferred manuscript work. The original deliberately vulnerable application remains the baseline. Each repair run makes another disposable clone and writes its patches there.

## Set up

Use Python 3.11 or newer in an isolated environment. Install the project and verification dependencies from `requirements-review.txt`. The environment actually used is recorded in `review_results/environment-freeze.txt`.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-review.txt
.\.venv\Scripts\python.exe -m pytest review_tests -q --basetemp=.review-work/verification
```

Set `GEMINI_API_KEY` for Gemini/Gemma. At the user's request, an existing `OPENAI_API_KEY` is also read as a Gemini credential **only when provider is `gemini`**. It is sent in a header to Google's native endpoint. No OpenAI API request is made by this integration. Credentials are never written to result files. `.env` is ignored by git.

The continued study uses free-tier Gemini/Gemma candidates and a downloaded Qwen model. Exact identities, access probes and the availability-driven supplemental candidate are recorded in `continuation/results`. The target is at least five completed A/B pairs; every attempted candidate remains visible. These are a separate cohort from the original paper's models. Pricing was checked against Google's [official pricing](https://ai.google.dev/gemini-api/docs/pricing); no paid-only fallback or billing setup is configured. Gemini's optional thinking is set to `minimal` for Gemma runs. Earlier default-thinking and full-context attempts remain separate.

## Scanners and source inputs

CodeQL CLI 2.27.4 and `codeql/python-queries@1.9.0` were downloaded from the official distribution. The CLI download's SHA256 was checked against the published checksum. Install the Windows CLI below `.review-work/codeql-cli/codeql/`, or supply `--codeql` to each scan command. The downloaded query pack is below `.review-work/packs/codeql/python-queries/1.9.0`.

```powershell
.\.review-work\codeql-cli\codeql\codeql.exe pack download codeql/python-queries@1.9.0 --dir=.review-work/packs
.\.venv\Scripts\python.exe review/runner.py scan --repo ..\vul-python-clone --out review_results/baseline-synthetic
.\.venv\Scripts\python.exe review/runner.py scan --repo benchmarks/pygoat --out review_results/baseline-pygoat
.\.venv\Scripts\python.exe review/runner.py scan --repo benchmarks/vampi --out review_results/baseline-vampi
```

Clone external inputs separately before running these commands:

```powershell
git clone https://github.com/adeyosemanputra/pygoat.git benchmarks/pygoat
git clone https://github.com/erev0s/VAmPI.git benchmarks/vampi
```

For exact reproduction, `python review/prepare_inputs.py` clones and checks out all three recorded input commits. It refuses to reset an edited checkout. The runner creates fresh disposable workspaces from those inputs. In a nested `avr_pipeline` installation, use `benchmarks/synthetic` as the original application input; scanning the surrounding repository would also scan the pipeline and measure a different project.

The source commits used for measurements are in the generated dataset manifest. A successful scan is required for a security result. Missing tools, invalid reports, API failures, and empty test collections are recorded as unavailable measurements.

## Run the experiments

Each run records the source commit, scanner-input hash, implementation hashes, prompt-library hash, generation settings, selected findings, full prompts, responses, token use, elapsed time, patch diffs, validation results, and application routes. Output directories must be new; reusing a source directory is rejected.

```powershell
.\.venv\Scripts\python.exe review/runner.py run --repo ..\vul-python-clone --sarif review_results/baseline-synthetic/scan.sarif --out review_results/example-A-r1 --provider gemini --model gemma-4-26b-a4b-it --condition A --rescan
```

Use `--zap path/to/scan.json` to include ZAP evidence as a CWE-class hint. This correlation does not prove that a source finding corresponds to a particular HTTP exploit. Report the exact evidence file used. ZAP evidence is optional; its absence is explicit in the prompt and manifest. If a `tests` directory exists, the runner selects `tests -m "not network"`. Otherwise pass project-appropriate arguments with `--pytest-args`; an empty suite is not evidence of functional correctness.

| Condition | CWE rules | CWE examples | Inline gates | Attempts | Test policy |
|---|---|---|---|---|---|
| A | Yes | Yes | Yes | 3 | Record failures |
| B | No | No | Yes | 3 | Record failures |
| C | Yes | Yes | No | 1 | Final observation |
| no_guidance | No | Yes | Yes | 3 | Record failures |
| no_examples | Yes | No | Yes | 3 | Record failures |
| simple | No | No | No | 1 | Final observation |
| A_strict | Yes | Yes | Yes | 3 | Block new failures |

These are explicit definitions for this revision. A deliberately retains the paper's non-blocking test policy; it must not be described as preventing functional regressions. `A_strict` is the separate adoption-oriented condition. It rejects missing/empty test execution, collection errors, timeouts, and newly failing tests relative to the measured baseline. The simple baseline uses the same model and patch-application mechanism, with a shorter context and one attempt. It is not an independent tool-augmented coding agent.

The normal legacy entry point now defaults to `test_policy: block`, with explicit project test arguments in `llm/config.json`. Changing this adoption setting does not change the explicitly selected A/B research conditions. Publishing remains disabled by default.

The supplied application tests include assumptions about intentionally vulnerable behaviour. Newly failing assertions need review before they can be labelled functional regressions or changed. `A_strict` conservatively blocks any newly failing test. The manifest's `elapsed_seconds` measures the repair loop; it excludes baseline setup and the final batch re-scan.

Run each condition for every selected model and dataset, using three repetitions for the planned full study. `python review/runner.py matrix` writes the original five-model plan with every unexecuted cell marked `not_run`. A plan is not an experimental result. Do not replace the original five-model guidance contribution with a free-cohort result without changing the paper's description.

For an interrupted run, repeat the same command with `--resume`. Completed findings stay in place; the interrupted finding is retried after restoring its pre-finding bytes. Generation settings, source commit and input hashes must match. Earlier interrupted attempts and implementation hashes are retained in the run history. Do not edit a run's `source` folder manually before resuming it. Short provider-specified rate-limit delays are honoured; longer quota exhaustion remains an unavailable measurement.

For large scanner reports, `--context-profile compact` keeps up to two representative taint paths, prioritises paths spanning multiple files, and records omitted paths and steps. Full scanner context stays in `raw-contexts.json`. Use the same profile in every compared condition. `--cross-file-only` selects an explicit pilot subset; its result is not an overall repair rate.

`python review/run_matrix.py --dataset synthetic --model gemma-4-26b-a4b-it --conditions A B no_guidance no_examples C simple --jobs 1 --tag replication` executes the selected matrix and resumes previously interrupted cells with the same tag. Select a different tag to start a new series.

Run `python review/finalise.py` to regenerate the comparison tables, reviewer response and ZIP from the recorded results. This reads existing experiment records and does not make model requests.

## Acceptance and security measurement

The inline gates check actual added plus deleted source lines, Python compilation, and structured Pylint output. Small functions allow at most five changed lines; larger functions allow 50 percent, capped at 50. Pylint requires a score of at least 2 and no new fatal/error diagnostics; pre-existing dependency errors are counted separately. Every failed candidate, including the final attempt, restores the pre-finding bytes. Earlier accepted fixes remain intact. No candidate is committed before the gates finish.

AST targets are bound on the baseline and refreshed by qualified name. File paths must stay inside the clone. Async functions, nested methods, and multiline decorators are supported. Ambiguous unqualified names fail. Exact line replacement requires a current source snapshot. Approximate text matching is not an application route in this revision. Multi-function transactions and other programming languages remain unsupported; they must not be described as evaluated capabilities.

An accepted patch is not a security fix until it has been checked by the batch oracle. A fresh CodeQL re-scan compares multisets of rule, source file, and qualified function, retaining duplicate counts and reporting new findings separately. Module-level findings are aggregated by rule and file; the report states this matching limitation. A missing post-scan yields no fix rate. DAST and functional tests remain separate measurements.

## Dynamic scans

`review/run_dast.py` runs the official ZAP 2.17.0 cross-platform package against a local Flask benchmark only. It binds the app to `127.0.0.1`, reads the debug flag from the source, and disables the reloader. The generated plan uses an unauthenticated one-minute spider and a five-minute active scan. It is a bounded profile, distinct from the original paper's profile; it cannot support claims about authenticated coverage. The app process is terminated when the scan ends or fails.

Use a new output directory for each dynamic scan. The application starts from its source clone with a separate `target-state` working directory for its database and scanner side effects. Use a full Java 17+ installation on PATH; CodeQL's smaller Java runtime cannot load ZAP's scripting module.

```powershell
.\.venv\Scripts\python.exe review/run_dast.py --repo ..\vul-python-clone --out review_results/dast-baseline-synthetic
.\.venv\Scripts\python.exe review/run_dast.py --repo review_results/example-A-r1/source --out review_results/dast-example-A-r1
```

PyGoat and VAmPI require their own dependencies, server setup, authentication profiles, endpoint contracts, and regression tests before equivalent runtime claims can be made. Their static findings alone do not establish runtime exploitability or real production generalisation.

`review/pygoat_runtime.py` and `review/vampi_runtime.py` now supply nine ordinary HTTP checks each, including normal authentication. Each uses isolated runtime state; neither starts vulnerable lab containers nor probes external systems. Run them with the corresponding dedicated environment and a fresh output directory. They are regression checks, not an equivalent authenticated ZAP evaluation. Exact resolved dependency versions are saved in `continuation/results/environment-pygoat.txt` and `environment-vampi.txt`.

## Prompt library and provenance

`llm/guidance_library.json` contains 18 separately stored rules and illustrative before/after pairs. `llm/new_prompts.py` retains the original released library for inspection. The new entries were authored during this review and reference CWE definitions. They have not undergone independent expert review, and this package makes no claim about who reviewed the original examples. One pair per class is supplied by the new library, not per finding. The templates make both initial and retry prompts obey the assigned condition; there are no hidden class-specific retry examples.

`review/vet_guidance.py` executes bounded checks on every illustrative example and produces `guidance_library.review-2.json`. The historical review-1 library remains immutable for the ongoing matched cohort. The revised examples enable CSRF protection and handle invalid numeric input, with explicit application assumptions. Separate-model critique and available Git authorship evidence are recorded in `continuation/results`; neither establishes original expert-review provenance or independent human signoff.

## Coordinated edits and production pilots

`llm/patchset.py` supports coordinated Python/JavaScript edits bound to initial file SHA256 values and exact unique fragments. All files are parsed before writes; Python is also compiled. A project check command must pass after the complete edit set. Failed checks restore all original bytes. This is process rollback, not crash-atomic multi-file persistence. The default experimental single-function Python runner remains a separate protocol.

```powershell
python -m review.patchset_cli --repo CLONE --edits proposed-edits.json --out audit-folder --check python -m pytest tests
```

The JSON input is a list of objects with `path`, `sha256`, `before`, and `after` fields. Use source bytes decoded as UTF-8 when constructing fragments so Windows line endings remain exact. Never run a proposed validation command supplied by the model; the project owner defines it.

Production-source pilots use pinned urllib3 and minimist clones, recorded advisory descriptions, exact prompts/responses, digest-bound patches, and eight ordinary API/configuration checks each. Their results are narrow integration evidence. They do not establish security fix rates, production readiness, or performance across a language. The coordinated two-module check is an explicitly synthetic contract test.

Coverage is reported for each dataset. Unsupported CWE classes receive no library rule or example; a class with no entry cannot be used to estimate that entry's effect. Additions need a recorded provenance, security review, and tests for the intended application behavior.

This revision keeps the 18 identifiers in the released library so the coverage change can be audited. Twelve occur in the original synthetic scan; the other six are retained for broader inputs. The original authors' rationale for choosing those six was not recorded in the release. The ZIP includes the repair pipeline, experiment records and net patches. Full source clones remain in the workspace. Re-clone the pinned benchmark commits for a fresh run, or apply an observed `net.patch` to its matching commit.

## Local publication policy

The recommended runner contains no remote-writing operation. The legacy pipeline is retained for compatibility and has `repository.publish=false` by default. Its remote workflow and PR integrations require an explicit publishing configuration and are outside this local evaluation. Never run the old cleanup workflow as part of these experiments.
