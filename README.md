# AVR: vulnerability repair and evaluation

Latest work: [corrected study protocol](avr_pipeline/review_docs/VALIDATED_STUDY.md), [current measured results](avr_pipeline/public_results/review2/RESULTS.md), [measured cell inventory](avr_pipeline/public_results/review2/study-status.json) and [reproduction guide](avr_pipeline/review_docs/REPRODUCING_REVIEW2.md). The corrected study comprises 420 cells; the inventory distinguishes completed evidence, interrupted access and pending work. At the user's request, public exports contain summaries and figures, while new raw messages, logs and machine metadata remain local. Historical model results and agent-authored validation remain separate.

This repository contains the original deliberately vulnerable Flask benchmark and an automated vulnerability remediation (AVR) pipeline, with recorded experiments, defensive repairs and reproducible validation scripts.

**The root `vulnerable_app.py` remains the vulnerable baseline.** Hardened PyGoat and VAmPI applications are generated in separate clones. Run the benchmark and security checks in an isolated local environment.

## Start here

| What you need | Where to look |
|---|---|
| Latest repairs, security checks and active scans | [Security resolution report](avr_pipeline/oracle_validation/security-resolution-v6/SECURITY_RESOLUTION.md) |
| Five-model comparison and reviewer response | [Code review response](avr_pipeline/continuation/results/CODE_REVIEW_RESPONSE.md) |
| Production, multi-file and JavaScript measurements | [Expanded evaluation](avr_pipeline/continuation/results/completion/EXPANDED_EVALUATION.md) |
| Production experiment setup | [Reproduction guide](avr_pipeline/continuation/results/completion/REPRODUCE.md) |
| Pipeline design and experiment conditions | [Pipeline documentation](avr_pipeline/README.md) |
| Original benchmark description | [Vulnerable application documentation](VULNERABLE_APP_README.md) |

The reports and raw observations can be read directly on GitHub. API access, model downloads and scanners are needed only for the operations that use them.

## Recorded results

The current controlled cohort is hosted Gemma 4 26B A4B and local Qwen2.5 Coder 0.5B, 1.5B, 3B and 7B Q4_K_M. All use an 8,192-token reply cap, seven conditions and three repetitions on four pinned subjects. Public standard Linux runners execute the local models without API keys or paid runners. The separate 7B tool-agent comparison has three recorded repetitions. Read the current report before using older numbers below: the older validator implementation and local 180-second timeout pilots are excluded from the corrected study. Human guidance sign-off and Zenodo publication are deferred to the professor at the user's request.

### Defensive follow-up

These are **agent-authored repairs**, recorded separately from the free-model comparison. They must not be counted as additional successes of those models.

| Measurement | Result |
|---|---|
| VAmPI original security assertions | 8/8 pass; the baseline passed 2/8 |
| VAmPI extended security assertions | 11/11 pass, with legitimate password and email changes checked |
| PyGoat lesson suites | 21/21 pass, including the separate Django lesson |
| PyGoat host, build-directory and error checks | 19/19 pass |
| CodeQL findings: PyGoat | 62 baseline → 0 after repair |
| CodeQL findings: VAmPI | 3 baseline → 0 after repair |
| Authenticated active scans | Four paired baseline/hardened scans using SQL-injection and reflected-XSS rules |
| Pipeline verification | 40/40 checks passed, including from the unpacked delivery |

The repair scripts were replayed against fresh local benchmark clones. Python code was compared by AST and other changed files by text. Saved reports also regenerated offline.

The repairs cover ownership checks, privilege assignment, credential disclosure, login errors, ORM lookup, password hashing, signed sessions, safe parsing, path selection, bounded URL/command policies, CSRF, CSP nonces and debug/error handling. See the latest report for individual assertions and source manifests.

Zero CodeQL findings means zero results from the recorded security-extended query suite. It does not prove that every possible vulnerability is absent. Active scans use two selected rules; they do not cover every endpoint, attack class or deployed Docker/Traefik configuration. The vulnerable VAmPI SQL control was not detected by that active profile, so its explicit SQL/authentication regression tests remain important evidence.

### Model and production experiments

Five accessible models completed the recorded synthetic A/B comparison:

- `gemma-4-26b-a4b-it`
- `gemini-3.1-flash-lite`
- `gemini-3.5-flash-lite`
- `qwen2.5-coder-1.5b-instruct-q4km`
- `qwen2.5-coder-0.5b-instruct-q4km`

This is a new free-model cohort, rather than reproduction of the manuscript's original five models. Each completed pair has one repetition. The small Qwen pair uses a 1,024-token reply cap; the other pairs use 8,192. Provider access and availability can change.

Condition A includes both CWE guidance and examples; B removes both. Their observed joint effect ranges from **−10.34 to +6.90 percentage points**. This comparison does not isolate guidance alone, and differing resource budgets prevent an equal-resource model ranking. Separate historical factorial runs remove rules and examples individually. Interrupted and unsuccessful attempts remain in the results.

Production measurements cover four historical defects in **urllib3, Requests and minimist**, spanning Python and JavaScript. The original one-attempt protocol accepted **6/12** proposals; the separate context-and-feedback protocol accepted **11/12**. Those protocols change multiple factors and are reported separately. Vulnerable and maintainer-fixed controls validate the selected security checks.

A real two-module urllib3 repair also checks that partial changes fail, rejected edits roll back, stale digests are rejected, and re-fetching source permits a valid change after line drift. These selected cases do not establish performance across an entire language or all production projects.

## Repository layout

```text
vulnerable_app.py                  Original Flask benchmark
tests/                            Original application tests
VULNERABLE_APP_README.md           Original benchmark documentation
.github/workflows/                GitHub Actions workflows
avr_pipeline/
  requirements-review.txt         Pipeline and verification dependencies
  llm/                            Providers, prompts, guidance and patching
  context_builder/                Scanner parsing and source/AST context
  review/                         Repair runner, scanners and security checks
  review_tests/                   Pipeline regression checks
  review_results/                 Baselines, model outputs and scan evidence
  continuation/                   Extended experiments and defensive repairs
    results/security-resolution-v6/  Latest repair evidence and manifests
```

Downloaded benchmarks, model weights, installed environments, scanner tools and runtime databases are not checked in. Scripts recreate the required source clones from pinned public commits.

## Quick start: inspect and verify

The commands below use **Windows PowerShell and Python 3.12**, matching the verified setup. Node.js is needed for JavaScript checks. The original Flask application and the pipeline have separate dependency files; use the pipeline file for this setup.

```powershell
git clone https://github.com/RS1321/vul-python-clone.git
cd vul-python-clone\avr_pipeline

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-review.txt
.\.venv\Scripts\python.exe -m pytest review_tests -q

# Rebuild the latest report from saved observations; no model/scanner calls.
.\.venv\Scripts\python.exe continuation/security_resolution_report.py
```

The saved-report command uses standard-library processing. Reading or regenerating results does not require an API key. The 40/40 recorded verification includes JavaScript execution with Node available; missing prerequisites can produce skips or failures on another machine.

## Recreate the hardened applications

Run from `avr_pipeline`. Git downloads separate public inputs at the recorded commits. Preparation refuses to reset modified or unexpected checkouts.

```powershell
.\.venv\Scripts\python.exe review/prepare_inputs.py
.\.venv\Scripts\python.exe continuation/resolve_security.py vampi v6
.\.venv\Scripts\python.exe continuation/resolve_security.py pygoat v6
```

The complete repaired applications appear in:

```text
avr_pipeline/oracle_validation/security-resolution-v6/vampi/source/
avr_pipeline/oracle_validation/security-resolution-v6/pygoat/source/
```

The deterministic follow-up applies explicit repair logic; it makes no new model requests. PyGoat first receives the saved Gemini patch and then the agent-authored changes. Existing repair clones are preserved: use a fresh repository checkout to replay the documented `v6` sequence again.

**Use the scripts for reproduction.** Published review patches redact credential-shaped strings from the public vulnerable fixtures, including removed lines. Those sanitised diffs are review evidence and must not be passed directly to `git apply`.

For persistent sessions or multiple workers, supply `VAMPI_SECRET_KEY` and `PYGOAT_SECRET_KEY` securely. Random fallbacks are suitable for the local runs but invalidate sessions across restarts. Deployment also requires project-specific host, HTTPS, static-file and mail settings.

## Run fresh application checks

The Django host/lesson and Flask lessons use separate environments. Install the recorded versions from the pipeline root:

```powershell
python -m venv .review-work/vampi-env
.\.review-work\vampi-env\Scripts\python.exe -m pip install -r continuation/results/security-resolution-v6/environment-lessons.txt

python -m venv .review-work/pygoat-env
.\.review-work\pygoat-env\Scripts\python.exe -m pip install -r continuation/results/security-resolution-v6/environment-django.txt

.\.review-work\vampi-env\Scripts\python.exe review/vampi_resolution_checks.py --repo continuation/results/security-resolution-v6/vampi/source --out .review-work/local-validation/vampi-r1
.\.review-work\pygoat-env\Scripts\python.exe review/challenge_security.py --repo continuation/results/security-resolution-v6/pygoat/source --out .review-work/local-validation/host-r1
```

Output folders for these checks must be fresh. To execute all 21 lesson suites with fresh outputs, use a new controller output directory:

```powershell
.\.venv\Scripts\python.exe -c "import sys; from pathlib import Path; sys.path.insert(0, 'continuation'); import lesson_suite as s; s.OUT = Path('.review-work/local-validation/lessons-r1').resolve(); s.main()"
```

Controllers such as `lesson_suite.py` reuse existing observations by default. Running their default entry point against the checked-in result directories can read saved results instead of executing a fresh study. Keep new outputs separate from published evidence.

The lesson checks use fixture data and isolated state. Selected URL-fetch and subprocess sinks are mocked. Their assertions do not demonstrate real external network access or command execution.

## Static and authenticated active scans

The recorded scanner setup uses **CodeQL CLI 2.27.4**, **`codeql/python-queries@1.9.0`**, and **ZAP 2.17.0**. ZAP needs a complete Java 17+ runtime on PATH. Install the tools at the paths expected by the runner, or pass `--codeql` for a different CLI location:

```text
avr_pipeline/.review-work/codeql-cli/codeql/codeql.exe
avr_pipeline/.review-work/packs/
avr_pipeline/.review-work/zap/     Extracted official ZAP distribution
```

```powershell
.\.review-work\codeql-cli\codeql\codeql.exe pack download codeql/python-queries@1.9.0 --dir=.review-work/packs
.\.venv\Scripts\python.exe review/runner.py scan --repo continuation/results/security-resolution-v6/vampi/source --out .review-work/local-validation/vampi-sast-r1
.\.venv\Scripts\python.exe review/runner.py scan --repo continuation/results/security-resolution-v6/pygoat/source --out .review-work/local-validation/pygoat-sast-r1

# Execute the authenticated active profile with new output folders.
.\.venv\Scripts\python.exe -c "import sys; from pathlib import Path; sys.path.insert(0, 'continuation'); import active_security_scan as s; s.OUT = Path('.review-work/local-validation/active-r1').resolve(); s.main()"
```

The active profile binds disposable servers to loopback, verifies anonymous denial and authenticated access, and runs reflected-XSS rule `40012` and SQL-injection rule `40018`. CSRF remains enabled and valid form sessions are supplied. The PyGoat gateway exposes its SQL/XSS lessons behind real Django-session verification. It does not start Docker labs or scan external targets.

Raw plans, traffic counts, logs, SARIF/JSON reports and source manifests are under [the latest results](avr_pipeline/oracle_validation/security-resolution-v6/). Remaining WSGI server-version and informational observations are explained in the report.

## Configure and run new model experiments

Set `GEMINI_API_KEY` in the process environment or in an ignored `avr_pipeline/.env`. Use [the environment template](avr_pipeline/.env.example); never commit actual credentials.

For compatibility with the original local setup, **provider `gemini` also accepts `OPENAI_API_KEY` as a Gemini-key alias**. That value is sent only to Google's endpoint. It does not configure an OpenAI integration. Other providers need their own configuration; recorded local Qwen runs also require the downloaded model/runtime and the configured loopback service.

Use a prepared **`benchmarks/synthetic`** clone for the original 29-finding application. Scanning the surrounding repository would also scan the pipeline and measure a different input.

```powershell
.\.venv\Scripts\python.exe review/runner.py scan --repo benchmarks/synthetic --out .review-work/local-validation/synthetic-baseline-r1
.\.venv\Scripts\python.exe review/runner.py run --repo benchmarks/synthetic --sarif .review-work/local-validation/synthetic-baseline-r1/scan.sarif --out .review-work/local-validation/strict-repair-r1 --provider gemini --model gemini-3.5-flash-lite --condition A_strict --guidance-library llm/guidance_library.review-2.json --rescan
```

The model ID above is from the recorded cohort. New inference depends on current provider availability and quotas; it is not required to inspect or replay the saved defensive follow-up.

| Condition | Rules | Examples | Validation gates | Attempts | Tests |
|---|---|---|---|---:|---|
| `A` | Included | Included | Enabled | 3 | Failures recorded |
| `B` | Removed | Removed | Enabled | 3 | Failures recorded |
| `no_guidance` | Removed | Included | Enabled | 3 | Failures recorded |
| `no_examples` | Included | Removed | Enabled | 3 | Failures recorded |
| `C` | Included | Included | Disabled | 1 | Final observation |
| `simple` | Removed | Removed | Disabled | 1 | Final observation |
| `A_strict` | Included | Included | Enabled | 3 | New failures block acceptance |

`A_strict` is the adoption-oriented mode. The research A/B modes intentionally retain non-blocking tests and must not be described as preventing regressions. Add `--resume` only with matching inputs/settings for an interrupted run; use a fresh output directory for an independent run. Project-specific tests can be supplied through `--pytest-args`.

The measured cohort uses frozen review-1 guidance. The example strict command selects review-2; its bounded example checks do not establish a new model-comparison result. Prompts, responses, hashes, attempts, scan results and unsuccessful runs remain available for inspection.

## Validation and coordinated edits

The Python finding runner refreshes targets by qualified AST name, checks source scope and compilation, and records lint/test gates. Rejected attempts restore pre-edit bytes. Batch rescans report removed and newly introduced findings separately.

Coordinated Python/JavaScript edits use [the patch-set API](avr_pipeline/llm/patchset.py). Edits are bound to file digests and unique fragments. All source is checked before writing, project validation runs after the complete edit set, and failed validation restores the files. This is process rollback, with bounded retries for transient Windows file locks; it is not crash-atomic filesystem persistence.

```powershell
# From avr_pipeline; CLONE and proposed-edits.json are project-specific inputs.
.\.venv\Scripts\python.exe -m review.patchset_cli --repo CLONE --edits proposed-edits.json --out .review-work/local-validation/patchset-r1 --check python -m pytest tests
```

The project owner defines the validation command. Generated code does not select commands to execute. The single-function repair runner and coordinated patch-set runner are distinct execution modes.

## GitHub Actions and publication

[AVR pipeline checks](.github/workflows/avr-pipeline-checks.yml) supports manual dispatch and matching pull requests. It installs pipeline requirements on Windows/Python 3.12 and runs `review_tests`. It does not run the full model or scanner study on every push.

Experiment runners work on separate clones and do not automatically push changes. The legacy pipeline defaults to `repository.publish=false`. The old branch/PR cleanup workflow is archived outside `.github/workflows` and cannot be triggered as a workflow.

## Scope, provenance and sources

Earlier experiments and failed attempts are retained as evidence. The latest defensive revision is `security-resolution-v6`; its report identifies the final test and scan folders. Generated reports are measurements of the stated inputs and profiles, rather than proof of universal security or production readiness.

Manuscript revisions were deferred. Original human reviewer identities, qualifications and signoffs for the guidance/examples were not established. Automated checks, model critique and Git authorship records do not replace independent human expert review.

Sources: [original vulnerable application](https://github.com/Deep-Jiwan/vul-python-app), [original AVR pipeline](https://github.com/Deep-Jiwan/AVR-System), [PyGoat](https://github.com/adeyosemanputra/pygoat), and [VAmPI](https://github.com/erev0s/VAmPI). Production advisory references, input commits, environment records and implementation hashes are linked from the evaluation reports. Upstream source and licensing remain attributable to their respective projects.


The manuscript follow-up is on the `codex/manuscript-evaluation` branch. Read [the manuscript comparison](avr_pipeline/review_docs/MANUSCRIPT_CORRELATION.md) and [the review-2 reproduction guide](avr_pipeline/review_docs/REPRODUCING_REVIEW2.md). New model results remain separate from [agent-authored oracle validation](avr_pipeline/oracle_validation/README.md).

Current follow-up evidence: [measured results](avr_pipeline/review_docs/MEASURED_RESULTS.md), [delivery status and remaining work](avr_pipeline/review_docs/DELIVERY_STATUS.md), and [factorial figure](avr_pipeline/review_docs/figures/factorial-review2.png). The full 420-cell five-model study remains incomplete; see the status report for exact coverage.
