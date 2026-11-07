# Reproduce the expanded measurements

Run from the pipeline root. The benchmark inputs remain separate clones, never edits to upstream repositories. New study directories must be fresh. Existing complete observations are retained on resume; do not silently overwrite them to rerun an experiment.

## Inputs and dependencies

Install the pipeline requirements and run `python review/prepare_inputs.py` for the pinned synthetic, PyGoat and VAmPI inputs. Run `python continuation/prepare_production.py` for the pinned urllib3, Requests and minimist inputs and maintainer-fixed control tags. The latter script refuses to reset an existing modified or non-baseline checkout.

The following dedicated Windows environments were used:

| Environment | Resolved dependency list |
|---|---|
| `.review-work/pygoat-env` | `continuation/results/environment-pygoat.txt` |
| `.review-work/vampi-env` | `continuation/results/environment-vampi.txt` |
| `.review-work/production-env` | `continuation/results/environment-production-tests.txt` |

Create each with Python 3.12 (`python -m venv PATH`) and install its corresponding list with that environment's `python -m pip install -r FILE`. Embedded PyGoat Flask lessons use the VAmPI environment; the PyGoat host uses the Django environment. JavaScript checks require Node. For the upstream parser suite, install the recorded Tape version with `npm install --prefix .review-work/minimist-test-deps tape@3.5.0`. Install the official ZAP 2.17.0 distribution under `.review-work/zap` and provide a complete Java 17+ runtime on PATH.

## Saved and new inference

The delivery includes prompts, raw responses, proposed edits and per-attempt results for both production protocols. The original protocol has one attempt per case. The separate follow-up protocol changes response format/context and allows up to three attempts. Each has three independent proposals for each of four defects. Their results must not be pooled into one success rate.

New inference uses the free Google model `gemini-3.5-flash-lite`; set `GEMINI_API_KEY`, or use the existing documented Gemini-only `OPENAI_API_KEY` alias. The alias is never used for an OpenAI endpoint. Model calls contain only the audited public fragments and local fixture feedback. Quotas, availability and model identity may change; a rerun is not guaranteed to reproduce the same outputs.

```powershell
$env:AVR_INPUT_BUDGET_PER_MINUTE='12000'
python continuation/production_evaluation.py --controls-only
python continuation/production_evaluation.py
python continuation/production_feedback.py
python continuation/multifile_security_evaluation.py
python continuation/completion_upstream.py
python continuation/external_security_suite.py
python continuation/authenticated_scan.py
python continuation/completion_report.py
python -m pytest review_tests -q
```

Loopback HTTP is required for the production redirect and ZAP checks. The external behavior suite uses framework test clients. Network-fetch and process sinks in the selected PyGoat lessons are mocked. The authenticated scanner server only accepts GET on the saved route allowlist, creates disposable accounts/databases, and terminates after each scan. Its state and authentication headers are excluded from the delivery.

`completion_report.py` reads saved observations only and works offline without benchmarks, provider access, ZAP or the dedicated application environments. For a new independent study, choose a new output root in the study scripts and preserve the existing records.

## Scope and acceptance

Production proposals are retained only when syntax, file digests, unique fragments, changed-line budget, security checks and normal-use checks pass together. Candidate exceptions and failed checks are rejected, with all written source restored. A successful static rescan is separately reported and is not substituted for these behavioral checks. CLI security oracles return a nonzero exit code when their assertions fail, so they can be used as project validation gates.

Full active scanning, every PyGoat Docker lesson, a deployed reverse proxy, and arbitrary other languages are not covered. Read the exact coverage and failures in [the expanded report](EXPANDED_EVALUATION.md).
