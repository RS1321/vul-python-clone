# Implementation review and measured results

For the continued code-only response and latest free-model/external observations, see `continuation/results/CODE_REVIEW_RESPONSE.md`. The user deferred manuscript changes. The earlier factorial and DAST series below remain separate from that continuation.

The local code changes and the experiments below address execution-related comments in Comments Received.docx. The work is incomplete until the pending comparisons and runtime evaluations are measured. No result here should be substituted for the original paper’s five-model measurements.

Pipeline verification: 39 checks passed; 0 failed or errored. The unchanged synthetic app passed 68 selected functional tests before the repair attempts.

## Fresh security baselines

| Dataset | CodeQL findings | Affected files | CWE classes | Findings covered by the 18-entry library | Cross-file taint findings |
|---|---:|---:|---:|---:|---:|
| synthetic | 29 | 1 | 12 | 29 | 0 |
| pygoat | 62 | 25 | 16 | 55 | 2 |
| vampi | 3 | 1 | 1 | 0 | 0 |

CodeQL CLI 2.27.4 with Python queries 1.9.0 and the security-extended suite produced these new scans. PyGoat and VAmPI are independently maintained vulnerable training applications. They broaden source and framework coverage but do not establish performance on production CVEs. Repository-wide scans may cover several independently deployed lab apps; the file count is not a count of multi-file repair transactions.

## Repair observations

| Run | Status | Processed | Accepted patches | Resolved by re-scan | New findings | Post tests |
|---|---|---:|---:|---:|---:|---|
| gemini-3.1-flash-lite-A-pygoat-fivefree-v2-r1 | interrupted_api_error | 59/62 | 45 | unavailable | unavailable | not_configured |
| gemini-3.1-flash-lite-A-synthetic-fivefree-v2-r1 | complete | 29/29 | 5 | 5 | 0 | passed |
| gemini-3.1-flash-lite-A-vampi-fivefree-v2-r1 | interrupted_api_error | 1/3 | 0 | unavailable | unavailable | not_configured |
| gemini-3.1-flash-lite-B-synthetic-fivefree-v2-r1 | complete | 29/29 | 7 | 8 | 0 | failed (2 failures) |
| gemini-3.5-flash-lite-A-pygoat-fivefree-v2-r1 | complete | 62/62 | 47 | 39 | 2 | not_configured |
| gemini-3.5-flash-lite-A-synthetic-fivefree-v2-r1 | complete | 29/29 | 15 | 14 | 0 | failed (8 failures) |
| gemini-3.5-flash-lite-A-vampi-fivefree-v2-r1 | complete | 3/3 | 2 | 3 | 0 | not_configured |
| gemini-3.5-flash-lite-B-synthetic-fivefree-v2-r1 | complete | 29/29 | 15 | 14 | 0 | failed (2 failures) |
| gemini-3.6-flash-A-synthetic-fivefree-v2-r1 | interrupted_api_error | 10/29 | 5 | unavailable | unavailable | passed |
| gemini-3.6-flash-B-synthetic-fivefree-v2-r1 | interrupted_api_error | 1/29 | 0 | unavailable | unavailable | passed |
| gemma-4-26b-a4b-it-A-pygoat-fivefree-v2-r1 | complete | 62/62 | 47 | 38 | 0 | not_configured |
| gemma-4-26b-a4b-it-A-synthetic-fivefree-v2-r1 | complete | 29/29 | 12 | 11 | 0 | failed (3 failures) |
| gemma-4-26b-a4b-it-A-vampi-fivefree-v2-r1 | complete | 3/3 | 3 | 3 | 0 | not_configured |
| gemma-4-26b-a4b-it-B-synthetic-fivefree-v2-r1 | complete | 29/29 | 11 | 11 | 0 | passed |
| gemma-4-26b-a4b-it-B-synthetic-matched-r1 | complete | 29/29 | 12 | 11 | 0 | failed (1 failures) |
| gemma-4-26b-a4b-it-C-synthetic-matched-r1 | complete | 29/29 | 25 | 24 | 2 | failed (10 failures) |
| gemma-4-26b-a4b-it-no_examples-synthetic-matched-r1 | complete | 29/29 | 12 | 11 | 0 | passed |
| gemma-4-26b-a4b-it-no_guidance-synthetic-matched-r1 | complete | 29/29 | 11 | 11 | 0 | passed |
| gemma-4-26b-a4b-it-simple-synthetic-matched-r1 | complete | 29/29 | 26 | 23 | 0 | failed (8 failures) |
| gemma-4-31b-it-A-pygoat-fivefree-v2-r1 | interrupted_api_error | 13/62 | 11 | unavailable | unavailable | not_configured |
| gemma-4-31b-it-A-synthetic-fivefree-v2-r1 | interrupted_api_error | 22/29 | 13 | unavailable | unavailable | failed (2 failures) |
| gemma-4-31b-it-A-vampi-fivefree-v2-r1 | complete | 3/3 | 3 | 2 | 0 | not_configured |
| gemma-4-31b-it-B-synthetic-fivefree-v2-r1 | interrupted_api_error | 9/29 | 5 | unavailable | unavailable | passed |
| gemma26-A-pygoat-cross-file-r1 | complete | 2/62 | 1 | unavailable | unavailable | not_configured |
| gemma26-A-pygoat-r1 | interrupted_api_error | 16/62 | 11 | unavailable | unavailable | not_configured |
| gemma26-A-synthetic-r1 | interrupted_api_error | 1/29 | 0 | unavailable | unavailable | passed |
| gemma26-A-synthetic-v3-r1 | complete | 29/29 | 12 | 13 | 0 | failed (6 failures) |
| gemma26-A-vampi-r1 | complete | 3/3 | 3 | 2 | 0 | not_configured |
| gemma26-simple-vampi-r1 | complete | 3/3 | 3 | 3 | 0 | not_configured |
| gemma31-A-synthetic-r1 | interrupted_api_error | 2/29 | 0 | unavailable | unavailable | passed |
| gemma31-A-synthetic-v2-r1 | interrupted_api_error | 5/29 | 2 | unavailable | unavailable | passed |
| gemma31-A-vampi-r1 | complete | 3/3 | 3 | 2 | 0 | not_configured |
| gemma31-B-synthetic-v2-r1 | interrupted_api_error | 4/29 | 2 | unavailable | unavailable | passed |
| qwen2.5-coder-0.5b-instruct-q4km-A-synthetic-fivefree-v2-r1 | interrupted_api_error | 6/29 | 1 | unavailable | unavailable | passed |
| qwen2.5-coder-0.5b-instruct-q4km-A-synthetic-fivefree-v3-1024-r1 | complete | 29/29 | 10 | 0 | 0 | passed |
| qwen2.5-coder-0.5b-instruct-q4km-B-synthetic-fivefree-v2-r1 | interrupted_api_error | 1/29 | 0 | unavailable | unavailable | passed |
| qwen2.5-coder-0.5b-instruct-q4km-B-synthetic-fivefree-v3-1024-r1 | complete | 29/29 | 14 | 0 | 0 | passed |
| qwen2.5-coder-1.5b-instruct-q4km-A-pygoat-fivefree-v2-r1 | complete | 62/62 | 21 | 20 | 0 | not_configured |
| qwen2.5-coder-1.5b-instruct-q4km-A-synthetic-fivefree-v2-r1 | complete | 29/29 | 8 | 5 | 0 | failed (4 failures) |
| qwen2.5-coder-1.5b-instruct-q4km-A-vampi-fivefree-v2-r1 | complete | 3/3 | 2 | 0 | 0 | not_configured |
| qwen2.5-coder-1.5b-instruct-q4km-B-synthetic-fivefree-v2-r1 | complete | 29/29 | 5 | 3 | 0 | passed |

On the original app, the same-model simpler run removed 23 CodeQL findings versus 13 for A. The simpler run changed 209 lines across accepted patches and had 8 failing assertions; A changed 68 lines and had 6 failing assertions. This comparison does not establish that either workflow is preferable across models or projects.

Acceptance means that the configured inline gates passed. Security resolution is calculated only for a completed full-selection run with a fresh re-scan. Interrupted requests are access failures, not measurements of model patch quality. Default-thinking pilots and explicitly minimal-thinking runs are separate cohorts. A run without project tests supplies static evidence only. Changes to regexes or API input handling still require behavioral review.

## Reviewer concerns

| Concern | Implementation and evidence | Remaining work |
|---|---|---|
| R1 external validity; R2 question 2; R3 evaluation breadth | Separate PyGoat and VAmPI clones; pinned commits, fresh SARIF, source contexts, and library coverage counts | Complete matched repair runs, project regression suites, authenticated runtime checks, and production-CVE evaluation before broad claims |
| R1 single-model Run B | Explicit seven-condition experiment plan retains all five original model identifiers; new free models are recorded separately | Complete B and A for each model in the chosen cohort; original five-model access is not configured |
| R2 question 5 confounded guidance/examples ablation | One scaffold with independently controlled rules and examples; tested in initial and retry prompts | Execute all four guidance/example cells with matched settings and report per-model differences; no guidance contribution is inferred from missing cells |
| R1 marginal validation benefit | Per-attempt gates, rollback, token use, time and churn; C disables gates with one attempt; A_strict separates blocking tests | Complete A/C matched comparisons; report security resolution, patch scope and regressions separately |
| R2 questions 3 and 4 guidance and expert examples | Full new 18-entry library with sources and one before/after pair per CWE; original library retained in new_prompts.py | Independent expert vetting and original-author provenance remain unknown; no expert-review claim is made |
| R2 question 6 adoption requirements | README gives credentials, scanners, source pins, test policies, local publication policy and runtime limits | Project-specific setup, authorization rules, authentication profiles, regression contracts and deployment checks |
| R2 question 7 patch fallback counts | Each real application records ast_name, ast_line_fallback, verified_line or rejected, with successes/failures; run-summary.json aggregates observed counts | Historical fallback frequencies cannot be reconstructed without original attempt logs; approximate fallback is intentionally absent in this revision |
| R2 question 9 full prompt | Every attempted finding saves prompt.json and attempt files; prompt-example.md exports a complete readable example | Any paper appendix must identify the revision and matching generation settings |
| R3 external baseline | A simpler one-shot, shorter-context condition is implemented using the same model, source and re-scan oracle | Complete matched simple/A runs; a modern independent coding-agent baseline remains unevaluated |
| R3 clean replication and released-method mismatch | Corrected enabled-gate configuration, local-only runner, pinned inputs, environment snapshot, raw outputs, CSV and JSON tables | Original A/B/C results are not claimed reproduced; completed new comparisons are needed |
| Manuscript-only issues | Title terminology, RQ ordering, citations, claims, grammar and figure sizing identified as outside this implementation task | The paper was not supplied and has not been edited |

## Patch application counts

| Run | Attempts to apply | Applied | Failed to apply | AST name | AST line fallback | Verified line |
|---|---:|---:|---:|---:|---:|---:|
| gemini-3.1-flash-lite-A-pygoat-fivefree-v2-r1 | 89 | 85 | 4 | 64 | 0 | 24 |
| gemini-3.1-flash-lite-A-synthetic-fivefree-v2-r1 | 81 | 78 | 3 | 78 | 0 | 0 |
| gemini-3.1-flash-lite-A-vampi-fivefree-v2-r1 | 0 | 0 | 0 | 0 | 0 | 0 |
| gemini-3.1-flash-lite-B-synthetic-fivefree-v2-r1 | 76 | 71 | 5 | 74 | 0 | 0 |
| gemini-3.5-flash-lite-A-pygoat-fivefree-v2-r1 | 104 | 79 | 25 | 60 | 0 | 25 |
| gemini-3.5-flash-lite-A-synthetic-fivefree-v2-r1 | 61 | 48 | 13 | 50 | 0 | 0 |
| gemini-3.5-flash-lite-A-vampi-fivefree-v2-r1 | 7 | 7 | 0 | 7 | 0 | 0 |
| gemini-3.5-flash-lite-B-synthetic-fivefree-v2-r1 | 63 | 55 | 8 | 58 | 0 | 0 |
| gemini-3.6-flash-A-synthetic-fivefree-v2-r1 | 28 | 20 | 8 | 20 | 0 | 0 |
| gemini-3.6-flash-B-synthetic-fivefree-v2-r1 | 0 | 0 | 0 | 0 | 0 | 0 |
| gemma-4-26b-a4b-it-A-pygoat-fivefree-v2-r1 | 103 | 89 | 14 | 73 | 0 | 25 |
| gemma-4-26b-a4b-it-A-synthetic-fivefree-v2-r1 | 68 | 61 | 7 | 61 | 0 | 0 |
| gemma-4-26b-a4b-it-A-vampi-fivefree-v2-r1 | 3 | 3 | 0 | 3 | 0 | 0 |
| gemma-4-26b-a4b-it-B-synthetic-fivefree-v2-r1 | 68 | 56 | 12 | 56 | 0 | 0 |
| gemma-4-26b-a4b-it-B-synthetic-matched-r1 | 65 | 57 | 8 | 56 | 0 | 2 |
| gemma-4-26b-a4b-it-C-synthetic-matched-r1 | 28 | 25 | 3 | 25 | 0 | 0 |
| gemma-4-26b-a4b-it-no_examples-synthetic-matched-r1 | 64 | 59 | 5 | 59 | 0 | 0 |
| gemma-4-26b-a4b-it-no_guidance-synthetic-matched-r1 | 65 | 58 | 7 | 58 | 0 | 2 |
| gemma-4-26b-a4b-it-simple-synthetic-matched-r1 | 27 | 26 | 1 | 26 | 0 | 0 |
| gemma-4-31b-it-A-pygoat-fivefree-v2-r1 | 16 | 15 | 1 | 12 | 0 | 3 |
| gemma-4-31b-it-A-synthetic-fivefree-v2-r1 | 67 | 42 | 25 | 52 | 0 | 0 |
| gemma-4-31b-it-A-vampi-fivefree-v2-r1 | 5 | 4 | 1 | 4 | 0 | 0 |
| gemma-4-31b-it-B-synthetic-fivefree-v2-r1 | 17 | 15 | 2 | 15 | 0 | 0 |
| gemma26-A-pygoat-cross-file-r1 | 5 | 5 | 0 | 5 | 0 | 0 |
| gemma26-A-pygoat-r1 | 23 | 19 | 4 | 17 | 0 | 3 |
| gemma26-A-synthetic-r1 | 1 | 1 | 0 | 1 | 0 | 0 |
| gemma26-A-synthetic-v3-r1 | 68 | 60 | 8 | 58 | 0 | 2 |
| gemma26-A-vampi-r1 | 3 | 3 | 0 | 3 | 0 | 0 |
| gemma26-simple-vampi-r1 | 3 | 3 | 0 | 3 | 0 | 0 |
| gemma31-A-synthetic-r1 | 1 | 1 | 0 | 1 | 0 | 0 |
| gemma31-A-synthetic-v2-r1 | 7 | 6 | 1 | 4 | 0 | 2 |
| gemma31-A-vampi-r1 | 5 | 4 | 1 | 4 | 0 | 0 |
| gemma31-B-synthetic-v2-r1 | 7 | 6 | 1 | 6 | 0 | 0 |
| qwen2.5-coder-0.5b-instruct-q4km-A-synthetic-fivefree-v2-r1 | 17 | 14 | 3 | 17 | 0 | 0 |
| qwen2.5-coder-0.5b-instruct-q4km-A-synthetic-fivefree-v3-1024-r1 | 54 | 41 | 13 | 54 | 0 | 0 |
| qwen2.5-coder-0.5b-instruct-q4km-B-synthetic-fivefree-v2-r1 | 0 | 0 | 0 | 0 | 0 | 0 |
| qwen2.5-coder-0.5b-instruct-q4km-B-synthetic-fivefree-v3-1024-r1 | 59 | 26 | 33 | 59 | 0 | 0 |
| qwen2.5-coder-1.5b-instruct-q4km-A-pygoat-fivefree-v2-r1 | 147 | 33 | 114 | 16 | 0 | 19 |
| qwen2.5-coder-1.5b-instruct-q4km-A-synthetic-fivefree-v2-r1 | 79 | 9 | 70 | 10 | 0 | 0 |
| qwen2.5-coder-1.5b-instruct-q4km-A-vampi-fivefree-v2-r1 | 7 | 2 | 5 | 3 | 0 | 0 |
| qwen2.5-coder-1.5b-instruct-q4km-B-synthetic-fivefree-v2-r1 | 82 | 5 | 77 | 5 | 0 | 0 |

The following partial re-scans describe checkpoint source states. They are excluded from full-run rates:

- gemini-3.6-flash-A-synthetic-fivefree-v2-r1: 5 baseline alerts absent after 10/29 findings were processed.
- gemma-4-31b-it-A-pygoat-fivefree-v2-r1: 11 baseline alerts absent after 13/62 findings were processed.
- gemma-4-31b-it-B-synthetic-fivefree-v2-r1: 5 baseline alerts absent after 9/29 findings were processed.
- gemma26-A-pygoat-cross-file-r1: 0 baseline alerts absent after 2/62 findings were processed.
- gemma26-A-pygoat-r1: 11 baseline alerts absent after 16/62 findings were processed.
- gemma31-A-synthetic-v2-r1: 2 baseline alerts absent after 5/29 findings were processed.
- gemma31-B-synthetic-v2-r1: 2 baseline alerts absent after 4/29 findings were processed.

An API attempt that produces no candidate is not an application attempt. A syntactically applied candidate may later be rejected by a gate and rolled back. These are distinct counts.

## Dynamic scan status

- dast-baseline-synthetic: failed. Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.
- dast-baseline-synthetic-v2: complete; 63 unique alert groups. Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.
- dast-baseline-synthetic-v3: complete; 57 unique alert groups. Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.
- dast-post-synthetic-A: complete; 52 unique alert groups. Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.
- dast-post-synthetic-full-A: complete; 45 unique alert groups. Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.
- dast-post-synthetic-simple: complete; 36 unique alert groups. Unauthenticated spider; five-minute active scan; not equivalent to original paper profile.

Matched local scan profile, using the original app's seven-patch checkpoint: 17 baseline alert groups absent in the post-scan, 40 retained, 12 new. A missing group may also reflect changed crawl reachability; this is an alert-group comparison, not a finding-level exploitability guarantee.

After the completed guided run: 20 baseline alert groups absent, 37 retained, and 8 new under the same profile.

After the completed simpler run: 37 baseline alert groups absent, 20 retained, and 16 new under the same profile.

The bounded ZAP profile is unauthenticated. Scanner alert groups and SAST findings are separate units.

## Bounded external runtime check

The VAmPI regex probe extracts the actual regex constants from the baseline and patched sources. It measures a bounded near-miss input and checks whether several email strings match, without importing or running the service. The generated `vampi-regex-check.csv` records five-repeat medians and match results. Both 26B variants changed acceptance of `alice@localhost` in one branch, which illustrates why static resolution alone does not establish preserved behaviour. This is a regex-level check, not a full HTTP, authentication, or regression test.

## Evidence files

- `baseline-summary.json` and `.csv`: current scanner baselines and source commits.
- `run-summary.json` and `.csv`: only observed attempts and completed scanner results.
- `experiment-plan.json`: planned original five-model cells, explicitly not run.
- `paired-effects.json`: comparisons computed only from completed matched conditions.
- `verification.xml`: pipeline regression checks.
- `environment-freeze.txt`: exact installed package versions.
- Each run folder: source clone, contexts, full prompts, responses, diffs, test records, and re-scan reports. Finished or interrupted runs with changes also have a net.patch against their exact source commit.
- Each baseline folder: fresh SARIF, CodeQL logs and source identity.

No credential is needed to inspect these records. Do not publish vulnerable app runtime data or API credentials with the package.

## Completed paired effects

Values are percentage-point changes in the CodeQL resolution rate within a matched run. One repetition provides a descriptive result; missing cells stay unavailable.

| Model | A minus B | Guidance with examples fixed | Examples with guidance fixed | Factorial guidance | Factorial examples | Interaction | A minus C |
|---|---:|---:|---:|---:|---:|---:|---:|
| gemma-4-26b-a4b-it | +6.90 | +6.90 | +6.90 | +3.45 | +3.45 | +6.90 | -37.93 |
