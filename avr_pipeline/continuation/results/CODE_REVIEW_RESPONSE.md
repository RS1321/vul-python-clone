# Code revision: evidence and remaining limits

The expanded follow-up measurements are in [External and production evaluation](completion/EXPANDED_EVALUATION.md). That report adds authenticated application checks and passive ZAP measurements, repeated production security trials in Python/JavaScript, and a real two-module repair with rollback/drift controls. The historical pilot sections below remain for comparison; their missing measurements are superseded only within the exact follow-up scope.

The user deferred manuscript work. No title, claims, references, numbering or paper figures were edited.

Pipeline verification: 40 passed, 0 failed/errored. This includes coordinated two-module contracts, rollback of every file on failed checks, stale-digest rejection, and JavaScript syntax/runtime checks.

Ordinary startup contract: 17/17 recorded baseline/finished synthetic configurations pass with the Flask server mocked. This executes initialization and checks the server call without opening a network server.

## Five-model comparison

The cohort uses exact model identities, the same pinned application, compact context, review-1 library, A/B definitions and one repetition. Supplemental Gemini 3.6 Flash and local Qwen 0.5B candidates were selected based on availability checks after hosted-service failures and quota exhaustion. All attempted candidates remain visible; the target is at least five completed pairs. Hosted and local inference have different resource and timeout constraints. Elapsed times include service delays, local queues and host pauses and are not normalized model-speed comparisons. These results describe this free cohort, not the paper’s original models. The small Qwen pair uses a declared 1024-token output limit after its original 8192-token run repeatedly timed out; other models use 8192. Both arms of each pair use the same limit. Effects are conditional on these budgets; this is not a model ranking under equal resources. A removes neither component; B removes both guidance and examples, so A−B is their joint effect. Earlier factorial runs isolate them separately.

| Model | Reply cap | A progress/status | A alerts absent | B progress/status | B alerts absent | A−B (pp) |
|---|---:|---|---:|---|---:|---:|
| gemma-4-26b-a4b-it | 8192 | 29/29; complete | 11 | 29/29; complete | 11 | 0.0 |
| gemma-4-31b-it | 8192 | 22/29; interrupted_api_error | unavailable | 9/29; interrupted_api_error | unavailable | unavailable |
| gemini-3.1-flash-lite | 8192 | 29/29; complete | 5 | 29/29; complete | 8 | -10.3448 |
| gemini-3.5-flash-lite | 8192 | 29/29; complete | 14 | 29/29; complete | 14 | 0.0 |
| qwen2.5-coder-1.5b-instruct-q4km | 8192 | 29/29; complete | 5 | 29/29; complete | 3 | 6.8966 |
| gemini-3.6-flash | 8192 | 10/29; interrupted_api_error | unavailable | 1/29; interrupted_api_error | unavailable | unavailable |
| qwen2.5-coder-0.5b-instruct-q4km | 1024 | 29/29; complete | 0 | 29/29; complete | 0 | 0.0 |

Completed paired models: 5 of 7 attempted; target at least five. Observed joint-effect range: -10.34 to +6.90 percentage points.

A partial run has no overall fix rate. Service failures are recorded as infrastructure interruptions, not rejected patches or completed results.

## External applications

PyGoat has 62 baseline CodeQL findings across 25 affected files; VAmPI has three findings. Separate clones preserve the pinned public inputs. All-findings runs are distinguished from the earlier two-finding cross-file pilot. Normal HTTP regression checks run in dedicated environments and isolated databases.

| Run | Progress/status | Alerts absent | New alerts | Changed files |
|---|---|---:|---:|---:|
| gemma-4-26b-a4b-it-A-pygoat-fivefree-v2-r1 | 62/62; complete | 38 | 0 | 22 |
| gemma-4-26b-a4b-it-A-vampi-fivefree-v2-r1 | 3/3; complete | 3 | 0 | 1 |
| gemma-4-31b-it-A-pygoat-fivefree-v2-r1 | 13/62; interrupted_api_error | unavailable | unavailable | 4 |
| gemma-4-31b-it-A-vampi-fivefree-v2-r1 | 3/3; complete | 2 | 0 | 1 |
| gemini-3.1-flash-lite-A-pygoat-fivefree-v2-r1 | 59/62; interrupted_api_error | unavailable | unavailable | 20 |
| gemini-3.1-flash-lite-A-vampi-fivefree-v2-r1 | 1/3; interrupted_api_error | unavailable | unavailable | pending |
| gemini-3.5-flash-lite-A-pygoat-fivefree-v2-r1 | 62/62; complete | 39 | 2 | 23 |
| gemini-3.5-flash-lite-A-vampi-fivefree-v2-r1 | 3/3; complete | 3 | 0 | 1 |
| qwen2.5-coder-1.5b-instruct-q4km-A-pygoat-fivefree-v2-r1 | 62/62; complete | 20 | 0 | 20 |
| qwen2.5-coder-1.5b-instruct-q4km-A-vampi-fivefree-v2-r1 | 3/3; complete | 0 | 0 | 1 |
| gemini-3.6-flash-A-pygoat-fivefree-v2-r1 | 0/62; not_run | unavailable | unavailable | pending |
| gemini-3.6-flash-A-vampi-fivefree-v2-r1 | 0/3; not_run | unavailable | unavailable | pending |
| qwen2.5-coder-0.5b-instruct-q4km-A-pygoat-fivefree-v3-1024-r1 | 0/62; not_run | unavailable | unavailable | pending |
| qwen2.5-coder-0.5b-instruct-q4km-A-vampi-fivefree-v3-1024-r1 | 0/3; not_run | unavailable | unavailable | pending |

Completed post-repair application runtime checks recorded: 7. See external-runtime-summary.json for individual observations and infrastructure failures. Baseline PyGoat and VAmPI each pass nine normal-use checks. These ordinary checks alone are not security measurements. The expanded follow-up separately records authenticated targeted checks and a fixed-route passive ZAP profile.

## Multi-file, production and language scope

The coordinated edit API accepts digest-bound Python and JavaScript fragments, checks all source syntax before writing, and requires project checks after all edits. Failed validation restores all pre-edit bytes. This is process rollback, not crash-atomic filesystem persistence.

| Production pilot | Applied and passed normal checks | Changed source lines | Security resolution |
|---|---|---:|---|
| production-minimist | False | 0 | not established; configuration/API checks only |
| production-minimist-v2 | True | 4 | not established; configuration/API checks only |
| production-urllib3 | True | 2 | not established; configuration/API checks only |

Generated two-module fixture: accepted=True; 2 files changed in one coordinated proposal. Four round trips, four output-format checks and one invalid-version check passed. The exact prompt, response, original fragments and proposed edits are saved in multifile-pilot. This is an explicitly synthetic contract-migration pilot, not a production vulnerability repair rate.

Corrected upstream ordinary unit checks:

| Library / state | Collected | Failed | Skipped |
|---|---:|---:|---:|
| urllib3 / baseline | 59 | 0 | 18 |
| urllib3 / patched | 59 | 1 | 18 |
| minimist / baseline | 127 | 0 | 0 |
| minimist / patched | 127 | 0 | 0 |

The original urllib3 test expects Authorization to be the only default removed header. Its sole new failure is the deliberate addition of Cookie required by the maintainer advisory; the separate eight API/configuration checks verify that policy and preserved custom settings. Eighteen timezone cases are skipped by the upstream fixture on Windows. The first harness trial omitted the timezone fixture and used an asynchronous legacy JavaScript loader; its failures are retained as invalid harness observations. The corrected baseline and patched minimist runs each pass 127 assertions. Prototype reproducer tests remain outside this ordinary unit profile.

The first minimist application rejected a CRLF-normalized fragment; that failure is retained. The second attempt preserved exact file bytes. These one-attempt model pilots cover real production source, but configuration/API checks do not establish production vulnerability fix rates or language-wide generalisation. The coordinated multi-file contract is a synthetic fixture; the production pilot changes each touch one file.

Production sources: [urllib3 maintainer advisory](https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f) and [minimist advisory](https://github.com/advisories/GHSA-xvch-5gv4-984h). Input commits, source hashes, exact prompts, model responses and patches are saved with each pilot.

## Guidance checks and original provenance

- review-1: 16/18 entries pass bounded automated checks.
- review-2: 18/18 entries pass bounded automated checks.

The new revision enables the CSRF extension and handles invalid numeric input; it also makes several size bounds and context assumptions explicit. The measured cohort uses frozen review-1. Adoption defaults select review-2, whose security performance remains unmeasured. The 18/18 result covers those documented checks, not all possible application contexts. A separate Gemini model critique is saved in independent-model-review; its suggestions were not automatically adopted. Some suggestions require stronger application-specific validation than the critique describes.

Original Git authorship and prompt-file histories are recorded in guidance-provenance.json. The public pipeline repository has no PR or issue records in the inspected snapshot; public application PR metadata is preserved separately in public-review-records.json. No original reviewer identities, qualifications or signoffs were established. Commit authorship is not evidence of expert vetting. There is no independent human expert signoff for either revision.

## Deferred and unestablished work

- Manuscript revisions are deferred at the user’s request.
- Missing or interrupted experiment cells remain unavailable; the tables above are generated from saved observations.
- Exhaustive active DAST coverage, language-wide generalisation, and original expert-review provenance remain unestablished. The follow-up provides bounded production performance and three proposals per selected defect.

The Daybreak message reported by the user is a ChatGPT cybersecurity access safeguard. No attempt was made to grant that access or route around blocked content. The historical pilot checks above used normal behavior only; the follow-up adds fixture-based security assertions in isolated local environments.
