# Expanded external and production evaluation

For the subsequent agent-authored repairs and authenticated active scans, read [Security resolution](../security-resolution-v6/SECURITY_RESOLUTION.md). The model-cohort results below remain historical measurements and have not been replaced by agent repair successes.

This follow-up completes the additional measurements for two externally sourced applications and four historical security defects in three production repositories, spanning Python and JavaScript. Completion describes the recorded evaluation, not a claim that every candidate fixed every vulnerability or that these samples establish language-wide performance. Manuscript work remains deferred.

## External applications: paired security behavior

The previous completed CodeQL evaluations remain: three PyGoat candidates process all 62 findings each; four VAmPI candidates process all three findings each. The same baseline and all seven completed candidates now receive targeted security regression checks. PyGoat host authentication is tested with real Django sessions and isolated fixture databases; its embedded Flask lessons run separately without Docker. Private URL and process execution sinks are mocked, so these are dynamic request/behavior and sink-argument checks, not real command execution or arbitrary network probes. The allowed public URL and ordinary command output must still work. HTML markers are inert; escaping checks do not execute a browser.

| Application / state | Security assertions passing | Functional checks |
|---|---:|---|
| pygoat / baseline | 13/19 | pass |
| pygoat / gemini-3.5-flash-lite-A-pygoat-fivefree-v2-r1 | 17/19 | pass |
| pygoat / gemma-4-26b-a4b-it-A-pygoat-fivefree-v2-r1 | 16/19 | pass |
| pygoat / qwen2.5-coder-1.5b-instruct-q4km-A-pygoat-fivefree-v2-r1 | 13/19 | pass |
| vampi / baseline | 2/8 | pass |
| vampi / gemini-3.5-flash-lite-A-vampi-fivefree-v2-r1 | 2/8 | pass |
| vampi / gemma-4-26b-a4b-it-A-vampi-fivefree-v2-r1 | 2/8 | pass |
| vampi / gemma-4-31b-it-A-vampi-fivefree-v2-r1 | 2/8 | pass |
| vampi / qwen2.5-coder-1.5b-instruct-q4km-A-vampi-fivefree-v2-r1 | 2/8 | pass |

PyGoat checks cover anonymous access, valid and invalid login, ownership of forwarded lab hosts, unknown labs, suffix confusion, registration CSRF, logout, reflected markup, external redirects, SQL login bypass, private URL blocking and shell-free command invocation. The authenticated host already passes its 12 security assertions at baseline; those passes must not be counted as repaired vulnerabilities. The lessons contribute seven additional security assertions. VAmPI covers token rejection, cross-account book/password access, admin self-assignment, debug disclosure, account enumeration and SQL-shaped lookup input. All normal-use checks pass, but VAmPI remains at 2/8 security assertions: scanner-alert removal did not repair these authorization and disclosure problems. Security-assertion counts are correlated case observations, not independent vulnerability counts or statistical samples.

The dynamic lesson checks exercise four PyGoat source files containing eight of its original 62 static findings. This is location overlap, not proof that each of those eight findings has an independent dynamic oracle. The other 54 static findings remain covered by the recorded CodeQL evaluation, not by these targeted lesson tests. Docker orchestration, every embedded lesson, deployment proxies and exhaustive authenticated active scanning are outside this profile.

## Authenticated ZAP observations

Four baseline/post-repair scans use ZAP 2.17.0 requestor jobs and passive scanning on a fixed read-only route list. Each run first verifies that an anonymous request is denied and the same request with an ephemeral fixture session or bearer token returns 200. No spider or active scanner runs. This is authenticated passive DAST plus the separate targeted behavior checks above; it is not full active DAST coverage.

| Application / state | Authentication preflight | Routes | Alert groups |
|---|---|---:|---:|
| pygoat / baseline | 302 → 200 | 5 | 3 |
| pygoat / gemini-3.5-flash-lite | 302 → 200 | 5 | 3 |
| vampi / baseline | 401 → 200 | 4 | 2 |
| vampi / gemini-3.5-flash-lite | 401 → 200 | 4 | 2 |

The alert groups remain 3→3 for PyGoat and 2→2 for VAmPI. The WSGI test server contributes the server-version header alerts; these are test-environment observations, not a model regression or production-deployment claim. Raw reports, public plans with fixture authentication removed, logs and exact route lists are saved under authenticated-zap. The requestor profile follows the [official ZAP documentation](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/).

## Production security repair: three repositories, two languages

Four historical defects are selected from pinned public urllib3, Requests and minimist releases. Each oracle is validated against both the vulnerable revision and the maintainer-fixed revision before model evaluation. All four vulnerable controls fail the relevant security assertions while retaining normal behavior; all four maintainer controls pass every assertion. The model sees only public source fragments and advisory requirements, with no maintainer patch or test code. The model is gemini-3.5-flash-lite, temperature 0.1, output cap 8192, no seed, three independent proposals per defect.

| Defect / language | Original one-attempt protocol | Context + feedback protocol (≤3 attempts) |
|---|---:|---:|
| urllib3-cookie / Python | 3/3 | 3/3 |
| urllib3-303 / Python | 0/3 | 2/3 |
| requests-proxy / Python | 0/3 | 3/3 |
| minimist-constructor / JavaScript | 3/3 | 3/3 |

Total accepted: 6/12 in the original one-attempt protocol; 11/12 in the follow-up protocol. Accepted means the security and normal-use assertions passed after digest-bound application. Rejected proposals are restored; malformed JSON, indentation errors and undefined helpers remain recorded. The follow-up changes the response schema, source context, edit scope for Requests, and allowed feedback attempts together. This is not an isolated causal estimate of retry benefit or a matched comparison with the original five-model synthetic study. Three proposals per case give a small descriptive sample, not a reliable population estimate. Runtime includes provider waiting and is not a normalized speed comparison.

Advisories: [urllib3 cookie redirects](https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f), [urllib3 303 body redirects](https://github.com/urllib3/urllib3/security/advisories/GHSA-g4mx-q9vg-27p4), [Requests proxy credentials](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q), [minimist constructor traversal](https://github.com/advisories/GHSA-xvch-5gv4-984h). Exact baseline/fixed commits, fragment/file hashes, prompts, raw responses, proposed edits, per-attempt checks and retained patches are saved with the runs.

## Real multi-file production repair and drift

The urllib3 303 repair updates connectionpool.py and poolmanager.py in one coordinated proposal, rather than modifying a synthetic fixture. The oracle exercises both entry points over temporary loopback HTTP servers, checking body/header removal after 303 and preservation after 307. Two of three follow-up proposals pass. Replaying the successful r2 proposal demonstrates:

- Connection-pool-only and pool-manager-only changes both fail the combined oracle; every pre-edit byte is restored.
- Both module changes together pass the security and functionality checks.
- An owner-inserted comment causes stale file digests to reject before any write; re-fetching the source and rebinding the same exact fragments allows the coordinated fix to pass.

This establishes one real cross-module security case, plus transactional rollback and line-drift behavior. It does not establish arbitrary semantic merge handling, automatic cross-module localization, or performance on every inter-procedural taint graph. The existing single-function runner and this coordinated-patch runner are separate documented execution modes.

## Upstream regressions

| Library / state | Collected | Failed | Skipped |
|---|---:|---:|---:|
| urllib3 / baseline | 59 | 0 | 18 |
| minimist / baseline | 144 | 0 | 0 |
| minimist / minimist-constructor-r1 | 144 | 0 | 0 |
| minimist / minimist-constructor-r2 | 144 | 0 | 0 |
| minimist / minimist-constructor-r3 | 144 | 0 | 0 |
| urllib3 / urllib3-303-r2 | 59 | 0 | 18 |
| urllib3 / urllib3-303-r3 | 59 | 0 | 18 |
| urllib3 / urllib3-cookie-r1 | 59 | 1 | 18 |
| urllib3 / urllib3-cookie-r2 | 59 | 1 | 18 |
| urllib3 / urllib3-cookie-r3 | 59 | 1 | 18 |

All 144 assertions in the pinned minimist test files, including proto.js, pass at baseline and after each accepted JavaScript repair. The urllib3 retry module collects 59 tests; 18 timezone cases are skipped by the upstream Windows fixture. The only failures for the cookie-policy repairs are the old test expecting Authorization as the sole stripped default header; adding Cookie deliberately changes that contract. The dedicated loopback security oracle confirms that cross-origin Cookie removal works and same-origin behavior remains. Requests uses the recorded offline proxy/prepared-request contract suite; its complete upstream network suite is not claimed.

## Reproduction

See [setup and commands](REPRODUCE.md). Reports regenerate offline with `python continuation/completion_report.py`. Saved model outputs can be checked without API calls; new inference requires the configured free Google model and available quota. External source clones, fixture databases, runtime environments and ZAP installations are intentionally excluded from the delivery ZIP.

Delivery verification also exposed a transient Windows file lock during rollback. The delivered patch writer now retries PermissionError on the same atomic replacement up to six times, then propagates persistent errors. A regression check reproduces a temporary lock during two-file rollback and verifies exact restoration. The pipeline checks now pass 40/40. The recorded repair trials preceded this filesystem retry change; no new model success is inferred from it.

Known boundaries remain explicit: targeted route/lesson coverage rather than exhaustive active testing; one production model; four historical defects; two languages; three proposals per case; no original human-review provenance. The previous missing measurements now have recorded positive and negative results; unsupported general claims are not inferred.
