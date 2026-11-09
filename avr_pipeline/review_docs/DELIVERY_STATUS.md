# Scope and remaining work

**This is the retained status of the earlier validator study.** The current matrix, including all completed cells and remaining interruptions, is in [VALIDATED_RESULTS.md](VALIDATED_RESULTS.md) and `review_results/validated-study-status.json`. The [current protocol](VALIDATED_STUDY.md) replaces quota-limited cohort members with four local Qwen sizes and hosted Gemma. Three current 7B tool-agent repetitions are recorded, and Linux Docker/ZAP/CodeQL execution has passed. The user explicitly deferred human sign-off and Zenodo publication to the professor. Read the historical table below with these later changes in mind.

This delivery implements the experimental infrastructure and records real completed runs. It does **not** claim the full five-model study is finished or that the paper's headline results have been reproduced.

The controlled implementation at `12f7847` completed 42 matched factorial runs: Gemini-3.5-flash-lite, VAmPI and flask-webgoat, seven conditions, three repetitions each. Three tool-agent comparator repetitions also completed. Additional Gemma-31B and Flash-3.6 runs remain in the corpus, including access failures. Flash 3.6 completed three cells before this key hit its observed **20 requests/day** free quota; Gemma completed one pilot before repeated HTTP 500/503 failures. Access failures are excluded from repair-effect estimates. The exact plan coverage is in `manuscript-study-status.json`.

The full plan has 420 cells. With 101 baseline findings across the four subjects, its maximum generation budget is 25,755 logical generation attempts, before transport retries (three repetitions and the recorded attempt caps). Early acceptance can reduce that number. A free model with a 20-request daily limit cannot complete that plan in one session. No paid access or quota bypass was used.

| Requested item | Delivered | Remaining / limitation |
|---|---|---|
| 1. Three repetitions | Three per condition for both external subjects in the completed one-model factorial; three agent repetitions | All other model/subject cells still need their own matched repetitions |
| 2. Full factorial | All six requested conditions plus A_strict on VAmPI and flask-webgoat for one model | Not all five models or all four subjects |
| 3. Interrupted runs | Resumed the interrupted strict run; retained access failures and added deferral/resume safeguards | Flash 3.6 daily quota reset and stable Gemma service; old synthetic/PyGoat gaps remain |
| 4. Larger/stronger hosted models | Gemma-31B pilot and Flash-3.6 additional runs | Full comparisons limited by free access; no paid model study |
| 5. Equal reply cap | New plans use 8,192 for every model | Historical 1,024-cap Qwen runs remain separately labelled |
| 6. Tool-agent baseline | Bounded file/edit/git-diff/pytest/CodeQL tools; three actual repetitions; shared final oracle and finding exports | Different strategies/gates and tool compute are explicit; no claim of identical total compute |
| 7. flask-webgoat | Pinned clone, baseline SARIF (7 findings in 5 files), full one-model factorial | A supporting `main.md` with other figures was not found; those numbers are not claimed reproduced |
| 9. External conditions | VAmPI all conditions complete in the one-model factorial | PyGoat B/C/simple and other models still need execution |
| 10a. A_strict | Three repetitions on VAmPI and flask-webgoat; candidate-blocking audit | Synthetic and PyGoat strict runs remain |
| 10b. Statistics | Wilson intervals, exact McNemar, matched effect sizes, Holm correction, repetition bootstrap; missing cells stay null | Small fixed subjects and correlated findings limit inference |
| 11. Finding/CWE outcomes | JSON/CSV with acceptance, resolution, attempts, test changes and CWE breakdown | Partial duplicate-group identities remain ambiguous |
| 12. Joint security | Resolution, no new SAST alerts, no measured regression, passing behavioral assertions | Missing evidence remains null; DAST scope is separately reported |
| 13. Configuration table | JSON/CSV with gates, minimality policy, tests, guidance, reply caps, code/environment hashes | Historical omissions remain null |
| 14. Synthetic behavior | Eight fixed checks; baseline 1/8, exactly replayed model patch 3/8 | Five security failures remain in that model patch |
| 15. Model-patch DAST | Paired authenticated active SQL/XSS scans on synthetic and flask-webgoat | Bounded routes/rules, not a full crawl or native authorization proof |
| 16. Test classification | Frozen exact-ID policy and per-run data; unlisted failures conservatively count as regressions | These labels are not independent human judgments of every failure |
| 17. Guidance freeze | review-2 bytes and hash retained for all new model runs | Future library edits require a new version |
| 18. Independent sign-off | Explicit pending record for every entry | A real independent reviewer and original expert-review provenance are unavailable |
| 19. Coverage | Dataset/CWE coverage exported, including unsupported CWE-1333 | No unreviewed new entry was added to the frozen library |
| 20. Legacy hygiene | Legacy repair/prompts and destructive workflow archived; oracle results relocated | Historical evidence remains available |
| 21. Linux/CI | Platform tool paths, local-runtime path support, Ubuntu/Windows CI and offline smoke | Ubuntu and Windows core CI passed; Docker/scanner execution on Linux remains unverified |
| 22. Dependencies/container | Exact-version transitive snapshots and scanner/pipeline Dockerfile; official Linux scanner checksum pinned | Docker build not executed on this host; OS package/image reproducibility is limited to the provided definition |
| 23. Version/DOI | Versioned code/citation metadata and checksummed archive helper | Zenodo connection, author-approved archive metadata and an actual minted DOI |
| 24. Oracle separation | `oracle_validation/security-resolution-v6` | Agent-authored hardening is never pooled with model results |

The latest code also fixes an execution issue discovered during the study: Pylint now resolves dependencies from the same dedicated target environment used for behavioral tests. One saved candidate was incorrectly rejected for a missing `jsonschema` import in the pipeline environment; the corrected validator accepts it, and its independent CodeQL scan removes 2/3 alerts without new ones. The six authorization/disclosure checks still fail. This is a single-candidate validator audit, not a new full model run or a causal whole-pipeline improvement estimate.

The original controlled code is preserved in Git, and its recorded implementation hashes were checked against `12f7847`. Later validator/outcome corrections and future runs must remain versioned separately. Numerical results are not altered to agree with the paper.

Earlier production/JavaScript pilots remain historical evidence. The new controlled matrix does not establish performance across all production applications or programming languages.
