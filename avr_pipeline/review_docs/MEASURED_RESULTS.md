# Measured manuscript follow-up

Primary matrix: **45/420 cells complete**. All remaining cells are listed in `manuscript-study-status.json`; plans and warm-ups do not count as completed evidence.

Controlled execution uses code commit `12f7847`. The later target-environment validator correction is audited separately. New runs of the corrected implementation require a new study tag and must not be pooled with these runs.

| Model | Subject | Condition | Repetitions | Mean SAST resolution | New SAST alerts per run | Behavioral assertions passing per run |
|---|---|---|---|---:|---|---|
| gemini-3.5-flash-lite | flask-webgoat | A | 1, 2, 3 | 23.81% | 0, 1, 1 | 2/5, 3/5, 3/5 |
| gemini-3.5-flash-lite | flask-webgoat | A_strict | 1, 2, 3 | 28.57% | 0, 1, 0 | 3/5, 4/5, 3/5 |
| gemini-3.5-flash-lite | flask-webgoat | B | 1, 2, 3 | 52.38% | 0, 1, 0 | 3/5, 3/5, 3/5 |
| gemini-3.5-flash-lite | flask-webgoat | C | 1, 2, 3 | 38.10% | 2, 1, 1 | 4/5, 4/5, 4/5 |
| gemini-3.5-flash-lite | flask-webgoat | no_examples | 1, 2, 3 | 28.57% | 1, 1, 1 | 3/5, 3/5, 3/5 |
| gemini-3.5-flash-lite | flask-webgoat | no_guidance | 1, 2, 3 | 52.38% | 1, 1, 1 | 3/5, 3/5, 4/5 |
| gemini-3.5-flash-lite | flask-webgoat | simple | 1, 2, 3 | 14.29% | 0, 0, 0 | 3/5, 2/5, 3/5 |
| gemini-3.5-flash-lite | vampi | A | 1, 2, 3 | 88.89% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.5-flash-lite | vampi | A_strict | 1, 2, 3 | 77.78% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.5-flash-lite | vampi | B | 1, 2, 3 | 66.67% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.5-flash-lite | vampi | C | 1, 2, 3 | 100.00% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.5-flash-lite | vampi | no_examples | 1, 2, 3 | 88.89% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.5-flash-lite | vampi | no_guidance | 1, 2, 3 | 77.78% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.5-flash-lite | vampi | simple | 1, 2, 3 | 100.00% | 0, 0, 0 | 5/11, 5/11, 5/11 |
| gemini-3.6-flash | vampi | A | 1, 2 | 100.00% | 0, 0 | 5/11, 5/11 |
| gemini-3.6-flash | vampi | B | 1 | 100.00% | 0 | 5/11 |
| gemma-4-31b-it | vampi | A | 1 | 66.67% | 0 | 5/11 |

VAmPI CWE-1333 has no review-2 library entry. Its guidance/example switches add no library treatment, so differences between those named conditions cannot establish guidance effectiveness. Alert resolution does not repair the authorization/disclosure failures outside those alerts.

See `matched-statistics.json`, `external-baseline-effects.json` and `repeat-effects.json` for matched outcomes and uncertainty. Missing or duplicate cells remain explicit. Completed comparator runs use a different strategy with the same pinned input, reply cap and final CodeQL oracle.

Agent-authored security-resolution-v6 results are under `oracle_validation` and excluded. Linux CI/container execution, independent human review and a minted DOI remain outstanding.
