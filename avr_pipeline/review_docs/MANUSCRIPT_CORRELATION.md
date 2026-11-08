# Manuscript and executable evidence

Source: user-supplied `1-2.pdf`, 44 pages. Tables 9 and 10 were checked in a rendered image of page 19; Table 14 was checked on page 27. Other comparisons below refer to extracted text on pages 17, 30 and 33. The manuscript is not edited by this work.

## What the paper reports

Table 9 reports Run A SAST resolution of 29/29 for Qwen 3.5 Flash, Kimi K2.5, Minimax M2.5 and DeepSeek V3.2, and 28/29 for GLM-5. These are the paper's reported measurements, not independently reproduced results.

Table 10 also reports 1–2 newly introduced DAST alert types for every model. Its DAST validation rates range from 47.8% to 91.3%, with different denominators and matching rules from the SAST metric. Table 14 records three genuine functional regressions for Minimax in both A and C. Therefore 100% SAST resolution in the paper does not establish a joint security-and-behavior success rate of 100%.

Table 17 reports DeepSeek A 29/29 versus B 22/29, a 24.14 percentage-point difference. Table 7 shows that B removes both CWE guidance and examples, so this estimates their combined contribution in that one model/run. It does not separately identify guidance and example effects. C also changes both validation gates and maximum attempts; A–C is the combined validation/retry policy effect, not a retry-only or gate-only effect.

## Saved five-model comparison in this repository

These earlier matched synthetic A/B runs use review-1 guidance and compact context. They have one repetition each and a different model cohort from the paper.

| Model | A resolved / 29 | B resolved / 29 | A − B, percentage points | Reply cap |
|---|---:|---:|---:|---:|
| Gemma-4-26B-A4B | 11 | 11 | 0.00 | 8,192 |
| Gemini-3.1-flash-lite | 5 | 8 | −10.34 | 8,192 |
| Gemini-3.5-flash-lite | 14 | 14 | 0.00 | 8,192 |
| Qwen2.5-Coder-1.5B Q4_K_M | 5 | 3 | +6.90 | 8,192 |
| Qwen2.5-Coder-0.5B Q4_K_M | 0 | 0 | 0.00 | **1,024** |

The run names end in `synthetic-fivefree-v2-r1`, except the 0.5B pair, which ends in `synthetic-fivefree-v3-1024-r1`. Each run's manifest and SARIF remain the authority. Accepted patches are counted separately from alerts resolved. An accepted patch can leave the vulnerability intact.

These values cannot substantiate or refute the paper's model-specific 96.55–100% claim: the exact paper models, prompt/context protocol and resource settings differ. The 0.5B pair is additionally unsuitable for an equal-cap cross-model comparison. No constant correction factor can convert these results into the paper's results.

The earlier `security-resolution-v6` hardening is now under `oracle_validation`. It was authored by the coding agent and must not replace model outcomes in any paper table.

## New study and interpretation

`review/study-protocol.json` freezes the review-2 library bytes and the conservative test classification policy. `review/run_matrix.py` plans all seven conditions and three repetitions with an 8,192 reply cap. The four-subject, five-model plan has 420 cells. A plan entry is not a completed experiment. `review_results/manuscript-study-status.json` records actual completion separately.

The new flask-webgoat input is pinned to `c481018c39e76e5758fabc27efabadc34a0d4dd6` from ShiftLeftSecurity/flask-webgoat. Its measured baseline is **7 CodeQL findings in 5 files**. It is a separate subject from the 29-finding synthetic application. A `main.md` file supporting other flask-webgoat figures was not supplied or found in the checked code; those numbers are not claimed as reproduced.

Use `matched-statistics.json` for exact McNemar tests, matched risk differences, odds-ratio boundaries and Holm adjustment. Use `repeat-effects.json` for whole-repetition bootstrap intervals, which remain null below three matched repetitions. Wilson intervals are descriptive per-run intervals, not evidence that correlated findings are independent. Matching requires the same source, baseline, model, guidance, reply cap, test policy and implementation hashes. Warm-up runs made while correcting the harness remain visible but are not pooled with a different implementation.

Every run has a per-finding outcome export and a CWE breakdown. Partial resolution of duplicate findings in the same rule/file/function group cannot identify which finding disappeared and remains null at finding level. Tests and behavioral evidence are batch-level observations, not causal attribution to an individual patch. Missing tests, missing active scans, interrupted model access and absent comparisons remain unmeasured.

The new joint metric requires alert resolution, no new SAST alerts, no newly failing ordinary test classified as a regression, and passing behavioral assertions. This is stricter than the paper's SAST-only headline. Bounded DAST measurements are reported separately, with exact routes and traffic evidence; they do not cover all endpoints or establish native authorization correctness.

No numerical improvement is promised by the infrastructure changes. The purpose is to measure reliable repairs, avoid counting broken/ineffective patches as successes, and make both improvements and failures reproducible.


Completed run summaries are in `MEASURED_RESULTS.md`; the complete item-by-item boundary is in `DELIVERY_STATUS.md`. The controlled execution code is `12f7847`. The later target-dependency validation fix is separately audited rather than mixed into the earlier experiment. The latest derived tables also correct early test-summary classifications from retained JUnit evidence while preserving the original manifests.

The compared historical runs record no ZAP input hash. The later paired DAST measurements evaluate saved patches and were not prompt inputs to those runs. This is another difference from the paper's SAST/DAST-guided setup. VAmPI's six authorization/disclosure assertions test weaknesses outside its three regex alerts: a failing batch-wide joint metric does not establish that every individual regex repair is wrong.
