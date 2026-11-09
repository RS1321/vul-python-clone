# Corrected free-model study: measured results

Snapshot: 2026-11-09T10:28:12.382140+00:00. **203/420 cells complete**. 217 cells remain unevaluated or interrupted. Planned cells never count as model failures.

The study uses four pinned Python subjects, five accessible free models, seven conditions and three repetitions per cell. Every model receives an 8,192-token reply cap. Within-model contrasts use the same source, library, tests and patch gates. All four local Qwen models share a family and use Q4_K_M CPU inference; model sizes do not provide five independent architectures.

## Measured outcomes

Rows use completed repetitions only. A missing result is shown as a dash. Partial rows are interim observations. Intervals resample whole repetitions and are withheld below three repetitions; with only three repetitions they are descriptive and unstable. Joint success requires an alert resolved, no new alerts, no measured ordinary-test regression and passing batch behavioral assertions. Unknown joint outcomes remain unknown, rather than becoming successes.

| Model | Subject | Condition | Repetitions / 3 | Mean SAST resolved | Repetition CI | Joint successes / all findings | Unknown joint findings | Mean new alerts |
|---|---|---|---:|---:|---|---:|---:|---:|
| gemma-4-26b-a4b-it | vampi | A | 3 | 88.9% | 66.7%–100.0% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | vampi | B | 3 | 88.9% | 66.7%–100.0% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | vampi | A_strict | 3 | 66.7% | 66.7%–66.7% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | vampi | no_guidance | 3 | 77.8% | 66.7%–100.0% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | vampi | no_examples | 3 | 88.9% | 66.7%–100.0% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | vampi | C | 3 | 100.0% | 100.0%–100.0% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | vampi | simple | 3 | 100.0% | 100.0%–100.0% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | flask-webgoat | A | 3 | 38.1% | 28.6%–42.9% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | flask-webgoat | B | 3 | 42.9% | 42.9%–42.9% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | flask-webgoat | A_strict | 3 | 47.6% | 42.9%–57.1% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | flask-webgoat | no_guidance | 3 | 42.9% | 42.9%–42.9% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | flask-webgoat | no_examples | 3 | 42.9% | 42.9%–42.9% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | flask-webgoat | C | 3 | 57.1% | 57.1%–57.1% | 0.0% | 0 | 1.00 |
| gemma-4-26b-a4b-it | flask-webgoat | simple | 3 | 47.6% | 42.9%–57.1% | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | synthetic | A | 0 | — | — | — | 0 | — |
| gemma-4-26b-a4b-it | synthetic | B | 0 | — | — | — | 0 | — |
| gemma-4-26b-a4b-it | synthetic | A_strict | 1 | 37.9% | — | 0.0% | 0 | 1.00 |
| gemma-4-26b-a4b-it | synthetic | no_guidance | 0 | — | — | — | 0 | — |
| gemma-4-26b-a4b-it | synthetic | no_examples | 0 | — | — | — | 0 | — |
| gemma-4-26b-a4b-it | synthetic | C | 1 | 86.2% | — | 0.0% | 0 | 3.00 |
| gemma-4-26b-a4b-it | synthetic | simple | 1 | 82.8% | — | 0.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | pygoat | A | 1 | 67.7% | — | 0.0% | 0 | 1.00 |
| gemma-4-26b-a4b-it | pygoat | B | 0 | — | — | — | 0 | — |
| gemma-4-26b-a4b-it | pygoat | A_strict | 0 | — | — | — | 0 | — |
| gemma-4-26b-a4b-it | pygoat | no_guidance | 1 | 71.0% | — | 71.0% | 0 | 0.00 |
| gemma-4-26b-a4b-it | pygoat | no_examples | 1 | 69.4% | — | 0.0% | 0 | 2.00 |
| gemma-4-26b-a4b-it | pygoat | C | 3 | 72.0% | 71.0%–74.2% | 0.0% | 0 | 3.00 |
| gemma-4-26b-a4b-it | pygoat | simple | 2 | 79.8% | — | 78.2% | 4 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | A | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | B | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | A_strict | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | no_guidance | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | no_examples | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | C | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | vampi | simple | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | A | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | B | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | A_strict | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | no_guidance | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | no_examples | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | C | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.67 |
| qwen2.5-coder-0.5b-instruct-q4km | flask-webgoat | simple | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | A | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | B | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | A_strict | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | no_guidance | 3 | 4.6% | 0.0%–6.9% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | no_examples | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | C | 3 | 24.1% | 20.7%–27.6% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | synthetic | simple | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | A | 3 | 3.2% | 1.6%–4.8% | 3.2% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | B | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | A_strict | 3 | 3.8% | 1.6%–4.8% | 3.8% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | no_guidance | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | no_examples | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | C | 3 | 3.8% | 3.2%–4.8% | 3.8% | 0 | 0.00 |
| qwen2.5-coder-0.5b-instruct-q4km | pygoat | simple | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | B | 1 | 0.0% | — | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | vampi | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | A | 3 | 23.8% | 14.3%–28.6% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | B | 3 | 14.3% | 14.3%–14.3% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | A_strict | 3 | 23.8% | 14.3%–28.6% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | no_guidance | 3 | 14.3% | 14.3%–14.3% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | no_examples | 3 | 19.0% | 14.3%–28.6% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | C | 3 | 9.5% | 0.0%–14.3% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | flask-webgoat | simple | 3 | 14.3% | 14.3%–14.3% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | synthetic | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | A | 3 | 31.7% | 30.6%–32.3% | 31.7% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | B | 3 | 33.3% | 32.3%–33.9% | 32.8% | 2 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | A_strict | 3 | 31.7% | 30.6%–32.3% | 31.2% | 2 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | no_guidance | 1 | 32.3% | — | 32.3% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | C | 3 | 22.6% | 17.7%–25.8% | 22.6% | 0 | 0.00 |
| qwen2.5-coder-1.5b-instruct-q4km | pygoat | simple | 1 | 32.3% | — | 32.3% | 0 | 0.00 |
| qwen2.5-coder-3b-instruct-q4km | vampi | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | vampi | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | vampi | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | vampi | no_guidance | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-3b-instruct-q4km | vampi | no_examples | 1 | 0.0% | — | 0.0% | 0 | 0.00 |
| qwen2.5-coder-3b-instruct-q4km | vampi | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | vampi | simple | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | flask-webgoat | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | synthetic | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-3b-instruct-q4km | pygoat | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | vampi | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | A | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | B | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | A_strict | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | no_guidance | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | no_examples | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | C | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | flask-webgoat | simple | 3 | 0.0% | 0.0%–0.0% | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | synthetic | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | synthetic | B | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | synthetic | A_strict | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | synthetic | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | synthetic | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | synthetic | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | synthetic | simple | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | pygoat | A | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | pygoat | B | 1 | 0.0% | — | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | pygoat | A_strict | 1 | 0.0% | — | 0.0% | 0 | 0.00 |
| qwen2.5-coder-7b-instruct-q4km | pygoat | no_guidance | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | pygoat | no_examples | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | pygoat | C | 0 | — | — | — | 0 | — |
| qwen2.5-coder-7b-instruct-q4km | pygoat | simple | 0 | — | — | — | 0 | — |

## Tool-agent comparator

| Model | Repetition | SAST resolved | New alerts | New ordinary-test regressions | Behavioral assertions | Turns used / cap |
|---|---:|---:|---:|---:|---|---:|
| qwen2.5-coder-7b-instruct-q4km | 1 | 3/7 | 1 | 2 | 0/5 | 8/21 |
| qwen2.5-coder-7b-instruct-q4km | 2 | 3/7 | 1 | 2 | 0/5 | 8/21 |
| qwen2.5-coder-7b-instruct-q4km | 3 | 3/7 | 1 | 2 | 0/5 | 8/21 |

The comparator uses the same pinned flask-webgoat input, final CodeQL oracle, tests and reply cap as the corresponding 7B AVR runs. The model chose its tool actions and stopping point within 21 turns. In the recorded comparator patches, deleting a required importable function breaks startup; the ordinary-test and behavioral results expose that failure despite alert removal.

## Paired model-patch DAST

| Subject | Model run | Status | Alert types before → after | Instances before → after | Authenticated SQL/XSS requests before → after | New types |
|---|---|---|---|---|---|---|
| flask-webgoat | gemma-4-26b-a4b-it-A-flask-webgoat-review2-recovery3-r1 | complete | 7 → 7 | 14 → 13 | 40/32 → 40/32 | [] |

These are bounded active SQL/XSS scans of fixed routes in isolated copies, with verified authenticated traffic. The identical outer session gateway is measurement containment and does not establish native authorization correctness. A failed application start or missing active traffic is an incomplete scan, not zero alerts. Historical DAST pairs remain separately labelled.


## Interpretation and reproducibility

The paper reports 28–29 of 29 synthetic SAST alerts resolved using a different five-model cohort. These runs do not reproduce that model-specific claim. The paper also reports new DAST alert types and functional regressions, so its SAST headline is not a joint security success rate. See [the manuscript comparison](../../review_docs/MANUSCRIPT_CORRELATION.md) for table numbers and protocol differences.

The current matrix supplied no ZAP report as a model prompt input. The later paired scans independently evaluate model-generated patches. This is another protocol difference from the paper; the optional class-level ZAP hint is not endpoint-to-source exploit attribution.

VAmPI has three CWE-1333 alerts and no applicable review-2 guidance entry. Differences among its named prompt factors are descriptive; they do not estimate the effect of guidance that was never supplied. Its authorization/disclosure assertions cover additional weaknesses outside those three alerts.

The three local 7B tool-agent runs use the same pinned flask-webgoat input, 21-turn limit, 8,192-token reply cap and final CodeQL oracle. Their file-editing strategy and tool calls differ from AVR. Source-local missing-function import failures after a working baseline count as startup regressions in the derived analysis; raw logs/manifests are unchanged. See `external-baseline-effects.json`, per-run test audits and the full configuration table.

Raw evidence is retained locally under `review_results/<run>/`; publication of raw messages and machine metadata requires separate approval. Public allowlisted exports are under `public_results/review2/`. configuration and finding tables, exact McNemar tests, Holm adjustments, factorial effects, whole-repetition intervals and strict-gate audits are under `review_results/validated-analysis/`. McNemar comparisons are exploratory because findings can share functions and are not independent. The original validator study and 180-second local-timeout pilots are excluded from this primary cohort.

Agent-authored hardening remains under `oracle_validation/` and is never counted as a model result. Independent human guidance sign-off and Zenodo publication are deferred to the professor, as requested. The manuscript has not been edited.
