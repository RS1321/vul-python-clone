"""Availability-driven supplemental candidate; retained alongside all originals."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuation.sweep import worker
from review.runner import dump

dump(ROOT / 'continuation/results/cohort-amendment.json', {
    'supplemental_model': 'gemini-3.6-flash',
    'reason': 'Gemma 31B repeatedly interrupted by service errors; its partial observations and recovery remain in the report. Gemini 2.5 Flash-Lite catalog listing did not confer access.',
    'decision_basis': 'Availability probe only; no candidate patch outcomes inspected for the supplemental model.',
    'free_pricing_source': 'https://ai.google.dev/gemini-api/docs/pricing',
    'scope': 'At least five completed free-model A/B pairs; all attempted candidates reported, including unavailable/partial ones.',
    'protocol': 'Unchanged fivefree-v2 runner, compact context, review-1, one repetition.'})
result = worker('gemini-3.6-flash', [('synthetic', 'A'), ('synthetic', 'B')])
dump(ROOT / 'continuation/results/gemini-3.6-flash-final.json', result)
