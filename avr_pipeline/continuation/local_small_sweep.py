"""Supplemental local candidate selected for availability before patch outcomes."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuation.sweep import worker
from review.runner import dump
dump(ROOT / 'continuation/results/local-small-cohort-amendment.json', {
    'model': 'qwen2.5-coder-0.5b-instruct-q4km',
    'reason': 'Repeated hosted-service interruptions and the 3.6 Flash daily free limit; local availability verified before patch outcomes.',
    'scope': 'Supplemental A/B candidate; all original candidates remain reported.',
    'protocol': 'Same prompts, compact context, gates and generation limit. Fixed separate loopback endpoint; no external service.'})
dump(ROOT / 'continuation/results/qwen05-final.json', worker('qwen2.5-coder-0.5b-instruct-q4km', [('synthetic', 'A'), ('synthetic', 'B')]))
