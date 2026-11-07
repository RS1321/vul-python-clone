"""Resolve the benchmark in sibling-workspace and nested repository layouts."""
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[1]


def synthetic_repo():
    override = os.getenv('AVR_SYNTHETIC_REPO')
    if override:
        return Path(override).resolve()
    if (ROOT / 'benchmarks/synthetic/.git').exists():
        return ROOT / 'benchmarks/synthetic'
    if (ROOT.parent / 'vulnerable_app.py').is_file():
        return ROOT.parent
    return ROOT.parent / 'vul-python-clone'
