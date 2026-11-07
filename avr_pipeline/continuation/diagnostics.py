"""Summarize experiment errors without printing source or API credentials."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
for manifest in sorted((ROOT / 'review_results').glob('*fivefree*/manifest.json')):
    state = json.loads(manifest.read_text())
    path = manifest.parent / 'results.json'
    rows = json.loads(path.read_text()) if path.exists() else []
    errors = [a.get('error') for a in (rows[-1].get('attempts', []) if rows else []) if a.get('error')]
    print(json.dumps({'run': manifest.parent.name, 'status': state['status'], 'processed': len(rows), 'last_errors': errors}))
