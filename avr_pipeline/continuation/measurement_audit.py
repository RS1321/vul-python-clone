"""Check reported measurements and input identities before publishing evidence."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.runner import dump, digest

data = json.loads((ROOT / 'continuation/results/five-model-observations.json').read_text())
pairs = [p for p in data['pairs'] if p['complete']]
assert len(pairs) >= 5, 'Five completed pairs are required'
old_budget_errors = []
for pair in pairs:
    for condition in ('A', 'B'):
        row = pair[condition]
        folder = ROOT / 'review_results' / row['run']
        state = json.loads((folder / 'manifest.json').read_text())
        assert state['status'] == 'complete'
        assert state['selected_findings'] == state['eligible_findings'] == 29
        assert state['settings']['attempts'] == 3 and state['settings']['gates']
        assert state['settings']['guidance'] is (condition == 'A')
        assert state['settings']['examples'] is (condition == 'A')
        assert abs(state['sast']['resolution_rate'] * 29 - state['sast']['resolved_findings']) < 1e-8
        for path in folder.glob('interrupted-finding-*.json'):
            text = path.read_text()
            if 'MAX_TOKENS' in text or 'Local API error: incomplete output' in text:
                old_budget_errors.append({'run': row['run'], 'record': path.name})
inputs = []
for name in ('synthetic', 'pygoat', 'vampi'):
    baseline = ROOT / f'review_results/baseline-{name}'
    record = json.loads((baseline / 'dataset-manifest.json').read_text())
    assert digest(baseline / 'scan.sarif') == record['sarif_sha256']
    inputs.append({'dataset': name, 'source_commit': record['source_commit'], 'sarif_sha256': record['sarif_sha256']})
effects = [p['A_minus_B_pp'] for p in pairs]
external = json.loads((ROOT / 'continuation/results/external-runtime-summary.json').read_text())
startup = json.loads((ROOT / 'continuation/results/startup-summary.json').read_text())
result = {'completed_pairs': len(pairs), 'joint_effect_range_pp': [min(effects), max(effects)],
          'inputs_verified': inputs, 'historical_output_limit_interruptions': old_budget_errors,
          'external_runtime_runs': len(external), 'external_runtime_passed': sum(r['runtime']['passed'] for r in external),
          'startup_runs': len(startup), 'startup_passed': sum(r['passed'] for r in startup),
          'scope': 'Within-model comparisons; the smaller local model uses a separately declared output cap. No original expert-review provenance or broad security guarantee is inferred.'}
dump(ROOT / 'continuation/results/measurement-audit.json', result)
print(json.dumps({k: result[k] for k in ('completed_pairs', 'joint_effect_range_pp', 'external_runtime_runs', 'external_runtime_passed', 'startup_runs', 'startup_passed', 'historical_output_limit_interruptions')}))
