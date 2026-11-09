"""Select only infrastructure-interrupted local cells for a fresh CI trial."""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.study_progress import build_status
from review.continue_study import CONDITIONS, DATASETS


def parse_name(name, models):
    match = re.search(r'-review2-validated-r([123])$', name)
    if not match:
        return None
    for model in models:
        if not name.startswith(model+'-'):
            continue
        middle = name[len(model)+1:match.start()]
        for dataset in DATASETS:
            if middle.endswith('-'+dataset):
                condition = middle[:-len(dataset)-1]
                if condition in CONDITIONS:
                    return dict(model=model,dataset=dataset,condition=condition,repetition=int(match[1]))
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wave', type=int, required=True)
    parser.add_argument('--limit', type=int, default=128)
    parser.add_argument('--all-missing', action='store_true', help='Run all remaining cells after a global common-budget correction')
    args = parser.parse_args()
    results = ROOT/'review_results'
    cohort = json.loads((ROOT/'review/validated-cohort.json').read_text())
    models = [m['model'] for m in cohort if m['provider']=='local']
    protocol = json.loads((ROOT/'review/study-protocol.validated.json').read_text())
    status = build_status(results,protocol,cohort)
    key = lambda c:(c['model'],c['dataset'],c['condition'],c['repetition'])
    completed = {key(c) for c in status['cells'] if c['status']=='complete'}
    scheduled_path = results/'ci-retry-schedules.json'
    schedules = json.loads(scheduled_path.read_text()) if scheduled_path.exists() else []
    scheduled = {key(c) for s in schedules for c in s['cells']}
    candidates = {}
    if args.all_missing:
        for cell in status['cells']:
            if cell['provider'] == 'local' and cell['status'] != 'complete':
                selected = {k:cell[k] for k in ('model','dataset','condition','repetition')}
                candidates[key(selected)] = dict(selected,reasons=['Global common-budget replacement: all local cells use the full 3600-second wait, independent of pilot scores'])
    for path in (results/'ci-bootstrap-failures').glob('*/*/ci-error.json'):
        cell = parse_name(path.parent.name,models)
        if cell:
            candidates.setdefault(key(cell),dict(cell,reasons=[]))['reasons'].append('bootstrap failure: '+str(path.relative_to(ROOT)))
    for path in results.glob('*/manifest.json'):
        m = json.loads(path.read_text())
        if m.get('provider') != 'local' or m.get('status') not in ('interrupted_api_error','interrupted_validator_error') or m.get('model') not in models:
            continue
        if m.get('selected_findings') != m.get('eligible_findings'):
            continue
        cell = dict(model=m['model'],dataset=next((d for d in DATASETS if d in path.parent.name),None),
                    condition=m['condition'],repetition=m['repetition'])
        if cell['dataset'] and cell['condition'] in CONDITIONS:
            candidates.setdefault(key(cell),dict(cell,reasons=[]))['reasons'].append('retained infrastructure interruption: '+path.parent.name)
    cells = [candidates[k] for k in sorted(candidates) if k not in completed and k not in scheduled][:args.limit]
    plan = {'wave':args.wave,'selection':'Infrastructure status only; no score-based selection. Partial trials retained; completed trial uses original attempt caps.', 'cells':cells}
    (ROOT/'review/ci-rescue-cells.json').write_text(json.dumps(plan,indent=2)+'\n')
    schedules.append(plan)
    scheduled_path.write_text(json.dumps(schedules,indent=2)+'\n')
    print(json.dumps({'wave':args.wave,'cells':len(cells),'completed_cells_reused':len(completed)}))


if __name__ == '__main__':
    main()
