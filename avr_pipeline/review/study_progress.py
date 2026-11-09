"""Report all declared cells of a selected study; missing evidence stays missing."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.continue_study import CONDITIONS, DATASETS, identity
from review.evidence_io import durable_dump as dump, recorded_outages
from review.protocol_compatibility import budget_violations


def build_status(results, protocol, cohort):
    sources = {d:dict(source_commit=json.loads((results/f'baseline-{d}/dataset-manifest.json').read_text(encoding='utf-8'))['source_commit'],
                      sarif_sha256=hashlib.sha256((results/f'baseline-{d}/scan.sarif').read_bytes()).hexdigest()) for d in DATASETS}
    index = {}
    for path in sorted(results.glob('*/manifest.json')):
        manifest = json.loads(path.read_text(encoding='utf-8'))
        key = identity(manifest, protocol, sources)
        if key:
            index.setdefault(key, []).append((path.parent, manifest))
    cells = []
    for model in cohort:
        for dataset in DATASETS:
            for condition in CONDITIONS:
                for repetition in (1, 2, 3):
                    key = (model['provider'], model['model'], dataset, condition, repetition)
                    runs = index.get(key, [])
                    complete = [(p,m) for p,m in runs if m.get('status') == 'complete' and m.get('sast') and not recorded_outages(p) and not budget_violations(p)]
                    status = ('complete' if len(complete) == 1 else 'ambiguous_duplicate' if complete else
                              'running' if any(m.get('status') == 'running' for p,m in runs) else
                              'interrupted' if runs else 'not_run')
                    cell = dict(model, dataset=dataset, condition=condition, repetition=repetition,
                                status=status, runs=[p.name for p,m in runs])
                    outages = {p.name:recorded_outages(p) for p,m in runs if recorded_outages(p)}
                    if outages:
                        cell['measurement_outages'] = outages
                    if status == 'complete':
                        m = complete[0][1]
                        cell.update(resolved=m['sast']['resolved_findings'], new_alerts=m['sast']['new_findings'],
                                    accepted=m.get('accepted_patches'), behavioral_tests=m.get('behavioral_tests'))
                    cells.append(cell)
    counts = Counter(c['status'] for c in cells)
    return {'generated_utc':datetime.now(timezone.utc).isoformat(), 'protocol_id':protocol.get('protocol_id'),
            'controlled_code_commit':protocol['controlled_code_commit'], 'planned_cells':len(cells),
            'completed_cells':counts['complete'], 'remaining_cells':len(cells)-counts['complete'],
            'counts':dict(counts), 'spending':'free/local only',
            'status_scope':'Verified local artifacts. not_run means no compatible local manifest yet and can include remote queued/running jobs whose evidence has not been imported.',
            'deferred_by_user':['independent human guidance sign-off','Zenodo author details/publication'], 'cells':cells}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol', type=Path, default=ROOT/'review/study-protocol.validated.json')
    parser.add_argument('--cohort', type=Path, default=ROOT/'review/validated-cohort.json')
    parser.add_argument('--results', type=Path, default=ROOT/'review_results')
    args = parser.parse_args()
    report = build_status(args.results, json.loads(args.protocol.read_text(encoding='utf-8')), json.loads(args.cohort.read_text(encoding='utf-8')))
    dump(args.results/'validated-study-status.json', report)
    print(json.dumps({k:v for k,v in report.items() if k != 'cells'}, indent=2))


if __name__ == '__main__':
    main()
