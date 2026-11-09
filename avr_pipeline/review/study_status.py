"""Report actual study coverage separately from plans, warm-ups and oracle repairs."""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.runner import dump
from review.matrix_study import FACTORIAL, DATASETS
from review.validation_health import recorded_outages


def main():
    results = ROOT/'review_results'
    protocol = json.loads((ROOT/'review/study-protocol.json').read_text())
    cohort = json.loads((ROOT/'review/free-cohort.json').read_text())
    sources = {d:json.loads((results/f'baseline-{d}/dataset-manifest.json').read_text())['source_commit'] for d in DATASETS}
    covered = defaultdict(list)
    warmups, interrupted, agents = [], [], []
    grouped = defaultdict(list)
    for path in sorted(results.glob('*/manifest.json')):
        m = json.loads(path.read_text())
        if m.get('library_sha256') != protocol['library_sha256']:
            continue
        dataset = next((d for d,sha in sources.items() if sha == m.get('source_commit')), None)
        full = m.get('status') == 'complete' and m.get('sast') and m.get('selected_findings') == m.get('eligible_findings')
        if recorded_outages(path.parent):
            interrupted.append({'run':path.parent.name,'status':'validator_outage_in_recorded_attempts'})
            continue
        if m.get('condition') == 'tool_agent':
            agents.append({'run':path.parent.name,'status':m.get('status'),'repetition':m.get('repetition'),
                           'resolved':m.get('sast',{}).get('resolved_findings'), 'new_alerts':m.get('sast',{}).get('new_findings'),
                           'behavior':m.get('behavioral_tests',{}).get('status')})
            continue
        if m.get('implementation_sha256') != protocol['primary_implementation_sha256']:
            warmups.append({'run':path.parent.name,'status':m.get('status')})
            continue
        if not full:
            interrupted.append({'run':path.parent.name,'status':m.get('status')})
            continue
        key = (m['provider'],m['model'],dataset,m['condition'],m['repetition'])
        covered[key].append(path.parent.name)
        grouped[(m['model'],dataset,m['condition'])].append(m)
    cells = []
    for model in cohort:
        for dataset in DATASETS:
            for condition in FACTORIAL:
                for r in (1,2,3):
                    key = (model['provider'],model['model'],dataset,condition,r)
                    runs = covered[key]
                    cells.append(dict(model,dataset=dataset,condition=condition,repetition=r,runs=runs,
                                      status='complete' if len(runs)==1 else 'ambiguous_duplicate' if runs else 'not_complete'))
    count = sum(c['status']=='complete' for c in cells)
    record = {'generated_utc':datetime.now(timezone.utc).isoformat(),'planned_cells':len(cells),'completed_primary_cells':count,
              'controlled_code_commit':protocol.get('controlled_code_commit'),
              'implementation_boundary':protocol.get('latest_code_note'),
              'remaining_primary_cells':len(cells)-count,'spending':'free/local only','cells':cells,
              'tool_agent_attempts':agents,'harness_warmups_excluded':warmups,'incomplete_primary_runs':interrupted,
              'human_review':'pending; no independent sign-off or original expert provenance established',
              'zenodo_doi':None,'linux_and_docker':'definitions added; no local Linux distribution or Docker installation available'}
    dump(results/'manuscript-study-status.json',record)
    lines = ['# Measured manuscript follow-up', '', f'Primary matrix: **{count}/{len(cells)} cells complete**. All remaining cells are listed in `manuscript-study-status.json`; plans and warm-ups do not count as completed evidence.', '',
             'Controlled execution uses code commit `12f7847`. The later target-environment validator correction is audited separately. New runs of the corrected implementation require a new study tag and must not be pooled with these runs.', '',
             '| Model | Subject | Condition | Repetitions | Mean SAST resolution | New SAST alerts per run | Behavioral assertions passing per run |',
             '|---|---|---|---|---:|---|---|']
    for (model,dataset,condition),values in sorted(grouped.items()):
        values.sort(key=lambda m:m['repetition'])
        rates = [m['sast']['resolution_rate'] for m in values]
        behavior = [str(m.get('behavioral_tests',{}).get('tests',0)-len(m.get('behavioral_tests',{}).get('failures',[]) or []))+'/'+str(m.get('behavioral_tests',{}).get('tests',0)) for m in values]
        lines.append(f"| {model} | {dataset} | {condition} | {', '.join(str(m['repetition']) for m in values)} | {100*sum(rates)/len(rates):.2f}% | {', '.join(str(m['sast']['new_findings']) for m in values)} | {', '.join(behavior)} |")
    lines += ['', 'VAmPI CWE-1333 has no review-2 library entry. Its guidance/example switches add no library treatment, so differences between those named conditions cannot establish guidance effectiveness. Alert resolution does not repair the authorization/disclosure failures outside those alerts.', '',
              'See `matched-statistics.json`, `external-baseline-effects.json` and `repeat-effects.json` for matched outcomes and uncertainty. Missing or duplicate cells remain explicit. Completed comparator runs use a different strategy with the same pinned input, reply cap and final CodeQL oracle.', '',
              'Agent-authored security-resolution-v6 results are under `oracle_validation` and excluded. Linux CI/container execution, independent human review and a minted DOI remain outstanding.']
    (ROOT/'review_docs/MEASURED_RESULTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(f'Primary cells complete: {count}/{len(cells)}')


if __name__ == '__main__':
    main()
