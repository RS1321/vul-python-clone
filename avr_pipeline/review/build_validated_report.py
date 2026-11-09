"""Build the current study report from completed evidence, never planned scores."""
import csv
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.analyze_study import analyze
from review.continue_study import CONDITIONS, DATASETS, identity
from review.study_progress import build_status
from review.study_statistics import repeated_cluster_ci
from review.evidence_io import durable_dump as dump, recorded_outages
from review.protocol_compatibility import budget_violations, matches_implementation, runner_hashes


def secondary_tables(lines, results, protocol):
    lines += ['', '## Tool-agent comparator','',
        '| Model | Repetition | SAST resolved | New alerts | New ordinary-test regressions | Behavioral assertions | Turns used / cap |',
        '|---|---:|---:|---:|---:|---|---:|']
    for path in sorted(results.glob('*tool-agent*validated*/manifest.json')):
        m = json.loads(path.read_text(encoding='utf-8'))
        if (m.get('status')!='complete' or not m.get('sast') or
                m.get('implementation_sha256',{}).get('review/runner.py') not in runner_hashes(protocol,m.get('provider'))):
            continue
        rows = json.loads((path.parent/'finding-outcomes.json').read_text(encoding='utf-8'))
        tests = m.get('behavioral_tests',{})
        total = tests.get('tests',0)
        passed = total-len(tests.get('failures') or [])
        regressions = rows[0]['test_change']['regressions'] if rows else None
        lines.append(f"| {m['model']} | {m['repetition']} | {m['sast']['resolved_findings']}/{m['eligible_findings']} | {m['sast']['new_findings']} | {regressions if regressions is not None else 'unknown'} | {passed}/{total} | {len(list(path.parent.glob('turn-*.json')))}/{m['settings']['max_turns']} |")
    lines += ['', 'The comparator uses the same pinned flask-webgoat input, final CodeQL oracle, tests and reply cap as the corresponding 7B AVR runs. '
        'The model chose its tool actions and stopping point within 21 turns. In the recorded comparator patches, deleting a required importable function breaks startup; '
        'the ordinary-test and behavioral results expose that failure despite alert removal.','',
        '## Paired model-patch DAST','',
        '| Subject | Model run | Status | Alert types before → after | Instances before → after | Authenticated SQL/XSS requests before → after | New types |',
        '|---|---|---|---|---|---|---|']
    count = 0
    for path in sorted(results.glob('model-dast-*-validated-*/paired-status.json')):
        pair = json.loads(path.read_text(encoding='utf-8'))
        run = results/pair['model_run']
        manifest_path = run/'manifest.json'
        if not manifest_path.exists():
            continue
        m = json.loads(manifest_path.read_text(encoding='utf-8'))
        if not matches_implementation(m,protocol) or recorded_outages(run) or budget_violations(run):
            continue
        before,after = pair['baseline'],pair['model']
        metrics = lambda key: f"{before.get(key,'unknown')} → {after.get(key,'unknown')}"
        traffic = lambda item: '/'.join(str(item.get('traffic',{}).get('active_authenticated_rules',{}).get(rule,0)) for rule in ['40012','40018'])
        lines.append(f"| {pair['dataset']} | {pair['model_run']} | {pair['status']} | {metrics('alert_types')} | {metrics('alert_instances')} | {traffic(before)} → {traffic(after)} | {pair.get('new_alert_types')} |")
        count += 1
    if not count:
        lines.append('| Pending | — | No completed current pair | — | — | — | — |')
    lines += ['', 'These are bounded active SQL/XSS scans of fixed routes in isolated copies, with verified authenticated traffic. '
        'The identical outer session gateway is measurement containment and does not establish native authorization correctness. '
        'A failed application start or missing active traffic is an incomplete scan, not zero alerts. Historical DAST pairs remain separately labelled.','']


def generate():
    results = ROOT/'review_results'
    output = results/'validated-analysis'
    protocol_path = ROOT/'review/study-protocol.validated.json'
    protocol = json.loads(protocol_path.read_text(encoding='utf-8'))
    cohort = json.loads((ROOT/'review/validated-cohort.json').read_text(encoding='utf-8'))
    analyze(results, protocol_path, output, primary_only=True)
    status = build_status(results, protocol, cohort)
    dump(results/'validated-study-status.json', status)
    dump(output/'study-status-snapshot.json', status)
    frozen_cells = {(c['provider'],c['model'],c['dataset'],c['condition'],c['repetition'])
                    for c in status['cells'] if c['status']=='complete'}
    sources = {d:dict(source_commit=json.loads((results/f'baseline-{d}/dataset-manifest.json').read_text(encoding='utf-8'))['source_commit'],
        sarif_sha256=hashlib.sha256((results/f'baseline-{d}/scan.sarif').read_bytes()).hexdigest()) for d in DATASETS}
    runs = defaultdict(list)
    for path in sorted(results.glob('*/manifest.json')):
        manifest = json.loads(path.read_text(encoding='utf-8'))
        key = identity(manifest, protocol, sources)
        if (key in frozen_cells and manifest.get('status') == 'complete' and manifest.get('sast') and
                not recorded_outages(path.parent) and not budget_violations(path.parent)):
            runs[key].append((path.parent, manifest))
    data, findings = [], []
    for model in cohort:
        for dataset in DATASETS:
            for condition in CONDITIONS:
                selected = []
                for repetition in (1,2,3):
                    options = runs.get((model['provider'],model['model'],dataset,condition,repetition), [])
                    if len(options) != 1:
                        continue
                    path, manifest = options[0]
                    rows = json.loads((path/'finding-outcomes.json').read_text(encoding='utf-8'))
                    selected.append((manifest, rows))
                    for row in rows:
                        findings.append(dict(run=path.name, model=model['model'], dataset=dataset,
                            condition=condition, repetition=repetition, **row))
                rates = [m['sast']['resolution_rate'] for m,rows in selected]
                joint = [sum(r['joint_security'] is True for r in rows)/len(rows) for m,rows in selected]
                unknown = sum(sum(r['joint_security'] is None for r in rows) for m,rows in selected)
                data.append(dict(model=model['model'],dataset=dataset,condition=condition,
                    repetitions=len(selected), mean_resolution_rate=statistics.mean(rates) if rates else None,
                    resolution_repetition_ci95=repeated_cluster_ci(rates),
                    mean_joint_rate=statistics.mean(joint) if joint else None,
                    joint_unknown_findings=unknown,
                    mean_new_alerts=statistics.mean(m['sast']['new_findings'] for m,rows in selected) if selected else None))
    dump(output/'summary-by-condition.json', data)
    assert sum(row['repetitions'] for row in data) == status['completed_cells'], 'Snapshot changed during reporting; regenerate after active writes finish'
    fields = list(data[0])
    with (output/'summary-by-condition.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(data)
    fields = ['run','model','dataset','condition','repetition','finding','cwe','rule','file','function',
              'accepted','resolved','resolution_identity','attempts','test_change','behavioral_assertions_pass','joint_security']
    with (output/'per-finding-outcomes.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore');writer.writeheader()
        writer.writerows({k:json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v for k,v in row.items()} for row in findings)
    percent = lambda value: '—' if value is None else f'{value*100:.1f}%'
    lines = ['# Corrected free-model study: measured results','',
        f"Snapshot: {status['generated_utc']}. **{status['completed_cells']}/{status['planned_cells']} cells complete**. "
        f"{status['remaining_cells']} cells remain unevaluated or interrupted. Planned cells never count as model failures.",'',
        'The study uses four pinned Python subjects, five accessible free models, seven conditions and three repetitions per cell. '
        'Every model receives an 8,192-token reply cap. Within-model contrasts use the same source, library, tests and patch gates. '
        'All four local Qwen models share a family and use Q4_K_M CPU inference; model sizes do not provide five independent architectures.','',
        '## Measured outcomes','',
        'Rows use completed repetitions only. A missing result is shown as a dash. Partial rows are interim observations. '
        'Intervals resample whole repetitions and are withheld below three repetitions; with only three repetitions they are descriptive and unstable. '
        'Joint success requires an alert resolved, no new alerts, no measured ordinary-test regression and passing batch behavioral assertions. '
        'Unknown joint outcomes remain unknown, rather than becoming successes.','',
        '| Model | Subject | Condition | Repetitions / 3 | Mean SAST resolved | Repetition CI | Joint successes / all findings | Unknown joint findings | Mean new alerts |',
        '|---|---|---|---:|---:|---|---:|---:|---:|']
    for row in data:
        interval=row['resolution_repetition_ci95']
        ci='—' if interval is None else f'{percent(interval[0])}–{percent(interval[1])}'
        alerts='—' if row['mean_new_alerts'] is None else f"{row['mean_new_alerts']:.2f}"
        lines.append(f"| {row['model']} | {row['dataset']} | {row['condition']} | {row['repetitions']} | {percent(row['mean_resolution_rate'])} | {ci} | {percent(row['mean_joint_rate'])} | {row['joint_unknown_findings']} | {alerts} |")
    secondary_tables(lines,results,protocol)
    lines += ['', '## Interpretation and reproducibility','',
        'The paper reports 28–29 of 29 synthetic SAST alerts resolved using a different five-model cohort. These runs do not reproduce that model-specific claim. '
        'The paper also reports new DAST alert types and functional regressions, so its SAST headline is not a joint security success rate. '
        'See [the manuscript comparison](MANUSCRIPT_CORRELATION.md) for table numbers and protocol differences.','',
        'VAmPI has three CWE-1333 alerts and no applicable review-2 guidance entry. Differences among its named prompt factors are descriptive; '
        'they do not estimate the effect of guidance that was never supplied. Its authorization/disclosure assertions cover additional weaknesses outside those three alerts.','',
        'The three local 7B tool-agent runs use the same pinned flask-webgoat input, 21-turn limit, 8,192-token reply cap and final CodeQL oracle. '
        'Their file-editing strategy and tool calls differ from AVR. Source-local missing-function import failures after a working baseline count as startup regressions in the derived analysis; raw logs/manifests are unchanged. '
        'See `external-baseline-effects.json`, per-run test audits and the full configuration table.','',
        'Raw evidence is under `review_results/<run>/`; configuration and finding tables, exact McNemar tests, Holm adjustments, factorial effects, '
        'whole-repetition intervals and strict-gate audits are under `review_results/validated-analysis/`. '
        'McNemar comparisons are exploratory because findings can share functions and are not independent. '
        'The original validator study and 180-second local-timeout pilots are excluded from this primary cohort.','',
        'Agent-authored hardening remains under `oracle_validation/` and is never counted as a model result. '
        'Independent human guidance sign-off and Zenodo publication are deferred to the professor, as requested. The manuscript has not been edited.','']
    (ROOT/'review_docs/VALIDATED_RESULTS.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({'completed_cells':status['completed_cells'],'planned_cells':status['planned_cells'],'finding_rows':len(findings)}))
    return data


if __name__ == '__main__':
    generate()
