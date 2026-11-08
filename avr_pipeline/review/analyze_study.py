"""Export findings/configuration and matched statistics from actual run artifacts."""
import argparse
import csv
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.outcomes import export_run, configuration, write_rows
from review.study_statistics import paired, repeated_cluster_ci, holm, wilson

COMPARISONS = [('A', 'B'), ('A', 'no_guidance'), ('A', 'no_examples'), ('A', 'C'), ('A', 'simple'), ('A_strict', 'A')]


def identity(m):
    keys = ('source_commit', 'provider', 'model', 'sarif_sha256', 'library_sha256', 'max_tokens',
            'temperature', 'thinking_level', 'context_profile', 'zap_sha256', 'pytest_args',
            'test_policy_sha256', 'behavioral_test_sha256', 'implementation_sha256', 'minimality_policy',
            'lint_environment_sha256', 'validation_environment')
    return json.dumps({k: m.get(k) for k in keys}, sort_keys=True)


def analyze(root):
    groups = defaultdict(lambda: defaultdict(list))
    configurations, inventory, baseline_cells, strict_audits = [], [], defaultdict(lambda: defaultdict(list)), []
    protocol = json.loads((ROOT/'review/study-protocol.json').read_text())
    ids = {int(e['cwe'].split('-')[1]) for e in json.loads((ROOT/'llm/guidance_library.review-2.json').read_text())['entries']}
    condition_rates = defaultdict(list)
    policy_path = ROOT / 'review/test-policy.json'
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes)
    for path in sorted(root.glob('*/manifest.json')):
        m = json.loads(path.read_text(encoding='utf-8'))
        if not (path.parent / 'contexts.json').exists():
            continue
        rows = export_run(path.parent, policy)
        if m.get('condition') == 'tool_agent':
            result_path = path.parent/'results.json'
            records = json.loads(result_path.read_text()) if result_path.exists() else []
            turns = {r['finding_id']:r.get('agent_turns') for r in records}
            for r in rows:
                r['attempts'] = None
                r['agent_turns'] = turns.get(r['finding'])
            write_rows(path.parent,rows)
        configurations.append(dict(run=path.parent.name, **configuration(m),
             transport_policy=m.get('transport_policy'),
             agent_turn_cap=m.get('settings', {}).get('max_turns')))
        eligible = m.get('eligible_findings')
        complete = m.get('status') == 'complete' and 'sast' in m and m.get('selected_findings') == eligible
        inventory.append({'run': path.parent.name, 'status': m.get('status'), 'full_run': complete,
                          'findings': len(rows), 'resolved': m.get('sast', {}).get('resolved_findings'),
                          'resolution_ci95': wilson(m['sast']['resolved_findings'], eligible) if complete else None,
                          'behavioral_evidence': m.get('behavioral_tests', {}).get('status', 'unmeasured'),
                          'joint_true': sum(r['joint_security'] is True for r in rows),
                          'joint_unknown': sum(r['joint_security'] is None for r in rows)})
        if complete:
            groups[(identity(m), m.get('repetition', 1))][m['condition']].append((path.parent.name, m, rows))
            is_primary = m.get('implementation_sha256') == protocol.get('primary_implementation_sha256')
            if is_primary and m['condition'] == 'A_strict':
                raw = json.loads((path.parent/'results.json').read_text())
                blocked = [{'finding':r['finding_id'],'attempt':a['attempt'],'new_failures':a['validation']['new_test_failures']}
                           for r in raw for a in r.get('attempts',[]) if not a.get('accepted') and a.get('validation',{}).get('new_test_failures')]
                strict_audits.append({'run':path.parent.name,'model':m['model'],'source_commit':m['source_commit'],
                    'repetition':m['repetition'],'resolved':m['sast']['resolved_findings'],'new_alerts':m['sast']['new_findings'],
                    'blocked_candidates':blocked,'blocked_candidate_count':len(blocked),
                    'distinct_findings_with_blocked_candidates':len({b['finding'] for b in blocked}),
                    'final_test_change':rows[0]['test_change'] if rows else None,
                    'interpretation':'Candidate-level observed rejection evidence; not a count of causal failures prevented in an otherwise identical full model run. A_strict blocks all new failures, including tests requiring old vulnerable behavior.'})
            if m.get('condition') == 'tool_agent' or (m.get('condition') == 'A' and is_primary):
                keys = ('source_commit','provider','model','sarif_sha256','max_tokens','temperature',
                        'repetition','pytest_args','test_policy_sha256','behavioral_test_sha256')
                key = json.dumps({k:m.get(k) for k in keys}, sort_keys=True)
                baseline_cells[key][m['condition']].append((path.parent.name,m,rows))
    effects, clustered = [], defaultdict(list)
    factorial, legacy_effects = [], []
    for (ident, repetition), cells in groups.items():
        valid = {k: v[0] for k, v in cells.items() if len(v) == 1}
        metadata = json.loads(ident)
        sample_rows = next(iter(valid.values()))[2] if valid else []
        covered = (sum(int(r['cwe'].split('-')[1]) in ids for r in sample_rows)
                   if metadata.get('library_sha256') == protocol['library_sha256'] else None)
        fac = dict(model=metadata['model'], source_commit=metadata['source_commit'], repetition=repetition,
                   identity_sha256=hashlib.sha256(ident.encode()).hexdigest(),
                   missing=[c for c in ('A', 'B', 'no_guidance', 'no_examples') if c not in valid],
                   ambiguous=[c for c in cells if len(cells[c]) > 1], guidance_main_effect_pp=None,
                   examples_main_effect_pp=None, interaction_pp=None)
        fac['guidance_covered_findings'] = covered
        fac['interpretation'] = ('No library entry applies; named prompt-factor differences are not guidance/example treatment effects.'
                                  if covered == 0 else 'Interpret within the reported library coverage and fixed subject.')
        if not fac['missing'] and covered != 0:
            rate = lambda c: valid[c][1]['sast']['resolution_rate']
            fac.update(guidance_main_effect_pp=50*((rate('A')-rate('no_guidance'))+(rate('no_examples')-rate('B'))),
                       examples_main_effect_pp=50*((rate('A')-rate('no_examples'))+(rate('no_guidance')-rate('B'))),
                       interaction_pp=100*(rate('A')-rate('no_guidance')-rate('no_examples')+rate('B')))
        factorial.append(fac)
        rate = lambda c: valid[c][1]['sast']['resolution_rate']
        difference = lambda a,b: 100*(rate(a)-rate(b)) if a in valid and b in valid else None
        legacy_effects.append(dict(model=metadata['model'], source_commit=metadata['source_commit'], repetition=repetition,
            completed_conditions=list(valid), missing_factorial_conditions=fac['missing'], ambiguous_duplicate_conditions=fac['ambiguous'],
            guidance_plus_examples_pp=difference('A','B'), guidance_given_examples_pp=difference('A','no_guidance'),
            examples_given_guidance_pp=difference('A','no_examples'), isolated_guidance_effect_pp=fac['guidance_main_effect_pp'],
            isolated_example_effect_pp=fac['examples_main_effect_pp'], interaction_pp=fac['interaction_pp'], A_minus_C_security_pp=difference('A','C')))
        for a, b in COMPARISONS:
            for metric in ('resolved', 'joint_security'):
                row = dict(model=metadata['model'], source_commit=metadata['source_commit'], repetition=repetition,
                           comparison=f'{a}-{b}', metric=metric, identity_sha256=fac['identity_sha256'],
                           status='missing_or_duplicate_condition', n=0, mcnemar_exact_p=None, risk_difference=None)
                row['guidance_covered_findings'] = covered
                if covered == 0 and (a,b) in COMPARISONS[:3]:
                    row['interpretation'] = fac['interpretation']
                if a in valid and b in valid:
                    row.update(paired({r['finding']: r[metric] for r in valid[a][2]},
                                      {r['finding']: r[metric] for r in valid[b][2]}))
                    row.update(status='measured' if row['n'] else 'unmeasured_or_ambiguous',
                               a_run=valid[a][0], b_run=valid[b][0])
                    if row['n']:
                        clustered[(ident, a, b, metric)].append((repetition, row['risk_difference']))
                effects.append(row)
        for c, (_, m, _) in valid.items():
            condition_rates[(ident,c)].append((repetition,m['sast']['resolution_rate']))
    adjusted = holm([r['mcnemar_exact_p'] for r in effects])
    for r, p in zip(effects, adjusted):
        r['holm_p_all_reported_comparisons'] = p
    repeat_effects = []
    for (ident, a, b, metric), values in clustered.items():
        repeat_effects.append(dict(identity=json.loads(ident), comparison=f'{a}-{b}', metric=metric,
                                  repetitions=[r for r, v in values], mean_risk_difference=sum(v for r, v in values)/len(values),
                                  repetition_cluster_bootstrap_ci95=repeated_cluster_ci([v for r, v in values]),
                                  note='Requires >=3 matched repetitions; inference limited to this fixed finding set.'))
    baseline_effects = []
    for key,cells in baseline_cells.items():
        for metric in ('resolved','joint_security'):
            row = dict(identity=json.loads(key), metric=metric, comparison='tool_agent-A',
                       status='missing_or_duplicate_method', n=0)
            if len(cells.get('A',[])) == len(cells.get('tool_agent',[])) == 1:
                a,b = cells['tool_agent'][0],cells['A'][0]
                row.update(paired({r['finding']:r[metric] for r in a[2]}, {r['finding']:r[metric] for r in b[2]}))
                row.update(status='measured' if row['n'] else 'unmeasured', tool_agent_run=a[0], avr_run=b[0],
                           interpretation='End-to-end method comparison with the same pinned input, reply cap, tests and final oracle; strategies and local gates differ.')
            baseline_effects.append(row)
    baseline_p = holm([r.get('mcnemar_exact_p') for r in baseline_effects])
    for row,p in zip(baseline_effects,baseline_p):
        row['holm_p_baseline_family'] = p
    rate_rows = [dict(identity=json.loads(ident), condition=c, repetitions=[r for r,v in values],
                     mean_resolution_rate=sum(v for r,v in values)/len(values),
                     repetition_cluster_ci95=repeated_cluster_ci([v for r,v in values]))
                 for (ident,c),values in condition_rates.items()]
    outputs = {'paired-effects.json': legacy_effects, 'matched-statistics.json': effects, 'factorial-effects.json': factorial,
               'external-baseline-effects.json':baseline_effects, 'rates-by-condition.json':rate_rows,'strict-gate-audit.json':strict_audits,
               'repeat-effects.json': repeat_effects, 'configuration-as-run.json': configurations,
               'outcome-inventory.json': inventory}
    for name, data in outputs.items():
        (root / name).write_text(json.dumps(data, indent=2), encoding='utf-8')
    fields = ['run','model','provider','source_commit','condition','repetition','gates','test_policy','pytest_args',
              'minimality_policy','library_version','library_sha256','max_tokens','context_profile','test_policy_sha256',
              'lint_environment_sha256','implementation_sha256','transport_policy','agent_turn_cap','status']
    flat = [dict(r,gates=(r.get('settings') or {}).get('gates'),test_policy=(r.get('settings') or {}).get('tests')) for r in configurations]
    with (root/'configuration-as-run.csv').open('w',encoding='utf-8',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore')
        writer.writeheader()
        writer.writerows({k:json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v for k,v in r.items()} for r in flat)
    (root / 'analysis-provenance.json').write_text(json.dumps({'policy_sha256': hashlib.sha256(policy_bytes).hexdigest(),
        'implementation_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'review/outcomes.py',ROOT/'review/study_statistics.py']},
        'policy_application': 'Historical exports are retrospective; runner records frozen policy prospectively for new runs.',
        'junit_normalization':'Retained JUnit setup/collection errors override early summaries in derived tables only; original manifests are unchanged.',
        'unknowns': 'No imputation of missing conditions, behavior tests, interrupted runs, or partial duplicate-group identities.',
        'statistics': 'Wilson descriptive per-run intervals; exact conditional McNemar; matched risk difference and odds ratio; Holm across reported tests; repetition-cluster bootstrap only with >=3 repetitions. Finding-level McNemar assumes independent discordances; shared functions can violate this, so these are exploratory fixed-subject comparisons.'}, indent=2))
    return {'runs': len(inventory), 'full_runs': sum(r['full_run'] for r in inventory),
            'matched_tests': sum(r['status'] == 'measured' for r in effects)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results', type=Path, default=ROOT / 'review_results')
    args = p.parse_args()
    print(json.dumps(analyze(args.results), indent=2))


if __name__ == '__main__':
    main()
