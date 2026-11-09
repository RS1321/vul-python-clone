"""Export measured finding outcomes without guessing identities or missing evidence."""
import csv
from collections import Counter
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from review.validation_health import outages_in_results


def group_key(finding):
    s = finding['sast']
    return (s['rule_id'], s['location']['file_path'], s['location']['function'] or '<module>')


def test_changes(before, after, policy=None):
    if not before or not after or before.get('status') == 'not_configured' or after.get('status') == 'not_configured':
        return {'status': 'unmeasured', 'new_failures': None, 'regressions': None}
    if before.get('infrastructure_error') or after.get('infrastructure_error') or before.get('failures') is None or after.get('failures') is None:
        return {'status': 'infrastructure_error', 'new_failures': None, 'regressions': None}
    rules = (policy or {}).get('vulnerable_behavior_tests', {})
    added = sorted(set(after['failures']) - set(before['failures']))
    labels = [{'test': t, 'classification': 'old_vulnerable_behavior' if t in rules else 'regression',
               'reason': rules.get(t, 'Unlisted failure: conservatively treated as regression')} for t in added]
    return {'status': 'measured', 'new_failures': labels,
            'regressions': sum(t['classification'] == 'regression' for t in labels),
            'old_behavior_failures': sum(t['classification'] == 'old_vulnerable_behavior' for t in labels)}


def make_rows(findings, results, manifest, baseline_tests, policy=None):
    totals = Counter(group_key(f) for f in findings)
    removed = {tuple(g['key']): g['count'] for g in manifest.get('sast', {}).get('resolved_groups', [])}
    by_id = {r['finding_id']: r for r in results}
    changes = test_changes(baseline_tests, manifest.get('post_tests'), policy)
    measured = manifest.get('status') == 'complete' and 'sast' in manifest and not outages_in_results(results)
    behavior = manifest.get('behavioral_tests', {})
    # A suite result is batch-level evidence, never attribution to one patch.
    behavior_pass = None
    if behavior and not behavior.get('infrastructure_error') and behavior.get('tests',0) > 0:
        behavior_pass = behavior.get('status') == 'passed'
    rows = []
    for f in findings:
        key = group_key(f)
        count = removed.get(key, 0)
        resolved = (True if count == totals[key] else False if count == 0 else None) if measured else None
        r = by_id.get(f['finding_id'], {})
        joint = None
        if resolved is False or (measured and manifest['sast'].get('new_findings', 0) > 0) or changes['regressions'] not in (None, 0) or behavior_pass is False:
            joint = False
        elif resolved is True and changes['regressions'] == 0 and behavior_pass is True:
            joint = True
        rows.append({'finding': f['finding_id'], 'cwe': f['sast'].get('cwe'), 'all_cwes': f['sast'].get('all_cwes', []),
                     'rule': key[0], 'file': key[1], 'function': key[2], 'accepted': r.get('accepted'),
                     'resolved': resolved, 'resolution_identity': 'unmeasured' if not measured else
                         'ambiguous_partial_duplicate_group' if resolved is None else 'group_all_or_none',
                     'attempts': None if manifest.get('condition') == 'tool_agent' else len(r.get('attempts', [])),
                     'agent_turns':r.get('agent_turns'), 'test_change': changes,
                     'behavioral_assertions_pass': behavior_pass, 'joint_security': joint,
                     'test_attribution': 'batch outcome; not a causal per-patch test attribution'})
    return rows


def write_rows(out, rows):
    out = Path(out)
    (out/'finding-outcomes.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    fields = ['finding','cwe','rule','file','function','accepted','resolved','resolution_identity','attempts',
              'agent_turns','test_measurement_status','new_test_failures','regressions','old_behavior_failures','joint_security']
    flat = [dict(r, test_measurement_status=r['test_change']['status'],
                 new_test_failures=json.dumps(r['test_change']['new_failures']),
                 regressions=r['test_change']['regressions'],
                 old_behavior_failures=r['test_change'].get('old_behavior_failures')) for r in rows]
    with (out/'finding-outcomes.csv').open('w',encoding='utf-8',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore')
        writer.writeheader(); writer.writerows(flat)


def export_run(out, policy=None):
    out = Path(out)
    read = lambda name, default: json.loads((out / name).read_text(encoding='utf-8')) if (out / name).exists() else default
    m = read('manifest.json', {})
    def measured_tests(record, folder):
        record = dict(record or {})
        junit = out/folder/'pytest.xml'
        if junit.exists():
            errors = sum(c.find('error') is not None for c in ET.parse(junit).iter('testcase'))
            if errors:
                record.update(errors=errors,infrastructure_error=True)
        return record
    # Correct the early harness summaries from their retained JUnit evidence;
    # immutable manifests are preserved and only derived outcome tables change.
    m['post_tests'] = measured_tests(m.get('post_tests'), 'post-tests')
    m['behavioral_tests'] = measured_tests(m.get('behavioral_tests'), 'behavioral-tests')
    rows = make_rows(read('contexts.json', []), read('results.json', []), m,
                     measured_tests(read('baseline-tests.json', {}),'baseline-tests'), policy)
    write_rows(out,rows)
    by_cwe = {}
    for cwe in sorted({r['cwe'] or 'unknown' for r in rows}):
        selected = [r for r in rows if (r['cwe'] or 'unknown') == cwe]
        by_cwe[cwe] = {k: sum(r[k] is True for r in selected) for k in ('accepted', 'resolved', 'joint_security')}
        by_cwe[cwe].update(findings=len(selected), ambiguous_or_unmeasured=sum(r['resolved'] is None for r in selected))
    (out / 'outcomes-by-cwe.json').write_text(json.dumps(by_cwe, indent=2), encoding='utf-8')
    return rows


def configuration(m):
    return {k: m.get(k) for k in ('source_commit', 'provider', 'model', 'condition', 'repetition',
            'settings', 'minimality_policy', 'pytest_args', 'test_policy_sha256', 'library_version',
            'library_sha256', 'max_tokens', 'context_profile', 'implementation_sha256', 'sarif_sha256',
            'behavioral_test_sha256', 'validation_environment', 'lint_environment_sha256', 'status')}
