"""Derive test outcomes from retained evidence without rewriting raw manifests.

A working baseline followed by a source-local missing-symbol import error is
an application startup regression. Other setup errors remain unmeasured until
their cause can be established; missing dependencies are never assumed repaired.
"""
from collections import Counter
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from review.outcomes import make_rows, write_rows


def junit_errors(path):
    if not path.exists():
        return []
    return [case.find('error') for case in ET.parse(path).iter('testcase')
            if case.find('error') is not None]


def audit_tests(run, record, folder, baseline_folder):
    result = dict(record or {})
    errors = junit_errors(run/folder/'pytest.xml')
    if not errors:
        return result
    baseline = run/baseline_folder/'pytest.xml'
    baseline_works = baseline.exists() and not junit_errors(baseline)
    # This narrow rule requires the traceback to identify the patched source.
    # Dependency errors, timeouts and unavailable services remain infrastructure.
    source_error = lambda error: (
        'ImportError: cannot import name ' in ''.join(error.itertext()) and
        re.search(r'[/\\]source[/\\]', ''.join(error.itertext())) is not None)
    caused_by_patch = baseline_works and all(source_error(error) for error in errors)
    result.update(errors=len(errors), infrastructure_error=not caused_by_patch,
                  setup_error_classification='application_startup_regression' if caused_by_patch else 'unresolved_setup_error',
                  classification_rule='working baseline + every setup error is a missing-symbol ImportError within the patched source tree',
                  evidence=str(Path(folder)/'pytest.xml'))
    if caused_by_patch:
        result['status'] = 'failed'
    return result


def export_run(out, policy=None):
    out = Path(out)
    read = lambda name, default: json.loads((out/name).read_text(encoding='utf-8')) if (out/name).exists() else default
    manifest = read('manifest.json', {})
    manifest['post_tests'] = audit_tests(out, manifest.get('post_tests'), 'post-tests', 'baseline-tests')
    manifest['behavioral_tests'] = audit_tests(out, manifest.get('behavioral_tests'), 'behavioral-tests', 'baseline-behavioral-tests')
    baseline = audit_tests(out, read('baseline-tests.json', {}), 'baseline-tests', 'baseline-tests')
    rows = make_rows(read('contexts.json', []), read('results.json', []), manifest, baseline, policy)
    write_rows(out, rows)
    by_cwe = {}
    for cwe in sorted({r['cwe'] or 'unknown' for r in rows}):
        selected = [r for r in rows if (r['cwe'] or 'unknown') == cwe]
        by_cwe[cwe] = {key:sum(r[key] is True for r in selected) for key in ('accepted','resolved','joint_security')}
        by_cwe[cwe].update(findings=len(selected), ambiguous_or_unmeasured=sum(r['resolved'] is None for r in selected))
    (out/'outcomes-by-cwe.json').write_text(json.dumps(by_cwe, indent=2), encoding='utf-8')
    audits = {name:record for name,record in [('post_tests',manifest['post_tests']),('behavioral_tests',manifest['behavioral_tests'])]
              if record.get('setup_error_classification')}
    if audits:
        (out/'test-measurement-audit.json').write_text(json.dumps(audits, indent=2), encoding='utf-8')
    return rows
