"""Derived assertion-category changes; never rewrite supplemental raw evidence."""
import hashlib
import json
from pathlib import Path
from review.supplemental_security import changes


def enrich(path):
    report=json.loads(path.read_text(encoding='utf-8'))
    root=path.parent
    cases={(a['model'],a['dataset']):a for a in report['source_verification']}
    for row in report['results']:
        case=cases[row['model'],row['dataset']]
        paths=[root/'baseline'/row['dataset']/row['suite']/'execution.json',
               root/'models'/case['case_id']/row['suite']/'execution.json']
        if any(not p.resolve().is_relative_to(root.resolve()) for p in paths):
            raise ValueError('Supplemental assertion evidence escapes its declared root')
        records=[json.loads(p.read_text(encoding='utf-8')) for p in paths]
        if any(r['configuration']['suite']!=row['suite'] for r in records):
            raise ValueError('Supplemental assertion suite differs')
        if records[0]['configuration']['script_sha256']!=records[1]['configuration']['script_sha256']:
            raise ValueError('Matched supplemental oracles differ')
        before,after=[r['checks'] for r in records]
        row['matched_changes_by_category']={category:changes(
            [c for c in before if c['category']==category] if before is not None else None,
            [c for c in after if c['category']==category] if after is not None else None)
            for category in ('security','functionality','coverage')}
        row['baseline_execution_sha256']=hashlib.sha256(paths[0].read_bytes()).hexdigest()
        row['model_execution_sha256']=hashlib.sha256(paths[1].read_bytes()).hexdigest()
    report['category_analysis_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return report
