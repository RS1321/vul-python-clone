"""Export allowlisted result tables, excluding raw messages and machine paths."""
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
LOCAL_PATH = re.compile(r'(?<![A-Za-z0-9])[A-Za-z]:[/\\]|(?:^|[\s\"\'(])/(?:home|Users|tmp|workspace)/')
SECRET = re.compile(r'AIza[0-9A-Za-z_-]{35}|gh[pousr]_[0-9A-Za-z]{20,}|(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{24,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
FORBIDDEN = {'prompt','response','messages','system_prompt','transport_execution_history','validation_environment','worker_pid'}


def portable(value):
    if isinstance(value,dict):
        return {key:portable(item) for key,item in value.items()}
    if isinstance(value,list):
        return [portable(item) for item in value]
    if isinstance(value,str) and LOCAL_PATH.search(value):
        return '[local path omitted from public summary]'
    return value


def assert_safe(value):
    if isinstance(value,dict):
        if FORBIDDEN.intersection(value):
            raise ValueError('Raw message or machine-metadata field excluded from public export')
        for item in value.values():assert_safe(item)
    elif isinstance(value,list):
        for item in value:assert_safe(item)
    elif isinstance(value,str) and (LOCAL_PATH.search(value) or SECRET.search(value)):
        raise ValueError('Local path or credential pattern excluded from public export')


def select(row, fields):
    return portable({field:row.get(field) for field in fields})


def public_config(row):
    fields = ['run','model','provider','source_commit','condition','repetition','minimality_policy','library_version',
              'library_sha256','max_tokens','context_profile','test_policy_sha256','behavioral_test_sha256',
              'lint_environment_sha256','implementation_sha256','sarif_sha256','status','agent_turn_cap',
              'local_request_timeout_seconds','local_timeout_origin','ci_configuration','transport_policy','temperature','guidance_used']
    result = select(row,fields)
    settings = row.get('settings') or {}
    result['settings'] = select(settings,['guidance','examples','gates','attempts','tests','simple','max_turns'])
    args=[]
    for value in row.get('pytest_args') or []:
        if isinstance(value,str) and LOCAL_PATH.search(value):
            path=re.sub('/+','/',value.replace('\\','/'))
            marker='/review/behavioral/'
            value='review/behavioral/'+path.split(marker,1)[1] if marker in path else '[local test path omitted]'
        args.append(value)
    result['pytest_args']=args
    result['test_command'] = 'owner-fixed pytest arguments; machine prefixes normalized to repository paths'
    return result


def main():
    source = ROOT/'review_results/validated-analysis'
    out = ROOT/'public_results/review2'
    out.mkdir(parents=True,exist_ok=True)
    records = []
    def write(name, value):
        value = portable(value);assert_safe(value)
        path=out/name;path.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf-8')
        records.append(path)
    def read(name):return json.loads((source/name).read_text(encoding='utf-8'))
    write('study-status.json',read('study-status-snapshot.json'))
    summary=read('summary-by-condition.json');write('summary-by-condition.json',summary)
    cwe_rows=read('outcomes-by-cwe.json');write('outcomes-by-cwe.json',cwe_rows)
    configs=[public_config(row) for row in read('configuration-as-run.json')]
    write('configuration-as-run.json',configs)
    write('factorial-effects.json',read('factorial-effects.json'))
    write('strict-gate-audit.json',read('strict-gate-audit.json'))
    for name in ['matched-statistics.json','repeat-effects.json','external-baseline-effects.json','rates-by-condition.json']:
        rows=[]
        for raw in read(name):
            row={key:value for key,value in raw.items() if key!='identity'}
            if 'identity' in raw:
                row.update(select(raw['identity'],['model','provider','source_commit']))
                row['configuration_identity_sha256']=hashlib.sha256(json.dumps(raw['identity'],sort_keys=True).encode()).hexdigest()
            rows.append(row)
        write(name,rows)
    fields = ['run','model','dataset','condition','repetition','finding','cwe','rule','file','function',
              'accepted','resolved','resolution_identity','attempts','test_change','behavioral_assertions_pass','joint_security']
    path=out/'per-finding-outcomes.csv'
    with (source/'per-finding-outcomes.csv').open(encoding='utf-8',newline='') as incoming,path.open('w',encoding='utf-8',newline='') as target:
        writer=csv.DictWriter(target,fieldnames=fields);writer.writeheader()
        for raw in csv.DictReader(incoming):
            row=select(raw,fields);assert_safe(row);writer.writerow(row)
    records.append(path)
    path=out/'outcomes-by-cwe.csv'
    with path.open('w',encoding='utf-8',newline='') as target:
        writer=csv.DictWriter(target,fieldnames=list(cwe_rows[0]));writer.writeheader();writer.writerows(cwe_rows)
    records.append(path)
    path=out/'summary-by-condition.csv'
    with path.open('w',encoding='utf-8',newline='') as target:
        writer=csv.DictWriter(target,fieldnames=list(summary[0]));writer.writeheader();writer.writerows(summary)
    records.append(path)
    dast=[]
    for path in (ROOT/'review_results').glob('model-dast-*-validated-*/paired-status.json'):
        raw=json.loads(path.read_text(encoding='utf-8'));row=select(raw,['dataset','model_run','source_commit','status','new_alert_types','scope'])
        for phase in ['baseline','model']:
            row[phase]=select(raw[phase],['status','alert_types','alert_instances','alerts_by_plugin','anonymous_status','authenticated_status','policy'])
            row[phase]['authenticated_rule_requests']=raw[phase].get('traffic',{}).get('active_authenticated_rules',{})
        dast.append(row)
    write('paired-dast.json',dast)
    figures=ROOT/'review_docs/figures/validated'
    for source_file in figures.glob('*'):
        if source_file.suffix not in ('.png','.svg','.json'):continue
        if source_file.suffix!='.png':assert_safe(source_file.read_text(encoding='utf-8'))
        destination=out/'figures'/source_file.name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source_file,destination);records.append(destination)
    report=(ROOT/'review_docs/VALIDATED_RESULTS.md').read_text(encoding='utf-8')
    report=report.replace('Raw evidence is under `review_results/<run>/`;','Raw evidence is retained locally under `review_results/<run>/`, as the user chose summary-and-figure publication only. Public allowlisted exports are under `public_results/review2/`. The')
    report=report.replace('(MANUSCRIPT_CORRELATION.md)','(../../review_docs/MANUSCRIPT_CORRELATION.md)')
    assert_safe(report)
    destination=out/'RESULTS.md';destination.write_text(report,encoding='utf-8');records.append(destination)
    manifest=dict(scope='Allowlisted aggregates, relative finding identifiers and figures. Raw prompts, responses, patches, test logs, worker metadata and machine paths are excluded. Originals remain local.',
                  exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  files=[dict(path=str(path.relative_to(out)).replace('\\','/'),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in records])
    (out/'export-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Exported',len(records),'allowlisted summary files; raw evidence excluded')


if __name__=='__main__':main()
