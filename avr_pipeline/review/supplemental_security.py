"""Evaluate fixed A/r1 model patches with the broader existing external oracles.

This post-hoc validation is separate from the frozen matrix and its joint metric.
No model requests, source repairs or selection of successful repetitions occur.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from review.continue_study import identity
from review.evidence_io import durable_dump as dump, recorded_outages
from review.protocol_compatibility import budget_violations
from review.replay_run import replay
from review.runner import checked
from review.target_environment import describe

ORACLES=['review/lesson_security.py','review/data_exposure_security.py',
         'review/external_security.py','review/vampi_resolution_checks.py','review/security_test_client.py']
TARGETED=['xss_lab','sql_injection_lab','ssrf_lab','command_injection_lab']


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def counts(checks):
    if checks is None:return None
    return {category:dict(passed=sum(c['passed'] is True for c in checks if c['category']==category),
                         total=sum(c['category']==category for c in checks))
            for category in ('security','functionality','coverage')}


def changes(before,after):
    if before is None or after is None:return None
    left={c['name']:c for c in before};right={c['name']:c for c in after}
    if len(left)!=len(before) or len(right)!=len(after):
        raise ValueError('Ambiguous duplicate assertion identifiers')
    common=sorted(left.keys()&right.keys())
    return dict(matched_assertions=len(common),
                newly_passing=sum(not left[n]['passed'] and right[n]['passed'] for n in common),
                newly_failing=sum(left[n]['passed'] and not right[n]['passed'] for n in common),
                added_assertions=len(right.keys()-left.keys()),missing_assertions=len(left.keys()-right.keys()))


def suites(dataset,baseline):
    if dataset=='vampi':return [('extended','vampi','review/vampi_resolution_checks.py',[],'checks.json')]
    result=[('django-host','pygoat','review/external_security.py',['--kind','pygoat'],'security.json')]
    for folder in sorted((baseline/'dockerized_labs').iterdir()):
        if not folder.is_dir():continue
        if folder.name=='sensitive_data_exposure':
            result.append((folder.name,'pygoat','review/data_exposure_security.py',[],'checks.json'))
        else:
            result.append((folder.name,'vampi','review/lesson_security.py',['--lesson',folder.name],'checks.json'))
    for lesson in TARGETED:
        result.append(('targeted-'+lesson,'vampi','review/external_security.py',['--kind',lesson],'security.json'))
    return result


def measure(source,out,suite,runtimes,configuration):
    name,runtime,script,extra,result_file=suite
    marker=out/'execution.json'
    if marker.exists():
        saved=json.loads(marker.read_text(encoding='utf-8'))
        if saved['configuration']!=configuration:raise ValueError('Existing supplemental evidence has different inputs')
        return saved
    if out.exists():raise ValueError('Retain incomplete execution and use an explicitly new output revision: '+str(out))
    out.parent.mkdir(parents=True,exist_ok=True)
    env={k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential',k,re.I)}
    command=[runtimes[runtime],str(ROOT/script),'--repo',str(source),'--out',str(out),*extra]
    record=dict(configuration=configuration,checks=None,execution_status='incomplete')
    try:
        proc=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,
                            encoding='utf-8',errors='replace',timeout=240)
        out.mkdir(parents=True,exist_ok=True)
        (out/'runner.log').write_text(proc.stdout+proc.stderr,encoding='utf-8')
        record.update(returncode=proc.returncode,execution_status='completed')
        if (out/result_file).exists():
            data=json.loads((out/result_file).read_text(encoding='utf-8'))
            if data.get('checks'):record['checks']=data['checks']
        if record['checks'] is None:record['execution_status']='no_assertion_results'
    except subprocess.TimeoutExpired as exc:
        record['execution_status']='timeout'
        out.mkdir(parents=True,exist_ok=True)
        decode=lambda value:value.decode('utf-8',errors='replace') if isinstance(value,bytes) else value or ''
        (out/'runner.log').write_text(decode(exc.stdout)+decode(exc.stderr),encoding='utf-8')
    except OSError as exc:
        record.update(execution_status='execution_error',error_type=type(exc).__name__)
    out.mkdir(parents=True,exist_ok=True);dump(marker,record)
    return record


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,default=ROOT/'review_results/supplemental-model-security-v2')
    p.add_argument('--execute',action='store_true')
    p.add_argument('--jobs',type=int,choices=(1,2),default=2)
    args=p.parse_args();out=args.out.resolve()
    results=ROOT/'review_results'
    protocol=json.loads((ROOT/'review/study-protocol.validated.json').read_text(encoding='utf-8'))
    cohort=json.loads((ROOT/'review/validated-cohort.json').read_text(encoding='utf-8'))
    datasets=['pygoat','vampi']
    sources={d:dict(source_commit=json.loads((results/f'baseline-{d}/dataset-manifest.json').read_text(encoding='utf-8'))['source_commit'],
                    sarif_sha256=sha(results/f'baseline-{d}/scan.sarif')) for d in datasets}
    tool_root=Path(os.getenv('AVR_TOOL_ROOT',str(ROOT)))
    runtimes={kind:os.getenv('AVR_'+kind.upper()+'_PYTHON',str(tool_root/'.review-work'/f'{kind}-env'/
                     ('Scripts/python.exe' if os.name=='nt' else 'bin/python'))) for kind in datasets}
    environments={kind:describe(executable) for kind,executable in runtimes.items()}
    plan=dict(selection='All five frozen-cohort models, A, repetition 1, on PyGoat and VAmPI; no outcome-based substitution.',
              role='Post-hoc supplemental validation; not pooled into the frozen matrix joint metric.',
              model_requests=0,condition='A',repetition=1,cohort=cohort,sources=sources,
              oracle_sha256={name:sha(ROOT/name) for name in ORACLES},
              runner_sha256=sha(Path(__file__)),environments=environments,
              suites={d:[s[0] for s in suites(d,ROOT/'benchmarks'/d)] for d in datasets})
    out.mkdir(parents=True,exist_ok=True)
    if (out/'plan.json').exists():
        if json.loads((out/'plan.json').read_text(encoding='utf-8'))!=plan:
            raise ValueError('Supplemental declaration changed; retain previous evidence and use a new output revision')
    else:dump(out/'plan.json',plan)
    if not args.execute:
        print(json.dumps(dict(status='planned',models=len(cohort),datasets=datasets,suites=plan['suites'])));return
    base={}
    for dataset in datasets:
        repo=ROOT/'benchmarks'/dataset
        if checked(['git','rev-parse','HEAD'],repo)!=sources[dataset]['source_commit'] or checked(['git','status','--porcelain','--untracked-files=no'],repo):
            raise ValueError('Supplemental baseline must remain pristine and pinned')
        jobs=suites(dataset,repo)
        def baseline_case(suite):
            config=dict(source_commit=sources[dataset]['source_commit'],suite=suite[0],state='baseline',
                        script_sha256=plan['oracle_sha256'][suite[2]],runtime=environments[suite[1]])
            return suite[0],measure(repo,out/'baseline'/dataset/suite[0],suite,runtimes,config)
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            base[dataset]=dict(pool.map(baseline_case,jobs))
    index={}
    for path in results.glob('*/manifest.json'):
        m=json.loads(path.read_text(encoding='utf-8'));key=identity(m,protocol,sources)
        if key and m.get('status')=='complete' and m.get('sast') and not recorded_outages(path.parent) and not budget_violations(path.parent):
            index.setdefault(key,[]).append((path.parent,m))
    summary=[];pending=[];source_audits=[]
    for model_index,model in enumerate(cohort,1):
        for dataset in datasets:
            options=index.get((model['provider'],model['model'],dataset,'A',1),[])
            if not options:
                pending.append(dict(model=model['model'],dataset=dataset));continue
            if len(options)!=1:raise ValueError('Ambiguous primary A/r1 source; no outcome-based selection')
            # Keep Git pack paths below Windows' limit. The frozen cohort order
            # and the full run identity are recorded rather than encoded here.
            run,m=options[0];case_id=dataset+'-m'+str(model_index);target=out/'models'/case_id
            replay_dir=target/'replay'
            if not (replay_dir/'replay.json').exists():
                replay(run,ROOT/'benchmarks'/dataset,replay_dir)
            audit=json.loads((replay_dir/'replay.json').read_text(encoding='utf-8'))
            if audit['saved_manifest_sha256']!=sha(run/'manifest.json'):
                raise ValueError('Replayed model manifest changed')
            patch=(replay_dir/'model.patch').read_text(encoding='utf-8').rstrip('\r\n')
            if checked(['git','diff','--no-ext-diff'],replay_dir/'source')!=patch:
                raise ValueError('Supplemental replay source changed after reconstruction')
            if (run/'model.patch').exists():
                if (run/'model.patch').read_text(encoding='utf-8').rstrip('\r\n')!=patch:
                    raise ValueError('Replayed source differs from saved CI model patch')
            elif (run/'source/.git').exists():
                if checked(['git','diff','--no-ext-diff'],run/'source')!=patch:
                    raise ValueError('Supplemental source differs from the completed native model source')
            else:raise ValueError('Saved final model patch or native source is required')
            source_audits.append(dict(model=model['model'],dataset=dataset,run=run.name,case_id=case_id,
                model_manifest_sha256=audit['saved_manifest_sha256'],replayed_patch_sha256=audit['model_patch_sha256'],
                accepted_responses_replayed=len(audit['verified_accepted_findings'])))
            def model_case(suite):
                config=dict(source_commit=m['source_commit'],suite=suite[0],state=run.name,
                            manifest_sha256=audit['saved_manifest_sha256'],script_sha256=plan['oracle_sha256'][suite[2]],
                            runtime=environments[suite[1]])
                observed=measure(replay_dir/'source',target/suite[0],suite,runtimes,config)
                baseline=base[dataset][suite[0]]
                return dict(model=model['model'],dataset=dataset,run=run.name,suite=suite[0],
                    baseline_status=baseline['execution_status'],model_status=observed['execution_status'],
                    baseline_counts=counts(baseline['checks']),model_counts=counts(observed['checks']),
                    matched_changes=changes(baseline['checks'],observed['checks']),
                    all_observed_model_assertions_pass=all(c['passed'] for c in observed['checks']) if observed['checks'] is not None else None)
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:summary.extend(pool.map(model_case,suites(dataset,ROOT/'benchmarks'/dataset)))
            print(json.dumps(dict(model=model['model'],dataset=dataset,status='evaluated')),flush=True)
    report=dict(generated_utc=datetime.now(timezone.utc).isoformat(),
        status='pending_primary_runs' if pending else 'all_selected_sources_evaluated',
        role=plan['role'],selection=plan['selection'],condition='A',repetition=1,model_requests=0,
        plan_sha256=sha(out/'plan.json'),oracle_sha256=plan['oracle_sha256'],runner_sha256=plan['runner_sha256'],
        runtime_distribution_sha256={kind:env['distribution_sha256'] for kind,env in environments.items()},
        pending=pending,source_verification=source_audits,results=summary,
        scope='Isolated fixtures for all 21 PyGoat lesson directories, four targeted lesson suites, 14 host assertions and extended VAmPI checks. Shared headers are repeated checks, not independent vulnerabilities. No Docker deployment or full endpoint coverage claim. Baseline execution failures remain unmeasured, not model security improvements.')
    dump(out/'summary.json',report)
    print(json.dumps(dict(status=report['status'],evaluated_sources=len(source_audits),pending=len(pending),suite_rows=len(summary))))


if __name__=='__main__':main()
