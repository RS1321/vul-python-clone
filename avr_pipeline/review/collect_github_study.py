"""Collect current study jobs using an existing GitHub sign-in, without logging it.

This is a read-only GitHub client. It downloads only bounded study artifacts,
verifies their digests and declared protocol, and retains original measurements.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.collect_ci_results import unpack
from review.evidence_io import durable_dump as dump
from review.study_progress import build_status

REPOSITORY = 'RS1321/vul-python-clone'
API = 'https://api.github.com/repos/'+REPOSITORY


def authenticated_session(use_git_credential):
    token = os.getenv('GH_TOKEN') or os.getenv('GITHUB_TOKEN')
    if not token and use_git_credential:
        env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GCM_INTERACTIVE='Never')
        result = subprocess.run(['git','credential','fill'], input='protocol=https\nhost=github.com\n\n',
             capture_output=True, text=True, env=env, timeout=30)
        if result.returncode:
            raise RuntimeError('Existing GitHub sign-in unavailable; credential contents are never logged')
        fields = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        token = fields.get('password')
    if not token:
        raise RuntimeError('Use the existing GitHub sign-in or an explicitly configured GitHub token')
    http = requests.Session()
    http.headers.update({'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json'})
    http.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=2,
                           status_forcelist=[429,500,502,503,504])))
    return http


def api_json(http, suffix):
    response = http.get(API+suffix, timeout=(30,90))
    response.raise_for_status()
    return response.json()


def download(http, artifact, cache):
    if artifact['size_in_bytes'] > 2*1024*1024:
        raise ValueError('Noncompact artifact excluded from this collector')
    path = cache/(str(artifact['id'])+'.zip')
    if path.exists():
        return path
    pending = path.with_suffix('.partial')
    size = 0
    # requests strips Authorization when following the signed storage redirect.
    with http.get(API+f'/actions/artifacts/{artifact["id"]}/zip', stream=True, timeout=(30,120)) as response:
        response.raise_for_status()
        with pending.open('wb') as handle:
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > 2*1024*1024:
                    raise ValueError('Downloaded artifact exceeds the compact budget')
                handle.write(chunk)
    pending.replace(path)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=int, nargs='+', required=True)
    parser.add_argument('--use-git-credential', action='store_true')
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--interval', type=int, default=45)
    args = parser.parse_args()
    if args.interval < 15:
        parser.error('Poll no more frequently than every 15 seconds')
    http = authenticated_session(args.use_git_credential)
    results = ROOT/'review_results'
    cache = ROOT/'.review-work/downloaded-study-artifacts'
    cache.mkdir(parents=True,exist_ok=True)
    index_path = results/'ci-imports.json'
    index = json.loads(index_path.read_text(encoding='utf-8')) if index_path.exists() else []
    seen = {r['artifact_id'] for r in index}
    protocol = json.loads((ROOT/'review/study-protocol.validated.json').read_text(encoding='utf-8'))
    cohort = json.loads((ROOT/'review/validated-cohort.json').read_text(encoding='utf-8'))
    failures, previous_summary = {}, None
    while True:
        workflows, new_records = [], []
        for run in args.run:
            data = api_json(http, f'/actions/runs/{run}')
            workflows.append({k:data[k] for k in ('id','name','status','conclusion','head_sha','html_url')})
            page = 1
            while True:
                listing = api_json(http, f'/actions/runs/{run}/artifacts?per_page=100&page={page}')
                artifacts = listing.get('artifacts',[])
                for artifact in artifacts:
                    if artifact['id'] in seen or artifact.get('expired') or not artifact['name'].startswith('review2-'):
                        continue
                    try:
                        archive = download(http, artifact, cache)
                        record = unpack(archive, artifact, results, protocol)
                    except Exception as error:
                        # Never save a token, request headers or signed redirect URL.
                        failures[str(artifact['id'])] = {'error_type':type(error).__name__,
                                                       'http_status':getattr(getattr(error,'response',None),'status_code',None)}
                        continue
                    seen.add(artifact['id'])
                    failures.pop(str(artifact['id']),None)
                    index.append(record)
                    new_records.append(record)
                    dump(index_path,index)
                if len(artifacts) < 100:
                    break
                page += 1
        report = build_status(results,protocol,cohort)
        dump(results/'validated-study-status.json',report)
        dump(results/'github-study-collection.json',{'workflows':workflows,'imported_artifacts':len(index),
                                                   'import_errors':failures,'completed_cells':report['completed_cells']})
        summary = {'completed_cells':report['completed_cells'],'remaining_cells':report['remaining_cells'],
                   'new_artifacts':len(new_records),'new_status_counts':dict(Counter(r['status'] for r in new_records)),
                   'remote_status_counts':dict(Counter(w['status'] for w in workflows)),
                   'import_errors':len(failures)}
        if new_records or summary != previous_summary:
            print(json.dumps(summary),flush=True)
            previous_summary = summary
        if not args.watch or all(w['status']=='completed' for w in workflows):
            break
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
