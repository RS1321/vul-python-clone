"""Recover omitted CI settings from verified immutable source, not guesses."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def local_timeout(run, manifest):
    if 'local_request_timeout_seconds' in manifest:
        return manifest['local_request_timeout_seconds'],'manifest'
    if manifest.get('provider')!='local':
        return None,None
    provenance = Path(run)/'ci-provenance.json'
    if not provenance.exists():
        return None,'unrecorded; no verified CI source'
    record = json.loads(provenance.read_text(encoding='utf-8'))
    commit = record.get('github_sha','')
    if not re.fullmatch('[0-9a-f]{40}',commit):
        return None,'unrecorded; invalid CI commit'
    def blob(path):
        return subprocess.check_output(['git','show',commit+':'+path],cwd=ROOT,stderr=subprocess.DEVNULL)
    try:
        orchestration = blob('avr_pipeline/review/ci_local_study.py')
        if hashlib.sha256(orchestration).hexdigest()!=record.get('orchestration_sha256'):
            return None,'unrecorded; CI orchestration checksum mismatch'
        workflow = '.github/workflows/avr-agent-baseline.yml' if manifest.get('condition')=='tool_agent' else '.github/workflows/avr-local-rescue.yml'
        data = blob(workflow)
    except subprocess.CalledProcessError:
        return None,'unrecorded; pinned source unavailable locally'
    values = {int(value) for value in re.findall(rb"AVR_LOCAL_REQUEST_TIMEOUT:\s*['\"]?([0-9]+)",data)}
    if len(values)!=1:
        return None,'unrecorded; workflow has no unique literal timeout'
    return values.pop(),f'verified CI workflow {workflow} at {commit}; sha256 {hashlib.sha256(data).hexdigest()}'


def ci_configuration(run):
    path=Path(run)/'ci-provenance.json'
    if not path.exists():return None
    record=json.loads(path.read_text(encoding='utf-8'))
    args=record.get('model_arguments',[])
    flags={}
    for flag in ['--threads','--ctx-size','--parallel','--n-gpu-layers','--batch-size']:
        if flag in args and args.index(flag)+1<len(args):
            flags[flag]=args[args.index(flag)+1]
    return dict(source_commit=record.get('github_sha'),orchestration_sha256=record.get('orchestration_sha256'),
                assets=record.get('assets'),runtime=record.get('runtime'),cpu_count=record.get('cpu_count'),
                inference_flags=flags)
