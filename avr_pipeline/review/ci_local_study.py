"""Evaluate pinned local models on free standard public-repository CI runners.

No hosted model keys or paid runners are used. Cached assets are checksum-verified.
Evidence archives contain raw measurements and exact patches, never databases or
runtime/source clones. The archive cap bounds this study's artifact storage.
"""
import argparse
import hashlib
from importlib.metadata import distributions
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.controlled_worker import verify_snapshot
from review.runner import checked, dump, CONDITIONS
from review.validation_health import require_lint_health


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def download(url, target, expected, fallback_url=None):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if digest(target) == expected:
            return
        raise ValueError('Existing asset checksum differs: '+str(target))
    session = requests.Session()
    session.mount('https://', HTTPAdapter(max_retries=Retry(total=4, backoff_factor=2,
                  status_forcelist=[429, 500, 502, 503, 504])))
    pending = target.with_suffix(target.suffix+'.partial')
    for address in [url]+([fallback_url] if fallback_url else []):
        try:
            headers = {'Accept':'application/octet-stream'} if address == fallback_url else {}
            with session.get(address, headers=headers, stream=True, timeout=(30, 180)) as response:
                response.raise_for_status()
                with pending.open('wb') as handle:
                    for chunk in response.iter_content(1024*1024):
                        handle.write(chunk)
            if digest(pending) != expected:
                raise ValueError('Downloaded asset checksum differs')
            pending.replace(target)
            return
        except (requests.RequestException, ValueError):
            continue
    raise RuntimeError('Unable to download the checksum-verified asset from its official endpoints')


def package_evidence(out, destination, maximum_bytes=1024*1024):
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination/(out.name+'.tar.xz')
    excluded = {'source', 'codeql-db', 'pytest-tmp', 'zap-home', 'target-state', '__pycache__'}
    with tarfile.open(archive, 'w:xz', preset=9) as bundle:
        for path in sorted(out.rglob('*')):
            relative = path.relative_to(out)
            if path.is_file() and not path.is_symlink() and not excluded.intersection(relative.parts):
                bundle.add(path, arcname=out.name+'/'+relative.as_posix(), recursive=False)
    if archive.stat().st_size > maximum_bytes:
        # Never silently trim evidence or upload beyond the declared free budget.
        archive.unlink()
        raise RuntimeError('Lossless evidence exceeds the 1 MiB per-cell storage cap')
    dump(destination/(out.name+'-archive.json'),
         {'archive': archive.name, 'bytes': archive.stat().st_size, 'sha256': digest(archive),
          'excludes': sorted(excluded), 'lossless_measurement_files': True})
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    assets = json.loads((ROOT/'review/local-study-assets.json').read_text())
    parser.add_argument('--model', choices=list(assets['models']), required=True)
    parser.add_argument('--dataset', choices=['synthetic', 'vampi', 'pygoat', 'flask-webgoat'], required=True)
    parser.add_argument('--condition', choices=list(CONDITIONS), required=True)
    parser.add_argument('--repetition', type=int, choices=[1, 2, 3], required=True)
    parser.add_argument('--pilot', action='store_true')
    parser.add_argument('--agent', action='store_true', help='Evaluate the tool-agent comparator with the same model assets')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('This runner is pinned to Linux amd64')
    protocol = json.loads((ROOT/'review/study-protocol.validated.json').read_text())
    verify_snapshot(ROOT, protocol)
    work = ROOT/'.review-work'
    tag = 'review2-ci-pilot' if args.pilot else 'review2-validated'
    name = f'{args.model}-{("tool-agent" if args.agent else args.condition)}-{args.dataset}-{tag}-r{args.repetition}'
    out = ROOT/'review_results'/name
    out.mkdir(parents=True, exist_ok=False)
    process = None
    code = 1
    try:
        asset = assets['models'][args.model]
        runtime = work/'ci-runtime'
        runtime.mkdir(parents=True, exist_ok=True)
        runtime_archive = work/'llama-linux.tar.gz'
        download(assets['runtime']['url'], runtime_archive, assets['runtime']['sha256'], assets['runtime'].get('api_url'))
        with tarfile.open(runtime_archive, 'r:gz') as bundle:
            bundle.extractall(runtime, filter='data')
        servers = list(runtime.rglob('llama-server'))
        if len(servers) != 1:
            raise RuntimeError('Pinned runtime does not contain exactly one model server')
        model_path = work/'ci-models'/asset['file']
        download(f'https://huggingface.co/{asset["repo"]}/resolve/{asset["revision"]}/{asset["file"]}',
                 model_path, asset['sha256'])
        scanner_archive = work/'codeql-linux64.zip'
        download(assets['codeql']['url'], scanner_archive, assets['codeql']['sha256'], assets['codeql'].get('api_url'))
        scanner_root = work/'codeql-cli'
        scanner_root.mkdir(parents=True, exist_ok=True)
        checked(['unzip', '-q', str(scanner_archive), '-d', str(scanner_root)], timeout=300)
        # The verified compressed archive is retained for the included CI cache.
        codeql = scanner_root/'codeql/codeql'
        packs = work/'packs'
        checked([codeql, 'pack', 'download', 'codeql/python-queries@1.9.0', '--dir='+str(packs)], timeout=600)
        os.environ['CODEQL_BIN'] = str(codeql)
        os.environ['CODEQL_PACK_ROOT'] = str(packs)
        os.environ['AVR_TOOL_ROOT'] = str(ROOT)
        checked([sys.executable, str(ROOT/'review/prepare_inputs.py'), '--datasets', args.dataset], timeout=600)
        if args.dataset in ('vampi', 'pygoat'):
            kind = args.dataset
            environment = work/f'{kind}-env'
            checked([sys.executable, '-m', 'venv', str(environment)], timeout=120)
            lock = ROOT/('requirements-vampi.lock' if kind == 'vampi' else 'requirements-django.lock')
            checked([environment/'bin/python', '-m', 'pip', 'install', '-r', str(lock)], timeout=900)
            os.environ[f'AVR_{kind.upper()}_PYTHON'] = str(environment/'bin/python')
        # Check the actual linter before spending generation compute.
        health_file = work/'lint-health.py'
        health_file.write_text('def healthy():\n    return True\n')
        health = checked([sys.executable, '-m', 'pylint', str(health_file), '--output-format=json2', '--exit-zero'])
        require_lint_health(json.loads(health))
        server_args = [str(servers[0]), '--model', str(model_path), '--host', '127.0.0.1',
                       '--port', str(asset['port']), '--alias', args.model, '--threads', '4',
                       '--ctx-size', '16384', '--parallel', '1', '--n-gpu-layers', '0', '--batch-size', '512']
        child_env = {k:v for k,v in os.environ.items() if not re.search(r'key|token|secret|password|credential', k, re.I)}
        with (out/'model-server.log').open('w', encoding='utf-8') as log:
            process = subprocess.Popen(server_args, env=child_env, stdout=log, stderr=subprocess.STDOUT)
        http = requests.Session()
        http.trust_env = False
        for _ in range(120):
            if process.poll() is not None:
                raise RuntimeError('Pinned model runtime failed; see model-server.log')
            try:
                if http.get(f'http://127.0.0.1:{asset["port"]}/health', timeout=1).status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('Model startup timed out')
        dump(out/'ci-provenance.json', {
             'orchestration_sha256': digest(Path(__file__)), 'assets': asset,
             'runtime': assets['runtime'], 'codeql': assets['codeql'], 'model_arguments': server_args,
             'platform': platform.platform(), 'python': sys.version, 'cpu_count': os.cpu_count(),
             'packages': sorted(d.metadata['Name']+'=='+d.version for d in distributions() if d.metadata.get('Name')),
             'github_run_id': os.getenv('GITHUB_RUN_ID'), 'github_run_attempt': os.getenv('GITHUB_RUN_ATTEMPT'),
             'github_sha': os.getenv('GITHUB_SHA'), 'spending': 'standard public-repository runner; local model; no API credentials'})
        cli = [sys.executable, str(ROOT/('review/agent_baseline.py' if args.agent else 'review/runner.py'))]
        if not args.agent:
            cli += ['run']
        cli += ['--repo', str(ROOT/'benchmarks'/args.dataset),
                '--sarif', str(ROOT/f'review_results/baseline-{args.dataset}/scan.sarif'), '--out', str(out),
                '--provider', 'local', '--model', args.model,
                '--repetition', str(args.repetition), '--max-tokens', '8192']
        if not args.agent:
            cli += ['--condition', args.condition, '--context-profile', 'compact',
                    '--guidance-library', str(ROOT/'llm/guidance_library.review-2.json'), '--rescan']
        if args.pilot:
            cli += ['--limit', '1']
        with (out/'runner.log').open('w', encoding='utf-8') as log:
            code = subprocess.run(cli, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode
        manifest = json.loads((out/'manifest.json').read_text())
        if (out/'source/.git').exists():
            (out/'model.patch').write_text(checked(['git', 'diff', '--no-ext-diff'], out/'source'), encoding='utf-8')
        print(json.dumps({'run': name, 'status': manifest.get('status'), 'sast': manifest.get('sast'),
                          'behavioral_tests': manifest.get('behavioral_tests')}, indent=2), flush=True)
    except Exception as error:
        dump(out/'ci-error.json', {'error_type': type(error).__name__, 'error': str(error)})
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
        package_evidence(out, work/'ci-evidence')
    raise SystemExit(code)


if __name__ == '__main__':
    main()
