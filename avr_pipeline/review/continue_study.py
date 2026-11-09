"""Continue missing frozen-study cells without changing or selecting outcomes.

The caller supplies the historical code snapshot. Completed, uniquely matched
cells are reused; a changed implementation is never silently pooled with them.
One worker per model, a shared scanner lock, and daily-quota deferral keep other
available models moving. This command never provisions credentials or paid APIs.
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
from threading import Lock
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from review.controlled_worker import require_budget_safe_resume, verify_snapshot
from review.project_paths import verify_input
from review.runner import checked
from review.evidence_io import durable_dump as dump, recorded_outages
from review.protocol_compatibility import budget_violations, matches_implementation

CONDITIONS = ('A', 'B', 'A_strict', 'no_guidance', 'no_examples', 'C', 'simple')
DATASETS = ('vampi', 'flask-webgoat', 'synthetic', 'pygoat')


def identity(manifest, protocol, sources):
    if (not matches_implementation(manifest, protocol)
            or manifest.get('library_sha256') != protocol['library_sha256']
            or manifest.get('test_policy_sha256') != protocol['test_policy_sha256']
            or manifest.get('max_tokens') != protocol['max_tokens']
            or manifest.get('context_profile') != protocol['context_profile']
            or manifest.get('selected_findings') != manifest.get('eligible_findings')
            or manifest.get('cross_file_only')):
        return None
    dataset = next((name for name, source in sources.items()
                    if source['source_commit'] == manifest.get('source_commit')
                    and source['sarif_sha256'] == manifest.get('sarif_sha256')), None)
    if not dataset:
        return None
    return (manifest.get('provider'), manifest.get('model'), dataset,
            manifest.get('condition'), manifest.get('repetition'))


def index_runs(results, protocol, sources):
    index = {}
    for path in sorted(results.glob('*/manifest.json')):
        manifest = json.loads(path.read_text(encoding='utf-8'))
        key = identity(manifest, protocol, sources)
        if key and not recorded_outages(path.parent) and not budget_violations(path.parent):
            index.setdefault(key, []).append((path.parent, manifest))
    return index


def select_run(matches):
    completed = [(path, m) for path, m in matches if m.get('status') == 'complete' and m.get('sast')]
    if len(completed) > 1:
        raise ValueError('Ambiguous completed cells; outcome-based selection is forbidden')
    if completed:
        return 'complete', completed[0]
    running = [(path, m) for path, m in matches if m.get('status') == 'running']
    if running:
        return 'already_running', running[0]
    if len(matches) > 1:
        raise ValueError('Multiple incomplete candidates need explicit adjudication')
    return ('resume', matches[0]) if matches else ('new', None)


def safe_interrupted_candidate(matches, protocol):
    """Resume the latest compatible checkpoint without resetting consumed replies.

    Ordering uses creation time and path, never patch acceptance or fix rate.
    Completed/running trials are handled by select_run before this function.
    Older declarations permit only zero-reply interruptions; version 1 carries
    recorded replies and their original rejection feedback within the same cap.
    """
    ordered = sorted(matches, key=lambda item: (item[1].get('utc', ''), item[0].name), reverse=True)
    for path, manifest in ordered:
        preserving = protocol.get('continuation_policy',{}).get('version')=='recorded-attempts-v1'
        if not (matches_implementation(manifest,protocol) if preserving else manifest.get('implementation_sha256')==protocol['primary_implementation_sha256']):
            continue
        if manifest.get('status') != 'interrupted_api_error':
            continue
        try:
            require_budget_safe_resume(path,preserve_replies=preserving)
        except ValueError:
            continue
        return path, manifest
    return None


def choose_trial(matches, protocol, fresh=False, resume_safe=False):
    finished_generation = [(p,m) for p,m in matches if m.get('status')=='patching_complete'
                           and m.get('processed_findings')==m.get('selected_findings')]
    if finished_generation and not any(m.get('status') in ('complete','running') for p,m in matches):
        # Rescan the same generated source. A compile/scanner failure is never
        # permission to generate another candidate and select a better score.
        return 'resume',sorted(finished_generation,key=lambda item:(item[1].get('utc',''),item[0].name))[-1]
    if fresh and matches and not any(m.get('status') in ('complete', 'running') for p,m in matches):
        prior = safe_interrupted_candidate(matches, protocol) if resume_safe else None
        return ('resume', prior) if prior else ('new', None)
    return select_run(matches)


def quota_reason(errors):
    text = ' '.join(errors).lower()
    if '429' in text and any(term in text for term in ('perday', 'per_day', 'per day', 'daily', 'requestsperday')):
        return 'daily_quota'
    if any(term in text for term in ('http 500', 'http 503', 'transport failure', 'local api error')):
        return 'service_unavailable'
    return None


def provider_retry_seconds(errors):
    """Use the provider's daily-reset delay, never repeated quota probes."""
    delays = [float(value) for error in errors
              for value in re.findall(r'"retryDelay"\s*:\s*"([0-9.]+)s"', error)]
    return max(delays)+10 if delays else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, default=ROOT)
    parser.add_argument('--protocol', type=Path, default=ROOT/'review/study-protocol.validated.json')
    parser.add_argument('--cohort', type=Path, default=ROOT/'review/validated-cohort.json')
    parser.add_argument('--models', nargs='+')
    parser.add_argument('--datasets', nargs='+', choices=DATASETS, default=list(DATASETS))
    parser.add_argument('--conditions', nargs='+', choices=CONDITIONS, default=list(CONDITIONS))
    parser.add_argument('--tag', default='review2-continued')
    parser.add_argument('--jobs', type=int, choices=range(1, 6), default=5)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--wait-for-quota', action='store_true',
                        help='Wait for an explicitly reported reset instead of ending that model queue')
    parser.add_argument('--fresh-interrupted', action='store_true',
                        help='Keep partial trials and start their missing cells afresh under a new tag')
    parser.add_argument('--resume-safe-interrupted', action='store_true',
                        help='Prefer a declared-compatible checkpoint without resetting its reply allowance')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z0-9-]+', args.tag):
        parser.error('Invalid study tag')
    protocol = json.loads(args.protocol.read_text(encoding='utf-8'))
    verify_snapshot(args.snapshot, protocol)
    cohort = json.loads(args.cohort.read_text(encoding='utf-8'))
    if args.models:
        unknown = set(args.models)-{m['model'] for m in cohort}
        if unknown:
            parser.error('Models outside the frozen cohort: '+', '.join(sorted(unknown)))
        cohort = [m for m in cohort if m['model'] in args.models]
    results = ROOT/'review_results'
    sources = {}
    for dataset in args.datasets:
        repo, sarif = ROOT/'benchmarks'/dataset, results/f'baseline-{dataset}'/'scan.sarif'
        verify_input(repo, sarif, checked, dataset)
        sources[dataset] = dict(source_commit=checked(['git', 'rev-parse', 'HEAD'], repo),
                                sarif_sha256=hashlib.sha256(sarif.read_bytes()).hexdigest())
    state = {'schema': 1, 'started_utc': datetime.now(timezone.utc).isoformat(),
             'coordinator_pid': os.getpid(),
             'controlled_code_commit': protocol['controlled_code_commit'],
             'coordinator_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in [Path(__file__), ROOT/'review/controlled_worker.py']},
             'scheduling': 'one sequential worker per model; serialized CodeQL; hosted calls spaced >=5.1s',
             'spending': 'free/local only', 'executed': args.execute, 'cells': []}
    # Disjoint condition queues can start in the same second with one tag.
    # Each coordinator owns its state file; model run names remain unchanged.
    output = results/f'continuation-{args.tag}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{os.getpid()}.json'
    state_lock = Lock()

    def record(cell):
        with state_lock:
            state['cells'].append(cell)
            dump(output, state)
        print(json.dumps(cell), flush=True)

    def model_worker(model):
        failures, blocked = 0, None
        for repetition in (1, 2, 3):
            for dataset in args.datasets:
                for condition in args.conditions:
                    cell = dict(model, dataset=dataset, condition=condition, repetition=repetition)
                    key = (model['provider'], model['model'], dataset, condition, repetition)
                    matches = index_runs(results, protocol, sources).get(key, [])
                    selection, prior = choose_trial(matches, protocol, args.fresh_interrupted, args.resume_safe_interrupted)
                    if matches and selection in ('new', 'resume'):
                        cell['previous_incomplete_trials'] = [p.name for p,m in matches]
                    # A prior coordinator may have exited while this worker was
                    # still finishing. Wait rather than queue concurrent calls
                    # to the same model or resume a source being written.
                    if selection == 'already_running' and args.execute:
                        record(dict(cell, run=prior[0].name, status='waiting_for_active_worker'))
                        while selection == 'already_running':
                            time.sleep(5)
                            matches = index_runs(results, protocol, sources).get(key, [])
                            selection, prior = choose_trial(matches, protocol, args.fresh_interrupted, args.resume_safe_interrupted)
                        if matches and selection in ('new', 'resume'):
                            cell['previous_incomplete_trials'] = [p.name for p,m in matches]
                    if selection in ('complete', 'already_running'):
                        record(dict(cell, run=prior[0].name, status=selection))
                        continue
                    if blocked:
                        record(dict(cell, status='deferred_'+blocked))
                        continue
                    if selection == 'resume':
                        out = prior[0]
                    else:
                        stem = re.sub(r'[^A-Za-z0-9.-]', '-', model['model'])
                        out = results/f'{stem}-{condition}-{dataset}-{args.tag}-r{repetition}'
                        if out.exists() and any(p.name != 'coordinator.log' for p in out.iterdir()):
                            raise ValueError('Unmatched existing output; refusing overwrite: '+str(out))
                    cell['run'] = out.name
                    if not args.execute:
                        record(dict(cell, status='planned_'+selection))
                        continue
                    cli = [sys.executable, str(ROOT/'review/controlled_worker.py'),
                           '--snapshot', str(args.snapshot.resolve()), '--study-root', str(ROOT),
                           '--protocol', str(args.protocol.resolve()),
                           'run', '--repo', str(ROOT/'benchmarks'/dataset),
                           '--sarif', str(results/f'baseline-{dataset}'/'scan.sarif'),
                           '--out', str(out), '--provider', model['provider'], '--model', model['model'],
                           '--condition', condition, '--repetition', str(repetition), '--max-tokens', '8192',
                           '--guidance-library', str(ROOT/'llm/guidance_library.review-2.json'),
                           '--context-profile', 'compact', '--rescan']
                    if selection == 'resume':
                        cli.append('--resume')
                    # The historical runner supplies its native synthetic test
                    # arguments internally. argparse would consume '-m' here.
                    if dataset != 'synthetic':
                        cli += ['--pytest-args', str(ROOT/'review/behavioral'/f'test_{dataset.replace("-", "_")}.py')]
                    out.mkdir(parents=True, exist_ok=True)
                    record(dict(cell, status='starting_'+selection))
                    with (out/'coordinator.log').open('a', encoding='utf-8') as log:
                        child = subprocess.run(cli, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                    path = out/'manifest.json'
                    manifest = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
                    entries = json.loads((out/'results.json').read_text(encoding='utf-8')) if (out/'results.json').exists() else []
                    errors = [a.get('error', '') for r in entries for a in r.get('attempts', [])
                              if a.get('infrastructure_error')]
                    reason = quota_reason(errors)
                    failures = failures+1 if reason == 'service_unavailable' else 0
                    if reason == 'daily_quota' or failures >= 3:
                        blocked = reason
                    record(dict(cell, status=manifest.get('status', 'worker_failed'), returncode=child.returncode))
                    if reason == 'daily_quota' and args.wait_for_quota:
                        delay = provider_retry_seconds(errors)
                        if delay is not None:
                            record(dict(cell, status='waiting_for_reported_quota_reset', retry_after_seconds=delay))
                            deadline = time.monotonic()+delay
                            while time.monotonic() < deadline:
                                time.sleep(min(30, deadline-time.monotonic()))
                            # Restart this model's queue using immutable saved
                            # attempts. Other model threads continue meanwhile.
                            return model_worker(model)
                    if child.returncode and not manifest:
                        raise RuntimeError('Worker failed before a manifest; inspect '+str(out/'coordinator.log'))

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(model_worker, cohort))
    state['finished_utc'] = datetime.now(timezone.utc).isoformat()
    dump(output, state)


if __name__ == '__main__':
    main()
