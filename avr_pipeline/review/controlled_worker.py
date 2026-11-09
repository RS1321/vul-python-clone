"""Run a byte-verified historical worker, serializing scanner use on one host.

Only scheduling changes here: patch generation, gates, tests and the scanner
arguments still execute from the supplied immutable snapshot.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def verify_snapshot(snapshot, protocol):
    for relative, expected in protocol['primary_implementation_sha256'].items():
        path = snapshot.joinpath(*relative.replace('\\', '/').split('/'))
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Controlled snapshot differs: ' + relative)
    for relative, key in [('review/test-policy.json', 'test_policy_sha256'),
                          ('llm/guidance_library.review-2.json', 'library_sha256')]:
        if hashlib.sha256((snapshot/relative).read_bytes()).hexdigest() != protocol[key]:
            raise ValueError('Frozen study input differs: ' + relative)


def require_budget_safe_resume(out, preserve_replies=False):
    """Keep uncertain budgets out; only the declared upgrade may carry replies."""
    path = out/'results.json'
    results = json.loads(path.read_text(encoding='utf-8')) if path.exists() else []
    for finding in results:
        for record in [finding]+finding.get('attempts', []):
            message = record.get('error','')
            if (('.json.tmp' in message and ('[WinError 5]' in message or 'Permission denied' in message)) or
                    message.startswith('Evidence storage unavailable:')):
                raise ValueError('Evidence storage failed and consumed replies cannot be established; retain the trial and start fresh')
    if results and any(a.get('infrastructure_error') for a in results[-1].get('attempts', [])):
        if not preserve_replies and any(a.get('response') is not None for a in results[-1].get('attempts', [])):
            raise ValueError('Resume would reset an already consumed generation budget; retain this partial attempt and start a fresh trial')


def require_resume_source(out):
    if not (out/'source/.git').exists():
        raise ValueError('Restore the exact saved model source before resuming; cloning the baseline would discard accepted repairs')


@contextmanager
def scanner_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as handle:
        if handle.tell() == 0:
            handle.write(b'0')
            handle.flush()
        while True:
            handle.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError):
                time.sleep(1)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--study-root', type=Path, required=True)
    parser.add_argument('--protocol', type=Path)
    args, remaining = parser.parse_known_args()
    root = args.study_root.resolve()
    snapshot = args.snapshot.resolve()
    protocol = args.protocol or root/'review/study-protocol.json'
    declaration = json.loads(protocol.read_text(encoding='utf-8'))
    verify_snapshot(snapshot, declaration)
    storage_policy = declaration.get('orchestration_io_policy')
    if storage_policy and hashlib.sha256((Path(__file__).parent/'evidence_io.py').read_bytes()).hexdigest() != storage_policy['implementation_sha256']:
        raise ValueError('Declared evidence I/O adapter differs')
    if '--out' in remaining:
        out = Path(remaining[remaining.index('--out')+1])
        if '--resume' in remaining:
            require_resume_source(out)
            require_budget_safe_resume(out,preserve_replies=declaration.get('continuation_policy',{}).get('version')=='recorded-attempts-v1')
            if declaration.get('continuation_policy',{}).get('version')=='recorded-attempts-v1':
                remaining += ['--resume-protocol',str(protocol.resolve())]
        out.mkdir(parents=True, exist_ok=True)
        execution = {'worker_pid': os.getpid(), 'snapshot': str(snapshot),
                     'utc': datetime.now(timezone.utc).isoformat(),
                     'worker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     'evidence_io_sha256': hashlib.sha256((Path(__file__).parent/'evidence_io.py').read_bytes()).hexdigest(),
                     'evidence_io_policy': 'retry identical JSON atomic writes for up to 30s; no generation/gate changes',
                     'arguments': remaining,
                     'transport_environment': {key:os.getenv(key) for key in (
                         'AVR_REQUEST_TIMEOUT','AVR_LOCAL_REQUEST_TIMEOUT','AVR_TRANSPORT_RETRIES',
                         'AVR_REQUEST_BUDGET_PER_MINUTE','AVR_INPUT_BUDGET_PER_MINUTE')},
                     'scheduling': 'serialized CodeQL; >=5.1s between hosted logical calls; no patch/gate changes'}
        prior_manifest = out/'manifest.json'
        if prior_manifest.exists():
            execution['previous_manifest_sha256'] = hashlib.sha256(prior_manifest.read_bytes()).hexdigest()
            execution['previous_transport_policy'] = json.loads(prior_manifest.read_text(encoding='utf-8')).get('transport_policy')
        with (out/'worker-executions.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(execution)+'\n')
    sys.path.insert(0, str(snapshot))
    from review import runner
    io_events = []
    if (snapshot/'review/evidence_io.py').exists():
        from review.evidence_io import durable_dump
        runner.dump = lambda path,value:durable_dump(path,value,io_events)
    original_scan = runner.scan

    def serialized_scan(*scan_args, **scan_kwargs):
        with scanner_lock(root/'.review-work/controlled-scanner.lock'):
            return original_scan(*scan_args, **scan_kwargs)

    runner.scan = serialized_scan
    # One sequential worker per hosted model; pacing changes only wall time.
    original_chat = runner.LLMClient.chat_completion
    last_request = [0.0]

    def paced_chat(client, *chat_args, **chat_kwargs):
        if client.provider == 'gemini':
            time.sleep(max(0, 5.1-(time.monotonic()-last_request[0])))
            last_request[0] = time.monotonic()
        return original_chat(client, *chat_args, **chat_kwargs)

    runner.LLMClient.chat_completion = paced_chat
    sys.argv = [str(snapshot/'review/runner.py'), *remaining]
    try:
        runner.main()
    finally:
        if io_events and '--out' in remaining:
            durable_dump(out/'evidence-io-retries.json', io_events)


if __name__ == '__main__':
    main()
