"""Run a byte-verified historical worker, serializing scanner use on one host.

Only scheduling changes here: patch generation, gates, tests and the scanner
arguments still execute from the supplied immutable snapshot.
"""
import argparse
from contextlib import contextmanager
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
    args, remaining = parser.parse_known_args()
    root = args.study_root.resolve()
    snapshot = args.snapshot.resolve()
    verify_snapshot(snapshot, json.loads((root/'review/study-protocol.json').read_text()))
    if '--out' in remaining:
        out = Path(remaining[remaining.index('--out')+1])
        out.mkdir(parents=True, exist_ok=True)
        execution = {'worker_pid': os.getpid(), 'snapshot': str(snapshot),
                     'worker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     'arguments': remaining,
                     'scheduling': 'serialized CodeQL; >=5.1s between hosted logical calls; no patch/gate changes'}
        with (out/'worker-executions.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(execution)+'\n')
    sys.path.insert(0, str(snapshot))
    from review import runner
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
    runner.main()


if __name__ == '__main__':
    main()
