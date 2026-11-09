"""Retry transient evidence-file locks without changing model or gate decisions."""
import json
from pathlib import Path
import time

from review.validation_health import ValidatorInfrastructureError, recorded_outages as validator_outages


class EvidenceStorageError(ValidatorInfrastructureError):
    pass


def durable_dump(path, value, events=None, timeout=30):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name+'.tmp')
    payload = json.dumps(value, indent=2, ensure_ascii=False)
    deadline, retries, written = time.monotonic()+timeout, 0, False
    while True:
        try:
            if not written:
                pending.write_text(payload, encoding='utf-8')
                written = True
            pending.replace(path)
            break
        except PermissionError:
            retries += 1
            if time.monotonic() >= deadline:
                raise EvidenceStorageError('Evidence storage unavailable: transient file lock exceeded retry deadline') from None
            time.sleep(min(.1*2**min(retries-1,4), 1))
    if retries and events is not None:
        events.append({'file':str(path), 'permission_retries':retries,
                       'policy':'same serialized bytes; retry file I/O only; no model call or gate change'})


def storage_outages(run):
    path = run/'results.json'
    if not path.exists():
        return []
    outages = []
    for result in json.loads(path.read_text(encoding='utf-8')):
        records = [result]+result.get('attempts', [])
        for record in records:
            message = record.get('error','')
            if (('.json.tmp' in message and ('[WinError 5]' in message or 'Permission denied' in message)) or
                    message.startswith('Evidence storage unavailable:')):
                outages.append({'finding':result['finding_id'], 'attempt':record.get('attempt'),
                    'reason':'evidence file save failed; generation/gate evidence is incomplete; not a model quality failure'})
    return outages


def recorded_outages(run):
    storage = storage_outages(run)
    keys = {(entry['finding'],entry['attempt']) for entry in storage}
    return [entry for entry in validator_outages(run) if (entry['finding'],entry['attempt']) not in keys]+storage
