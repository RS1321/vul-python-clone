import json
from pathlib import Path

import pytest

from review.controlled_worker import require_budget_safe_resume
from review.evidence_io import EvidenceStorageError, durable_dump, storage_outages


def test_transient_file_lock_retries_identical_bytes(tmp_path, monkeypatch):
    original = Path.replace
    calls = []
    def locked(path, target):
        calls.append(path.read_bytes())
        if len(calls) < 3:
            raise PermissionError('fixture lock')
        return original(path, target)
    monkeypatch.setattr(Path, 'replace', locked)
    monkeypatch.setattr('review.evidence_io.time.sleep', lambda seconds:None)
    events = []
    value = {'unicode':'é','accepted':False}
    durable_dump(tmp_path/'result.json', value, events)
    assert len(calls)==3 and len(set(calls))==1
    assert json.loads((tmp_path/'result.json').read_text(encoding='utf-8'))==value
    assert events[0]['permission_retries']==2


def test_permanent_lock_preserves_previous_evidence_and_fails_closed(tmp_path, monkeypatch):
    path = tmp_path/'result.json'
    path.write_bytes(b'previous evidence')
    def locked(*args):
        raise PermissionError('fixture lock')
    monkeypatch.setattr(Path, 'replace', locked)
    with pytest.raises(EvidenceStorageError):
        durable_dump(path, {'replacement':True}, timeout=0)
    assert path.read_bytes()==b'previous evidence'


def test_lost_response_storage_is_not_a_model_failure_or_safe_resume(tmp_path):
    raw = [{'finding_id':'f','accepted':False,'attempts':[],
            'error':"[WinError 5] Access is denied: 'attempt-1.json.tmp' -> 'attempt-1.json'"}]
    path = tmp_path/'results.json'
    data = json.dumps(raw).encode();path.write_bytes(data)
    assert len(storage_outages(tmp_path))==1
    with pytest.raises(ValueError, match='consumed replies'):
        require_budget_safe_resume(tmp_path)
    assert path.read_bytes()==data
