import hashlib
import json
from pathlib import Path

from review.configuration_audit import local_timeout


def test_omitted_timeout_is_recovered_from_checksum_verified_ci(tmp_path,monkeypatch):
    code=b'pinned orchestration'
    (tmp_path/'ci-provenance.json').write_text(json.dumps(dict(github_sha='a'*40,orchestration_sha256=hashlib.sha256(code).hexdigest())))
    def blob(args,**kwargs):
        return code if args[-1].endswith('ci_local_study.py') else b"env:\n  AVR_LOCAL_REQUEST_TIMEOUT: '3600'\n"
    monkeypatch.setattr('review.configuration_audit.subprocess.check_output',blob)
    value,origin=local_timeout(tmp_path,dict(provider='local',condition='tool_agent'))
    assert value==3600 and 'verified CI workflow' in origin


def test_unknown_or_mismatched_provenance_does_not_invent_a_budget(tmp_path,monkeypatch):
    assert local_timeout(tmp_path,dict(provider='local'))[0] is None
    (tmp_path/'ci-provenance.json').write_text(json.dumps(dict(github_sha='a'*40,orchestration_sha256='wrong')))
    monkeypatch.setattr('review.configuration_audit.subprocess.check_output',lambda *a,**k:b'actual code')
    assert local_timeout(tmp_path,dict(provider='local'))[0] is None


def test_explicit_manifest_value_takes_precedence(tmp_path):
    assert local_timeout(tmp_path,dict(provider='local',local_request_timeout_seconds=3600))==(3600,'manifest')
