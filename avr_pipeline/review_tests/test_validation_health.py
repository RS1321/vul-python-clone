import json
from types import SimpleNamespace

import pytest

from review import runner
from review.validation_health import ValidatorInfrastructureError, recorded_outages, require_lint_health


def test_fatal_linter_crash_is_not_a_quality_rejection(tmp_path, monkeypatch):
    target = tmp_path/'app.py'
    original = b'def f():\n    return 1\n'
    target.write_bytes(b'def f():\n    return 2\n')
    report = dict(messages=[dict(type='fatal', symbol='astroid-error')], statistics=dict(score=0))
    monkeypatch.setattr(runner, 'command', lambda *a, **k: SimpleNamespace(stdout=json.dumps(report)))
    with pytest.raises(ValidatorInfrastructureError, match='fatal'):
        runner.gates(tmp_path, 'app.py', original, original.decode(), {}, runner.CONDITIONS['A'], [], {}, tmp_path/'tests')


def test_validator_outage_stops_attempts_and_restores_candidate(tmp_path, monkeypatch):
    (tmp_path/'app.py').write_text('def f():\n    return 1\n')
    finding = {'finding_id':'fixture','sast':{'cwe':'CWE-089','rule_id':'fixture',
        'description':'fixture','location':{'file_path':'app.py','function':'f','start_line':1,'end_line':2}}}
    class Client:
        calls = 0
        def chat_completion(self, *args, **kwargs):
            self.calls += 1
            return {'content':'SCOPE: function\n```python\ndef f():\n    return 2\n```'}
    def unavailable(*args, **kwargs):
        raise ValidatorInfrastructureError('Validator infrastructure: fixture crash')
    monkeypatch.setattr(runner, 'gates', unavailable)
    client = Client()
    result = runner.repair_one(tmp_path, finding, runner.CONDITIONS['A'], client, [], {}, tmp_path/'result')
    assert client.calls == 1 and not result['accepted']
    assert result['attempts'][0]['infrastructure_kind'] == 'validator'
    assert (tmp_path/'app.py').read_text() == 'def f():\n    return 1\n'


def test_historical_crash_is_detected_without_rewriting_raw_data(tmp_path):
    raw = [{'finding_id':'f', 'attempts':[{'attempt':1,'validation':{'pylint':{
        'new_errors':[['astroid-error','','Fatal error']]}}}]}]
    data = json.dumps(raw).encode()
    path = tmp_path/'results.json'
    path.write_bytes(data)
    assert len(recorded_outages(tmp_path)) == 1
    assert path.read_bytes() == data
    require_lint_health({'messages':[{'type':'error','symbol':'undefined-variable'}]})
