import json

from review.protocol_compatibility import budget_violations, matches_implementation
from llm_client import LLMClient
from review.continuation_state import compatible_resume


def test_transport_timeout_does_not_change_model_payload(monkeypatch):
    captured = []
    class Response:
        def raise_for_status(self):
            pass
        def json(self):
            return {'model':'qwen2.5-coder-0.5b-instruct-q4km',
                    'choices':[{'finish_reason':'stop','message':{'content':'OK'}}]}
    class Session:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, **kwargs):
            captured.append(kwargs)
            return Response()
    monkeypatch.setattr('llm_client.requests.Session', Session)
    client = LLMClient('local','qwen2.5-coder-0.5b-instruct-q4km',max_tokens=8192)
    monkeypatch.setenv('AVR_LOCAL_REQUEST_TIMEOUT','180')
    first = client.chat_completion([{'role':'user','content':'fixture'}])
    monkeypatch.setenv('AVR_LOCAL_REQUEST_TIMEOUT','3600')
    second = client.chat_completion([{'role':'user','content':'fixture'}])
    assert captured[0]['json'] == captured[1]['json']
    assert captured[0]['timeout'] == 180 and captured[1]['timeout'] == 3600
    assert first == second


def test_only_declared_source_variant_is_compatible():
    protocol = {'primary_implementation_sha256':{'runner':'new'},
                'transport_only_compatible_implementations':[{'implementation_sha256':{'runner':'old'}}]}
    assert matches_implementation({'implementation_sha256':{'runner':'old'}}, protocol)
    assert not matches_implementation({'implementation_sha256':{'runner':'unknown'}}, protocol)
    protocol['transport_only_compatible_implementations'][0]['providers'] = ['gemini']
    assert matches_implementation({'implementation_sha256':{'runner':'old'},'provider':'gemini'}, protocol)
    assert not matches_implementation({'implementation_sha256':{'runner':'old'},'provider':'local'}, protocol)


def test_retries_cannot_hide_consumed_generations(tmp_path):
    (tmp_path/'manifest.json').write_text(json.dumps({'settings':{'attempts':3}}))
    result = {'finding_id':'f','attempts':[{'response':{'content':'patch'}}]*3}
    (tmp_path/'results.json').write_text(json.dumps([result]))
    assert budget_violations(tmp_path) == []
    (tmp_path/'interrupted-finding-001-1.json').write_text(json.dumps({'finding_id':'f','attempts':[{'response':{'content':'old reply'}}]}))
    assert budget_violations(tmp_path)[0]['acknowledged_generations'] == 4


def test_continuation_upgrade_requires_explicit_exact_declaration(tmp_path):
    old, current = {'runner':'old'}, {'runner':'current','continuation':'frozen'}
    protocol=dict(primary_implementation_sha256=current,
                  continuation_only_compatible_implementations=[dict(implementation_sha256=old,providers=['gemini'])])
    path=tmp_path/'protocol.json';path.write_text(json.dumps(protocol))
    assert compatible_resume(old,current,'gemini',path)
    assert not compatible_resume(old,current,'local',path)
    assert not compatible_resume(old,current,'gemini',None)
    assert not compatible_resume(old,{'runner':'undeclared'},'gemini',path)
    assert matches_implementation({'implementation_sha256':old,'provider':'gemini'},protocol)
