import hashlib
from pathlib import Path

import pytest

from review.continue_study import identity, provider_retry_seconds, quota_reason, select_run, safe_interrupted_candidate
from review.controlled_worker import require_budget_safe_resume, verify_snapshot
from review.controlled_worker import require_resume_source
from review.continue_study import choose_trial
from review.continue_study import index_runs
from review.controlled_worker import paced_call,hosted_lock
from contextlib import contextmanager
from types import SimpleNamespace
import json


def test_completed_duplicate_is_never_selected_by_result():
    with pytest.raises(ValueError, match='Ambiguous'):
        select_run([(Path('one'), {'status': 'complete', 'sast': {'resolved': 1}}),
                    (Path('two'), {'status': 'complete', 'sast': {'resolved': 9}})])


def test_running_and_finished_cells_are_not_resumed():
    running = (Path('active'), {'status': 'running'})
    complete = (Path('finished'), {'status': 'complete', 'sast': {'resolved': 0}})
    assert select_run([running]) == ('already_running', running)
    assert select_run([running, complete]) == ('complete', complete)


def test_changed_budget_or_implementation_cannot_enter_existing_cohort():
    protocol = dict(primary_implementation_sha256={'runner': 'a'}, library_sha256='lib',
                    test_policy_sha256='policy', max_tokens=8192, context_profile='compact')
    manifest = dict(implementation_sha256={'runner': 'a'}, library_sha256='lib',
                    test_policy_sha256='policy', max_tokens=8192, context_profile='compact',
                    selected_findings=3, eligible_findings=3, source_commit='pin',
                    sarif_sha256='sarif', provider='local', model='qwen', condition='A', repetition=2)
    sources = {'vampi': dict(source_commit='pin', sarif_sha256='sarif')}
    assert identity(manifest, protocol, sources) == ('local', 'qwen', 'vampi', 'A', 2)
    assert identity(dict(manifest, max_tokens=1024), protocol, sources) is None
    assert identity(dict(manifest, implementation_sha256={'runner': 'b'}), protocol, sources) is None
    assert identity(dict(manifest, selected_findings=1), protocol, sources) is None


def test_daily_quota_is_separate_from_bad_model_output():
    assert quota_reason(['Gemini HTTP 429 requestsPerDay limit 20']) == 'daily_quota'
    assert quota_reason(['Gemini HTTP 503 unavailable']) == 'service_unavailable'
    assert quota_reason(['Gemini returned incomplete/blocked output: SAFETY']) is None
    assert provider_retry_seconds(['{"retryDelay": "10448s"}']) == 10458
    assert provider_retry_seconds(['quota exceeded']) is None


def test_historical_snapshot_requires_exact_bytes(tmp_path):
    source = tmp_path/'review/runner.py'
    source.parent.mkdir()
    source.write_bytes(b'original\r\n')
    policy = tmp_path/'review/test-policy.json'
    policy.write_bytes(b'policy')
    library = tmp_path/'llm/guidance_library.review-2.json'
    library.parent.mkdir()
    library.write_bytes(b'library')
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    protocol = dict(primary_implementation_sha256={'review\\runner.py': digest(source)},
                    test_policy_sha256=digest(policy), library_sha256=digest(library))
    verify_snapshot(tmp_path, protocol)
    source.write_bytes(b'original\n')
    with pytest.raises(ValueError, match='snapshot differs'):
        verify_snapshot(tmp_path, protocol)


def test_resume_cannot_reset_consumed_generation_attempts(tmp_path):
    result = [{'attempts':[{'attempt':1,'response':{'content':'rejected patch'}},
                            {'attempt':2,'infrastructure_error':True}]}]
    (tmp_path/'results.json').write_text(json.dumps(result))
    with pytest.raises(ValueError, match='consumed generation budget'):
        require_budget_safe_resume(tmp_path)
    result[0]['attempts'] = [{'attempt':1,'infrastructure_error':True}]
    (tmp_path/'results.json').write_text(json.dumps(result))
    require_budget_safe_resume(tmp_path)


def test_safe_checkpoint_selection_uses_no_fix_rate_and_requires_same_bytes(tmp_path):
    matches = []
    for name, stamp, implementation, consumed in [('old','1','same',False),
            ('new','2','same',False), ('unsafe','3','same',True), ('changed','4','other',False)]:
        path = tmp_path/name
        path.mkdir()
        attempts = [{'infrastructure_error':True}]
        if consumed:
            attempts.insert(0, {'response':{'content':'a rejected reply'}})
        (path/'results.json').write_text(json.dumps([{'attempts':attempts}]))
        matches.append((path, dict(utc=stamp, implementation_sha256={'r':implementation}, status='interrupted_api_error')))
    selected = safe_interrupted_candidate(matches, {'primary_implementation_sha256':{'r':'same'}})
    assert selected[0].name == 'new'


def test_finished_generations_are_rescanned_instead_of_retried_for_a_better_score():
    saved=(Path('saved'),dict(status='patching_complete',processed_findings=3,selected_findings=3,rescan_error='invalid source'))
    assert choose_trial([saved],{},fresh=True,resume_safe=True)==('resume',saved)


def test_missing_source_cannot_silently_resume_against_the_baseline(tmp_path):
    with pytest.raises(ValueError,match='discard accepted repairs'):
        require_resume_source(tmp_path)
    (tmp_path/'source/.git').mkdir(parents=True)
    require_resume_source(tmp_path)


def test_single_cell_lookup_does_not_open_unrelated_large_response_files(tmp_path):
    protocol=dict(primary_implementation_sha256={'runner':'same'},library_sha256='lib',
        test_policy_sha256='policy',max_tokens=8192,context_profile='compact')
    base=dict(implementation_sha256={'runner':'same'},library_sha256='lib',test_policy_sha256='policy',
        max_tokens=8192,context_profile='compact',source_commit='pin',sarif_sha256='sarif',
        selected_findings=3,eligible_findings=3,provider='local',condition='A',repetition=1)
    for model in ['selected','unrelated']:
        path=tmp_path/model;path.mkdir()
        (path/'manifest.json').write_text(json.dumps(dict(base,model=model)))
        (path/'results.json').write_text('[]' if model=='selected' else 'unrelated file must not be read')
    key=('local','selected','vampi','A',1)
    result=index_runs(tmp_path,protocol,{'vampi':dict(source_commit='pin',sarif_sha256='sarif')},only_key=key)
    assert list(result)==[key]


def test_hosted_pacing_preserves_payload_and_uses_a_shared_model_lock(tmp_path,monkeypatch):
    import review.controlled_worker as module
    held=[];paths=[];payload=[dict(role='user',content='Exact frozen input')]
    @contextmanager
    def lock(path):
        paths.append(path);held.append(True)
        try:yield
        finally:held.pop()
    monkeypatch.setattr(module,'scanner_lock',lock)
    monkeypatch.setattr(module.time,'sleep',lambda seconds:None)
    def original(client,messages,**kwargs):
        assert held and messages is payload and kwargs=={'system_prompt':'unchanged'}
        return 'original response'
    for model in ['same','same','different']:
        assert paced_call(tmp_path,SimpleNamespace(provider='gemini',model=model),original,[0.0],payload,system_prompt='unchanged')=='original response'
    assert paths[0]==paths[1] and paths[0]!=paths[2]


def test_local_inference_does_not_enter_the_hosted_lock(tmp_path,monkeypatch):
    import review.controlled_worker as module
    def forbidden(*args):raise AssertionError('Local inference must keep its original path')
    monkeypatch.setattr(module,'scanner_lock',forbidden)
    assert paced_call(tmp_path,SimpleNamespace(provider='local'),lambda client,value:value,[0.0],'unchanged')=='unchanged'


@pytest.mark.parametrize('callback_error',[False,True])
def test_unlock_failure_cannot_discard_a_received_reply_or_generation_exception(tmp_path,monkeypatch,callback_error):
    import review.controlled_worker as module
    class Lock:
        def __enter__(self):pass
        def __exit__(self,*args):raise PermissionError('transient unlock failure after handle closure')
    monkeypatch.setattr(module,'scanner_lock',lambda path:Lock())
    received=RuntimeError('acknowledged generation limit')
    if callback_error:
        with pytest.raises(RuntimeError) as error:
            with hosted_lock(tmp_path/'lock'):raise received
        assert error.value is received
    else:
        with hosted_lock(tmp_path/'lock'):result='received model reply'
        assert result=='received model reply'


def test_coordination_failure_is_infrastructure_before_a_model_request(tmp_path,monkeypatch):
    import review.controlled_worker as module
    class Lock:
        def __enter__(self):raise PermissionError('temporary file lock')
    monkeypatch.setattr(module,'scanner_lock',lambda path:Lock())
    with pytest.raises(RuntimeError,match='^Gemini hosted coordination unavailable'):
        with hosted_lock(tmp_path/'lock'):raise AssertionError('No model request may start')
