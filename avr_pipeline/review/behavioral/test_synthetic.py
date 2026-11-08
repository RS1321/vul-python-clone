"""Fixed behavioral oracles, evaluated against pristine and model-repaired sources.

Dangerous sinks are replaced by spies; no injected shell command or network request runs.
"""
import importlib.util
from pathlib import Path
import subprocess
import urllib.request
import pickle
from types import SimpleNamespace
import pytest

SOURCE = Path.cwd()


@pytest.fixture
def subject(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location('measured_synthetic', SOURCE / 'vulnerable_app.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    module.init_database()
    return module, module.app.test_client()


def test_health_contract(subject):
    assert subject[1].get('/health').status_code == 200


def test_sql_login_cannot_bypass(subject):
    response = subject[1].post('/login', data={'username': "' OR 1=1 -- ", 'password': 'invalid'})
    assert 'Login successful' not in response.get_data(as_text=True)
    cookie = response.headers.get('Set-Cookie', '').split(';', 1)[0]
    with subject[0].app.test_request_context(headers={'Cookie': cookie}):
        from flask import session
        assert not session.get('username') and not session.get('user_id')


def test_html_is_encoded(subject):
    marker = '<b data-security-probe="1">probe</b>'
    response = subject[1].get('/profile', query_string={'name': marker})
    assert response.status_code < 500
    assert marker not in response.get_data(as_text=True)


def test_external_redirect_rejected(subject):
    response = subject[1].get('/redirect', query_string={'url': 'https://untrusted.invalid/probe'})
    assert not response.headers.get('Location', '').startswith('https://untrusted.invalid')


def test_loopback_fetch_never_reaches_network(subject, monkeypatch):
    calls = []
    def spy(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(read=lambda: b'harmless probe')
    monkeypatch.setattr(urllib.request, 'urlopen', spy)
    response = subject[1].get('/fetch_url', query_string={'url': 'http://127.0.0.1:9/probe'})
    assert response.status_code < 500
    assert not calls


def test_shell_input_rejected_before_execution(subject, monkeypatch):
    calls = []
    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return b'probe'
    monkeypatch.setattr(subprocess, 'check_output', spy)
    monkeypatch.setattr(subprocess, 'run', spy)
    response = subject[1].get('/ping', query_string={'host': '127.0.0.1;echo probe'})
    assert response.status_code < 500
    assert not calls


def test_untrusted_pickle_never_deserialized(subject, monkeypatch):
    calls = []
    def spy(*args, **kwargs):
        calls.append(True)
        return {'probe': True}
    monkeypatch.setattr(pickle, 'loads', spy)
    response = subject[1].post('/load_object', data=b'not-a-trusted-object')
    assert response.status_code < 500
    assert not calls


def test_arbitrary_file_not_disclosed(subject, tmp_path):
    target = tmp_path / 'private-probe.txt'
    target.write_text('PRIVATE-BEHAVIOR-PROBE')
    response = subject[1].get('/download', query_string={'file': str(target)})
    assert 'PRIVATE-BEHAVIOR-PROBE' not in response.get_data(as_text=True)
