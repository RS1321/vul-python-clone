"""Read-only and sink-spied behavioral checks in a disposable database directory."""
from pathlib import Path
import sys
import subprocess
import pytest

SOURCE = Path.cwd()


@pytest.fixture
def client(tmp_path, monkeypatch):
    sys.path.insert(0, str(SOURCE))
    monkeypatch.chdir(tmp_path)
    import flask_webgoat
    app = flask_webgoat.create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_status_contract(client):
    assert client.get('/status').status_code == 200


def test_legitimate_login(client):
    assert client.post('/login', data={'username': 'admin', 'password': 'admin'}).json.get('success') is True


def test_sql_authentication_bypass_rejected(client):
    response = client.post('/login', data={'username': "' OR 1=1 -- ", 'password': 'wrong'})
    assert not (response.json or {}).get('success')


def test_external_redirect_rejected(client):
    response = client.get('/login_and_redirect', query_string={'username': 'nobody', 'password': 'wrong',
                                                             'url': 'https://untrusted.invalid/probe'})
    assert not response.headers.get('Location', '').startswith('https://untrusted.invalid')


def test_command_input_does_not_reach_shell(client, monkeypatch):
    calls = []
    def spy(*args, **kwargs):
        calls.append(kwargs.get('shell', False))
        return subprocess.CompletedProcess([], 0, stdout=b'probe')
    monkeypatch.setattr(subprocess, 'run', spy)
    response = client.get('/grep_processes', query_string={'name': 'probe;echo probe'})
    assert response.status_code < 500
    assert not any(calls)
