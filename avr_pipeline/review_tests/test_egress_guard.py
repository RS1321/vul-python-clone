import pytest
from egress_guard import sanitise,check_messages


def test_actual_local_key_is_blocked_before_redaction(monkeypatch):
    secret='AIza'+'A'*35
    monkeypatch.setenv('GEMINI_API_KEY',secret)
    with pytest.raises(RuntimeError,match='credential from GEMINI_API_KEY'):
        sanitise('key = '+secret)


def test_public_key_pattern_is_redacted_without_changing_surrounding_source():
    source='TOKEN = "'+'AIza'+'Z'*35+'"\nprint(TOKEN)'
    clean=sanitise(source)
    assert clean=='TOKEN = "REDACTED_BENCHMARK_CREDENTIAL"\nprint(TOKEN)'
    check_messages([{'content':clean}])
