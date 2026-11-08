import pytest
from external_assertions import collect

CHECKS = collect('pygoat')


@pytest.mark.parametrize('check', CHECKS, ids=[c['name'] for c in CHECKS])
def test_behavioral_assertion(check):
    assert check['passed'], check
