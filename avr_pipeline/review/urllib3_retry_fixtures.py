"""Supply the upstream retry test's timezone fixture without server fixtures."""
import pytest


@pytest.fixture
def stub_timezone(request):
    from test.tz_stub import stub_timezone_ctx
    with stub_timezone_ctx(request.param):
        yield
