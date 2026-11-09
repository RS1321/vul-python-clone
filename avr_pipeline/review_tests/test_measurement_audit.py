import xml.etree.ElementTree as ET

from review.measurement_audit import audit_tests


def write_suite(path, message=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    suite = ET.Element('testsuite')
    case = ET.SubElement(suite, 'testcase', name='login')
    if message:
        ET.SubElement(case, 'error').text = message
    ET.ElementTree(suite).write(path)


def test_removed_application_symbol_is_a_regression(tmp_path):
    write_suite(tmp_path/'baseline-tests/pytest.xml')
    write_suite(tmp_path/'post-tests/pytest.xml', "ImportError: cannot import name 'query_db' from 'app' (/run/source/app/__init__.py)")
    raw = dict(status='failed', infrastructure_error=True, failures=['login'])
    audited = audit_tests(tmp_path, raw, 'post-tests', 'baseline-tests')
    assert audited['setup_error_classification'] == 'application_startup_regression'
    assert audited['infrastructure_error'] is False
    assert raw['infrastructure_error'] is True


def test_dependency_failure_is_not_assumed_to_be_a_code_regression(tmp_path):
    write_suite(tmp_path/'baseline-tests/pytest.xml')
    write_suite(tmp_path/'post-tests/pytest.xml', "ModuleNotFoundError: No module named 'flask'")
    assert audit_tests(tmp_path, {}, 'post-tests', 'baseline-tests')['infrastructure_error'] is True


def test_failed_baseline_does_not_establish_patch_causation(tmp_path):
    message = "ImportError: cannot import name 'query_db' from 'app' (C:\\run\\source\\app.py)"
    write_suite(tmp_path/'baseline-tests/pytest.xml', message)
    write_suite(tmp_path/'post-tests/pytest.xml', message)
    assert audit_tests(tmp_path, {}, 'post-tests', 'baseline-tests')['infrastructure_error'] is True
