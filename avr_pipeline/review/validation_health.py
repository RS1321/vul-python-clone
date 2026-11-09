"""Keep validator outages separate from model patch-quality measurements."""
import json


class ValidatorInfrastructureError(RuntimeError):
    pass


def require_lint_health(report):
    if not isinstance(report, dict) or not isinstance(report.get('messages'), list):
        raise ValidatorInfrastructureError('Validator infrastructure: invalid Pylint report')
    fatal = [m for m in report['messages'] if m.get('type') == 'fatal']
    if fatal:
        raise ValidatorInfrastructureError('Validator infrastructure: Pylint fatal error: '+
                                           ', '.join(str(m.get('symbol')) for m in fatal))


def recorded_outages(run):
    path = run/'results.json'
    if not path.exists():
        return []
    return outages_in_results(json.loads(path.read_text(encoding='utf-8')))


def outages_in_results(results):
    outages = []
    for finding in results:
        for attempt in finding.get('attempts', []):
            lint = attempt.get('validation', {}).get('pylint', {})
            symbols = [error[0] for error in lint.get('new_errors', []) if isinstance(error, (list, tuple)) and error]
            if ('astroid-error' in symbols or 'fatal' in symbols or
                    lint.get('error') == 'Pylint unavailable or invalid structured report' or
                    attempt.get('infrastructure_kind') == 'validator'):
                outages.append({'finding': finding['finding_id'], 'attempt': attempt['attempt'],
                                'reason': 'validator unavailable or crashed; not a model repair failure'})
    return outages
