"""Ordinary VAmPI registration/login checks in an isolated source copy/database."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    if out.is_relative_to(repo) or out.exists():
        raise ValueError('Use a fresh output folder outside source')
    source = out / 'source'
    shutil.copytree(repo, source, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.db', '*.sqlite3'))
    os.chdir(source)
    sys.path.insert(0, str(source))
    import config
    from config import db
    app = config.vuln_app.app
    client = app.test_client()
    with app.app_context():
        db.create_all()
    records = []
    def check(name, actual, expected):
        records.append({'name': name, 'observed': actual, 'expected': expected, 'passed': actual == expected})
    check('home', client.get('/').status_code, 200)
    check('users list', client.get('/users/v1').status_code, 200)
    check('missing authentication', client.get('/me').status_code, 401)
    account = {'username': 'avr_fixture', 'password': 'NormalFixture-48219', 'email': 'fixture@example.com'}
    registered = client.post('/users/v1/register', json=account)
    check('normal registration', registered.status_code, 200)
    check('registration succeeds', (registered.get_json() or {}).get('status'), 'success')
    logged_in = client.post('/users/v1/login', json={'username': account['username'], 'password': account['password']})
    check('normal login', logged_in.status_code, 200)
    token = (logged_in.get_json() or {}).get('auth_token', '')
    check('login produces token', bool(token), True)
    profile = client.get('/me', headers={'Authorization': 'Bearer ' + token})
    check('authenticated profile', profile.status_code, 200)
    check('profile retains username', (profile.get_json() or {}).get('data', {}).get('username'), account['username'])
    result = {'repo': str(repo), 'scope': 'ordinary HTTP regression checks; not a security oracle',
              'checks': records, 'passed': all(r['passed'] for r in records)}
    (out / 'runtime.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'passed': result['passed'], 'checks': len(records), 'out': str(out)}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
