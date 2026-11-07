"""Ordinary Django behavior checks; isolated database, no lab containers/network.

Run with the dedicated PyGoat environment, not the pipeline environment.
This checks application behavior, not vulnerability resolution or exploitability.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    if out.is_relative_to(repo):
        raise ValueError('Runtime state must stay outside source')
    out.mkdir(parents=True, exist_ok=True)
    db = out / 'runtime.sqlite3'
    if db.exists():
        raise ValueError('Use a fresh output folder for each runtime check')
    sys.path.insert(0, str(repo))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'pygoat.settings'
    from django.conf import settings
    settings.DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(db)}}
    settings.ALLOWED_HOSTS = ['testserver', 'localhost']
    settings.TRAEFIK_URLS = []
    settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
    import django
    django.setup()
    from django.core.management import call_command
    from django.contrib.auth import get_user_model
    from django.test import Client
    call_command('migrate', verbosity=0, interactive=False)
    client = Client(raise_request_exception=False)
    records = []
    def check(name, observed, expected):
        records.append({'name': name, 'observed': observed, 'expected': expected,
                        'passed': observed == expected})
    for path, expected in [('/', 302), ('/accounts/login/', 200), ('/register', 200),
                           ('/auth/verify/', 401), ('/robots.txt', 302)]:
        check('anonymous GET ' + path, client.get(path).status_code, expected)
    # A local fixture account verifies normal authentication and rendering.
    # It does not start PyGoat's deliberately insecure lab containers.
    User = get_user_model()
    user = User.objects.create_user(username='avr_runtime_fixture', email='fixture@example.invalid',
                                    password='LocalTestFixture-48219')
    check('normal login', client.login(username=user.username, password='LocalTestFixture-48219'), True)
    check('authenticated homepage', client.get('/').status_code, 200)
    check('normal lesson page', client.get('/xss').status_code, 200)
    client.logout()
    check('logout restores login redirect', client.get('/').status_code, 302)
    result = {'scope': 'Django application regression checks; not a security oracle',
              'repo': str(repo), 'django': django.get_version(), 'checks': records,
              'passed': all(r['passed'] for r in records)}
    (out / 'runtime.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'passed': result['passed'], 'checks': len(records), 'out': str(out)}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
