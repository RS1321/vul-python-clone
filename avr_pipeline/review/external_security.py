"""Local security regression oracles, using fixture data and no lab containers.

Run in the existing dedicated application environment. The Django host and its
embedded Flask lessons are measured separately; neither implies Docker coverage.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
from unittest.mock import patch


def run(kind, repo, out):
    source = out / 'source'
    shutil.copytree(repo, source, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.db', '*.sqlite3'))
    os.chdir(source)
    sys.path.insert(0, str(source))
    checks = []

    def record(name, secure, detail=None, category='security'):
        checks.append(dict(name=name, passed=bool(secure), category=category, detail=detail))

    if kind == 'pygoat':
        os.environ['DJANGO_SETTINGS_MODULE'] = 'pygoat.settings'
        from django.conf import settings
        settings.DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(out / 'fixture.sqlite3')}}
        settings.ALLOWED_HOSTS = ['testserver', 'localhost']
        settings.TRAEFIK_URLS = []
        settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
        settings.LAB_DOMAIN = 'localhost'
        import django
        django.setup()
        from django.core.management import call_command
        from django.contrib.auth import get_user_model
        from django.test import Client
        from challenge.models import Lab
        call_command('migrate', verbosity=0, interactive=False)
        User = get_user_model()
        owner = User.objects.create_user(username='avr_owner', password='LocalFixture-4812')
        User.objects.create_user(username='avr_other', password='OtherFixture-4812')
        Lab.objects.create(name='xss_lab', build_location='unused', port=5006)
        client = Client(raise_request_exception=False, enforce_csrf_checks=True)
        for path in ['/', '/xss', '/scoring/scores/', '/scoring/achievements/', '/challenge/list-labs/']:
            r = client.get(path)
            record('anonymous denied ' + path, r.status_code in (302, 401, 403), r.status_code)
        record('wrong password rejected', not client.login(username=owner.username, password='wrong'))
        record('valid login works', client.login(username=owner.username, password='LocalFixture-4812'), category='functionality')
        record('authenticated home works', client.get('/').status_code == 200, category='functionality')
        for host, expected in [('lab-avr_owner-xss_lab.localhost', 200),
                               ('lab-avr_other-xss_lab.localhost', 403),
                               ('lab-avr_owner-unknown.localhost', 403),
                               ('lab-avr_owner-xss_lab.localhost.evil.invalid', 400)]:
            r = client.get('/auth/verify/', HTTP_X_FORWARDED_HOST=host)
            record('forward-auth ' + host, r.status_code == expected, r.status_code)
        r = client.post('/register', {'username': 'csrf_fixture', 'password1': 'LocalFixture-4812', 'password2': 'LocalFixture-4812'})
        record('CSRF enforced on registration', r.status_code == 403, r.status_code)
        client.logout()
        record('logout invalidates access', client.get('/auth/verify/').status_code == 401)
    elif kind == 'vampi':
        import config
        from config import db
        from models.user_model import User
        from models.books_model import Book
        app = config.vuln_app.app
        from security_test_client import test_client
        client = test_client(app)
        with app.app_context():
            db.create_all()
            owner = User(username='avr_owner', password='LocalFixture-4812', email='owner@example.com')
            other = User(username='avr_other', password='OtherFixture-4812', email='other@example.com')
            db.session.add_all([owner, other])
            db.session.commit()
            db.session.add(Book(book_title='private_fixture', secret_content='fixture-private-marker', user_id=owner.id))
            db.session.commit()
        def login(name, password):
            r = client.post('/users/v1/login', json={'username': name, 'password': password})
            return (r.get_json() or {}).get('auth_token', '')
        owner_token = login('avr_owner', 'LocalFixture-4812')
        other_token = login('avr_other', 'OtherFixture-4812')
        record('both valid accounts log in', bool(owner_token and other_token), category='functionality')
        h_owner = {'Authorization': 'Bearer ' + str(owner_token)}
        h_other = {'Authorization': 'Bearer ' + str(other_token)}
        record('anonymous profile denied', client.get('/me').status_code in (401, 403))
        record('malformed token denied', client.get('/me', headers={'Authorization': 'Bearer invalid'}).status_code in (401, 403))
        record('owner profile works', client.get('/me', headers=h_owner).status_code == 200, category='functionality')
        r = client.get('/books/v1/private_fixture', headers=h_owner)
        record('owner reads own book', r.status_code == 200 and b'fixture-private-marker' in r.data, category='functionality')
        r = client.get('/books/v1/private_fixture', headers=h_other)
        record('other account cannot read private book', r.status_code in (401, 403, 404) and b'fixture-private-marker' not in r.data, r.status_code)
        with app.app_context():
            original_password = User.query.filter_by(username='avr_owner').first().password
        r = client.put('/users/v1/avr_owner/password', headers=h_other, json={'password': 'ChangedFixture-4812'})
        with app.app_context():
            record('other account cannot change owner password', User.query.filter_by(username='avr_owner').first().password == original_password, r.status_code)
        client.post('/users/v1/register', json={'username': 'avr_selfadmin', 'password': 'LocalFixture-4812', 'email': 'new@example.com', 'admin': True})
        with app.app_context():
            user = User.query.filter_by(username='avr_selfadmin').first()
            record('registration cannot self-assign admin', user is None or not user.admin)
        r = client.get('/users/v1/_debug')
        record('debug does not disclose fixture password', b'LocalFixture-4812' not in r.data and r.status_code < 500, r.status_code)
        known = client.post('/users/v1/login', json={'username': 'avr_owner', 'password': 'incorrect'}).data
        unknown = client.post('/users/v1/login', json={'username': 'nonexistent_fixture', 'password': 'incorrect'}).data
        record('failed login does not enumerate account', known == unknown)
        from urllib.parse import quote
        r = client.get('/users/v1/' + quote("' OR '1'='1' --", safe=''))
        record('SQL-shaped username returns no fixture account', r.status_code in (400, 404) and b'owner@example.com' not in r.data, r.status_code)
    else:
        lab = kind.removeprefix('lab-')
        folder = source / 'dockerized_labs' / lab
        os.chdir(folder)
        spec = importlib.util.spec_from_file_location('avr_lesson', folder / 'app.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        app = module.app
        from security_test_client import test_client
        client = test_client(app)
        record('lesson homepage works', client.get('/').status_code == 200, category='functionality')
        if lab == 'xss_lab':
            marker = '<b data-avr="fixture">inert-marker</b>'
            for path, method, data in [('/lab1', 'get', {'q': marker}), ('/lab2', 'post', {'username': marker})]:
                r = client.get(path, query_string=data) if method == 'get' else client.post(path, data=data)
                record('untrusted markup escaped ' + path, r.status_code < 400 and marker.encode() not in r.data and b'inert-marker' in r.data, r.status_code)
            r = client.get('/toggle-theme', headers={'Referer': 'https://outside.example.invalid/'})
            record('theme redirect remains local', r.status_code in (301, 302, 303) and not r.headers.get('Location', '').startswith('https://outside.'), r.status_code)
        elif lab == 'sql_injection_lab':
            module.init_db()
            import sqlite3
            with sqlite3.connect('database.db') as c:
                c.execute('INSERT OR REPLACE INTO users VALUES (?,?)', ('avr_fixture', 'LocalFixture-4812'))
            normal = client.post('/lab', data={'username': 'avr_fixture', 'password': 'LocalFixture-4812'})
            wrong = client.post('/lab', data={'username': 'avr_fixture', 'password': 'wrong'})
            record('valid login reaches success view', b'avr_fixture' in normal.data and b'Invalid username' not in normal.data, category='functionality')
            record('wrong password denied', b'Invalid username or password' in wrong.data)
            r = client.post('/lab', data={'username': "avr_fixture' --", 'password': 'wrong'})
            record('quoted username cannot bypass password', b'Invalid username or password' in r.data and r.status_code < 500, r.status_code)
        elif lab == 'ssrf_lab':
            with patch.object(module.requests, 'get', return_value=SimpleNamespace(text='fixture-response')) as get:
                normal = client.post('/lab2', data={'url': 'http://example.com'})
                record('allowed public URL still fetched', get.call_count == 1 and b'fixture-response' in normal.data, category='functionality')
                get.reset_mock()
                r = client.post('/lab2', data={'url': 'http://127.0.0.1/private-fixture'})
                record('private destination blocked before fetch', get.call_count == 0 and r.status_code < 500, {'status': r.status_code, 'fetches': get.call_count})
        elif lab == 'command_injection_lab':
            fake = SimpleNamespace(communicate=lambda **kwargs: (b'fixture-result', b''), returncode=0)
            with patch.object(module.subprocess, 'Popen', return_value=fake) as popen:
                r = client.post('/lab1', data={'domain': 'example.invalid', 'os': 'win'})
                record('ordinary command route responds', r.status_code == 200 and popen.call_count == 1 and b'fixture-result' in r.data, category='functionality')
                record('command invocation avoids shell', popen.call_count == 1 and all(not call.kwargs.get('shell', False) and isinstance(call.args[0], (list, tuple)) for call in popen.call_args_list), {'calls': popen.call_count})
    return {'kind': kind, 'checks': checks, 'security_passed': sum(c['passed'] for c in checks if c['category'] == 'security'),
            'security_total': sum(c['category'] == 'security' for c in checks), 'functionality_passed': all(c['passed'] for c in checks if c['category'] == 'functionality'),
            'scope': 'Local fixture requests; Django authenticated host and embedded lessons separate; outbound URL and process sinks mocked.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--kind', required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    if out.exists() or out.is_relative_to(repo):
        raise ValueError('Use a fresh output outside source')
    out.mkdir(parents=True)
    result = run(args.kind, repo, out)
    (out / 'security.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('kind', 'security_passed', 'security_total', 'functionality_passed')}))
    raise SystemExit(0 if result['functionality_passed'] and result['security_passed'] == result['security_total'] else 1)
