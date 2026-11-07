"""Ephemeral allowlisted HTTP target with real fixture-session authentication."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
from wsgiref.simple_server import make_server

parser = argparse.ArgumentParser()
parser.add_argument('--dataset', choices=['pygoat', 'vampi'], required=True)
parser.add_argument('--repo', required=True, type=Path)
parser.add_argument('--out', required=True, type=Path)
parser.add_argument('--port', required=True, type=int)
args = parser.parse_args()
repo, out = args.repo.resolve(), args.out.resolve()
if out.exists() or out.is_relative_to(repo):
    raise ValueError('Use fresh state outside source')
source = out / 'source'
shutil.copytree(repo, source, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.db', '*.sqlite3'))
os.chdir(source)
sys.path.insert(0, str(source))
if args.dataset == 'pygoat':
    os.environ['DJANGO_SETTINGS_MODULE'] = 'pygoat.settings'
    from django.conf import settings
    settings.DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(out / 'fixture.sqlite3')}}
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'testserver']
    settings.TRAEFIK_URLS = []
    settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
    import django
    django.setup()
    from django.core.management import call_command
    from django.contrib.auth import get_user_model
    from django.test import Client
    from django.core.wsgi import get_wsgi_application
    call_command('migrate', verbosity=0, interactive=False)
    user = get_user_model().objects.create_user(username='avr_scan_fixture', password='LocalFixture-4812')
    client = Client()
    assert client.login(username=user.username, password='LocalFixture-4812')
    headers = {'Cookie': 'sessionid=' + client.cookies['sessionid'].value}
    paths = ['/', '/xss', '/sql', '/scoring/scores/', '/scoring/achievements/']
    verify = '/'
    application = get_wsgi_application()
else:
    import config
    from config import db
    from models.user_model import User
    from models.books_model import Book
    application = config.vuln_app.app
    with application.app_context():
        db.create_all()
        user = User(username='avr_scan_fixture', password='LocalFixture-4812', email='scan@example.com')
        db.session.add(user)
        db.session.commit()
        db.session.add(Book(book_title='scan_fixture', secret_content='scan-fixture-data', user_id=user.id))
        db.session.commit()
    client = application.test_client()
    result = client.post('/users/v1/login', json={'username':'avr_scan_fixture', 'password':'LocalFixture-4812'})
    token = result.get_json()['auth_token']
    headers = {'Authorization': 'Bearer ' + token}
    paths = ['/me', '/users/v1', '/books/v1', '/books/v1/scan_fixture']
    verify = '/me'


def bounded(environ, start_response):
    if environ.get('REQUEST_METHOD') != 'GET' or environ.get('PATH_INFO') not in paths:
        start_response('403 Forbidden', [('Content-Type', 'text/plain')])
        return [b'Outside fixed read-only scan profile']
    return application(environ, start_response)


with make_server('127.0.0.1', args.port, bounded) as server:
    (out / 'ready.json').write_text(json.dumps(dict(headers=headers, paths=paths, verify=verify)), encoding='utf-8')
    server.serve_forever()
