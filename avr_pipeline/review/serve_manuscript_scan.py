"""Loopback-only SQL/XSS measurement surface with real fixture login cookies.

An outer session gate bounds scanner access; it is not an application repair and
does not establish that the application's native authorization is correct.
"""
import argparse
import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import sys
from wsgiref.simple_server import make_server

p = argparse.ArgumentParser()
p.add_argument('--dataset', choices=('synthetic', 'flask-webgoat'), required=True)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--port', type=int, required=True)
args = p.parse_args()
source, out = args.repo.resolve(), args.out.resolve()
if out.exists() or out.is_relative_to(source):
    raise ValueError('Fresh scanner state must be outside source')
out.mkdir(parents=True)
copy = out/'source'
shutil.copytree(source, copy, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.db', '*.sqlite3', '.pytest_cache'))
os.chdir(copy)
sys.path.insert(0, str(copy))
import werkzeug
if not hasattr(werkzeug, '__version__'):
    werkzeug.__version__ = version('werkzeug')
if args.dataset == 'synthetic':
    spec = importlib.util.spec_from_file_location('scan_subject', copy/'vulnerable_app.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = module.app
    module.init_database()
    path, credentials = '/login', {'username':'alice', 'password':'alice123'}
    seeds = [{'path':'/profile?name=fixture'}, {'path':'/search?q=alice'}]
else:
    from flask_webgoat import create_app
    app = create_app()
    path, credentials = '/login', {'username':'admin', 'password':'admin'}
    seeds = [{'path':'/login', 'method':'POST', 'body':'username=admin&password=admin'},
             {'path':'/login_and_redirect?username=admin&password=admin&url=%2Fstatus'}]
app.config['PROPAGATE_EXCEPTIONS'] = False
from security_test_client import test_client
client = test_client(app)
login = client.post(path, data=credentials)
cookie = next((v.split(';',1)[0] for v in login.headers.getlist('Set-Cookie') if v.startswith(app.config.get('SESSION_COOKIE_NAME', 'session')+'=')), None)
if not cookie:
    raise RuntimeError('Login supplied no session cookie')
with app.test_request_context(headers={'Cookie':cookie}):
    from flask import session
    logged_in = bool(session.get('username') or session.get('user_info'))
if not logged_in:
    raise RuntimeError('Legitimate fixture login did not establish a session')
stats = {'requests':0, 'authenticated_requests':0, 'active_rules':{}, 'active_authenticated_rules':{}, 'statuses':{}}
allowed = {'/profile','/search'} if args.dataset == 'synthetic' else {'/login','/login_and_redirect'}


def measured(environ, start_response):
    stats['requests'] += 1
    with app.request_context(environ):
        from flask import session
        valid = bool(session.get('username') or session.get('user_info'))
    if valid:
        stats['authenticated_requests'] += 1
    rule = environ.get('HTTP_X_ZAP_SCAN_ID')
    if rule:
        stats['active_rules'][rule] = stats['active_rules'].get(rule, 0)+1
        if valid:
            stats['active_authenticated_rules'][rule] = stats['active_authenticated_rules'].get(rule, 0)+1
    def respond(status, headers, exc_info=None):
        stats['statuses'][status] = stats['statuses'].get(status, 0)+1
        (out/'traffic.json').write_text(json.dumps(stats, indent=2))
        return start_response(status, headers, exc_info)
    if not valid:
        respond('401 Unauthorized', [('Content-Type','text/plain')])
        return [b'Fixture session required by measurement gateway']
    if environ.get('PATH_INFO') == '/_verify':
        respond('200 OK', [('Content-Type','text/plain')])
        return [b'Fixture session verified']
    if environ.get('PATH_INFO') not in allowed:
        respond('403 Forbidden', [('Content-Type','text/plain')])
        return [b'Outside fixed SQL/XSS measurement profile']
    return app(environ, respond)


with make_server('127.0.0.1', args.port, measured) as server:
    (out/'ready.json').write_text(json.dumps({'headers':{'Cookie':cookie}, 'verify':'/_verify', 'seeds':seeds}))
    server.serve_forever()
