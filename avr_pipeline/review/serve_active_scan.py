"""Loopback-only active-scan targets with fixture authentication and SQL/XSS routes.

PyGoat lessons are mounted behind verification against the real Django fixture
session, representing the authenticated lesson boundary without Docker/Traefik.
Only the SQL/XSS lessons are mounted; command/file/network lessons are absent.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
from wsgiref.simple_server import make_server

p=argparse.ArgumentParser();p.add_argument('--dataset',choices=['pygoat','vampi'],required=True);p.add_argument('--repo',type=Path,required=True)
p.add_argument('--out',type=Path,required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--auth-host');p.add_argument('--auth-ready',type=Path);args=p.parse_args()
repo,out=args.repo.resolve(),args.out.resolve()
if out.exists() or out.is_relative_to(repo):raise ValueError('Fresh state outside input required')
out.mkdir(parents=True);source=out/'source'
shutil.copytree(repo,source,ignore=shutil.ignore_patterns('.git','__pycache__','*.db','*.sqlite3'))
os.chdir(source);sys.path.insert(0,str(source))
if args.dataset=='vampi':
    import config
    from config import db
    from models.user_model import User
    from models.books_model import Book
    application=config.vuln_app.app
    application.config['PROPAGATE_EXCEPTIONS']=False
    with application.app_context():
        db.create_all();user=User(username='avr_scan_fixture',password='LocalFixture-4812',email='scan@example.com');db.session.add(user);db.session.commit()
        db.session.add(Book(book_title='scan_fixture',secret_content='scan-fixture-data',user_id=user.id));db.session.commit()
    login=application.test_client().post('/users/v1/login',json={'username':'avr_scan_fixture','password':'LocalFixture-4812'}).get_json()
    headers={'Authorization':'Bearer '+login['auth_token']}
    verify='/me'
    seeds=[dict(path='/me'),dict(path='/users/v1/avr_scan_fixture'),dict(path='/books/v1/scan_fixture')]
else:
    import requests
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    auth=requests.Session();auth.trust_env=False
    data=json.loads(args.auth_ready.read_text());headers={'X-AVR-Django-Session':data['headers']['Cookie']};verify='/_verify'
    mounts={}
    for name in ['sql_injection_lab','xss_lab']:
        folder=source/'dockerized_labs'/name;os.chdir(folder)
        spec=importlib.util.spec_from_file_location('active_'+name,folder/'app.py')
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        module.app.config['PROPAGATE_EXCEPTIONS']=False
        module.app.config['SESSION_COOKIE_PATH']='/_lessons/'+name
        if name=='sql_injection_lab':
            module.init_db()
            import sqlite3
            with sqlite3.connect('database.db') as connection:connection.execute('INSERT OR REPLACE INTO users VALUES (?,?)',('avr_scan_fixture','LocalFixture-4812'))
        def with_cwd(environ,start_response,folder=folder,application=module.app):
            prior=os.getcwd();os.chdir(folder)
            try:return list(application(environ,start_response))
            finally:os.chdir(prior)
        mounts['/_lessons/'+name]=with_cwd
    def root(environ,start_response):
        start_response('200 OK',[('Content-Type','text/plain')]);return [b'Authenticated lesson gateway']
    application=DispatcherMiddleware(root,mounts)
    seeds=[dict(path='/_lessons/xss_lab/lab1?q=fixture'),dict(path='/_lessons/xss_lab/lab2',method='POST',body='username=fixture'),
           dict(path='/_lessons/sql_injection_lab/lab',method='POST',body='username=avr_scan_fixture&password=LocalFixture-4812')]

stats={'requests':0,'authenticated_requests':0,'active_rules':{},'statuses':{}}
def bounded(environ,start_response):
    stats['requests']+=1
    if args.dataset=='pygoat':
        cookie=environ.get('HTTP_X_AVR_DJANGO_SESSION','')
        valid=bool(cookie) and auth.get(args.auth_host+'/',headers={'Cookie':cookie},allow_redirects=False,timeout=3).status_code==200
        allowed=environ.get('PATH_INFO')=='/_verify' or any(environ.get('PATH_INFO','').startswith('/_lessons/'+lab+'/') for lab in ['sql_injection_lab','xss_lab'])
    else:
        valid=environ.get('HTTP_AUTHORIZATION')==headers['Authorization']
        path=environ.get('PATH_INFO','')
        allowed=environ.get('REQUEST_METHOD')=='GET' and (path=='/me' or path.startswith('/users/v1/') or path.startswith('/books/v1/'))
    if valid:stats['authenticated_requests']+=1
    rule=environ.get('HTTP_X_ZAP_SCAN_ID')
    if rule:stats['active_rules'][rule]=stats['active_rules'].get(rule,0)+1
    def response(status,header_list,exc_info=None):
        stats['statuses'][status]=stats['statuses'].get(status,0)+1
        (out/'traffic.json').write_text(json.dumps(stats,indent=2),encoding='utf-8')
        return start_response(status,header_list,exc_info)
    if not allowed:
        response('403 Forbidden',[('Content-Type','text/plain')]);return [b'Outside scan profile']
    # VAmPI's native authorization is measured unchanged on individual endpoints.
    # The PyGoat gateway enforces the outer Django authentication boundary.
    if args.dataset=='pygoat' and not valid:
        response('401 Unauthorized',[('Content-Type','text/plain')]);return [b'Authentication required']
    return application(environ,response)

with make_server('127.0.0.1',args.port,bounded) as server:
    (out/'ready.json').write_text(json.dumps(dict(headers=headers,verify=verify,seeds=seeds)),encoding='utf-8')
    server.serve_forever()
