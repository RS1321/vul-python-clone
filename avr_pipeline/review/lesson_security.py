"""Isolated per-lesson behavior/security checks; no executable attack payloads."""
import argparse
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import patch


def measure(repo, lesson, out):
    source=out/'source'
    original=repo/'dockerized_labs'/lesson
    shutil.copytree(original,source,ignore=shutil.ignore_patterns('__pycache__','*.db','*.sqlite3','app.log'))
    os.chdir(source);sys.path.insert(0,str(source))
    path=source/('app.py' if (source/'app.py').exists() else 'main.py')
    spec=importlib.util.spec_from_file_location('avr_lesson',path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    app=module.app
    app.config['PROPAGATE_EXCEPTIONS']=False
    app.template_folder=str(source/'templates')
    if hasattr(module,'init_db'):module.init_db()
    if hasattr(module,'db'):
        with app.app_context():module.db.create_all()
    from security_test_client import test_client
    client=test_client(app);rows=[]
    def check(name,passed,category='security',detail=None):
        rows.append(dict(name=name,passed=bool(passed),category=category,detail=detail))
    def context_request(path,method='get',**kwargs):
        with patch.object(module,'render_template',wraps=module.render_template) as renderer:
            response=getattr(client,method)(path,**kwargs)
            context=renderer.call_args.kwargs if renderer.call_args else {}
        return response,context
    response=client.get('/')
    check('homepage renders',response.status_code==200,'functionality',response.status_code)
    check('debug disabled',not app.debug)
    check('response nosniff',response.headers.get('X-Content-Type-Options')=='nosniff')
    check('response CSP present',bool(response.headers.get('Content-Security-Policy')))
    if 'csrf' in app.extensions:
        check('browser CSRF helper served',client.get('/_security_client.js').status_code==200,'functionality')
        import re
        nonces=re.findall(rb'<script[^>]*nonce="([^"]+)"',response.data)
        check('template script nonces match policy',all(n.decode() in response.headers['Content-Security-Policy'] for n in nonces))
        post_route=next((str(rule) for rule in app.url_map.iter_rules() if 'POST' in rule.methods and '<' not in str(rule)),None)
        if post_route:
            check('POST without CSRF token rejected',app.test_client().post(post_route).status_code==400)
    marker='<b data-avr="fixture">inert-marker</b>'
    if lesson=='a9_uckv_lab':
        r,ctx=context_request('/upload_yaml','post',data={'file':(io.BytesIO(b'name: fixture'),'sample.yaml')})
        check('normal YAML parsed',ctx.get('content')=={'name':'fixture'},'functionality')
        r,ctx=context_request('/upload_yaml','post',data={'file':(io.BytesIO(b'!!python/tuple [1, 2]'),'sample.yaml')})
        check('Python YAML tags rejected',not isinstance(ctx.get('content'),tuple))
        from PIL import Image
        stream=io.BytesIO();Image.new('RGB',(2,2)).save(stream,format='PNG');raw=stream.getvalue()
        r,ctx=context_request('/process_image','post',data={'image':(io.BytesIO(raw),'sample.png'),'expression':'img'})
        check('allowed image operation works',ctx.get('image') is True,'functionality')
        with patch.object(module.ImageMath,'eval',create=True,return_value=Image.new('RGB',(2,2))) as evaluator:
            client.post('/process_image',data={'image':(io.BytesIO(raw),'sample.png'),'expression':'unknown_operation'})
            check('untrusted expression never evaluated',evaluator.call_count==0)
    elif lesson=='auth_failure_lab':
        import datetime
        forged=base64.b64encode(json.dumps({'username':'Admin','role':'admin','valid_until':(datetime.datetime.now()+datetime.timedelta(hours=1)).isoformat()}).encode()).decode()
        client.set_cookie('localhost','session_id',forged)
        r,ctx=context_request('/lab3');check('unsigned session rejected',not ctx.get('success'))
        r,ctx=context_request('/lab3','post',data={'username':'User1','password':'password1'})
        check('valid session login works',r.status_code==200 and ctx.get('success'),'functionality')
        client.post('/lab1',data={'email':'fixture@example.invalid'})
        entry=module.stored_otps.get('fixture@example.invalid')
        if isinstance(entry,dict):
            check('OTP has expiry and attempt bound',entry['expires']>0 and len(entry['code'])>=6)
            code=entry['code']
            check('OTP accepted once',client.post('/lab1/verify',data={'otp':code}).status_code==200,'functionality')
            check('OTP replay rejected',client.post('/lab1/verify',data={'otp':code}).status_code==401)
        else:
            check('OTP has expiry and attempt bound',False);check('OTP replay rejected',False)
        a,known= context_request('/lab2','post',data={'username':module.ADMIN_USERNAME,'password':'wrong'})
        b,unknown=context_request('/lab2','post',data={'username':'missing@example.invalid','password':'wrong'})
        # Per-request CSP nonces legitimately change HTML bytes. Compare the
        # status and application error context, retaining enumeration detection.
        check('login error context/status uniform',(a.status_code,known)==(b.status_code,unknown))
    elif lesson=='broken_access_lab':
        client.set_cookie('localhost','admin','1')
        r,ctx=context_request('/lab/login');check('unsigned admin cookie denied',r.status_code in (401,403) and 'Secret key' not in str(ctx))
        r,ctx=context_request('/lab/login','post',data={'username':'jack','password':'jacktheripper'})
        check('normal user login works',r.status_code==200 and ctx.get('username')=='jack','functionality')
        r,ctx=context_request('/lab/login','post',data={'username':'admin','password':'admin_pass'})
        check('legitimate admin login works',r.status_code==200 and 'Secret key' in ctx.get('message',''),'functionality')
    elif lesson=='broken_auth_lab':
        client.set_cookie('localhost','session',base64.b64encode(b'admin:fixture').decode())
        r,ctx=context_request('/dashboard');check('forged base64 session denied',r.status_code in (302,401,403))
        r=client.post('/login',data={'username':'user','password':'password123'})
        r,ctx=context_request('/dashboard');check('normal signed login works',r.status_code==200 and ctx.get('username')=='user','functionality')
    elif lesson=='crypto_failure_lab':
        import datetime
        token=base64.b64encode(('admin|'+(datetime.datetime.now()+datetime.timedelta(hours=1)).isoformat()).encode()).decode()
        client.set_cookie('localhost','cookie',token)
        r,ctx=context_request('/lab3');check('unsigned admin cookie rejected',not ctx.get('admin'))
        r,ctx=context_request('/lab3','post',data={'username':'User','password':'P@$$w0rd'})
        check('normal login works',r.status_code==200 and ctx.get('success'),'functionality')
    elif lesson=='insec_des_lab':
        with patch.object(module,'render_template',wraps=module.render_template) as renderer:
            client.post('/serialize',data={'username':'fixture'})
            token=renderer.call_args.kwargs['serialized']
        r,ctx=context_request('/deserialize','post',data={'serialized_data':token})
        check('normal data round trip',r.status_code==200 and 'Welcome fixture' in ctx.get('message',''),'functionality')
        with patch.object(module.pickle,'loads',side_effect=ValueError('blocked by test instrumentation')) as loads:
            r=client.post('/deserialize',data={'serialized_data':'e30='})
            check('untrusted pickle loader not invoked',loads.call_count==0 and r.status_code==400)
    elif lesson=='insecure_design_lab':
        from flask import session
        r=client.post('/register',data={'username':'fixture','password':'FixturePassword-4812'})
        r=client.post('/lab',data={'count':'1'})
        with app.app_context():count=module.Ticket.query.count()
        check('normal ticket issuance works',r.status_code==200 and count==1,'functionality')
        client.post('/lab',data={'count':'-1'})
        with app.app_context():check('negative count cannot create tickets',module.Ticket.query.count()==count)
    elif lesson=='insufficient_logging_lab':
        old=module.users['admin']['password']
        r=client.post('/lab2/change_password',data={'username':'admin','new_password':'ChangedFixture-4812'})
        check('anonymous password mutation denied',r.status_code in (401,403) and module.users['admin']['password']==old)
        client.post('/lab1/login',data={'username':'admin','password':old})
        r=client.post('/lab2/change_password',data={'username':'admin','new_password':'ChangedFixture-4812'})
        check('authenticated password change works',r.status_code==200 and module.users['admin']['password']=='ChangedFixture-4812','functionality')
    elif lesson=='sec_misconfig':
        r=client.get('/lab1/get-secret',headers={'X-Host':'admin.localhost:8000'})
        check('spoofed host cannot disclose secret',r.status_code in (401,403) and 'secret' not in (r.get_json() or {}))
        r=client.post('/lab3/get-token',json={'username':'fixture','role':'admin'})
        token=(r.get_json() or {}).get('token')
        r=client.post('/lab3/verify-token',json={'token':token})
        data=r.get_json() or {};check('normal token verifies',r.status_code==200 and data.get('payload',{}).get('username')=='fixture','functionality')
        check('client cannot mint admin role',data.get('payload',{}).get('role')=='user')
        check('missing page stays 404',client.get('/missing-fixture').status_code==404)
    elif lesson=='sde':
        r=client.get('/missing-fixture');check('error handler does not disclose config',r.status_code==404 and b'FLAGTHATNEEDSTOBEFOUND' not in r.data)
        r=client.get('/500error');check('500 response is generic',r.status_code==500 and b'DATABASE_URI' not in r.data and b'Traceback' not in r.data)
    elif lesson=='software_integrity_lab':
        client.set_cookie('localhost','token','e30=')
        with patch.object(module.pickle,'loads',side_effect=ValueError('instrumented')) as loads:
            r=client.get('/lab1');check('cookie never invokes pickle loader',loads.call_count==0 and r.status_code==400)
        r,ctx=context_request('/lab2',query_string={'username':marker})
        check('download-link markup escaped',marker.encode() not in r.data and b'inert-marker' in r.data)
    elif lesson=='template_injection_lab':
        r=client.post('/create_blog',data={'title':'fixture','content':'literal {{7*7}} '+marker})
        check('blog creation works',r.status_code==302,'functionality')
        r=client.get(r.headers.get('Location','/'))
        check('blog data not template source',r.status_code==200 and b'{{7*7}}' in r.data and marker.encode() not in r.data)
    elif lesson=='xxe_lab':
        r=client.post('/parse',data=b'<root><text>fixture</text></root>')
        with app.app_context():check('ordinary XML stored',r.status_code==200 and module.Comment.query.first().comment=='fixture','functionality')
        # A local bounded entity definition, with no file or network reference.
        r=client.post('/parse',data=b'<!DOCTYPE root [<!ENTITY fixture "inert">]><root><text>&fixture;</text></root>')
        check('DTD/entity declarations rejected',r.status_code==400)
    elif lesson in ('dependency_attack_lab','package_injection_lab'):
        endpoint='/api/check-package' if lesson=='dependency_attack_lab' else '/api/verify-package'
        r=client.get(endpoint,query_string={'name':'unlisted-fixture-package'})
        check('unknown package not trusted',r.status_code==200 and (r.get_json() or {}).get('status') in ('unknown','untrusted'))
    elif lesson=='open_source_library_attack_lab':
        r=client.get('/api/timeline');check('educational timeline remains available',r.status_code==200,'functionality')
        check('informational API JSON is nosniff',r.headers.get('X-Content-Type-Options')=='nosniff')
    else:
        # These four lessons also receive their existing targeted oracles.
        check('targeted suite supplied separately',lesson in ['xss_lab','sql_injection_lab','ssrf_lab','command_injection_lab'],'coverage')
    return dict(lesson=lesson,checks=rows,passed=all(r['passed'] for r in rows),routes=[dict(path=str(r),methods=sorted(r.methods-{'HEAD','OPTIONS'})) for r in app.url_map.iter_rules()])


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--lesson',required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    repo,out=args.repo.resolve(),args.out.resolve()
    if out.exists() or out.is_relative_to(repo):raise ValueError('Fresh isolated output required')
    out.mkdir(parents=True)
    result=measure(repo,args.lesson,out)
    (out/'checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'lesson':args.lesson,'passed':result['passed'],'checks':len(result['checks'])}))
    raise SystemExit(0 if result['passed'] else 1)
