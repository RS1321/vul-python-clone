"""Separate Django lesson: anonymous, owner and staff disclosure checks."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
out=args.out.resolve();repo=args.repo.resolve()
if out.exists() or out.is_relative_to(repo):raise ValueError('Fresh output required')
source=out/'source'
shutil.copytree(repo/'dockerized_labs/sensitive_data_exposure',source,ignore=shutil.ignore_patterns('__pycache__','*.db','*.sqlite3'))
sys.path.insert(0,str(source));os.environ['DJANGO_SETTINGS_MODULE']='sensitive_data_lab.settings'
from django.conf import settings
settings.DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':str(out/'fixture.sqlite3')}}
settings.ALLOWED_HOSTS=['testserver']
settings.DEBUG=False
import django
django.setup()
from django.core.management import call_command
from django.contrib.auth.models import User
from django.test import Client
from dataexposure.models import UserData
call_command('migrate',verbosity=0,interactive=False)
owner=User.objects.create_user(username='avr_owner',password='LocalFixture-4812')
other=User.objects.create_user(username='avr_other',password='OtherFixture-4812')
staff=User.objects.create_user(username='avr_staff',password='StaffFixture-4812',is_staff=True)
UserData.objects.create(user=owner,credit_card='4111111111111111',ssn='123456789',api_key='fixture-private-key')
rows=[]
def check(name,passed,category='security'):rows.append(dict(name=name,passed=bool(passed),category=category))
client=Client(raise_request_exception=False)
r=client.get('/api/all-users/');check('anonymous bulk data denied',r.status_code in (401,403))
client.force_login(other);r=client.get('/api/all-users/');check('ordinary account bulk data denied',r.status_code in (401,403))
client.force_login(owner);r=client.get('/api/user-data/');check('owner API remains available',r.status_code==200,'functionality')
check('owner API omits raw secrets',all(v not in r.content for v in [b'4111111111111111',b'123456789',b'fixture-private-key']))
client.force_login(staff);r=client.get('/api/all-users/');check('authorized staff listing works',r.status_code==200 and b'avr_owner' in r.content,'functionality')
check('staff listing omits raw secrets',all(v not in r.content for v in [b'4111111111111111',b'123456789',b'fixture-private-key']))
result=dict(lesson='sensitive_data_exposure',checks=rows,passed=all(r['passed'] for r in rows))
(out/'checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(dict(lesson=result['lesson'],passed=result['passed'],checks=len(rows))))
raise SystemExit(0 if result['passed'] else 1)
