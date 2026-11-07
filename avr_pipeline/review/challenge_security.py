"""Django host regressions plus local build-directory and error-disclosure checks."""
import argparse
import json
from pathlib import Path
from unittest.mock import patch

from external_security import run

p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
repo,out=a.repo.resolve(),a.out.resolve()
if out.exists() or out.is_relative_to(repo):raise ValueError('Fresh output required')
out.mkdir(parents=True)
result=run('pygoat',repo,out)
from challenge.views import _resolve_build_path
from django.test import Client
from django.contrib.auth import get_user_model
from django.conf import settings
def check(name,passed,category='security'):result['checks'].append(dict(name=name,passed=bool(passed),category=category))
check('known local build directory accepted',Path(_resolve_build_path('dockerized_labs/xss_lab')).is_relative_to(Path(settings.BASE_DIR).resolve()),'functionality')
for value in ['../../outside','C:/Windows','unknown/lab']:
    try:_resolve_build_path(value)
    except ValueError:accepted=False
    else:accepted=True
    check('unregistered build path rejected '+value,not accepted)
client=Client(raise_request_exception=False);client.force_login(get_user_model().objects.get(username='avr_owner'))
with patch('challenge.views.get_docker_client',side_effect=RuntimeError('private-container-fixture-detail')):
    r=client.get('/challenge/list-labs/')
    check('container error not disclosed',r.status_code==500 and b'private-container-fixture-detail' not in r.content)
result['passed']=all(r['passed'] for r in result['checks'])
(out/'checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(dict(passed=result['passed'],checks=len(result['checks']))))
raise SystemExit(0 if result['passed'] else 1)
