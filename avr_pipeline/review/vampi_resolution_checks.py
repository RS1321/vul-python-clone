"""Original eight checks plus legitimate password/email update regressions."""
import argparse
import json
from pathlib import Path

from external_security import run

p=argparse.ArgumentParser();p.add_argument('--repo',required=True,type=Path);p.add_argument('--out',required=True,type=Path);args=p.parse_args()
out=args.out.resolve();repo=args.repo.resolve()
if out.exists() or out.is_relative_to(repo):raise ValueError('Fresh output required')
out.mkdir(parents=True)
result=run('vampi',repo,out)
from config import db,vuln_app
from models.user_model import User
from werkzeug.security import check_password_hash
app=vuln_app.app;client=app.test_client()
def record(name,passed,category='security'):
    result['checks'].append(dict(name=name,passed=bool(passed),category=category))
def login(name,password):
    r=client.post('/users/v1/login',json={'username':name,'password':password})
    return r,(r.get_json() or {}).get('auth_token','')
r,token=login('avr_owner','LocalFixture-4812');owner={'Authorization':'Bearer '+token}
r,token=login('avr_other','OtherFixture-4812');other={'Authorization':'Bearer '+token}
client.put('/users/v1/avr_owner/email',headers=other,json={'email':'wrong@example.com'})
with app.app_context():record('other account cannot change owner email',User.query.filter_by(username='avr_owner').first().email=='owner@example.com')
r=client.put('/users/v1/avr_owner/email',headers=owner,json={'email':'changed@example.com'})
with app.app_context():record('owner email change works',r.status_code==204 and User.query.filter_by(username='avr_owner').first().email=='changed@example.com','functionality')
r=client.put('/users/v1/avr_owner/password',headers=owner,json={'password':'ChangedOwner-4812'})
record('owner password change works',r.status_code==204,'functionality')
with app.app_context():
    stored=User.query.filter_by(username='avr_owner').first().password
    record('password stored as KDF hash',stored!='ChangedOwner-4812' and check_password_hash(stored,'ChangedOwner-4812'))
r,token=login('avr_owner','ChangedOwner-4812');record('new password logs in',r.status_code==200 and bool(token),'functionality')
r,token=login('avr_owner','LocalFixture-4812');record('old password no longer works',r.status_code==401 and not token)
security=[r for r in result['checks'] if r['category']=='security']
result.update(security_passed=sum(r['passed'] for r in security),security_total=len(security),functionality_passed=all(r['passed'] for r in result['checks'] if r['category']=='functionality'))
result['passed']=all(r['passed'] for r in result['checks'])
(out/'checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({k:result[k] for k in ['passed','security_passed','security_total','functionality_passed']}))
raise SystemExit(0 if result['passed'] else 1)
