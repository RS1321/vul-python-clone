"""Explicit agent-authored defensive repairs; separate from measured LLM trials.

Only new local clones are changed. Original benchmark/model observations remain
immutable. Exact net patches and hashes are emitted for review and replay.
"""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'continuation/results/security-resolution'


def function(path, name, replacement):
    text = path.read_text(encoding='utf-8')
    nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise ValueError('Ambiguous target: ' + name)
    node = nodes[0]
    lines = text.splitlines(keepends=True)
    start = min([node.lineno] + [d.lineno for d in node.decorator_list])-1
    change = textwrap.indent(textwrap.dedent(replacement).strip()+'\n', ' '*node.col_offset)
    lines[start:node.end_lineno] = [change]
    result = ''.join(lines)
    compile(result, str(path), 'exec')
    path.write_text(result, encoding='utf-8')


def replace(path, before, after):
    text = path.read_text(encoding='utf-8')
    if text.count(before) != 1:
        raise ValueError('Non-unique exact repair fragment in ' + str(path))
    path.write_text(text.replace(before, after), encoding='utf-8')


def clone(dataset):
    dest = OUT / dataset / 'source'
    if dest.exists():
        raise ValueError('Preserving existing repair clone: ' + str(dest))
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git','clone','--quiet','--no-hardlinks',str(ROOT/'benchmarks'/dataset),str(dest)],check=True)
    return dest


def vampi(repo):
    users = repo/'api_views/users.py'
    books = repo/'api_views/books.py'
    model = repo/'models/user_model.py'
    replace(users, 'import re', 'import re\nimport hmac')
    function(users, 'error_message_helper', '''
def error_message_helper(msg):
    return json.dumps({'status': 'fail', 'message': msg.get('error', 'Invalid request') if isinstance(msg, dict) else str(msg)})
''')
    function(users, 'debug', '''
def debug():
    # Debug data is unavailable on the public API, even to authenticated users.
    return Response(error_message_helper('Not found'), 404, mimetype='application/json')
''')
    function(users, 'register_user', '''
def register_user():
    data = request.get_json(silent=True)
    try:
        jsonschema.validate(data, register_user_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper('Invalid registration'), 400, mimetype='application/json')
    if User.query.filter_by(username=data['username']).first():
        return Response(error_message_helper('Registration unavailable'), 400, mimetype='application/json')
    user = User(username=data['username'], password=data['password'], email=data['email'], admin=False)
    db.session.add(user)
    db.session.commit()
    return jsonify({'status':'success','message':'Registered'})
''')
    function(users, 'login_user', '''
def login_user():
    data = request.get_json(silent=True)
    try:
        jsonschema.validate(data, login_user_schema)
    except jsonschema.exceptions.ValidationError:
        return Response(error_message_helper('Invalid login'), 400, mimetype='application/json')
    user = User.query.filter_by(username=data['username']).first()
    # Run the password KDF for unknown accounts as well as known accounts.
    stored = user.password if user else DUMMY_PASSWORD_HASH
    valid = check_password_hash(stored, data['password'])
    if user and valid:
        return jsonify({'status':'success','message':'Logged in','auth_token':user.encode_auth_token(user.username)})
    return Response(error_message_helper('Username or Password Incorrect!'), 401, mimetype='application/json')
''')
    replace(users, 'import hmac', 'from werkzeug.security import check_password_hash, generate_password_hash\nDUMMY_PASSWORD_HASH = generate_password_hash("not-a-user-password")')
    function(users, 'get_by_username', '''
def get_by_username(username):
    user = User.get_user(username)
    if user is None:
        return Response(error_message_helper('User not found'), 404, mimetype='application/json')
    return jsonify({'username':user.username,'email':user.email})
''')
    function(users, 'update_password', '''
def update_password(username):
    identity = token_validator(request.headers.get('Authorization'))
    if 'error' in identity:
        return Response(error_message_helper('Authentication required'), 401, mimetype='application/json')
    if identity.get('sub') != username:
        return Response(error_message_helper('Forbidden'), 403, mimetype='application/json')
    data = request.get_json(silent=True) or {}
    password = data.get('password')
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return Response(error_message_helper('Invalid password'), 400, mimetype='application/json')
    user = User.query.filter_by(username=username).first()
    if user is None:
        return Response(error_message_helper('User not found'), 404, mimetype='application/json')
    user.password = generate_password_hash(password)
    db.session.commit()
    return Response(status=204)
''')
    function(users, 'update_email', '''
def update_email(username):
    identity = token_validator(request.headers.get('Authorization'))
    if 'error' in identity:
        return Response(error_message_helper('Authentication required'), 401, mimetype='application/json')
    if identity.get('sub') != username:
        return Response(error_message_helper('Forbidden'), 403, mimetype='application/json')
    data = request.get_json(silent=True) or {}
    email = data.get('email')
    if not isinstance(email, str) or len(email) > 254 or re.fullmatch(r'[^@\\s]+@[^@\\s]+\\.[^@\\s]+', email) is None:
        return Response(error_message_helper('Invalid email'), 400, mimetype='application/json')
    user = User.query.filter_by(username=username).first()
    if user is None:
        return Response(error_message_helper('User not found'), 404, mimetype='application/json')
    user.email = email
    db.session.commit()
    return Response(status=204)
''')
    function(books, 'get_by_title', '''
def get_by_title(book_title):
    identity = token_validator(request.headers.get('Authorization'))
    if 'error' in identity:
        return Response(error_message_helper('Authentication required'), 401, mimetype='application/json')
    user = User.query.filter_by(username=identity.get('sub')).first()
    if user is None:
        return Response(error_message_helper('Invalid account'), 401, mimetype='application/json')
    book = Book.query.filter_by(user_id=user.id, book_title=book_title).first()
    if book is None:
        return Response(error_message_helper('Book not found'), 404, mimetype='application/json')
    return jsonify({'book_title':book.book_title,'secret':book.secret_content,'owner':user.username})
''')
    replace(model, 'import datetime', 'import datetime\nfrom werkzeug.security import generate_password_hash')
    replace(model, 'self.password = password', 'self.password = generate_password_hash(password)')
    function(model, 'get_user', '''
@staticmethod
def get_user(username):
    return User.query.filter_by(username=username).first()
''')
    config = repo/'config.py'
    replace(config, "vuln_app.app.config['SECRET_KEY'] = 'random'", "vuln_app.app.config['SECRET_KEY'] = os.environ.get('VAMPI_SECRET_KEY') or os.urandom(32)")
    with config.open('a',encoding='utf-8') as stream:
        stream.write('''

@vuln_app.app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Security-Policy']="default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    return response
''')


def save(dataset, repo):
    out = OUT/dataset
    diff = subprocess.check_output(['git','-C',str(repo),'diff','--binary','--'])
    # A patch can contain committed CRLF lines as well as LF diff delimiters.
    # Text-mode writing would double CR characters and break replay.
    (out/'hardening.patch').write_bytes(diff)
    files = subprocess.check_output(['git','-C',str(repo),'diff','--name-only']).decode().splitlines()
    manifest = dict(dataset=dataset, author='agent-authored defensive follow-up; not a measured free-model trial',
        source_commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD']).decode().strip(),
        files=[dict(path=p,sha256=hashlib.sha256((repo/p).read_bytes()).hexdigest()) for p in files])
    (out/'repair-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'dataset':dataset,'changed_files':len(files)}))


if __name__ == '__main__':
    dataset=sys.argv[1]
    if len(sys.argv)>2:
        import re
        label=sys.argv[2]
        if not re.fullmatch(r'[a-z0-9-]+',label):raise ValueError('Invalid label')
        OUT=ROOT/('continuation/results/security-resolution-'+label)
    repo=clone(dataset)
    if dataset=='vampi':vampi(repo)
    elif dataset=='pygoat':
        # Retain the best previous generated patch, then apply explicit follow-up.
        patch=ROOT/'review_results/gemini-3.5-flash-lite-A-pygoat-fivefree-v2-r1/net.patch'
        subprocess.run(['git','-C',str(repo),'apply','--whitespace=nowarn',str(patch)],check=True)
        from pygoat_hardening import harden
        harden(repo)
    else:raise ValueError('Unexpected dataset')
    if len(sys.argv)>2 and sys.argv[2] in ('v5','v6'):
        import static_followup
        getattr(static_followup,dataset)(repo)
    save(dataset,repo)
