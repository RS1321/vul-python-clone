"""Agent-authored follow-up policies for separate PyGoat lesson clones."""
from pathlib import Path
import ast
import re


def harden_settings(repo):
    for path in [repo/'pygoat/settings.py',repo/'dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py']:
        text=path.read_text(encoding='utf-8');lines=text.splitlines(keepends=True)
        for node in sorted(ast.parse(text).body,key=lambda n:n.lineno,reverse=True):
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEBUG' for t in node.targets):
                lines[node.lineno-1:node.end_lineno]=['DEBUG = False\n']
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SECRET_KEY' for t in node.targets):
                lines[node.lineno-1:node.end_lineno]=["import os as _security_os\nimport secrets as _security_secrets\nSECRET_KEY = _security_os.environ.get('PYGOAT_SECRET_KEY') or _security_secrets.token_hex(32)\n"]
        text=''.join(lines);compile(text,str(path),'exec');path.write_text(text,encoding='utf-8')
from resolve_security import function, replace


def harden(repo):
    harden_settings(repo)
    labs=repo/'dockerized_labs'
    # Drop unsafe template trust markers, including nested stored-blog templates.
    for p in labs.rglob('*.html'):
        text=p.read_text(encoding='utf-8')
        text=text.replace('|safe','').replace('| safe','')
        if 'sensitive_data_exposure' not in p.parts:
            text=re.sub(r'(<form\b[^>]*method=[\"\x27]post[\"\x27][^>]*>)',r'\1<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">',text,flags=re.I)
            text=re.sub(r'<(script|style)\b(?![^>]*\bnonce=)',r'<\1 nonce="{{ csp_nonce }}"',text,flags=re.I)
        p.write_text(text,encoding='utf-8')
    # A shared defense-in-depth response policy is attached to every Flask app.
    # It does not replace per-route ownership and input-validation repairs.
    for p in list(labs.glob('*/app.py'))+list(labs.glob('*/main.py')):
        text=p.read_text(encoding='utf-8')
        policy = '''

# Defensive follow-up for the isolated hardened clone.
import secrets as _security_secrets
from flask_wtf import CSRFProtect as _CSRFProtect
from flask import g as _g, request as _req, url_for as _url_for, Response as _Response
from flask_wtf.csrf import generate_csrf as _generate_csrf
app.config.update(DEBUG=False, SECRET_KEY=_security_secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  MAX_CONTENT_LENGTH=1024 * 1024)
_CSRFProtect(app)
def _csp_nonce():
    if not hasattr(_g,'csp_nonce'):_g.csp_nonce=_security_secrets.token_urlsafe(24)
    return _g.csp_nonce
@app.context_processor
def _security_context():
    return {'csp_nonce':_csp_nonce()}
@app.route('/_security_client.js')
def _security_client():
    return _Response("""(() => {
      const original = window.fetch;
      window.fetch = function(input, init) {
        const request = new Request(input, init);
        if (new URL(request.url).origin === location.origin && !['GET','HEAD','OPTIONS'].includes(request.method)) {
          const token = document.querySelector('meta[name=csrf-token]');
          if (token) { const headers = new Headers(request.headers); headers.set('X-CSRFToken', token.content); return original(new Request(request, {headers})); }
        }
        return original(request);
      };
    })();""",mimetype='application/javascript')
@app.after_request
def _security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    nonce=_csp_nonce()
    response.headers['Content-Security-Policy'] = ("default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
        "script-src 'self' 'nonce-"+nonce+"' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'nonce-"+nonce+"' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com")
    response.headers['Cache-Control'] = 'no-store'
    if response.mimetype=='text/html' and not response.direct_passthrough:
        html=response.get_data(as_text=True)
        if '</head>' in html:
            tag='<meta name="csrf-token" content="'+_generate_csrf()+'"><script src="'+_url_for('_security_client')+'"></script>'
            response.set_data(html.replace('</head>',tag+'</head>',1))
    return response
'''
        guard=next((n for n in ast.parse(text).body if isinstance(n,ast.If) and '__name__' in ast.unparse(n.test)),None)
        if guard:
            lines=text.splitlines(keepends=True)
            lines.insert(guard.lineno-1,policy+'\n')
            text=''.join(lines)
        else:text+=policy
        text=text.replace('debug=True','debug=False').replace('use_reloader=True','use_reloader=False')
        p.write_text(text,encoding='utf-8')
    p=labs/'dependency_attack_lab/app.py'
    function(p,'check_package','''
@app.route('/api/check-package')
def check_package():
    name=request.args.get('name','').strip().lower()
    if name=='data-utils':return jsonify({'package':name,'status':'untrusted'})
    if name in {'flask','requests','common-helpers'}:
        return jsonify({'package':name,'status':'trusted','note':'Illustrative local allowlist only; not signature verification'})
    return jsonify({'package':name,'status':'unknown'})
''')
    p=labs/'xss_lab/app.py'
    function(p,'toggle_theme','''
@app.route('/toggle-theme')
def toggle_theme():
    resp=make_response(redirect('/'))
    resp.set_cookie('theme','dark' if request.cookies.get('theme')=='light' else 'light',httponly=True,samesite='Lax')
    return resp
''')
    p=labs/'template_injection_lab/app.py'
    function(p,'create_blog_post','''
def create_blog_post(title, content):
    from markupsafe import escape
    filename=f'{uuid.uuid4()}.html'
    # Literal user text is escaped before insertion into the template source;
    # template delimiters are never evaluated as user-provided Jinja source.
    import json
    with open(os.path.join(BLOG_DIR,filename), 'w',encoding='utf-8') as stream:
        json.dump({'title':title,'content':content},stream)
    return filename
''')
    function(p,'view_blog','''
@app.route('/blog/<filename>')
def view_blog(filename):
    import json
    from pathlib import Path
    from markupsafe import escape
    if Path(filename).name!=filename or not filename.endswith('.html'):
        return 'Not found',404
    try:
        data=json.loads((Path(BLOG_DIR)/filename).read_text(encoding='utf-8'))
    except (OSError,ValueError):
        return 'Not found',404
    return '<h3>'+str(escape(data['title']))+'</h3><div>'+str(escape(data['content']))+'</div>'
''')
    function(p,'get_blog_posts','''
def get_blog_posts():
    import json
    posts=[]
    for filename in os.listdir(BLOG_DIR):
        if filename.endswith('.html'):
            try:
                with open(os.path.join(BLOG_DIR,filename),encoding='utf-8') as stream:data=json.load(stream)
                posts.append({'filename':filename,'title':data['title']})
            except (OSError,ValueError,KeyError):continue
    return posts
''')
    p=labs/'a9_uckv_lab/app.py'
    if 'data = yaml.safe_load(file.stream)' not in p.read_text(encoding='utf-8'):
        replace(p,'data = yaml.load(file.stream, Loader=yaml.Loader)','data = yaml.safe_load(file.stream)')
    replace(p,'output = ImageMath.eval(expression, img=img, r=r, g=g, b=b)',"output = {'img': img, 'r': r.convert('RGB'), 'g': g.convert('RGB'), 'b': b.convert('RGB')}[expression]")
    p=labs/'insec_des_lab/main.py'
    function(p,'serialize_data','''
@app.route('/serialize',methods=['POST'])
def serialize_data():
    from itsdangerous import URLSafeTimedSerializer
    token=URLSafeTimedSerializer(app.secret_key,salt='lesson-user').dumps({'username':request.form.get('username','guest'),'is_admin':False})
    return render_template('result.html',serialized=token)
''')
    function(p,'deserialize_data','''
@app.route('/deserialize',methods=['POST'])
def deserialize_data():
    from itsdangerous import URLSafeTimedSerializer,BadSignature
    try:
        data=URLSafeTimedSerializer(app.secret_key,salt='lesson-user').loads(request.form.get('serialized_data',''),max_age=3600)
        return render_template('result.html',message=f"Welcome {data['username']}. Only admins can see the secret content.")
    except (BadSignature,KeyError,TypeError):return render_template('result.html',message='Invalid user data'),400
''')
    p=labs/'software_integrity_lab/app.py'
    function(p,'lab1','''
@app.route('/lab1')
def lab1():
    from itsdangerous import URLSafeTimedSerializer,BadSignature
    codec=URLSafeTimedSerializer(app.secret_key,salt='integrity-user')
    token=request.cookies.get('token')
    if token:
        try:codec.loads(token,max_age=3600)
        except BadSignature:return render_template('lab1.html',error='Invalid token'),400
    response=make_response(render_template('lab1.html',message='Only Admins can see this page'))
    response.set_cookie('token',codec.dumps({'admin':False}),httponly=True,samesite='Lax')
    return response
''')
    p=labs/'xxe_lab/app.py'
    function(p,'xxe_parse','''
@app.route('/parse',methods=['POST'])
def xxe_parse():
    from defusedxml import ElementTree
    try:
        if len(request.data)>65536:return 'XML too large',413
        root=ElementTree.fromstring(request.data)
        node=root.find('.//text') if root.tag!='text' else root
        text=node.text if node is not None else ''
        row=Comment.query.first()
        if row is None:row=Comment(comment=text or '');db.session.add(row)
        else:row.comment=text or ''
        db.session.commit()
        return render_template('xxe_lab.html')
    except Exception:
        return render_template('xxe_lab.html',error='Invalid XML'),400
''')
    p=labs/'broken_access_lab/main.py'
    function(p,'lab_login','''
@app.route('/lab/login',methods=['GET','POST'])
def lab_login():
    from flask import session
    if request.method=='POST':
        username=request.form.get('username','');password=request.form.get('password','')
        if username not in users or users[username].password!=password:
            return render_template('result.html',message='Invalid credentials'),401
        session.clear();session['username']=username
    user=users.get(session.get('username'))
    if user is None:return render_template('result.html',message='Authentication required'),401
    return render_template('result.html',username=user.username,message='Welcome Admin! Secret key: ADMIN_KEY_123' if user.is_admin else 'Welcome back!')
''')
    p=labs/'broken_auth_lab/app.py'
    function(p,'login','''
@app.route('/login',methods=['POST'])
def login():
    from flask import session
    username=request.form.get('username','');password=request.form.get('password','')
    if username in users and users[username]['password']==password:
        session.clear();session['username']=username
        return redirect(url_for('dashboard'))
    return render_template('lab.html',error='Invalid credentials'),401
''')
    function(p,'dashboard','''
@app.route('/dashboard')
def dashboard():
    from flask import session
    username=session.get('username')
    if username not in users:return redirect(url_for('lab'))
    return render_template('dashboard.html',username=username,role=users[username]['role'],email=users[username]['email'])
''')
    function(p,'reset_password','''
@app.route('/reset-password',methods=['POST'])
def reset_password():
    # A production mail transport is deliberately not configured in this lab.
    # Never return a live password-reset bearer token in the HTTP response.
    flash('If the account exists, reset instructions will be sent.')
    return redirect(url_for('lab'))
''')
    p=labs/'crypto_failure_lab/app.py'
    function(p,'lab3','''
@app.route('/lab3',methods=['GET','POST'])
def lab3():
    from flask import session
    if request.method=='POST':
        if request.form.get('username')!='User' or request.form.get('password')!='P@$$w0rd':
            return render_template('lab3.html',success=False,failure=True),401
        session.clear();session['crypto_user']='User'
    return render_template('lab3.html',success=bool(session.get('crypto_user')),admin=False,logged_in=bool(session.get('crypto_user')))
''')
    p=labs/'auth_failure_lab/app.py'
    function(p,'lab1','''
@app.route('/lab1',methods=['GET','POST'])
def lab1():
    from flask import session
    import secrets,time
    if request.method=='POST':
        email=request.form.get('email','')
        if not email or len(email)>254:return 'Invalid email',400
        stored_otps[email]={'code':f'{secrets.randbelow(1000000):06d}','expires':time.time()+300,'attempts':0}
        session['otp_email']=email
        # Delivery belongs to the configured mail transport, never the response.
        return render_template('lab1.html',otp_form=True)
    return render_template('lab1.html')
''')
    function(p,'verify_otp','''
@app.route('/lab1/verify',methods=['POST'])
def verify_otp():
    from flask import session
    import time,secrets
    email=session.get('otp_email');entry=stored_otps.get(email)
    if not entry or entry['expires']<time.time() or entry['attempts']>=5:
        return render_template('lab1.html',otp_form=True),401
    entry['attempts']+=1
    if not secrets.compare_digest(entry['code'],request.form.get('otp','')):
        return render_template('lab1.html',otp_form=True),401
    stored_otps.pop(email,None);session.pop('otp_email',None)
    return render_template('lab1.html',email=email)
''')
    function(p,'lab3','''
@app.route('/lab3',methods=['GET','POST'])
def lab3():
    from flask import session
    if request.method=='POST':
        username=request.form.get('username','');password=request.form.get('password','')
        if username not in USERS or USERS[username]['password']!=hashlib.sha256(password.encode()).hexdigest():
            return render_template('lab3.html',failure=True),401
        session.clear();session['auth_user']=username
    username=session.get('auth_user')
    return render_template('lab3.html',username=username,success=username in USERS)
''')
    function(p,'lab2','''
@app.route('/lab2',methods=['GET','POST'])
def lab2():
    if request.method=='POST':
        user=Admin.query.filter_by(username=request.form.get('username','')).first()
        try:
            if user is not None and not user.is_locked:
                PasswordHasher().verify(user.password,request.form.get('password',''))
                return render_template('lab2.html',user=user,success=True)
        except Exception:pass
        return render_template('lab2.html',success=False,failure=True,error='Invalid credentials'),401
    return render_template('lab2.html')
''')
    p=labs/'sec_misconfig/app.py'
    function(p,'get_secret','''
@app.route('/lab1/get-secret')
def get_secret():
    return jsonify({'error':'Forbidden'}),403
''')
    function(p,'page_not_found','''
@app.errorhandler(404)
def page_not_found(e):
    return 'Not found',404
''')
    function(p,'get_token','''
@app.route('/lab3/get-token',methods=['POST'])
def get_token():
    data=request.get_json(silent=True) or {}
    token=jwt.encode({'username':str(data.get('username','guest'))[:80],'role':'user','exp':datetime.utcnow()+timedelta(hours=1)},app.secret_key,algorithm='HS256')
    return jsonify({'token':token})
''')
    function(p,'verify_token','''
@app.route('/lab3/verify-token',methods=['POST'])
def verify_token():
    token=(request.get_json(silent=True) or {}).get('token','')
    try:
        payload=jwt.decode(token,app.secret_key,algorithms=['HS256'])
        return jsonify({'message':'Token verified','payload':payload})
    except jwt.InvalidTokenError:return jsonify({'error':'Invalid token'}),401
''')
    p=labs/'sde/app.py'
    function(p,'handle_404','''
@app.errorhandler(404)
def handle_404(e):
    return 'Not found',404
''')
    function(p,'trigger_error','''
@app.route('/500error')
def trigger_error():
    return 'Internal server error',500
''')
    p=labs/'insufficient_logging_lab/app.py'
    function(p,'lab1_login','''
@app.route('/lab1/login',methods=['POST'])
def lab1_login():
    from flask import session
    username=request.form.get('username','');password=request.form.get('password','')
    if username in users and users[username]['password']==password:
        session.clear();session['logging_user']=username
        app.logger.info('authentication_success')
        return redirect(url_for('lab2'))
    app.logger.warning('authentication_failure')
    return render_template('lab1.html',error='Invalid credentials'),401
''')
    function(p,'change_password','''
@app.route('/lab2/change_password',methods=['POST'])
def change_password():
    from flask import session
    username=request.form.get('username','')
    if session.get('logging_user')!=username:return 'Forbidden',403
    password=request.form.get('new_password','')
    if len(password)<8:return 'Invalid password',400
    users[username]['password']=password
    app.logger.info('password_changed')
    return render_template('lab2.html',message='Password changed')
''')
    function(p,'change_role','''
@app.route('/lab2/change_role',methods=['POST'])
def change_role():
    from flask import session
    actor=users.get(session.get('logging_user'))
    target=users.get(request.form.get('username'))
    role=request.form.get('new_role')
    if not actor or actor['role']!='admin':return 'Forbidden',403
    if not target or role not in ('user','admin'):return 'Invalid request',400
    target['role']=role;app.logger.info('role_changed')
    return render_template('lab2.html',message='Role changed')
''')
    p=labs/'sensitive_data_exposure/dataexposure/views.py'
    function(p,'generate_api_key','''
def generate_api_key():
    import secrets
    return secrets.token_urlsafe(32)
''')
    function(p,'api_data_view','''
@login_required
def api_data_view(request):
    return JsonResponse({'username':request.user.username})
''')
    function(p,'all_users_data_view','''
def all_users_data_view(request):
    if not request.user.is_authenticated:return JsonResponse({'error':'Authentication required'},status=401)
    if not request.user.is_staff:return JsonResponse({'error':'Forbidden'},status=403)
    return JsonResponse({'users':[{'username':row.user.username} for row in UserData.objects.select_related('user').all()]})
''')
