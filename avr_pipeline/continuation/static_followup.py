"""Close residual static findings using explicit bounded application policies."""
from pathlib import Path
from resolve_security import function


def pygoat(repo):
    labs=repo/'dockerized_labs'
    p=labs/'command_injection_lab/app.py'
    function(p,'lab1','''
@app.route('/lab1',methods=['GET','POST'])
def lab1():
    if request.method=='POST':
        # The local lesson permits these demonstration destinations only.
        domain={'example.com':'example.com','example.invalid':'example.invalid'}.get(request.form.get('domain',''))
        if domain is None:return render_template('lab1.html',output='Unsupported domain'),400
        command=['nslookup' if request.form.get('os')=='win' else 'dig',domain]
        try:
            process=subprocess.Popen(command,shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            stdout,stderr=process.communicate(timeout=5)
            output=(stdout+stderr).decode('utf-8',errors='replace')
        except Exception:output='Lookup failed'
        return render_template('lab1.html',output=output)
    return render_template('lab1.html')
''')
    p=labs/'ssrf_lab/app.py'
    function(p,'lab1','''
@app.route('/lab1',methods=['GET','POST'])
def lab1():
    from pathlib import Path
    if request.method=='POST':
        root=Path(__file__).resolve().parent
        choices={p.name:p for p in root.glob('*.txt') if not p.is_symlink()}
        selected=choices.get(request.form.get('blog',''))
        if selected is None:return render_template('lab1.html',blog='No blog found'),400
        return render_template('lab1.html',blog=selected.read_text(encoding='utf-8'))
    return render_template('lab1.html',blog='Read Blog About SSRF')
''')
    function(p,'lab2','''
@app.route('/lab2',methods=['GET','POST'])
def lab2():
    if request.method=='POST':
        selected={'http://example.com':'http://example.com','https://example.com':'https://example.com'}.get(request.form.get('url',''))
        if selected is None:return render_template('lab2.html',error='Invalid URL'),400
        try:
            response=requests.get(selected,allow_redirects=False,timeout=5)
            return render_template('lab2.html',response=response.text)
        except Exception:return render_template('lab2.html',error='Fetch failed'),400
    return render_template('lab2.html')
''')
    p=labs/'template_injection_lab/app.py'
    function(p,'view_blog','''
@app.route('/blog/<filename>')
def view_blog(filename):
    import json
    from pathlib import Path
    from markupsafe import escape
    root=Path(BLOG_DIR).resolve()
    choices={p.name:p for p in root.glob('*.html') if not p.is_symlink()}
    selected=choices.get(filename)
    if selected is None:return 'Not found',404
    try:data=json.loads(selected.read_text(encoding='utf-8'))
    except (OSError,ValueError):return 'Not found',404
    return '<h3>'+str(escape(data['title']))+'</h3><div>'+str(escape(data['content']))+'</div>'
''')
    p=labs/'crypto_failure_lab/app.py'
    function(p,'custom_hash','''
def custom_hash(password):
    from werkzeug.security import generate_password_hash
    return generate_password_hash(password)
''')
    for name,table in [('lab1','LAB1_USERS'),('lab2','LAB2_USERS')]:
        function(p,name,f'''
@app.route('/{name}',methods=['GET','POST'])
def {name}():
    from werkzeug.security import check_password_hash
    if request.method=='POST':
        username=request.form.get('username','');password=request.form.get('password','')
        if username in {table} and check_password_hash({table}[username],password):
            return render_template('{name}.html',user=username,success=True)
        return render_template('{name}.html',success=False,failure=True),401
    return render_template('{name}.html')
''')
    # Fixtures are migrated to salted password KDFs, not compared as fast hashes.
    text=p.read_text(encoding='utf-8');position=text.index('# Defensive follow-up')
    text=text[:position]+'''from werkzeug.security import generate_password_hash as _password_hash
LAB1_USERS={name:_password_hash(value) for name,value in {'user1':'abc123','admin':'admin','user2':'qwerty'}.items()}
LAB2_USERS={name:_password_hash(value) for name,value in {'user1':'123','admin':'admin','user2':'qwerty'}.items()}
\n'''+text[position:];p.write_text(text,encoding='utf-8')
    p=labs/'auth_failure_lab/app.py'
    text=p.read_text(encoding='utf-8');position=text.index('# Defensive follow-up')
    text=text[:position]+'''from werkzeug.security import generate_password_hash as _password_hash
for _name,_password in {'User1':'password1','User2':'password2','User3':'password3','Admin':'password4'}.items():
    USERS[_name]['password']=_password_hash(_password)
\n'''+text[position:];p.write_text(text,encoding='utf-8')
    function(p,'lab3','''
@app.route('/lab3',methods=['GET','POST'])
def lab3():
    from flask import session
    from werkzeug.security import check_password_hash
    if request.method=='POST':
        username=request.form.get('username','');password=request.form.get('password','')
        if username not in USERS or not check_password_hash(USERS[username]['password'],password):
            return render_template('lab3.html',failure=True),401
        session.clear();session['auth_user']=username
    username=session.get('auth_user')
    return render_template('lab3.html',username=username,success=username in USERS)
''')
    p=repo/'challenge/views.py'
    function(p,'_resolve_build_path','''
def _resolve_build_path(build_location):
    from pathlib import Path
    base=Path(settings.BASE_DIR).resolve()
    choices={}
    for root_name in LAB_BUILD_ROOTS:
        root=(base/root_name).resolve()
        for dockerfile in root.rglob('Dockerfile'):
            candidate=dockerfile.parent.resolve()
            if candidate.is_relative_to(root) and not dockerfile.is_symlink():
                choices[candidate.relative_to(base).as_posix()]=str(candidate)
    selected=choices.get(str(build_location or '').replace('\\\\','/').strip('/'))
    if selected is None:raise ValueError('Unknown local lab build directory')
    return selected
''')
    text=p.read_text(encoding='utf-8')
    text=text.replace('f"Failed to start challenge: {e}"','"Failed to start challenge"').replace('f"Failed to stop challenge: {e}"','"Failed to stop challenge"')
    text=text.replace("'message': str(e)","'message': 'Request could not be completed'")
    p.write_text(text,encoding='utf-8')
    p=repo/'challenge/management/commands/startuplabs.py'
    text=p.read_text(encoding='utf-8')
    text=text.replace('build_path = os.path.join(settings.BASE_DIR, build_location)',
        'from challenge.views import _resolve_build_path\n\t\t\ttry:\n\t\t\t\tbuild_path = _resolve_build_path(build_location)\n\t\t\texcept ValueError:\n\t\t\t\tself.stderr.write(self.style.ERROR("Unknown local lab build directory"))\n\t\t\t\tcontinue')
    compile(text,str(p),'exec');p.write_text(text,encoding='utf-8')
    p=repo/'challenge/labs/security_headers_lab/app.py'
    function(p,'toggle_secure_mode','''
@app.route('/toggle_secure_mode')
def toggle_secure_mode():
    init_session()
    session['secure_mode']=not session.get('secure_mode',False)
    session.modified=True
    return redirect(url_for('index'))
''')


def vampi(repo):
    p=repo/'api_views/users.py';text=p.read_text(encoding='utf-8')
    text=text.replace("re.fullmatch(r'[^@\\s]+@[^@\\s]+\\.[^@\\s]+', email) is None", "email.count('@') != 1 or '.' not in email.partition('@')[2] or not all(c.isascii() and (c.isalnum() or c in '.-_+@') for c in email)")
    compile(text,str(p),'exec');p.write_text(text,encoding='utf-8')
