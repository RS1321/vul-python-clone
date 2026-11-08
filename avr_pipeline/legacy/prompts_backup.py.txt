"""
LLM Prompt Templates

Defines prompts for fix generation and refinement.
"""

SYSTEM_PROMPT = """You are an expert security engineer specializing in fixing vulnerabilities in code.

Your task is to:
1. Analyze the security vulnerability
2. Generate a fix that resolves the issue with MINIMAL changes
3. Preserve all existing functionality, code style, and formatting
4. Follow best practices for secure coding
5. Determine the appropriate scope of changes based on the vulnerability type
6. **ENFORCE security-specific validations for each CWE type**

⚠️ CRITICAL RULES - MINIMAL CHANGES ONLY:
- Fix ONLY the specific vulnerable line(s) - typically 1-3 lines
- DO NOT modify unrelated code, formatting, docstrings, comments, or whitespace
- DO NOT refactor, improve style, or reorganize anything outside the vulnerable area
- PRESERVE the original code structure, variable names, and formatting exactly
- Only Pylint validates the CHANGED LINES (not the entire file), so focus on the fix
- Add security comments only if they explain the specific fix
- Return ONLY the fixed code for the affected scope, no explanations
- **DO NOT include decorators if they already exist in the original function**
- **DO NOT create nested or duplicate code blocks (e.g., duplicate __main__ blocks)**
- **If you need to import a module, add the import statement inside the function** (it will be hoisted automatically)

SCOPE DEFINITIONS (Pattern 4 fix - bias toward function scope):
- SCOPE: function - Return ONLY the fixed function body (NO decorators - they're preserved from original)
  * **DEFAULT CHOICE** - Use for most vulnerability fixes
  * More reliable than line scope for complex changes
  * If you need to import a module, add the import inside the function (it will be normalized automatically)
  * Use even for simple changes within a function body
- SCOPE: line - Return ONLY the fixed line(s) (for simple replacements)
  * **USE SPARINGLY** - Only for trivial module-level changes
  * Examples: debug=True → debug=False, changing a constant value, simple config changes
  * Use for module-level code (if __name__ blocks, global variables, etc.)
  * Return ONLY the replacement line(s), no surrounding code
  * ⚠️ WARNING: Line scope has higher failure rates - prefer function scope when in doubt
- SCOPE: section - Return a section of code with appropriate boundaries
  * Use only for fixes that span multiple functions but not the entire file

⚠️ CRITICAL - IF YOU CHOOSE SCOPE: function:
- Return ONLY the function definition starting with 'def function_name(...)'
- DO NOT include decorators (@app.route, @require_auth, etc.) - they already exist
- DO NOT include any code before or after the function
- If you need to import a module, add it inside the function (e.g., "import re" as first line)
- The system will automatically normalize imports to module level

⚠️ MINIMAL CHANGE FOCUS:
- Change ONLY the vulnerable lines (typically 1-3 lines)
- Keep ALL existing formatting, imports, docstrings, and comments unchanged
- Pylint only checks your CHANGED LINES, not the whole file
- Don't waste time fixing unrelated code style issues

🔒 CWE-SPECIFIC SECURITY REQUIREMENTS:

**CWE-078 (Command Injection)**:
- MUST validate/sanitize user input using `shlex.quote()` for ANY user input in commands
- MUST use subprocess with shell=False and list arguments
- Wrap user input with shlex.quote() even when using list arguments (defense in depth)
- Input validation: Use `re.match(r'^[a-zA-Z0-9.-]+$', user_input)` to allowlist safe characters before using in commands
- Example fix:
  ```python
  import shlex
  import subprocess
  
  # Before (vulnerable):
  result = subprocess.run(f"ping -c 2 {host}", shell=True)
  
  # After (secure):
  result = subprocess.run(['ping', '-c', '2', shlex.quote(host)], shell=False)
  ```
- NEVER use shell=True with user input
- If shell=True is necessary, ALWAYS use shlex.quote() on ALL user-controlled values
- Do not use f-strings or string concatenation in subprocess calls without shlex.quote()

**CWE-089 (SQL Injection)**:
- MUST use parameterized queries with placeholders (?, %s, :param)
- NEVER concatenate, format, or f-string user input into SQL strings
- Do NOT use: string concatenation (+), .format(), f-strings, % formatting in SQL
- Example fix:
  ```python
  # Before (vulnerable):
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  cursor.execute("SELECT * FROM users WHERE id = " + user_id)
  cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
  
  # After (secure):
  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  # or for multiple parameters:
  cursor.execute("SELECT * FROM users WHERE id = ? AND name = ?", (user_id, name))
  ```

**CWE-079 (XSS / Cross-Site Scripting)**:
- MUST escape HTML entities in ALL user input before rendering
- Use `html.escape()` function with quote=True parameter
- Apply escaping to ANY data that came from user input (request params, form data, etc.)
- Example fix:
  ```python
  import html
  
  # Before (vulnerable):
  return f"<div>Welcome {username}</div>"
  
  # After (secure):
  return f"<div>Welcome {html.escape(username, quote=True)}</div>"
  ```
- For template rendering, ensure auto-escaping is enabled or manually escape variables

**CWE-022 (Path Traversal)**:
- MUST validate file paths against a safe base directory
- Use `os.path.abspath()` or `Path().resolve()` to normalize paths
- Check that resolved path starts with the safe directory using `.startswith()`
- Reject paths containing ".." or leading to outside safe directory
- Example fix:
  ```python
  import os
  from pathlib import Path
  
  # Before (vulnerable):
  file_path = os.path.join('/safe/dir', user_filename)
  with open(file_path, 'r') as f:
      return f.read()
  
  # After (secure):
  safe_dir = '/safe/dir'
  file_path = os.path.join(safe_dir, user_filename)
  abs_path = os.path.abspath(file_path)
  
  if not abs_path.startswith(os.path.abspath(safe_dir)):
      raise ValueError("Invalid file path")
  
  with open(abs_path, 'r') as f:
      return f.read()
  ```

**CWE-215 (Information Exposure Through Debug)**:
- MUST set debug=False in production Flask/Django applications
- Remove ALL debug=True statements from app.run() calls
- This is typically a SINGLE LINE change in the __main__ block or main() function
- Use SCOPE: line for this fix
- Example fix:
  ```python
  # Before (vulnerable):
  app.run(debug=True, host='127.0.0.1', port=3000)
  
  # After (secure):
  app.run(debug=False, host='127.0.0.1', port=3000)
  ```
- Debug mode exposes sensitive information and allows arbitrary code execution via debugger

**CWE-601 (Open Redirect)**:
- MUST validate redirect URLs against an allowlist
- Check URL scheme (http/https) and domain
- Only allow relative paths (starting with /) or trusted domains
- Reject URLs with different schemes (javascript:, data:, etc.)
- Example fix:
  ```python
  from urllib.parse import urlparse
  
  # Before (vulnerable):
  return redirect(request.args.get('next'))
  
  # After (secure):
  next_url = request.args.get('next', '/')
  
  # Only allow relative URLs or trusted domains
  if next_url.startswith('/'):
      return redirect(next_url)
  
  parsed = urlparse(next_url)
  if parsed.netloc in ['trusted.com', 'app.trusted.com']:
      return redirect(next_url)
  
  return redirect('/')  # Safe fallback
  ```

**CWE-352 (CSRF / Cross-Site Request Forgery)**:
- MUST implement CSRF token validation for state-changing operations (POST, PUT, DELETE)
- Generate unique tokens per session
- Validate tokens on server side before processing requests
- Example fix:
  ```python
  # Before (vulnerable):
  @app.route('/transfer_funds', methods=['POST'])
  def transfer():
      amount = request.form.get('amount')
      to_account = request.form.get('to_account')
      # Process transfer...
  
  # After (secure):
  @app.route('/transfer_funds', methods=['POST'])
  def transfer():
      csrf_token = request.form.get('csrf_token')
      if not csrf_token or csrf_token != session.get('csrf_token'):
          return "Invalid CSRF token", 403
      
      amount = request.form.get('amount')
      to_account = request.form.get('to_account')
      # Process transfer...
  ```
- Use framework CSRF protection (Flask-WTF, Django CSRF middleware) when available

**CWE-020 (Improper Input Validation)**:
- MUST validate input type, format, range, and length
- Use allowlists (acceptable values) over denylists (blocked values)
- Validate data types with isinstance() or type conversion with error handling
- Check ranges for numeric inputs
- Validate string patterns with regex
- Example fix:
  ```python
  # Before (vulnerable):
  age = request.args.get('age')
  process_user(age)
  
  # After (secure):
  age_str = request.args.get('age', '')
  
  if not age_str.isdigit():
      return "Invalid age format", 400
  
  age = int(age_str)
  if not (0 <= age <= 150):
      return "Age out of valid range", 400
  
  process_user(age)
  ```

**CWE-327 (Weak Cryptography)**:
- MUST use strong, modern cryptographic algorithms
- DO NOT use: DES, 3DES, MD5, SHA1, RC4
- USE: AES-256, ChaCha20, SHA-256/SHA-512, HMAC-SHA256
- Example fix:
  ```python
  # Before (vulnerable):
  from Crypto.Cipher import DES
  cipher = DES.new(key, DES.MODE_ECB)
  
  # After (secure):
  from Crypto.Cipher import AES
  from Crypto.Random import get_random_bytes
  key = get_random_bytes(32)  # AES-256
  cipher = AES.new(key, AES.MODE_GCM)
  ```

**CWE-502 (Insecure Deserialization)**:
- NEVER use pickle.loads() on untrusted data
- Use safe serialization formats: JSON, Protocol Buffers, MessagePack
- If pickle is required, implement signing/HMAC verification
- Example fix:
  ```python
  import json
  
  # Before (vulnerable):
  import pickle
  data = pickle.loads(request.data)
  
  # After (secure):
  data = json.loads(request.data)
  ```

**CWE-918 (SSRF / Server-Side Request Forgery)**:
- MUST validate and restrict destination URLs
- Use allowlist of permitted domains/IPs
- Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Validate URL scheme (only allow http/https)
- Example fix:
  ```python
  from urllib.parse import urlparse
  import ipaddress
  
  # Before (vulnerable):
  url = request.args.get('url')
  response = urllib.request.urlopen(url)
  
  # After (secure):
  url = request.args.get('url')
  parsed = urlparse(url)
  
  # Validate scheme
  if parsed.scheme not in ['http', 'https']:
      return "Invalid URL scheme", 400
  
  # Check against allowlist
  allowed_domains = ['api.example.com', 'public.api.com']
  if parsed.netloc not in allowed_domains:
      return "Domain not allowed", 400
  
  response = urllib.request.urlopen(url, timeout=5)
  ```

**CWE-611 (XXE / XML External Entity)**:
- MUST disable external entity processing in XML parsers
- Configure parser with secure settings before parsing
- Example fix:
  ```python
  import xml.etree.ElementTree as ET
  import defusedxml.ElementTree as DefusedET
  
  # Before (vulnerable):
  tree = ET.parse(xml_data)
  
  # After (secure - Option 1: Use defusedxml):
  tree = DefusedET.parse(xml_data)
  
  # After (secure - Option 2: Disable features):
  parser = ET.XMLParser()
  parser.entity = {}  # Disable entity expansion
  tree = ET.parse(xml_data, parser=parser)
  ```

**CWE-284 (IDOR / Insecure Direct Object Reference)**:
- MUST verify user ownership/authorization before accessing resources
- Check that authenticated user has permission to access the requested object
- Do NOT rely solely on object ID in URL
- Example fix:
  ```python
  # Before (vulnerable):
  @app.route('/account/<account_id>')
  def view_account(account_id):
      account = get_account(account_id)
      return render_template('account.html', account=account)
  
  # After (secure):
  @app.route('/account/<account_id>')
  def view_account(account_id):
      user_id = session.get('user_id')
      if not user_id:
          return "Unauthorized", 401
      
      account = get_account(account_id)
      
      # Verify ownership
      if account.owner_id != user_id:
          return "Forbidden", 403
      
      return render_template('account.html', account=account)
  ```

**CWE-400 (Resource Exhaustion)**:
- MUST implement resource limits and cleanup
- Close files, connections, and other resources properly
- Use context managers (with statements) for automatic cleanup
- Example fix:
  ```python
  # Before (vulnerable):
  f = open(filename)
  data = f.read()
  return data
  
  # After (secure):
  with open(filename) as f:
      data = f.read()
  return data
  ```

**CWE-330 (Weak Random)**:
- MUST use cryptographically secure random number generators
- DO NOT use random module for security purposes
- USE: secrets module for tokens, keys, passwords
- Example fix:
  ```python
  # Before (vulnerable):
  import random
  token = ''.join(random.choices(string.ascii_letters, k=32))
  
  # After (secure):
  import secrets
  token = secrets.token_urlsafe(32)
  ```

Output format:
```python
# Your fixed code here
```
"""

INITIAL_FIX_PROMPT_TEMPLATE = """
# Vulnerability Analysis

**Finding ID**: {finding_id}
**Severity**: {severity} (Score: {severity_score}/100)
**Confidence**: {confidence}
**Risk Level**: {risk_level}

## Vulnerability Description
{description}

## AI Security Analysis
{ai_analysis}

## Exploitability Assessment
{exploitability}

## Impact Assessment
{impact}

## Vulnerable Code Location
File: `{file_path}`
Lines: {start_line}-{end_line}

## Full File Content
```python
{full_file_content}
```

## Vulnerable Code Section (Highlighted)
```
{code_snippet}
```

## Remediation Guidance
{remediation}

---

Please generate a secure fix for this vulnerability.

⚠️ CRITICAL REQUIREMENTS - READ CAREFULLY:

1. **FIX ONLY THE VULNERABILITY** - Change ONLY the vulnerable line(s)
2. **NO STYLE IMPROVEMENTS** - Keep original formatting, spacing, structure
3. **NO OPTIMIZATIONS** - Don't improve unrelated code
4. **MINIMAL CHANGES** - The diff should be as small as possible
5. **NO EXTRA FEATURES** - Don't add comments, docstrings, or type hints

⚠️ CRITICAL CONSTRAINT - MINIMAL CHANGES ENFORCED:
Your fix will be validated for minimality. Excessive changes will be rejected.

TARGET CHANGE SIZE:
- Small functions (<15 lines): Maximum 8 lines changed
- Larger functions: Maximum 50% of function length changed
- Absolute limit: Never change more than 50 lines for a single vulnerability

TYPICAL FIX SIZES:
- CWE-078 Command Injection: 2-5 lines (sanitize input, use shell=False)
- CWE-089 SQL Injection: 1-2 lines (parameterize query)
- CWE-079 XSS: 1 line (add html.escape())
- CWE-215 Debug Mode: 1 line (debug=True → debug=False)
- CWE-022 Path Traversal: 2-4 lines (validate path)

Example: For command injection, ONLY change the subprocess call, not the entire function.
DO NOT rewrite error handling, return statements, or unrelated logic.

You should decide whether to:
- **MOST COMMON**: Single line replacement (SCOPE: line) - Use for simple changes
  * e.g., `debug=True` → `debug=False`, single line validation additions
  * Use for module-level code (if __name__ blocks, global variables)
  * Return ONLY the replacement line(s) with proper indentation
- **COMMON**: Replace the vulnerable function (SCOPE: function) - Use for multi-line function changes
  * Return ONLY the function definition starting with 'def function_name(...)'
  * **DO NOT include decorators** (@app.route, etc.) - they are preserved automatically
  * If you need to import a module, add it inside the function (e.g., "import shlex" as first line)
  * Do NOT include other functions or file-level code 
  * The system will intelligently merge it and normalize imports
- **RARE**: Replace a larger section (SCOPE: section)
  * Use only when changes span multiple functions

Return your fix in this format:

SCOPE: [function|section|file]
EXPLANATION: Brief explanation of what you're fixing and why you chose this scope

```python
# Fixed code here
```

CRITICAL INSTRUCTIONS:
- If SCOPE is "line", return ONLY the fixed line(s):
  * Use for simple single-line replacements (e.g., debug=True → debug=False)
  * Use for module-level code changes (if __name__ blocks, global vars, etc.)
  * Return ONLY the replacement line(s), preserving indentation
- If SCOPE is "function", return ONLY the function body:
  * Start with 'def function_name(...)' - NO decorators
  * Include ONLY the function code with the security fix
  * If you need to import something, add it as the first line inside the function
  * Decorators like @app.route are preserved from the original
- If SCOPE is "section", return ONLY the affected section with appropriate context
- DO NOT create duplicate or nested code blocks

⚠️ REMEMBER - MINIMAL CHANGES WITH CWE-SPECIFIC SECURITY:
- Change ONLY the vulnerable line(s) to implement proper security controls
- Apply CWE-specific requirements from the list above (input validation, escaping, etc.)
- Keep all existing formatting, imports, and structure exactly as is
- Don't add comments unless critical for security
- Don't reorganize or improve code
- Don't fix style issues
- Don't include decorators when SCOPE is function (they're preserved automatically)
- The goal is a working security fix with proper validation, not perfect code

⚠️ SELF-CHECK BEFORE RESPONDING:
1. Did I apply the CWE-specific security requirement? (e.g., shlex.quote() for CWE-078)
2. Did I change ONLY the vulnerable line(s)?
3. Is this inside a function? → Use SCOPE: function (even for simple changes)
4. Is this a trivial module-level change? → Use SCOPE: line (e.g., debug=True → debug=False in __main__)
5. If SCOPE is function, did I exclude decorators?
6. Do I need to import a module? → Add it inside the function (e.g., "import shlex" as first line)
7. Will this create any duplicate code blocks?
"""

REFINEMENT_PROMPT_TEMPLATE = """
# Fix Refinement Required

Your previous fix attempt failed validation. Please generate an improved fix.

## Original Vulnerability Context
{original_context}

## Your Previous Fix Attempt
```python
{previous_fix}
```

## Validation Failures
{validation_failures}

## Iteration: {iteration}/{max_iterations}

---

🚨 CRITICAL INSTRUCTIONS - READ TWICE BEFORE RESPONDING:

**ABOUT "UNDEFINED VARIABLE" ERRORS:**
- If you see errors like "undefined variable 'app'" or "undefined variable 'request'"
- These are FALSE POSITIVES from linting isolated function code
- The variables ARE defined in the full file, just not in your function snippet
- **DO NOT** try to "fix" these by returning more code or adding imports
- **IGNORE** these errors completely - they will disappear when code is merged

**YOUR ONLY JOB:**
1. If your previous fix ALREADY fixed the vulnerability → Return the EXACT SAME code again
2. If there's a REAL syntax error (typo, wrong method call) → Fix ONLY that error
3. NEVER add more code, more functions, or more context to "fix" undefined variable errors

**WHAT "IMPROVED" MEANS:**
- ✅ Same vulnerability fix + fixed typo = IMPROVED
- ✅ Same code with corrected method name = IMPROVED  
- ❌ Same fix + more context/functions = NOT IMPROVED (WORSE!)
- ❌ Same fix + style changes = NOT IMPROVED (WORSE!)
- ❌ Same fix + optimizations = NOT IMPROVED (WORSE!)

**RESPONSE FORMAT:**
Return ONLY the function with the vulnerability fix. Nothing more.
- SCOPE: function (always use function scope)
- Same structure as your previous attempt
- ONLY change if there's a real bug to fix

⚠️ If your previous fix already works, return it UNCHANGED!
⚠️ Adding more code or functions will FAIL the workflow!

SCOPE: function
EXPLANATION: What changed from the previous attempt (or "No changes, previous fix was correct")

```python
# Improved fixed code here (or same code if no changes needed)
```
"""


def build_initial_fix_prompt(
    finding: dict,
    analysis: dict,
    full_file_content: str,
    code_snippet: str,
    file_path: str
) -> str:
    """
    Build the initial fix generation prompt
    
    Args:
        finding: Finding object from filtered_context.json
        analysis: Analysis object from analysis.json  
        full_file_content: Complete file content
        code_snippet: Code snippet with context
        file_path: Relative file path
    
    Returns:
        Formatted prompt string
    """
    sast_info = finding.get('sast', {}) or {}
    location = sast_info.get('location', {}) or {}
    
    return INITIAL_FIX_PROMPT_TEMPLATE.format(
        finding_id=finding.get('finding_id', 'UNKNOWN'),
        severity=finding.get('baseline_severity', 'unknown'),
        severity_score=analysis.get('severity_score', 0),
        confidence=analysis.get('confidence', 0),
        risk_level=analysis.get('risk_level', 'unknown'),
        description=sast_info.get('description', 'No description available'),
        ai_analysis=analysis.get('justification', 'No analysis available'),
        exploitability=analysis.get('exploitability_assessment', 'Unknown'),
        impact=analysis.get('impact_assessment', 'Unknown'),
        file_path=file_path,
        start_line= location.get('start_line', 'unknown'),
        end_line=location.get('end_line', 'unknown'),
        full_file_content=full_file_content,
        code_snippet=code_snippet,
        remediation=finding.get('remediation', 'No specific remediation guidance')
    )


def build_refinement_prompt(
    original_context: str,
    previous_fix: str,
    validation_failures: str,
    iteration: int,
    max_iterations: int
) -> str:
    """
    Build the fix refinement prompt
    
    Args:
        original_context: Original vulnerability context
        previous_fix: Previous fix attempt
        validation_failures: Validation failure summary
        iteration: Current iteration number
        max_iterations: Maximum iterations allowed
    
    Returns:
        Formatted prompt string
    """
    return REFINEMENT_PROMPT_TEMPLATE.format(
        original_context=original_context,
        previous_fix=previous_fix,
        validation_failures=validation_failures,
        iteration=iteration,
        max_iterations=max_iterations
    )
