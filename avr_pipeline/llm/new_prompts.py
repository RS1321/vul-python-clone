"""
LLM Prompt Templates - Optimized and CWE-Specific

Improvements over v1 (based on empirical analysis of 5 models × 29 SAST findings):

  NEW entries added:
    CWE-074  Template Injection  — was COMPLETELY MISSING; never fixed by any model
    CWE-209  Stack Trace Exposure — was COMPLETELY MISSING; fixed by only 1/5 models
    CWE-776  XML Bomb             — was missing key variant; fixed by only 2/5 models

  Enriched entries (were too vague; 0/5 models fixed these):
    CWE-078  Command Injection   — added shell=False requirement & list-args pattern
    CWE-601  Open Redirect       — replaced unsafe string check with urlparse pattern
    CWE-918  SSRF                — added concrete allowlist + urlparse before/after

  System prompt:
    - Added explicit guidance for multi-step taint flows
    - Added 1–5 line minimality limit (was 1–15 for small functions)

  Refinement prompt:
    - Added per-CWE "common failure modes" block so models self-correct faster
    - Re-framed "IMPROVED" examples to be goal-oriented not style-oriented
"""

import json

# ---------------------------------------------------------------------------
# CWE-specific security guidance
# Each entry follows: WHY flagged → concrete BEFORE/AFTER → hard rules
# Entries for rules never fixed by any model are the most detailed.
# ---------------------------------------------------------------------------
CWE_GUIDANCE = {

    # -----------------------------------------------------------------------
    # CWE-078  Command Injection  — 0/5 models fixed this
    # Root cause: taint flows through intermediate var into subprocess shell=True
    # -----------------------------------------------------------------------
    'CWE-078': """**CWE-078 (Command Injection)**:
- The vulnerability is that user input reaches a shell execution call.
- PREFERRED FIX — use allowlist AND shell=False with list args:
  ```python
  # BEFORE (vulnerable):
  command = f"ping -c 2 {host}"
  result = subprocess.run(command, shell=True, ...)

  # AFTER (safe):
  host = request.args.get('host', 'localhost')
  ALLOWED_HOSTS = {'localhost', '127.0.0.1', 'example.com'}
  if host not in ALLOWED_HOSTS:
      return "Invalid host", 400
  # Critical: retrieve value FROM the allowlist, not from user variable
  safe_host = next(h for h in ALLOWED_HOSTS if h == host)
  result = subprocess.run(['ping', '-c', '2', safe_host], shell=False, ...)
  ```
- RULES:
  - ALWAYS use an allowlist of valid values — regex validation does NOT break CodeQL's taint chain
  - After validating `if host in ALLOWED_HOSTS`, retrieve the value FROM the allowlist
  - Use `safe_host = next(h for h in ALLOWED_HOSTS if h == host)` to get untainted value
  - Set shell=False on ALL subprocess calls in the function
  - Pass args as a list, never as a single string
  - ⚠️ WHY REGEX DOESN'T WORK: CodeQL does not model `re.match()` as a sanitizer.
    Even with `if not re.match(...): return 400`, the original `host` variable is still
    considered tainted because CodeQL doesn't recognize early-return guards as breaking taint flow
  - ⚠️ CONDITIONAL COMMAND BUILDING: If the function builds commands differently per OS,
    you MUST replace ALL branches with lists — never leave any f-string or string
    interpolation anywhere in the function, even in branches not reached on the current OS:
  ```python
  # WRONG — f-strings remain even though subprocess call was fixed:
  if os.name == 'nt':
      command = f'ping -n 2 {host}'   # ← still tainted, CodeQL still flags this
  else:
      command = f'ping -c 2 {host}'   # ← still tainted
  result = subprocess.check_output(command, shell=False, ...)  # too late

  # CORRECT — lists in every branch with allowlist:
  ALLOWED_HOSTS = {'localhost', '127.0.0.1'}
  if host not in ALLOWED_HOSTS:
      return "Invalid host", 400
  safe_host = next(h for h in ALLOWED_HOSTS if h == host)
  if os.name == 'nt':
      command = ['ping', '-n', '2', safe_host]
  else:
      command = ['ping', '-c', '2', safe_host]
  result = subprocess.check_output(command, shell=False, ...)
  ```""",

    # -----------------------------------------------------------------------
    # CWE-089  SQL Injection  — fixed by all 5 models (no change needed)
    # -----------------------------------------------------------------------
    'CWE-089': """**CWE-089 (SQL Injection)**:
- Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- NEVER concatenate or f-string user input into SQL""",

    # -----------------------------------------------------------------------
    # CWE-079  XSS  — fixed by all 5 models (no change needed)
    # -----------------------------------------------------------------------
    'CWE-079': """**CWE-079 (XSS)**:
- Escape HTML: `html.escape(user_input, quote=True)`
- Apply to ALL user input before rendering""",

    # -----------------------------------------------------------------------
    # CWE-074  Template Injection  — 0/5 models fixed this; was MISSING
    # Root cause: user input IS the template string, not a variable inside it
    # Lines 139 and 156 in vulnerable_app.py both hit this pattern
    # -----------------------------------------------------------------------
    'CWE-074': """**CWE-074 (Server-Side Template Injection)**:
- The vulnerability is that user input is passed as the TEMPLATE STRING ITSELF,
  not as a variable rendered inside the template.
- IDENTIFY the pattern:
  ```python
  # VULNERABLE — html_content (from request) is the template:
  render_template_string(html_content)
  Template(html_content).render(...)
  ```
- FIX — use a static template and pass user data only as a render variable:
  ```python
  # AFTER (safe):
  from jinja2 import escape
  render_template_string("{{ content }}", content=html_content)
  ```
- CRITICAL RULES:
  - Simply escaping html_content does NOT fix SSTI — CodeQL still sees user
    data as the template string
  - The fix MUST change WHAT is passed as the template (make it static)
  - render_template_string(html_content) → render_template_string("{{ content }}", content=html_content)""",

    # -----------------------------------------------------------------------
    # CWE-022  Path Traversal  — fixed by 4/5 models (minor tweak only)
    # -----------------------------------------------------------------------
    'CWE-022': """**CWE-022 (Path Traversal)**:
- Normalize and validate:
  `abs_path = os.path.normpath(os.path.join(base_dir, filename))`
- Then check prefix:
  `if not abs_path.startswith(base_dir + os.sep): raise ValueError`
- Or use werkzeug: `from werkzeug.utils import secure_filename; secure_filename(filename)`""",

    # -----------------------------------------------------------------------
    # CWE-215  Flask Debug Mode  — fixed by 3/5 models (no change needed)
    # -----------------------------------------------------------------------
    'CWE-215': """**CWE-215 (Debug Mode)**:
- Change: `app.run(debug=True)` → `app.run(debug=False)`
- Single line fix, use SCOPE: line""",

    # -----------------------------------------------------------------------
    # CWE-209  Stack Trace Exposure  — fixed by only 1/5 models; was MISSING
    # Root cause: exception variable `e` flows into HTTP response f-string
    # Pattern repeats 6 times in vulnerable_app.py (lines 116,241,355,393,415,433)
    # -----------------------------------------------------------------------
    'CWE-209': """**CWE-209 (Stack Trace / Exception Exposure)**:
- The vulnerability is that the exception object `e` (or traceback text) appears
  in the HTTP response body, leaking internal details to the client.
- IDENTIFY the pattern:
  ```python
  # VULNERABLE — `e` in return value:
  except Exception as e:
      return f"Error: {e}", 500
      return jsonify({"error": str(e)})
  ```
- FIX — log the exception server-side, return a generic message to the client:
  ```python
  # AFTER (safe):
  import logging
  except Exception as e:
      logging.error(f"Error: {e}")
      return "An internal error occurred", 500
  ```
  For JSON APIs:
  ```python
  except Exception as e:
      logging.error(f"Error: {e}")
      return jsonify({"error": "Internal server error"}), 500
  ```
- RULES:
  - Replace every `{e}`, `str(e)`, `traceback.format_exc()` in the RETURN value
  - Keep a logging line with the real error (server-side only, not returned)
  - Do NOT remove the except block — only change what is returned
  - This fix is typically 2 lines: add logging.error(...), change the return""",

    # -----------------------------------------------------------------------
    # CWE-601  Open Redirect  — 0/5 models fixed this
    # Root cause: target_url from request used directly in redirect()
    # -----------------------------------------------------------------------
    'CWE-601': """**CWE-601 (Open Redirect)**:
- The vulnerability is that a URL from user input is passed directly to redirect()
  without verifying it stays on the same host.
- IDENTIFY the pattern:
  ```python
  # VULNERABLE:
  target_url = request.args.get('next', '')
  return redirect(target_url)
  ```
- FIX — retrieve redirect target FROM hardcoded list, not from parsed.path:
  ```python
  # AFTER (safe — critical: pull value FROM the list):
  from urllib.parse import urlparse
  target_url = request.args.get('next', '/')
  parsed = urlparse(target_url)
  ALLOWED_PATHS = ['/', '/home', '/profile', '/settings']
  if parsed.path in ALLOWED_PATHS and not parsed.netloc and not parsed.scheme:
      # Critical: retrieve FROM list, not from parsed.path
      safe_path = next(p for p in ALLOWED_PATHS if p == parsed.path)
      return redirect(safe_path)
  return redirect('/')
  ```
- RULES:
  - NEVER pass `parsed.path` directly to redirect() — even inside `in ALLOWED_PATHS` check
  - CodeQL tracks taint through attribute access: `parsed.path` is always tainted
  - After validating `if parsed.path in ALLOWED_PATHS`, retrieve the value FROM the list
  - Use `safe_path = next(p for p in ALLOWED_PATHS if p == parsed.path)` to get untainted value
  - BOTH parsed.netloc AND parsed.scheme must be checked and must be falsy
  - ⚠️ WHY `redirect(parsed.path)` DOESN'T WORK: CodeQL sees `parsed.path` as an
    attribute access on the tainted `parsed` object. Even though you validated it's in
    the allowlist, the attribute access itself carries taint. You must retrieve the
    matching value FROM ALLOWED_PATHS to break the taint chain
  - A check like `if 'trusted.com' in url` is NOT safe — use urlparse
  - A check like `if parsed.path.startswith('/')` alone is NOT enough — use whitelist""",

    # -----------------------------------------------------------------------
    # CWE-352  CSRF
    # -----------------------------------------------------------------------
    'CWE-352': """**CWE-352 (CSRF)**:
- Generate and validate CSRF tokens
- Check token before processing: `if csrf_token != session.get('csrf_token'): return 403`""",

    # -----------------------------------------------------------------------
    # CWE-020  Input Validation
    # -----------------------------------------------------------------------
    'CWE-020': """**CWE-020 (Input Validation)**:
- Validate type, range, format
- Example: `if not isinstance(age, int) or not (0 <= age <= 150): return 400`""",

    # -----------------------------------------------------------------------
    # CWE-327  Weak Crypto  — fixed by all 5 models (no change needed)
    # -----------------------------------------------------------------------
    'CWE-327': """**CWE-327 (Weak Crypto)**:
- Replace DES/3DES/RC4 with AES-256; replace ECB mode with GCM or CBC
- Example: `cipher = AES.new(key, AES.MODE_GCM)`
- Key must be 16, 24, or 32 bytes for AES""",

    # -----------------------------------------------------------------------
    # CWE-502  Insecure Deserialization  — fixed by all 5 models (no change)
    # -----------------------------------------------------------------------
    'CWE-502': """**CWE-502 (Insecure Deserialization)**:
- Replace pickle with JSON: `data = json.loads(request.data)`
- Replace yaml.load with yaml.safe_load(data)
- Never: `pickle.loads()` on untrusted data""",

    # -----------------------------------------------------------------------
    # CWE-918  SSRF  — 0/5 models fixed this
    # Root cause: user-controlled URL passed directly to requests.get/post
    # -----------------------------------------------------------------------
    'CWE-918': """**CWE-918 (SSRF)**:
- The vulnerability is that the full URL for an outbound HTTP request is
  controlled by the user, allowing requests to internal services.
- IDENTIFY the pattern:
  ```python
  # VULNERABLE:
  url = request.args.get('url', '')
  resp = requests.get(url)
  ```
- FIX — validate AND reconstruct the URL before making the request:
  ```python
  # AFTER (safe):
  from urllib.parse import urlparse, urlunparse
  url = request.args.get('url', '')
  parsed = urlparse(url)
  ALLOWED_HOSTS = {'api.example.com', 'data.example.com'}
  if parsed.scheme not in ('http', 'https') or parsed.netloc not in ALLOWED_HOSTS:
      return "URL not permitted", 400
  safe_url = urlunparse(parsed)  # CRITICAL: reconstruct to break taint chain
  resp = requests.get(safe_url, timeout=5)  # use safe_url, NOT the original url
  ```
- RULES:
  - NEVER pass the original user-supplied `url` variable to the HTTP call
  - Always reconstruct with urlunparse(parsed) and pass that to the HTTP call
  - This breaks CodeQL's taint chain — passing raw `url` after a check is NOT enough
  - Checking only the scheme is NOT enough — netloc must also be validated
  - The allowlist check must appear BEFORE the HTTP call""",

    # -----------------------------------------------------------------------
    # CWE-611 / CWE-776  XXE / XML Bomb  — fixed by only 2/5 models
    # -----------------------------------------------------------------------
    'CWE-611': """**CWE-611 (XXE)**:
- Use defusedxml: `import defusedxml.ElementTree as ET; tree = ET.parse(xml_data)`
- Or disable entities: `parser.entity = {}`""",

    'CWE-776': """**CWE-776 (XML Bomb / Billion Laughs)**:
- Replace stdlib xml with defusedxml to block entity expansion:
  ```python
  # BEFORE:
  import xml.etree.ElementTree as ET

  # AFTER:
  import defusedxml.ElementTree as ET
  doc = ET.fromstring(xml_data)   # entity expansion is disabled automatically
  ```
- For lxml: `parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)`""",

    # -----------------------------------------------------------------------
    # CWE-284  IDOR
    # -----------------------------------------------------------------------
    'CWE-284': """**CWE-284 (IDOR)**:
- Verify ownership: `if account.owner_id != user_id: return 403`
- Check authorization before accessing resources""",

    # -----------------------------------------------------------------------
    # CWE-400  Resource Leak
    # -----------------------------------------------------------------------
    'CWE-400': """**CWE-400 (Resource Leak)**:
- Use context managers: `with open(filename) as f:`
- Always close resources properly""",

    # -----------------------------------------------------------------------
    # CWE-330  Weak Random
    # -----------------------------------------------------------------------
    'CWE-330': """**CWE-330 (Weak Random)**:
- Use secrets module: `token = secrets.token_urlsafe(32)`
- Never use random module for security""",
}


def get_cwe_guidance(cwe_id: str) -> str:
    """Extract relevant CWE guidance based on vulnerability CWE."""
    if not cwe_id:
        return ""

    # Normalize to CWE-XXX format
    if 'CWE-' in cwe_id:
        parts = cwe_id.split('CWE-')
        cwe_num = parts[-1].split('-')[0]  # Get last CWE number
        cwe_key = f'CWE-{cwe_num}'
    else:
        cwe_key = f'CWE-{cwe_id}'

    return CWE_GUIDANCE.get(cwe_key, "")


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a security engineer fixing vulnerabilities with MINIMAL code changes.

⚠️ CRITICAL RULES:
- Fix ONLY the vulnerable line(s) - typically 1-5 lines
- Keep ALL existing code structure, formatting, imports unchanged
- NO refactoring, style improvements, or extra features
- DO NOT include decorators when SCOPE is function (they're preserved automatically)
- DO NOT create nested/duplicate code blocks

SCOPE DEFINITIONS:
- **SCOPE: function** (DEFAULT - Use for most fixes)
  * Return ONLY 'def function_name(...)' body
  * **NO decorators** (@app.route, etc.) - they already exist and are preserved
  * Start with 'def function_name(...)' line
  * End with last line of function body
  * If you need imports, add inside function (e.g., "import shlex" as first line)
  * Use even for simple changes within functions

- **SCOPE: line** (Use sparingly - only for module-level changes)
  * Return ONLY the fixed line(s) with proper indentation
  * Use for module-level code: if __name__ blocks, global variables, simple config
  * Example: `debug=True` → `debug=False` in app.run()
  * NOT for changes inside functions - use SCOPE: function instead

- **SCOPE: section** (Rare - only when changes span multiple functions)
  * Return complete section with clear boundaries

IMPORTS:
- Add imports inside the function: `import shlex` as first line
- System automatically hoists them to module level

MINIMALITY:
- Small functions (<15 lines): Max 5 lines changed
- Larger functions: Max 50% changed
- Typical fixes: 1-5 lines only

MULTI-STEP TAINT FLOWS:
- When user input flows through intermediate variables before reaching the sink
  (e.g. request → host → command → subprocess), fix at the CALL SITE only
- Do NOT add validation at every intermediate step — one fix breaks the taint

CODE STYLE:
- Follow PEP 8 conventions in any new code you write (spacing, naming, line length)
- Preserve the surrounding code style — match the indentation, quote style, and
  naming conventions already present in the file

OUTPUT FORMAT:
SCOPE: [function|line|section]
EXPLANATION: One sentence describing the fix

```python
# Fixed code
```
"""


# ---------------------------------------------------------------------------
# Initial fix prompt template
# ---------------------------------------------------------------------------

INITIAL_FIX_PROMPT_TEMPLATE = """# Vulnerability Fix Request

## Complete Finding Context (JSON)

Below is the full vulnerability information from SAST/DAST scanning tools.
**IMPORTANT**: Line numbers shown are from the ORIGINAL scan. After fixes are applied,
line numbers may shift. Focus on the vulnerable CODE PATTERN, not exact line numbers.

```json
{finding_json}
```

---

## Key Information Summary

**Finding**: {finding_number}
**ID**: {finding_id}
**CWE**: {cwe}
**Severity**: {severity}

### Description
{description}

### SAST Details
{sast_details}

### DAST Details
{dast_details}

### Data Flow (Taint Tracking)
{data_flow}

{cwe_guidance}

---

## Vulnerable Code Context

File: `{file_path}`
Original Lines: {start_line}-{end_line}

```python
{vulnerable_function_code}
```

---

## Your Task: Generate a Minimal Security Fix

⚠️ CRITICAL REQUIREMENTS:
1. **FOLLOW THE CWE GUIDANCE EXACTLY** - The guidance above shows the precise
   before/after pattern. Match it as closely as possible.
2. **FIX ONLY THE VULNERABILITY** - Change ONLY the vulnerable line(s)
3. **NO STYLE IMPROVEMENTS** - Keep original formatting, spacing, structure
4. **MINIMAL CHANGES** - Typical fixes: 1-5 lines only
5. **ACCOUNT FOR LINE NUMBER CHANGES** - The line numbers shown are from the original scan.
   Focus on the VULNERABLE CODE PATTERN (e.g., the line with "ET.fromstring(xml_data)")
   rather than relying on exact line numbers.

SCOPE DECISION:
- Inside a function? → Use SCOPE: function (even for 1-line changes)
- Module-level code (if __name__, globals)? → Use SCOPE: line
- Multiple functions? → Use SCOPE: section (rare)

CRITICAL REMINDERS:
- If SCOPE: function → Return ONLY 'def function_name(...)' body, **NO decorators**
- If SCOPE: line → Return ONLY the fixed line(s) with indentation
- Need an import? → Add inside function, it will be hoisted automatically
- Don't reorganize, refactor, or improve unrelated code
- Line numbers may have shifted - match the CODE PATTERN, not the line number

SCOPE: [function|line|section]
EXPLANATION: Brief fix description

```python
# Fixed code
```
"""


# ---------------------------------------------------------------------------
# Refinement prompt template
# ---------------------------------------------------------------------------

REFINEMENT_PROMPT_TEMPLATE = """# Fix Refinement Required

Your previous fix failed validation. Generate an improved fix.

## Complete Finding Context (JSON)

**REMINDER**: Line numbers shown are from the ORIGINAL scan and may have shifted
after previous fixes. Focus on the vulnerable CODE PATTERN, not exact line numbers.

```json
{finding_json}
```

{cwe_guidance}

## Original Vulnerability
{original_context}

## Previous Fix Attempt
```python
{previous_fix}
```

## Validation Errors
{validation_failures}

---

🚨 CRITICAL INSTRUCTIONS:

**ABOUT "UNDEFINED VARIABLE" ERRORS:**
- If you see "undefined variable 'app'" or "undefined variable 'request'"
- These are FALSE POSITIVES from linting isolated function code
- Variables ARE defined in full file, just not in your function snippet
- **DO NOT** add more code or context to "fix" these
- **IGNORE** them completely - they disappear when code is merged

**ABOUT LINE NUMBERS:**
- Line numbers in the JSON above are from the ORIGINAL scan
- After applying fixes, line numbers WILL shift
- Match the VULNERABLE CODE PATTERN (e.g., "ET.fromstring(xml_data)")
- NOT the exact line number

**YOUR ONLY JOB:**
1. If previous fix ALREADY correct → Return EXACT SAME code
2. If real syntax error (typo, wrong method) → Fix ONLY that error
3. NEVER add more code/functions to "fix" undefined variable errors

**WHAT "IMPROVED" MEANS:**
- ✅ Same vulnerability fix + fixed typo = IMPROVED
- ✅ Same code with corrected method name = IMPROVED
- ❌ Same fix + more context/functions = NOT IMPROVED (WORSE!)
- ❌ Same fix + style changes = NOT IMPROVED
- ❌ Same fix + optimizations = NOT IMPROVED

**COMMON FIX MISTAKES BY VULNERABILITY TYPE:**
- CWE-074 (Template Injection): escaping html_content does NOT fix SSTI —
  the template string itself must be static; pass user data as a render variable:
  render_template_string("{{ content }}", content=html_content)
- CWE-918 (SSRF): NEVER pass the original url variable to requests.get() — you must
  reconstruct with safe_url = urlunparse(parsed) and pass that instead; CodeQL tracks
  taint flow and validation alone is NOT enough to break the chain
- CWE-078 (Command Injection): regex validation does NOT break taint — use allowlist
  and retrieve FROM list: safe_host = next(h for h in ALLOWED_HOSTS if h == host), then
  use safe_host in subprocess, not the original host variable; fix ALL command-building branches
- CWE-601 (Open Redirect): redirect(parsed.path) is ALWAYS tainted — even with whitelist check;
  you MUST retrieve FROM list: safe_path = next(p for p in ALLOWED_PATHS if p == parsed.path)
- CWE-209 (Stack Trace): the exception variable `e` must NOT appear in the
  return value — log it with logging.error() and return a generic string

**RESPONSE FORMAT:**
Return ONLY the function/line with vulnerability fix. Nothing more.
- Use same SCOPE as previous attempt (usually function)
- Same structure as before
- ONLY change if there's a real bug to fix

⚠️ Adding more code or functions will FAIL the workflow!

SCOPE: function
EXPLANATION: What changed (or "No changes, previous fix correct")

```python
# Improved code (or same if correct)
```
"""


# ---------------------------------------------------------------------------
# Builder functions — identical signatures to v1 (drop-in compatible)
# ---------------------------------------------------------------------------

def build_initial_fix_prompt(
    finding: dict,
    analysis: dict,
    vulnerable_function_code: str,
    file_path: str
) -> str:
    """Build initial fix prompt with complete finding context and CWE-specific guidance injected."""
    sast_info = finding.get('sast', {}) or {}
    dast_info = finding.get('dast', {}) or {}
    location = sast_info.get('location', {}) or {}

    # Extract CWE and inject specific guidance into user prompt
    cwe = sast_info.get('cwe', '')
    cwe_guidance = get_cwe_guidance(cwe)

    # Format the complete finding as JSON for context
    finding_json = json.dumps(finding, indent=2)
    
    # Format SAST details
    sast_details = ""
    if sast_info.get('present'):
        sast_details = f"""- Tool: {sast_info.get('tool', 'unknown')}
- Rule ID: {sast_info.get('rule_id', 'unknown')}
- Severity: {sast_info.get('severity', 'unknown')}
- Confidence: {sast_info.get('confidence', 'unknown')}
- Location: {location.get('file_path', 'unknown')} @ lines {location.get('start_line', '?')}-{location.get('end_line', '?')}
- Function: {location.get('function', 'unknown')}"""
    else:
        sast_details = "- SAST: Not detected"
    
    # Format DAST details
    dast_details = ""
    if dast_info.get('present'):
        dast_details = f"""- Tool: {dast_info.get('tool', 'unknown')}
- Alert ID: {dast_info.get('alert_id', 'unknown')}
- Risk: {dast_info.get('risk', 'unknown')}
- Confidence: {dast_info.get('confidence', 'unknown')}
- Description: {dast_info.get('description', 'N/A')}"""
    else:
        dast_details = f"""- DAST: Not detected (reason: {dast_info.get('reason', 'not scanned')})"""
    
    # Format data flow (taint tracking)
    data_flow = ""
    if sast_info.get('data_flow'):
        flow_data = sast_info['data_flow']
        if flow_data.get('full_path'):
            data_flow = "Taint path:\n"
            for step in flow_data['full_path']:
                step_num = step.get('step', '?')
                step_loc = step.get('location', 'unknown')
                step_node = step.get('node', 'unknown')
                data_flow += f"  {step_num}. {step_loc}: {step_node}\n"
        else:
            data_flow = "No detailed data flow available"
    else:
        data_flow = "No data flow tracking available"

    # Build user prompt with CWE guidance injected
    user_prompt = INITIAL_FIX_PROMPT_TEMPLATE.format(
        finding_json=finding_json,
        finding_number=finding.get('finding_number', 'UNKNOWN'),
        cwe_guidance=f"\n{cwe_guidance}\n" if cwe_guidance else "",
        finding_id=finding.get('finding_id', 'UNKNOWN'),
        cwe=cwe,
        severity=finding.get('baseline_severity', 'unknown'),
        description=sast_info.get('description', 'No description available'),
        sast_details=sast_details,
        dast_details=dast_details,
        data_flow=data_flow,
        file_path=file_path,
        start_line=location.get('start_line', 'unknown'),
        end_line=location.get('end_line', 'unknown'),
        vulnerable_function_code=vulnerable_function_code,
    )

    return user_prompt


def build_refinement_prompt(
    original_context: str,
    previous_fix: str,
    validation_failures: str,
    finding: dict,
    iteration: int = 2,
    max_iterations: int = 3
) -> str:
    """Build refinement prompt with complete finding context and explicit CWE guidance re-injection."""
    # Re-extract CWE and guidance to keep it prominent in refinement attempts
    sast_info = finding.get('sast', {}) or {}
    cwe = sast_info.get('cwe', '')
    cwe_guidance = get_cwe_guidance(cwe)

    # Format the complete finding as JSON for context
    finding_json = json.dumps(finding, indent=2)

    # Format CWE guidance block if we have it
    cwe_block = ""
    if cwe_guidance:
        cwe_block = f"""## 🎯 CWE-{cwe} Security Guidance (attempt {iteration}/{max_iterations})

{cwe_guidance}

⚠️ **REMINDER**: Your fix MUST follow the security pattern above!
---
"""

    return REFINEMENT_PROMPT_TEMPLATE.format(
        finding_json=finding_json,
        cwe_guidance=cwe_block,
        original_context=original_context,
        previous_fix=previous_fix,
        validation_failures=validation_failures,
    )