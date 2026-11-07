"""
LLM Prompt Templates - Optimized and CWE-Specific
"""

import json

# CWE-specific security guidance (extracted for conditional inclusion)
CWE_GUIDANCE = {
    'CWE-078': """**CWE-078 (Command Injection)**:
- Use subprocess with shell=False and list arguments
- Use allowlist: `ALLOWED_HOSTS = {'localhost', '127.0.0.1'}`
- Validate: `if host not in ALLOWED_HOSTS: return 400`
- Retrieve FROM list: `safe_host = next(h for h in ALLOWED_HOSTS if h == host)`
- Use safe_host in subprocess: `subprocess.run(['ping', '-c', '2', safe_host], shell=False)`
- Regex validation does NOT break CodeQL taint—must use allowlist retrieval""",
    
    'CWE-089': """**CWE-089 (SQL Injection)**:
- Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- NEVER concatenate or f-string user input into SQL""",
    
    'CWE-079': """**CWE-079 (XSS)**:
- Escape HTML: `html.escape(user_input, quote=True)`
- Apply to ALL user input before rendering""",
    
    'CWE-022': """**CWE-022 (Path Traversal)**:
- Validate paths: `abs_path = os.path.abspath(path)`
- Check prefix: `if not abs_path.startswith(safe_dir): raise ValueError`""",
    
    'CWE-215': """**CWE-215 (Debug Mode)**:
- Change: `app.run(debug=True)` → `app.run(debug=False)`
- Single line fix, use SCOPE: line""",
    
    'CWE-601': """**CWE-601 (Open Redirect)**:
- Parse URL with urlparse and check both netloc and scheme
- Validate: `if parsed.path in ALLOWED_PATHS and not netloc and not scheme`
- Retrieve FROM list: `safe_path = next(p for p in ALLOWED_PATHS if p == parsed.path)`
- Use safe_path: `return redirect(safe_path)`
- Never redirect(parsed.path) directly—always retrieve from hardcoded list""",
    
    'CWE-352': """**CWE-352 (CSRF)**:
- Generate and validate CSRF tokens
- Check token before processing: `if csrf_token != session.get('csrf_token'): return 403`""",
    
    'CWE-020': """**CWE-020 (Input Validation)**:
- Validate type, range, format
- Example: `if not isinstance(age, int) or not (0 <= age <= 150): return 400`""",
    
    'CWE-327': """**CWE-327 (Weak Crypto)**:
- Use AES-256, not DES/3DES
- Example: `cipher = AES.new(key, AES.MODE_GCM)`""",
    
    'CWE-502': """**CWE-502 (Insecure Deserialization)**:
- Use JSON instead of pickle: `data = json.loads(request.data)`
- Never: `pickle.loads()` on untrusted data""",
    
    'CWE-918': """**CWE-918 (SSRF)**:
- Allowlist domains: `if parsed.netloc not in allowed: return 400`
- Reconstruct URL: `safe_url = urlunparse(parsed)` and pass that to requests.get()
- NEVER pass the original user-supplied url variable""",
    
    'CWE-611': """**CWE-611 (XXE)**:
- Use defusedxml: `tree = DefusedET.parse(xml_data)`
- Or disable entities: `parser.entity = {}`""",
    
    'CWE-284': """**CWE-284 (IDOR)**:
- Verify ownership: `if account.owner_id != user_id: return 403`
- Check authorization before accessing resources""",
    
    'CWE-400': """**CWE-400 (Resource Leak)**:
- Use context managers: `with open(filename) as f:`
- Always close resources properly""",
    
    'CWE-330': """**CWE-330 (Weak Random)**:
- Use secrets module: `token = secrets.token_urlsafe(32)`
- Never use random module for security"""
}


def get_cwe_guidance(cwe_id: str) -> str:
    """Extract relevant CWE guidance based on vulnerability CWE"""
    # Extract CWE number (e.g., "CWE-078" from "CWE-CWE-078" or "078")
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


SYSTEM_PROMPT = """You are a security engineer fixing vulnerabilities with MINIMAL code changes.

⚠️ CRITICAL RULES:
- Fix ONLY the vulnerable line(s) - typically 1-3 lines
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
- Small functions (<15 lines): Max 15 lines changed
- Larger functions: Max 50% changed
- Typical fixes: 1-5 lines only

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
1. **FOLLOW THE CWE GUIDANCE EXACTLY** - The guidance above shows the precise pattern
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


def build_initial_fix_prompt(
    finding: dict,
    analysis: dict,
    vulnerable_function_code: str,
    file_path: str
) -> str:
    """Build initial fix prompt with complete finding context and CWE-specific guidance"""
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
    
    # Build user prompt with all context
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
        vulnerable_function_code=vulnerable_function_code
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
    """Build refinement prompt with complete finding context and explicit CWE guidance re-injection"""
    # Re-extract CWE and guidance to keep it prominent in refinement attempts
    sast_info = finding.get('sast', {}) or {}
    cwe = sast_info.get('cwe', '')
    cwe_guidance = get_cwe_guidance(cwe)
    
    # Format the complete finding as JSON for context
    finding_json = json.dumps(finding, indent=2)
    
    # Format CWE guidance block if we have it
    cwe_block = ""
    if cwe_guidance:
        cwe_block = f"""## 🎯 CWE-{cwe} Security Guidance (Attempt {iteration}/{max_iterations})

{cwe_guidance}

⚠️ **REMINDER**: Your fix MUST follow the security pattern above!
---
"""
    
    return REFINEMENT_PROMPT_TEMPLATE.format(
        finding_json=finding_json,
        cwe_guidance=cwe_block,
        original_context=original_context,
        previous_fix=previous_fix,
        validation_failures=validation_failures
    )
