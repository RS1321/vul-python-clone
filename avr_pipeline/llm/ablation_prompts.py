"""
LLM Prompt Templates - Ablation Condition (Run B)

Identical to new_prompts.py with ONE change:
  CWE_GUIDANCE is empty — no CWE-specific code snippets or fix examples are
  injected into either the initial fix prompt or the refinement prompt.

This is the ablation condition used to isolate the contribution of structured
CWE-specific context to remediation accuracy (addresses RQ2).

To activate, set in config.json:
    "pipeline": {
        "prompts_module": "ablation_prompts"
    }

To use the full guided prompts, set:
    "pipeline": {
        "prompts_module": "new_prompts"
    }
"""

import json

# ---------------------------------------------------------------------------
# CWE guidance — intentionally empty for ablation condition.
# get_cwe_guidance() will return "" for every CWE, so no guidance block is
# injected into either the initial fix prompt or the refinement prompt.
# ---------------------------------------------------------------------------
CWE_GUIDANCE = {}


def get_cwe_guidance(cwe_id: str) -> str:
    """Returns empty string for all CWEs in the ablation condition."""
    return ""


# ---------------------------------------------------------------------------
# System prompt  — identical to new_prompts.py
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
# Initial fix prompt template — identical to new_prompts.py
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
1. **FIX ONLY THE VULNERABILITY** - Change ONLY the vulnerable line(s)
2. **NO STYLE IMPROVEMENTS** - Keep original formatting, spacing, structure
3. **MINIMAL CHANGES** - Typical fixes: 1-5 lines only
4. **ACCOUNT FOR LINE NUMBER CHANGES** - The line numbers shown are from the original scan.
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
# Refinement prompt template — identical to new_prompts.py
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
# Builder functions — identical signatures to new_prompts.py (drop-in)
# ---------------------------------------------------------------------------

def build_initial_fix_prompt(
    finding: dict,
    analysis: dict,
    vulnerable_function_code: str,
    file_path: str
) -> str:
    """Build initial fix prompt without CWE-specific guidance (ablation condition)."""
    sast_info = finding.get('sast', {}) or {}
    dast_info = finding.get('dast', {}) or {}
    location = sast_info.get('location', {}) or {}

    cwe = sast_info.get('cwe', '')
    # Ablation: always returns ""
    cwe_guidance = get_cwe_guidance(cwe)

    finding_json = json.dumps(finding, indent=2)

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

    dast_details = ""
    if dast_info.get('present'):
        dast_details = f"""- Tool: {dast_info.get('tool', 'unknown')}
- Alert ID: {dast_info.get('alert_id', 'unknown')}
- Risk: {dast_info.get('risk', 'unknown')}
- Confidence: {dast_info.get('confidence', 'unknown')}
- Description: {dast_info.get('description', 'N/A')}"""
    else:
        dast_details = f"""- DAST: Not detected (reason: {dast_info.get('reason', 'not scanned')})"""

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
    """Build refinement prompt without CWE-specific guidance (ablation condition)."""
    sast_info = finding.get('sast', {}) or {}
    cwe = sast_info.get('cwe', '')
    # Ablation: always returns ""
    cwe_guidance = get_cwe_guidance(cwe)

    finding_json = json.dumps(finding, indent=2)

    # cwe_block will always be "" in ablation condition
    cwe_block = ""

    return REFINEMENT_PROMPT_TEMPLATE.format(
        finding_json=finding_json,
        cwe_guidance=cwe_block,
        original_context=original_context,
        previous_fix=previous_fix,
        validation_failures=validation_failures,
    )
