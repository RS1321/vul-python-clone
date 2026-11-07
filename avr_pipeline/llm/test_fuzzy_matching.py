"""
Test the fuzzy matching logic for line shifts
"""
import json

# Simulated data from the actual run
original_findings = {
    "py/command-line-injection:vulnerable_app.py:412": {
        "rule_id": "py/command-line-injection",
        "file_path": "vulnerable_app.py",
        "line": 412
    },
    "py/flask-debug:vulnerable_app.py:507": {
        "rule_id": "py/flask-debug",
        "file_path": "vulnerable_app.py",
        "line": 507
    },
    "py/stack-trace-exposure:vulnerable_app.py:116": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 116
    },
    "py/stack-trace-exposure:vulnerable_app.py:241": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 241
    },
    "py/stack-trace-exposure:vulnerable_app.py:355": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 355
    },
    "py/stack-trace-exposure:vulnerable_app.py:393": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 393
    },
    "py/stack-trace-exposure:vulnerable_app.py:415": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 415
    },
    "py/stack-trace-exposure:vulnerable_app.py:433": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 433
    },
    "py/xml-bomb:vulnerable_app.py:424": {
        "rule_id": "py/xml-bomb",
        "file_path": "vulnerable_app.py",
        "line": 424
    }
}

# "New" findings that are actually just shifted
new_findings_shifted = {
    "py/flask-debug:vulnerable_app.py:516": {
        "rule_id": "py/flask-debug",
        "file_path": "vulnerable_app.py",
        "line": 516
    },
    "py/command-line-injection:vulnerable_app.py:413": {
        "rule_id": "py/command-line-injection",
        "file_path": "vulnerable_app.py",
        "line": 413
    },
    "py/stack-trace-exposure:vulnerable_app.py:416": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 416
    },
    "py/xml-bomb:vulnerable_app.py:424": {
        "rule_id": "py/xml-bomb",
        "file_path": "vulnerable_app.py",
        "line": 424
    },
    "py/stack-trace-exposure:vulnerable_app.py:428": {
        "rule_id": "py/stack-trace-exposure",
        "file_path": "vulnerable_app.py",
        "line": 428
    }
}

LINE_SHIFT_TOLERANCE = 20

# Identify truly new vulnerabilities
new_vuln_keys = set(new_findings_shifted.keys()) - set(original_findings.keys())
print(f"\n{'='*70}")
print("TESTING FUZZY MATCHING FOR LINE SHIFTS")
print(f"{'='*70}")
print(f"\nPotential new vulnerabilities (before fuzzy matching): {len(new_vuln_keys)}")

truly_new_vulnerabilities = []

for new_key in new_vuln_keys:
    new_vuln = new_findings_shifted[new_key]
    is_false_positive = False
    
    # Check if this matches an original finding with line shift
    for orig_key, orig_vuln in original_findings.items():
        line_diff = abs(new_vuln['line'] - orig_vuln['line'])
        if (new_vuln['rule_id'] == orig_vuln['rule_id'] and
            new_vuln['file_path'] == orig_vuln['file_path'] and
            line_diff <= LINE_SHIFT_TOLERANCE):
            # This is likely the same vulnerability at a shifted line
            print(f"\n  🔍 Fuzzy Match Found:")
            print(f"     Original: {orig_vuln['rule_id']} at line {orig_vuln['line']}")
            print(f"     New:      {new_vuln['rule_id']} at line {new_vuln['line']}")
            print(f"     Shift:    {new_vuln['line'] - orig_vuln['line']:+d} lines")
            print(f"     ✓ Filtered as FALSE POSITIVE (likely line shift)")
            is_false_positive = True
            break
    
    if not is_false_positive:
        print(f"\n  ⚠️  Truly New Vulnerability:")
        print(f"     {new_vuln['rule_id']} at line {new_vuln['line']}")
        truly_new_vulnerabilities.append(new_vuln)

print(f"\n{'='*70}")
print(f"RESULTS:")
print(f"  Initial 'new' vulnerabilities: {len(new_vuln_keys)}")
print(f"  After fuzzy matching:          {len(truly_new_vulnerabilities)}")
print(f"  False positives filtered:      {len(new_vuln_keys) - len(truly_new_vulnerabilities)}")
print(f"{'='*70}\n")
