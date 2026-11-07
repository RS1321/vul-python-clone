# Security repair and active-validation results

This follow-up addresses the six failed VAmPI security assertions, extends execution to all 21 pinned PyGoat lesson directories, and runs authenticated active SQL/XSS scans. The repairs are explicitly agent-authored defensive changes. They are not additional successes of the five free models, and the earlier model outputs and scores remain unchanged. PyGoat starts from its pinned public baseline plus the previously saved Gemini patch; VAmPI starts from its pinned public baseline. Only separate local clones are changed.

| Check | Result |
|---|---|
| VAmPI original security assertions | 8/8 pass; baseline was 2/8 |
| VAmPI extended security assertions | 11/11 pass; legitimate password/email changes also pass |
| PyGoat lesson suites | 21/21 pass, including the separate Django lesson and main.py entrypoints |
| PyGoat original targeted assertions | 19/19 pass across host plus XSS, SQL, SSRF and command lessons |
| PyGoat host/build-directory/error checks | 19/19 pass |
| CodeQL findings: PyGoat | 62 baseline → 0 after repair |
| CodeQL findings: VAmPI | 3 baseline → 0 after repair |
| Pipeline checks | 40/40 pass |

Zero findings means no results from the same CodeQL security-extended query suite on the final source. It does not prove that every possible vulnerability is absent. The earlier static-only improvements were insufficient: targeted authorization tests remained red. Both static and behavioral gates are now recorded.

## Repairs

- VAmPI: enforce book/password/email ownership, ignore client-supplied admin assignment, remove public debug credentials, use uniform login failures, parameterize user lookup through the ORM, hash stored passwords, replace the costly email regex, generate the JWT secret securely, and add JSON response headers.
- PyGoat: replace unsigned/pickled user state with signed sessions or bounded safe parsing; prevent template/HTML injection; validate owned file/build selections; constrain lesson URL/command destinations; replace fast password hashes with salted password KDFs; bound OTP attempts, expiry and replay; enforce sensitive-data access; remove exception details from responses; disable debug mode and use securely generated/configured Django secrets.
- Forms: enable Flask-WTF CSRF protection, add tokens to real forms, provide a same-origin fetch helper, and use per-request CSP nonces in trusted templates. Debug/header controls are installed before direct startup. Browser scripts are syntax-checked; a complete visual browser/deployment test is not claimed.

The lookup lesson intentionally permits only example.com and example.invalid. The URL-fetch lesson permits only http(s)://example.com without redirects. File/build access uses enumerated local choices. These are explicit bounded application policies, not a claim to safely accept arbitrary commands, URLs or paths. The reset demonstration no longer returns a live reset bearer token in the response; production email delivery remains deployment configuration. For multiple workers or persistent logins, configure VAMPI_SECRET_KEY and PYGOAT_SECRET_KEY securely; random fallbacks deliberately invalidate sessions across restarts.

## All lesson observations

| Lesson | Hardened assertions | Result |
|---|---:|---|
| a9_uckv_lab | 11/11 | pass |
| auth_failure_lab | 13/13 | pass |
| broken_access_lab | 10/10 | pass |
| broken_auth_lab | 9/9 | pass |
| command_injection_lab | 8/8 | pass |
| crypto_failure_lab | 9/9 | pass |
| dependency_attack_lab | 8/8 | pass |
| insec_des_lab | 9/9 | pass |
| insecure_design_lab | 9/9 | pass |
| insufficient_logging_lab | 9/9 | pass |
| open_source_library_attack_lab | 9/9 | pass |
| package_injection_lab | 8/8 | pass |
| sde | 8/8 | pass |
| sec_misconfig | 11/11 | pass |
| sensitive_data_exposure | 6/6 | pass |
| software_integrity_lab | 8/8 | pass |
| sql_injection_lab | 8/8 | pass |
| ssrf_lab | 8/8 | pass |
| template_injection_lab | 9/9 | pass |
| xss_lab | 8/8 | pass |
| xxe_lab | 9/9 | pass |

Every suite includes execution/normal-use checks and relevant security assertions; several informational supply-chain lessons have narrower checks. Shared header assertions occur in multiple suites and are not independent vulnerabilities. Passing 21 suites is coverage of these cases, not exhaustive verification of every endpoint or deployment behavior. Baseline failures include known vulnerable behavior, missing headers, and the old Pillow ImageMath.eval API being unavailable on the recorded modern Pillow runtime. That compatibility failure is preserved and is not counted as a security improvement.

The initial final-run account-enumeration check compared complete HTML bytes. Once per-request CSP nonces were added, that comparison failed for legitimate nonce variation. The corrected oracle compares response status and application error context; the original enumeration behavior still fails and the uniform repaired response passes. Earlier observations are retained.

## Authenticated active scans

ZAP 2.17.0 runs active reflected-XSS rule 40012 and SQL-injection rule 40018 at low strength, with other active rules disabled, on disposable loopback targets. The PyGoat SQL/XSS lessons are mounted behind verification against a real Django fixture session; this models the authenticated lesson boundary without Docker/Traefik. VAmPI uses its native JWT. An anonymous denial and authenticated 200 response are verified before scanning. Valid form tokens/sessions are retained, so CSRF stays enabled. Traffic records count active-rule requests and fixture authentication. There is no active exposure of command execution, arbitrary file/network operations, container orchestration or external targets.

| Target / state | Active-rule requests | Authenticated requests / all | Active alert groups | Other alert IDs |
|---|---:|---:|---:|---|
| pygoat / baseline | 63 | 81/82 | 1 | 10020, 10021, 10036, 10038, 10109, 10202 |
| pygoat / hardened | 69 | 87/88 | 0 | 10036, 10109, 10111, 10112 |
| vampi / baseline | 36 | 55/56 | 0 | 10021, 10036 |
| vampi / hardened | 36 | 55/56 | 0 | 10036 |

The original PyGoat target produces a reflected-XSS alert; the hardened target does not. The missing-CSRF/header/CSP findings in the earlier scan are also absent from the final repaired scan. SQL rule requests execute, but this scan does not detect SQL injection in the vulnerable VAmPI control; its explicit SQL/auth regression tests provide the discriminating behavioral evidence. Remaining server-version alerts originate from the local WSGI test server. Modern-web-application/timing information is informational. No claim of exhaustive active DAST or zero alerts of every kind is made. Rules and authentication handling follow the [ZAP active-scan documentation](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/) and [header-authentication guidance](https://www.zaproxy.org/docs/getting-further/authentication/handling-auth-yourself/).

## Reproduce and review

The complete local repaired sources are in each dataset’s source directory alongside this report. The delivery omits source clones, databases, tool installations and credentials, but includes full repair scripts, pinned inputs, review hardening.patch files, manifests and raw results. Run the following from the pipeline root after the existing benchmark/environment setup. Use a fresh output location if the named repair clone already exists.

```powershell
python review/prepare_inputs.py
python continuation/resolve_security.py vampi v6
python continuation/resolve_security.py pygoat v6
python continuation/lesson_suite.py
python continuation/active_security_scan.py
python continuation/security_resolution_report.py
```

Some public benchmark fixtures resemble API credentials, including lines removed by the repair. Exported review diffs redact those strings and must not be used directly with git apply. Use resolve_security.py, which reproduces the changes from pinned public inputs without publishing the removed credential strings. The original Gemini PyGoat patch is checked in under review_results/gemini-3.5-flash-lite-A-pygoat-fivefree-v2-r1/net.patch and is applied before the agent changes. The lesson environment uses the VAmPI environment plus the recorded Pillow, Argon2, PyYAML, defusedxml and Flask-WTF packages; exact resolved versions are in environment-lessons.txt. The Django environment is recorded in environment-django.txt. Scanner setup matches the earlier package. Run review/vampi_resolution_checks.py, review/challenge_security.py and review/external_security.py with --repo and a fresh --out for the additional recorded checks. The static scans use review/runner.py scan --repo CLONE --out FRESH_SCAN_DIR. The report regenerates offline from saved JSON/SARIF/XML without source clones, scanner installs, provider access or credentials.

Agent iterations, initial failures and earlier model results remain in adjacent directories. Only security-resolution-v6 with the final scan/test folders is the delivery revision. No manuscript edits or original human-review provenance are asserted.
