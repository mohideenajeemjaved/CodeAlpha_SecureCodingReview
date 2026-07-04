# CodeAlpha_SecureCodingReview

**CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review**

## Overview
This project audits a small Python/Flask application ("MiniBlog") for common
security vulnerabilities, documents each finding with severity and CWE
mapping, and provides remediated code.

## Contents
- `sample_app/app.py` — the original application **as audited** (intentionally vulnerable)
- `sample_app/app_fixed.py` — the remediated version implementing every fix
- `SECURITY_REVIEW.docx` / `SECURITY_REVIEW.pdf` — full write-up: methodology, findings, severity ratings, vulnerable/fixed code, recommendations

## Findings at a glance
| ID | Finding | Severity |
|----|---------|----------|
| VULN-01 | Hardcoded Credentials & Secret Key | High |
| VULN-02 | SQL Injection | Critical |
| VULN-03 | Reflected XSS | High |
| VULN-04 | Weak, Unsalted Password Hashing (MD5) | High |
| VULN-05 | Insecure Deserialization (pickle) | Critical |
| VULN-06 | Missing Authorization on Destructive Endpoint | Critical |
| VULN-07 | Debug Mode Enabled / Bound to 0.0.0.0 | Medium |

## Methodology
Manual line-by-line static review of the source, threat-modeled per route,
each finding mapped to a CWE and rated by impact × exploitability, and
cross-checked against the OWASP Top 10 (2021).

## Disclaimer
`sample_app/app.py` contains intentional vulnerabilities for educational
purposes only. Do not deploy it as-is.

---
*Submitted as part of the CodeAlpha Cyber Security Internship.*
