---
name: security-analyzer
description: Comprehensive security vulnerability analysis for codebases and infrastructure. Use when users request security audits, vulnerability scans, penetration testing guidance, security posture assessment, or need to identify and remediate CVEs/exploits. Triggers on keywords like "security scan", "vulnerability", "CVE", "exploit", "security audit", "penetration test", "OWASP", "hardening", or requests to improve security posture. Supports cloud infra, web apps, APIs, containers, and on-prem environments.
---

# Security Analyzer

Analyze environments for vulnerabilities, fetch current CVE/exploit data, generate phased remediation plans with TDD validation.

## Workflow

### Phase 1: Environment Discovery

Scan working directory for:
- Dependencies: `package.json`, `requirements.txt`, `Gemfile`, `go.mod`, `Cargo.toml`, `pom.xml`
- Containers: `Dockerfile`, `docker-compose.yml`, `kubernetes/*.yaml`
- Cloud: `terraform/*.tf`, `cloudformation/*.yaml`, `*.bicep`
- Secrets: `.env*` files (flag exposure risk, never log values)

Run `scripts/discover_env.py` to build asset inventory JSON.

### Phase 2: Vulnerability Intelligence

Fetch current threat data using web search and `scripts/fetch_vulns.py`:

| Source | Priority | Use For |
|--------|----------|---------|
| CISA KEV | 1 | Actively exploited vulns |
| NVD | 2 | CVE details + CVSS scores |
| GitHub Advisories | 3 | Package-specific vulns |
| OSV.dev | 4 | Open source vulns |

### Phase 3: Risk Scoring

```
Risk = (CVSS * 0.3) + (Exploitability * 0.3) + (Criticality * 0.2) + (Exposure * 0.2)

Exploitability: 10=CISA KEV, 7=public exploit, 3=theoretical
Criticality: 10=auth/payment, 5=core business, 2=logging
Exposure: 10=internet-facing, 5=internal, 2=air-gapped
```

### Phase 4: Phased Remediation

Generate phases by risk score (highest first). Each finding includes:
1. Vulnerability details + risk score
2. Actual fix code/patch (not just recommendations)
3. Pre-fix test (proves vuln exists)
4. Remediation unit tests (tests the fix code)
5. Post-fix validation (proves vuln resolved)

See `references/report-templates.md` for output structure.

### Phase 5: Reports

Output to `/mnt/user-data/outputs/`:
- `security-report-technical.md` - Full details for engineers
- `security-report-executive.md` - Summary for leadership

## TDD Pattern

```python
# For each vulnerability:

def test_vuln_exists():
    """PASS before fix, FAIL after"""
    assert is_vulnerable("component") == True

def test_fix_works():
    """Unit test for remediation code"""
    result = apply_fix(vulnerable_config)
    assert result.is_secure()

def test_vuln_resolved():
    """FAIL before fix, PASS after"""  
    assert is_vulnerable("component") == False
```

## Fix Types

| Finding | Output |
|---------|--------|
| Dependency CVE | Version bump + lockfile command |
| Container issue | Dockerfile patch |
| IaC misconfiguration | Terraform/K8s fix |
| Code vuln | Source patch + test |
| Secret exposure | Rotation commands + `.gitignore` |
