# Security Analyzer: 20 Use Cases

Real-world situations where this skill helps secure your environment.

---

## Pre-Deployment & Release

### 1. Hardening Before Production Deployment

**Situation:** You've finished building a feature and are ready to deploy to production.

**How to use:**
```
"Run a security scan before I deploy this to production"
```

**What the skill does:**
- Scans all dependencies for known CVEs
- Checks Docker configurations for security misconfigurations
- Identifies any exposed secrets in environment files
- Generates a pre-deployment security checklist with fixes

---

### 2. Release Candidate Security Gate

**Situation:** Your team requires a security sign-off before releasing a new version.

**How to use:**
```
"Generate a security report for our v2.0 release candidate"
```

**What the skill does:**
- Produces executive summary for leadership approval
- Lists all vulnerabilities by severity with risk scores
- Provides estimated remediation effort
- Creates technical report for engineering handoff

---

### 3. CI/CD Pipeline Security Check

**Situation:** You want to add security scanning to your deployment pipeline.

**How to use:**
```
"What vulnerabilities would block this build from deploying?"
```

**What the skill does:**
- Identifies critical/high severity issues that should block deployment
- Provides fix commands that can be automated in CI
- Generates machine-readable output for pipeline integration

---

## During Development

### 4. New Dependency Evaluation

**Situation:** You're considering adding a new npm/pip/gem package to your project.

**How to use:**
```
"Check if adding lodash@4.17.15 would introduce vulnerabilities"
```

**What the skill does:**
- Queries OSV.dev for known vulnerabilities in that version
- Recommends the latest secure version
- Shows the CVE history for the package

---

### 5. After Major Dependency Updates

**Situation:** You just ran `npm update` or `pip install --upgrade` and want to verify nothing broke security-wise.

**How to use:**
```
"Scan my updated dependencies for new vulnerabilities"
```

**What the skill does:**
- Compares current versions against vulnerability databases
- Identifies if any updates introduced new CVEs
- Checks for dependency confusion risks

---

### 6. Legacy Code Audit

**Situation:** You inherited an old codebase and need to understand its security posture.

**How to use:**
```
"Audit this legacy project for security issues - it hasn't been updated in 2 years"
```

**What the skill does:**
- Discovers all outdated dependencies
- Prioritizes vulnerabilities by exploitability (CISA KEV first)
- Creates phased remediation plan to modernize safely

---

### 7. Design Review Security Check

**Situation:** You're reviewing architecture decisions before implementation.

**How to use:**
```
"Review our Terraform configs for security best practices before we build the infrastructure"
```

**What the skill does:**
- Analyzes IaC files for misconfigurations
- Checks for overly permissive IAM policies
- Identifies exposed ports and public resources
- Suggests security hardening before resources are created

---

## Incident Response

### 8. Zero-Day Response

**Situation:** A new critical CVE was announced (like Log4Shell) and you need to check if you're affected.

**How to use:**
```
"Am I affected by CVE-2021-44228? Scan for Log4j vulnerabilities"
```

**What the skill does:**
- Searches all dependency files for the affected package
- Checks transitive dependencies
- Provides immediate remediation steps
- Generates tests to verify the fix

---

### 9. Post-Breach Assessment

**Situation:** You suspect a security incident and need to identify potential entry points.

**How to use:**
```
"Identify all critical vulnerabilities that could have been exploited in this codebase"
```

**What the skill does:**
- Prioritizes actively exploited vulnerabilities (CISA KEV)
- Identifies exposed secrets that may need rotation
- Checks for common attack vectors (OWASP Top 10)

---

### 10. Vendor Security Questionnaire

**Situation:** A client or partner sent a security questionnaire about your application.

**How to use:**
```
"Generate a security posture report for our vendor assessment"
```

**What the skill does:**
- Creates executive-level security summary
- Documents current vulnerabilities and remediation status
- Provides evidence of security scanning practices

---

## Cloud & Infrastructure

### 11. Terraform Security Review

**Situation:** You're about to `terraform apply` new infrastructure.

**How to use:**
```
"Check my Terraform files for security misconfigurations"
```

**What the skill does:**
- Scans `.tf` files for common issues
- Identifies public S3 buckets, open security groups
- Checks for hardcoded secrets in IaC
- Suggests security group and IAM improvements

---

### 12. Kubernetes Deployment Hardening

**Situation:** You're deploying containers to Kubernetes and want to follow security best practices.

**How to use:**
```
"Review my Kubernetes manifests for security issues"
```

**What the skill does:**
- Checks for privileged containers
- Identifies missing security contexts
- Reviews network policies
- Flags containers running as root

---

### 13. Docker Image Security

**Situation:** You want to ensure your Docker images are secure before pushing to registry.

**How to use:**
```
"Scan my Dockerfiles for security best practices"
```

**What the skill does:**
- Checks base image for known vulnerabilities
- Identifies secrets in build layers
- Reviews multi-stage build security
- Suggests minimal base images

---

## Compliance & Governance

### 14. Compliance Audit Preparation

**Situation:** SOC 2, HIPAA, or PCI-DSS audit is coming up and you need to demonstrate security controls.

**How to use:**
```
"Generate a security compliance report for our SOC 2 audit"
```

**What the skill does:**
- Documents all identified vulnerabilities
- Shows remediation timelines and effort
- Provides evidence of regular scanning
- Creates executive summary for auditors

---

### 15. Third-Party Library Risk Assessment

**Situation:** Legal or security team needs a report on open source dependencies.

**How to use:**
```
"List all our dependencies with their known vulnerabilities and licenses"
```

**What the skill does:**
- Inventories all dependencies across ecosystems
- Maps CVEs to each package
- Identifies high-risk transitive dependencies
- Supports SBOM (Software Bill of Materials) requirements

---

## Team & Process

### 16. Security Training Material

**Situation:** You want to educate your team about real vulnerabilities in your codebase.

**How to use:**
```
"Find examples of security issues in our code I can use for team training"
```

**What the skill does:**
- Identifies real vulnerabilities with context
- Explains why each is dangerous
- Shows the fix with before/after comparison
- Provides test cases to demonstrate the issue

---

### 17. Pull Request Security Review

**Situation:** A PR adds new dependencies or changes security-sensitive code.

**How to use:**
```
"Check if the dependencies added in this PR have any vulnerabilities"
```

**What the skill does:**
- Scans only the changed/added dependencies
- Provides quick pass/fail assessment
- Suggests secure alternatives if issues found

---

### 18. Technical Debt Prioritization

**Situation:** You have limited time and need to know which security fixes matter most.

**How to use:**
```
"Rank our security vulnerabilities by actual risk, not just CVSS score"
```

**What the skill does:**
- Applies risk scoring formula (CVSS + exploitability + criticality + exposure)
- Prioritizes CISA KEV (actively exploited) vulnerabilities
- Considers your specific architecture context
- Creates actionable sprint backlog

---

## Secrets & Configuration

### 19. Secrets Exposure Check

**Situation:** You want to ensure no API keys, passwords, or tokens are exposed in the repo.

**How to use:**
```
"Check if any secrets or credentials are exposed in this project"
```

**What the skill does:**
- Scans for `.env` files not in `.gitignore`
- Identifies potential hardcoded credentials
- Checks for exposed API keys in config files
- Provides remediation (rotation commands, gitignore updates)

---

### 20. Environment Configuration Audit

**Situation:** You're setting up a new environment and want to ensure secure defaults.

**How to use:**
```
"Audit my environment configuration for security issues"
```

**What the skill does:**
- Reviews all configuration files
- Checks for debug modes enabled in production
- Identifies insecure default settings
- Validates SSL/TLS configurations

---

## Quick Reference

| Situation | Trigger Phrase |
|-----------|---------------|
| Pre-deployment | "security scan before deploy" |
| New dependency | "check if [package] is secure" |
| Zero-day response | "am I affected by CVE-XXXX-YYYY" |
| Compliance audit | "generate security compliance report" |
| Legacy code | "audit this old codebase" |
| Secrets check | "check for exposed secrets" |
| Infrastructure | "review my Terraform/Kubernetes" |
| Risk prioritization | "rank vulnerabilities by risk" |
| Team training | "find security examples for training" |
| PR review | "check dependencies in this PR" |

---

## Getting Started

In any Claude Code session with this skill installed:

```
"Run a security scan"
```

Claude will automatically:
1. Discover your environment (dependencies, containers, cloud configs)
2. Fetch current vulnerability data
3. Calculate risk scores
4. Generate phased remediation plan
5. Output technical and executive reports
