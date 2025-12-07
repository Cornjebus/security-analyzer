# Security Analyzer

A Claude Code skill for comprehensive security vulnerability analysis. Scans codebases, fetches current CVE/exploit data, and generates phased remediation plans with TDD validation.

## Features

| Feature | Description |
|---------|-------------|
| **Environment Discovery** | Scans dependencies, containers, cloud configs, secrets exposure |
| **Live Vulnerability Intel** | Fetches from CISA KEV, NVD, GitHub Advisories, OSV.dev |
| **Risk Scoring** | Weighted scoring: CVSS + exploitability + criticality + exposure |
| **Phased Remediation** | Prioritized fixes (critical → low) with actual patches |
| **TDD Validation** | Pre-fix tests, remediation unit tests, post-fix verification |
| **Dual Reports** | Technical (engineers) + Executive (leadership) |

## Supported Environments

- **Dependencies**: npm, pip, gem, go, cargo, maven, nuget
- **Containers**: Dockerfile, docker-compose, Kubernetes manifests
- **Cloud IaC**: Terraform, CloudFormation, Bicep
- **APIs**: OpenAPI specs, endpoint discovery
- **Secrets**: .env files, exposed credentials detection

## Installation

Claude Code automatically discovers skills from specific directories. Choose the method that works best for you.

### Option 1: Let Claude Install It (Easiest)

Just tell Claude Code to install the skill for you:

```
You: "Install the security-analyzer skill from https://github.com/Cornjebus/security-analyzer.git"
```

Or for global installation:

```
You: "Install the security-analyzer skill globally from https://github.com/Cornjebus/security-analyzer.git"
```

Claude will clone the repo, copy the skill to the correct location, and clean up automatically.

### Option 2: Install Globally (Available in All Projects)

```bash
# Create the skills directory if it doesn't exist
mkdir -p ~/.claude/skills

# Clone and copy the skill
git clone https://github.com/Cornjebus/security-analyzer.git
cp -r security-analyzer/.claude/skills/security-analyzer ~/.claude/skills/

# Clean up the cloned repo (optional)
rm -rf security-analyzer

# Verify installation - start Claude Code in any project
claude
# Ask: "What skills are available?"
```

The skill is now available in **every** Claude Code session.

### Option 2: Install for a Single Project

```bash
# Navigate to your project
cd /path/to/your-project

# Create the skills directory
mkdir -p .claude/skills

# Clone and copy the skill
git clone https://github.com/Cornjebus/security-analyzer.git
cp -r security-analyzer/.claude/skills/security-analyzer .claude/skills/

# Clean up
rm -rf security-analyzer

# Start Claude Code
claude
# Ask: "Run a security scan"
```

### Option 3: Add to Project and Share with Team

```bash
# Navigate to your project
cd /path/to/your-project

# Create the skills directory
mkdir -p .claude/skills

# Clone and copy the skill
git clone https://github.com/Cornjebus/security-analyzer.git
cp -r security-analyzer/.claude/skills/security-analyzer .claude/skills/
rm -rf security-analyzer

# Commit to version control
git add .claude/skills
git commit -m "Add security-analyzer skill"
git push

# Team members just pull and the skill is automatically available
```

When teammates pull the repo, the skill is **automatically discovered** — no additional setup needed.

### Verify Installation

In any Claude Code session:
```
You: "What skills are available?"
You: "Run a security scan"
```

If Claude recognizes the security-analyzer skill, installation was successful.

## Usage

In Claude Code, trigger with:

```
security scan
```

Or be specific:

```
security scan --quick          # Dependencies only
security scan /path/to/project # Specific directory
security fix CVE-2024-1234     # Fix specific vulnerability
security report                # Regenerate reports
```

## Example Interaction

**You:** "Run a security scan on this project"

**Claude:** 
1. Discovers 47 npm dependencies, 3 Dockerfiles, 2 Terraform configs
2. Fetches current CVE data from OSV.dev
3. Identifies 12 vulnerabilities (2 critical, 4 high, 6 medium)
4. Generates phased remediation plan with:
   - Actual fix commands (`npm install lodash@4.17.21`)
   - Code patches for IaC misconfigurations
   - TDD tests proving each fix works
5. Outputs `security-report-technical.md` and `security-report-executive.md`

## Output Example

### Technical Report (excerpt)

```markdown
## Phase 1: Critical Priority

### CVE-2024-4068: Prototype pollution in lodash
**Risk Score:** 9.2/10
**Package:** lodash@4.17.19
**CVSS:** 9.8 (CRITICAL)

#### Remediation
npm install lodash@4.17.21

#### Validation Tests
def test_cve_2024_4068_exists():
    """PASS before fix, FAIL after"""
    ...

def test_cve_2024_4068_resolved():
    """FAIL before fix, PASS after"""
    ...
```

### Executive Report (excerpt)

```markdown
## Overall Security Posture
**Risk Level:** HIGH - Critical vulnerabilities require immediate attention

| Priority | Count | Estimated Effort |
|----------|-------|------------------|
| Critical | 2     | 2.0 hours        |
| High     | 4     | 2.0 hours        |
| Total    | 12    | 5.5 hours        |
```

## Skill Structure

```
security-analyzer/
├── .claude/
│   └── skills/
│       └── security-analyzer/
│           ├── SKILL.md                # Main skill file (auto-discovered by Claude Code)
│           ├── scripts/
│           │   ├── discover_env.py     # Scans codebase for assets
│           │   ├── fetch_vulns.py      # Queries OSV.dev API
│           │   └── generate_report.py  # Creates markdown reports
│           └── references/
│               └── report-templates.md # Output format specs
├── README.md
└── LICENSE
```

## Risk Scoring Formula

```
Risk = (CVSS × 0.3) + (Exploitability × 0.3) + (Criticality × 0.2) + (Exposure × 0.2)

Exploitability:
  10 = In CISA KEV (actively exploited)
   7 = Public exploit available
   3 = Theoretical only

Criticality (asset importance):
  10 = Auth/payment systems
   5 = Core business logic
   2 = Logging/monitoring

Exposure:
  10 = Internet-facing
   5 = Internal network
   2 = Air-gapped
```

## TDD Approach

Each vulnerability gets three test types:

| Test Type | Purpose | Before Fix | After Fix |
|-----------|---------|------------|-----------|
| Pre-fix validation | Proves vuln exists | PASS | FAIL |
| Remediation unit test | Tests fix logic | N/A | PASS |
| Post-fix validation | Proves vuln resolved | FAIL | PASS |

## Vulnerability Sources

| Source | Priority | Data Type |
|--------|----------|-----------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 1 | Actively exploited vulns |
| [NVD](https://nvd.nist.gov/) | 2 | CVE details + CVSS |
| [GitHub Advisories](https://github.com/advisories) | 3 | Package-specific vulns |
| [OSV.dev](https://osv.dev/) | 4 | Open source vulns (API) |

## Customization

Edit `SKILL.md` to adjust:

- **Risk weights**: Change the 0.3/0.3/0.2/0.2 formula
- **Severity thresholds**: Modify phase groupings
- **Report format**: Update templates in `references/report-templates.md`
- **Vulnerability sources**: Add/remove feeds

## Requirements

- [Claude Code](https://claude.com/claude-code) CLI
- Python 3.8+ (for helper scripts)
- Network access to OSV.dev API

## License

MIT - use and modify as needed.

## Contributing

PRs welcome. Please include:
- Description of changes
- Test coverage for new features
- Updated documentation

## Related

- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OSV.dev](https://osv.dev/) - Open Source Vulnerability Database
