# Pretest Validator

A command-line tool for penetration testers to validate all engagement prerequisites before starting a security assessment. Ensures targets are reachable, credentials work, and configurations are correct—saving time and avoiding delays during the engagement.

## What It Does

Before a penetration test begins, testers need to verify:
- Target domains resolve and web servers respond
- IP ranges are valid and hosts are reachable
- VPN connectivity works and routes to internal networks
- API tokens authenticate successfully
- SSH credentials and keys are valid
- Web application logins work
- MFA secrets generate valid codes

**Pretest Validator automates all of these checks** and produces a clear report showing what's ready and what needs attention.

## Features

| Validator | What It Checks |
|-----------|----------------|
| **Domains** | DNS resolution (A records), HTTP/HTTPS connectivity, SSL certificates |
| **CIDRs** | IP range format, network calculations, sample host ping tests |
| **VPN** | Config file exists, public IP matches expected, internal hosts reachable |
| **API** | Endpoint connectivity, authentication, expected status codes |
| **SSH** | Port open, key-based auth, password auth |
| **Web Login** | Page loads, form submission, success/failure detection |
| **MFA** | TOTP secret validity, current code generation, backup codes |

## Requirements

- **Python**: 3.10 or higher
- **Operating System**: macOS, Linux, or Windows
- **Network**: Internet access for external targets; VPN for internal targets

### Python Dependencies

```
pyyaml>=6.0       # YAML configuration parsing
requests>=2.28    # HTTP/HTTPS requests for web and API validation
dnspython>=2.3    # DNS resolution and record lookups
rich>=13.0        # Beautiful console output with colors and tables
paramiko>=3.0     # SSH connectivity and authentication
```

## Installation

### Option 1: Clone and Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/pretest-validator.git
cd pretest-validator

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Option 2: Install Dependencies Only

If you already have the code:

```bash
cd pretest-validator
pip install pyyaml requests dnspython rich paramiko
```

### Verify Installation

```bash
# Check that the tool runs
python -m pretest_validator.cli --version
# Output: pretest-validator 0.1.0

# View help
python -m pretest_validator.cli --help
```

## Quick Start

### 1. Create Your Configuration

Copy the example config and customize it for your engagement:

```bash
cp pretest.example.yaml pretest.yaml
```

Edit `pretest.yaml` with your engagement details:

```yaml
client: Target Corp
engagement_id: TC-2026-001

domains:
  targets:
    - target-corp.com
    - www.target-corp.com
    - api.target-corp.com

cidrs:
  targets:
    - 10.10.10.0/24

ssh:
  targets:
    - host: jumpbox.target-corp.com
      port: 22
      username: pentester
      key_file: ~/.ssh/engagement_key
```

### 2. Run Validation

```bash
python -m pretest_validator.cli pretest.yaml
```

### 3. Review Results

The tool displays a color-coded table:
- ✓ (green) = Check passed
- ✗ (red) = Check failed
- ⚠ (yellow) = Warning, needs attention
- ○ (dim) = Skipped

## Example Commands

### Basic Usage

```bash
# Run all validators against a config file
python -m pretest_validator.cli pretest.yaml

# Run with a different config file
python -m pretest_validator.cli /path/to/engagement-config.yaml
```

### Export Reports

```bash
# Export results to JSON (for automation/parsing)
python -m pretest_validator.cli pretest.yaml --json report.json

# Export results to Markdown (for documentation)
python -m pretest_validator.cli pretest.yaml --markdown report.md

# Export to both formats
python -m pretest_validator.cli pretest.yaml --json report.json --md report.md

# Quiet mode - no console output, only file export
python -m pretest_validator.cli pretest.yaml --quiet --json report.json
```

### Selective Validation

```bash
# Only validate domains and CIDRs
python -m pretest_validator.cli pretest.yaml --only domains --only cidrs

# Only validate credentials (SSH, API, web logins)
python -m pretest_validator.cli pretest.yaml --only ssh --only api --only web_login

# Skip VPN validation (if not using VPN)
python -m pretest_validator.cli pretest.yaml --skip vpn

# Skip multiple validators
python -m pretest_validator.cli pretest.yaml --skip vpn --skip mfa --skip web_login
```

### Display Options

```bash
# Disable colored output (for logging/piping)
python -m pretest_validator.cli pretest.yaml --no-color

# Show version
python -m pretest_validator.cli --version

# Show help
python -m pretest_validator.cli --help
```

### Real-World Examples

```bash
# Quick connectivity check before engagement starts
python -m pretest_validator.cli pretest.yaml --only domains --only cidrs

# Validate all credentials are working
python -m pretest_validator.cli pretest.yaml --only ssh --only api --only web_login --only mfa

# Generate client-ready report
python -m pretest_validator.cli pretest.yaml --markdown pretest-report.md

# CI/CD integration - exit code 0 if all pass, 1 if failures
python -m pretest_validator.cli pretest.yaml --quiet --json results.json
echo "Exit code: $?"
```

## Configuration Reference

### Full Configuration Example

```yaml
# =============================================================================
# PRETEST VALIDATOR CONFIGURATION
# =============================================================================
# Copy this file to pretest.yaml and customize for your engagement.
# All sections are optional - only include what you need to validate.

# -----------------------------------------------------------------------------
# Engagement Information
# -----------------------------------------------------------------------------
client: ACME Corporation
engagement_id: ACME-2026-Q1-PENTEST

# -----------------------------------------------------------------------------
# Domain Validation
# -----------------------------------------------------------------------------
# Checks DNS resolution and HTTP/HTTPS connectivity for target domains.
domains:
  targets:
    - example.com
    - www.example.com
    - api.example.com
    - admin.example.com
  check_dns: true      # Verify DNS A record resolution
  check_http: true     # Test HTTP (port 80) connectivity
  check_https: true    # Test HTTPS (port 443) connectivity
  timeout: 10          # Seconds to wait for each request

# -----------------------------------------------------------------------------
# CIDR/IP Range Validation
# -----------------------------------------------------------------------------
# Validates IP ranges and tests sample host reachability.
cidrs:
  targets:
    - 192.168.1.0/24   # /24 = 254 hosts
    - 10.0.0.0/16      # /16 = 65534 hosts
    - 172.16.50.0/28   # /28 = 14 hosts
  ping_sample: 3       # Number of hosts to ping from each range
  timeout: 5           # Ping timeout in seconds

# -----------------------------------------------------------------------------
# VPN Configuration
# -----------------------------------------------------------------------------
# Validates VPN connectivity for internal network access.
vpn:
  enabled: true                    # Set to false to skip VPN validation
  type: openvpn                    # openvpn, wireguard, or ipsec
  config_file: ~/vpn/client.ovpn   # Path to VPN config file
  expected_ip: 203.0.113.50        # Your expected public IP when VPN is connected
  test_host: 10.10.10.1            # Internal host to verify VPN routing

# -----------------------------------------------------------------------------
# API Token Validation
# -----------------------------------------------------------------------------
# Tests API endpoints with provided credentials.
api:
  targets:
    - name: GitHub API
      url: https://api.github.com/user
      method: GET
      headers:
        Authorization: "Bearer ghp_your_token_here"
        Accept: "application/vnd.github.v3+json"
      expected_status: 200
      timeout: 30
      verify_ssl: true

    - name: Internal REST API
      url: https://api.internal.example.com/v1/health
      method: GET
      headers:
        X-API-Key: "your-api-key"
      expected_status: 200

    - name: GraphQL Endpoint
      url: https://graphql.example.com/query
      method: POST
      headers:
        Authorization: "Bearer token"
        Content-Type: "application/json"
      body:
        query: "{ __typename }"
      expected_status: 200

# -----------------------------------------------------------------------------
# SSH Validation
# -----------------------------------------------------------------------------
# Tests SSH connectivity and authentication.
ssh:
  targets:
    # Key-based authentication
    - host: jumpbox.example.com
      port: 22
      username: pentester
      key_file: ~/.ssh/id_rsa

    # Password authentication
    - host: 192.168.1.100
      port: 22
      username: admin
      password: "your-password"

    # Non-standard port
    - host: bastion.example.com
      port: 2222
      username: user
      key_file: ~/.ssh/engagement_key

  timeout: 10

# -----------------------------------------------------------------------------
# Web Login Validation
# -----------------------------------------------------------------------------
# Tests web application authentication.
web_login:
  targets:
    - name: Admin Portal
      url: https://admin.example.com/login
      login_url: https://admin.example.com/login    # POST target (if different)
      username: admin@example.com
      password: "your-password"
      username_field: email          # HTML form field name for username
      password_field: password       # HTML form field name for password
      success_indicator: "Dashboard" # Text that appears on successful login
      failure_indicator: "Invalid"   # Text that appears on failed login
      method: POST
      timeout: 30
      verify_ssl: true
      additional_fields:             # Extra form fields if needed
        remember_me: "true"

    - name: Customer Portal
      url: https://portal.example.com
      username: testuser
      password: "password123"
      success_indicator: "Welcome"

# -----------------------------------------------------------------------------
# MFA Validation
# -----------------------------------------------------------------------------
# Validates MFA configurations and generates test codes.
mfa:
  targets:
    # TOTP (Google Authenticator, Authy, etc.)
    - name: Admin Account TOTP
      type: totp
      secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # Base32 secret from QR code

    # SMS-based MFA (manual verification required)
    - name: User Account SMS
      type: sms
      description: "SMS sent to +1-555-123-4567"

    # Backup codes
    - name: Emergency Backup Codes
      type: backup_codes
      codes:
        - "12345678"
        - "87654321"
        - "11223344"
```

## Output Formats

### Console Output

Rich formatted table with color-coded results displayed in the terminal.

### JSON Output (`--json`)

```json
{
  "metadata": {
    "client": "ACME Corp",
    "engagement_id": "ACME-2026-02",
    "timestamp": "2026-02-03T10:30:00.000000",
    "version": "0.1.0"
  },
  "statistics": {
    "total": 25,
    "success": 20,
    "failure": 2,
    "warning": 2,
    "skipped": 1,
    "error": 0
  },
  "results": [
    {
      "name": "DNS: example.com",
      "status": "success",
      "message": "Resolved to 93.184.216.34",
      "details": {"ips": ["93.184.216.34"]}
    }
  ]
}
```

### Markdown Output (`--markdown`)

Professional report suitable for client documentation or engagement records.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (or only warnings) |
| 1 | One or more checks failed |

Use exit codes for CI/CD integration:

```bash
python -m pretest_validator.cli pretest.yaml --quiet
if [ $? -eq 0 ]; then
    echo "All pretest checks passed!"
else
    echo "Some checks failed - review before proceeding"
fi
```

## Security Considerations

- **Credential Storage**: Configuration files contain sensitive credentials. Store them securely and never commit to version control.
- **Git Ignore**: Add `pretest.yaml` to your `.gitignore` file.
- **File Permissions**: Restrict config file permissions: `chmod 600 pretest.yaml`
- **Environment Variables**: Consider using environment variables for sensitive values in CI/CD.
- **Network Traffic**: The tool makes real network requests. Only run against authorized targets.
- **Audit Trail**: JSON reports can serve as evidence of pretest validation.

## Troubleshooting

### Common Issues

**SSL Certificate Errors**
```yaml
api:
  targets:
    - name: Internal API
      url: https://internal.example.com
      verify_ssl: false  # Disable SSL verification for self-signed certs
```

**SSH Key Permissions**
```bash
chmod 600 ~/.ssh/your_key
```

**DNS Resolution Failures**
- Check your `/etc/resolv.conf` or DNS settings
- Try using a public DNS server temporarily

**VPN Not Detected**
- Ensure VPN is connected before running
- Verify `expected_ip` matches your actual VPN public IP

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - See LICENSE file for details.

---

**Pretest Validator** - Validate before you penetrate.
