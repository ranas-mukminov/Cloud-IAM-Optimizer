# Cloud-IAM-Optimizer

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-production--ready-green)

**Official Tripwire Tool of Ranas Security Stack**

Cloud-IAM-Optimizer is a powerful CLI tool designed to scan your AWS IAM environment for critical security risks. It identifies unused keys, users without MFA, and dangerous administrative privileges, helping you enforce least privilege and secure your cloud infrastructure.

**Powered by Ranas Security Stack (run-as-daemon.dev)**

## Features

- **MFA Audit:** Identifies users with Multi-Factor Authentication disabled.
- **Stale Key Detection:** Flags access keys older than 90 days.
- **Privilege Escalation Check:** Detects users with `AdministratorAccess` attached directly or via groups.
- **Production Ready:** Built with robust error handling and structured output.
- **Flexible Output:** Supports both human-readable text (with color coding) and JSON for automation.

## Quick Start

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ranas-mukminov/Cloud-IAM-Optimizer.git
   cd Cloud-IAM-Optimizer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

Run the audit against your default AWS profile:

```bash
python src/main.py audit
```

Specify a profile and output format:

```bash
python src/main.py audit --profile my-prod-profile --output json
```

Check version and support info:

```bash
python src/main.py version
```

## Commercial Support

Need a full infrastructure audit or custom security implementation?

**Book a 15-min slot with the author:** [https://run-as-daemon.dev](https://run-as-daemon.dev)

We offer:
- Comprehensive Cloud Security Audits
- DevSecOps Pipeline Implementation
- Infrastructure as Code (Terraform/Pulumi) Hardening
- Compliance Readiness (SOC2, ISO27001)

## Privacy & Compliance

This tool runs entirely locally on your machine. No data is sent to external servers.
- **Logs:** No sensitive data is logged to disk.
- **Credentials:** Uses standard AWS SDK (boto3) credential chains.

## License

MIT License. See [LICENSE](LICENSE) for details.
