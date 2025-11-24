# CHANGELOG

All notable changes to Cloud IAM Optimizer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- GCP IAM support
- Azure AD support
- Detailed policy permission analysis
- CloudTrail integration for unused permissions detection
- Prometheus metrics export
- Slack/Teams notifications

## [1.0.0] - 2025-11-24

### Added
- Initial release of Cloud IAM Optimizer
- AWS IAM user listing and analysis
- MFA status detection for AWS users
- Access keys audit
- Managed and inline policies listing
- Security findings generation (missing MFA, excessive privileges)
- JSON and text output formats
- Multi-account support via AWS profiles
- Comprehensive English and Russian documentation
- CI/CD workflow with GitHub Actions
- MIT License
- Privacy & Compliance documentation (152-FZ)

### Security
- No credentials or sensitive data logging
- .gitignore includes all sensitive file patterns
- Environment variable configuration via .env

---

**Repository:** [github.com/ranas-mukminov/Cloud-IAM-Optimizer](https://github.com/ranas-mukminov/Cloud-IAM-Optimizer)  
**Author:** [@ranas-mukminov](https://github.com/ranas-mukminov)  
**Website:** [run-as-daemon.ru](https://run-as-daemon.ru)
