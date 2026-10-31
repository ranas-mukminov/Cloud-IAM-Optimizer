# Security Policy

## Scope

Cloud-IAM-Optimizer audits IAM configurations. It is an audit helper, not
a compliance certification and not a guarantee that an account is secure.

## Safety

- Run it with read-only IAM credentials. Never commit cloud credentials
  to a repository.
- The tool is designed to run locally and does not send IAM data to
  external servers.
- Findings can contain account, user, and policy names. Redact them
  before sharing reports outside your organisation.

## Reporting a vulnerability

Please use GitHub's **Security → Report a vulnerability** private
disclosure for this repository. Do not open a public issue with exploit
details or with real account data. This project has no paid SLA for
security fixes.
