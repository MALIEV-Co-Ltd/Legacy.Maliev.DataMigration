# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting for
`MALIEV-Co-Ltd/Legacy.Maliev.DataMigration`. Do not disclose a vulnerability in a
public issue, discussion, pull request, commit, workflow log, or migration receipt.

Never include passwords, tokens, private keys, service-account JSON, environment
files, connection strings, customer data, backup contents, or other secrets in a
GitHub issue or public report. If sensitive material has been exposed, revoke or
rotate it immediately and use the private report only to identify the affected file
and rule without repeating the secret value.

Include a concise impact description, the affected migration boundary, reproduction
steps, and a safe proof of concept when available. Maintainers will coordinate
validation, remediation, and disclosure through the private report.

## Supported versions

Only the latest commit on the protected default branch is supported. No repository
workflow is authorized to deploy, restore, migrate, promote, or mutate a production
database.
