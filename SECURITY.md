# Security policy

ScopeGuard is a beta project. Security fixes are provided for the latest source on the `master` branch.

[Read the Turkish security policy / Türkçe güvenlik politikası](SECURITY.tr.md).

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting page](https://github.com/furkanersoy/ScopeGuard/security/advisories/new) when it is available. The repository owner must first enable private vulnerability reporting in **Settings → Security and quality → Advanced Security**.

If the private report option is unavailable, do not post exploit details in a public issue. Contact the repository owner through the contact information on their GitHub profile and request a private channel without including sensitive details.

Do not include real credentials, secrets, personal data, or information about systems you are not authorized to test. ScopeGuard's demo API intentionally includes a vulnerable endpoint for local training; it uses synthetic records and must remain bound to `127.0.0.1`. That intentional fixture is not a vulnerability report.
