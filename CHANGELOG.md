# ScopeGuard Changelog

## [0.2.0] - Unreleased

### Added

- Interactive bilingual terminal menus, a guided local quick scan, reusable scan profiles, and a local synthetic API demo.
- OpenAPI-based API authorization scenarios for explicitly configured `GET`, `HEAD`, and `OPTIONS` checks, with offline validation, planning, coverage, and local reports.
- Offline static checks for supported secret patterns, Python, configuration, Dockerfiles, Kubernetes manifests, and selected Terraform patterns.
- Optional dependency advisory lookups against OSV when the user explicitly enables network access.
- Local JSON, Markdown, SARIF 2.1.0, and self-contained HTML reports; finding suppressions with a reason and expiry; and comparison of saved reports.
- English and Turkish findings, help, README, and reporting options.
- An offline `scopeguard doctor` command to check the Python runtime, PyYAML, and bundled demo inputs.
- A GitHub Release workflow for validated package builds and PyPI Trusted Publishing.

### Scope and limitations

- Local source checks are heuristic and need human review; a clean result does not prove a project is secure.
- API checks run only configured safe methods. They do not discover endpoints, fuzz requests, or infer the application's authorization policy.
- Dependency lookup sends package names, ecosystems, and pinned versions to OSV; source files and lockfiles are not uploaded.
- Remote API testing is opt-in, HTTPS-only, and restricted by exact host and port allowlists.
