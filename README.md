# ScopeGuard

[English](README.md) | [Turkish version](README.tr.md)

**Status: beta.** ScopeGuard is a local-first security checking tool. It checks API authorization behavior and selected risks in source code, configuration, Dockerfiles, Kubernetes manifests, and Terraform files. It includes an offline request planner and coverage matrix, a read-only API scenario runner, offline source and Terraform checks, optional OSV dependency lookups, reasoned expiring suppressions, bilingual findings, and local JSON, Markdown, SARIF, and HTML reports with comparison support.

## Current milestone

- Local demo API binds to `127.0.0.1`; the runner defaults to loopback targets.
- All records and bearer tokens are synthetic.
- `GET /records/{id}` enforces record ownership.
- `GET /vulnerable/records/{id}` intentionally demonstrates a broken object-level authorization check.
- `scopeguard validate` checks the OpenAPI and YAML scenario structure without network access.
- `scopeguard run` executes only the configured, read-only `GET`, `HEAD`, and `OPTIONS` checks and writes a redacted JSON report.
- `scopeguard inspect` scans selected local source, configuration, Dockerfile, Kubernetes, and Terraform patterns without executing code, building containers, or using the network.
- API, local, and dependency findings can be saved as JSON, Markdown, SARIF 2.1.0, and self-contained HTML files at user-selected local paths. Reports stay local by default.
- Dependency checks query OSV only when `--allow-network` is explicitly provided; only package names, ecosystems, and pinned versions are sent.
- Suppressions require a rule, relative path pattern, reason, and expiry date; suppressed items remain visible in reports.
- `scopeguard compare` reports added, resolved, and unchanged findings between saved JSON reports.
- An optional GitHub Actions workflow scans source and uploads SARIF only after a manually dispatched run with the upload option enabled.
- Remote targets require an exact HTTPS host/port allowlist in the config and an explicit `--allow-remote` flag at run time.

## First scan (Windows)

1. Install Python 3.11 or newer, then clone or download this repository.
2. Double-click `ScopeGuard.bat`. On first launch it creates an isolated `.venv` and installs the dependencies; later launches reuse them.
3. For the easiest first scan, choose **7. Guided quick scan** in the menu, enter the project folder, and select a profile. The JSON, Markdown, SARIF, and HTML reports are saved locally.

You can also start a standard offline scan directly from PowerShell in the ScopeGuard folder:

```powershell
.\ScopeGuard.bat quick-scan
```

This scans the current folder without executing code or sending files over the network. Reports use the `scopeguard-scan` filename prefix. If `.scopeguard-profile.yaml` exists here, it is detected automatically; use `--config <path>` to choose another profile.

To open the interactive menu later, double-click `ScopeGuard.bat` or run `.\ScopeGuard.bat` with no arguments. For Linux/macOS, use `./scopeguard.sh quick-scan` or `./scopeguard.sh`.

To try API checks, start the included demo API in a second terminal and follow the API steps below. Only test real services when you have explicit authorization.

## Security checks and commands

| Command | What it checks or does | Network use |
| --- | --- | --- |
| `init` | Creates scenarios for anonymous access, BOLA/IDOR, BFLA, or custom GET/HEAD/OPTIONS status checks. | None |
| `configure` | Saves a reusable local scan profile; stores no API credentials or targets. | None |
| `quick-scan` | Runs a saved profile or built-in local scan preset and writes local reports. | None |
| `inspect` | Scans local secrets, Python, configuration, Dockerfile, Kubernetes, and selected Terraform risks; writes local reports. | None; source code is not run |
| `validate` | Validates the OpenAPI document and scenario configuration. | None |
| `plan` | Shows the exact requests and identities in a scenario. | None; tokens are not read |
| `coverage` | Shows configured identity/endpoint pairs; `--strict` enforces required coverage. | None; tokens are not read |
| `run` | Sends configured read-only GET, HEAD, and OPTIONS checks to the scoped target and writes local reports. | Yes, to the configured target only |
| `dependencies` | Checks pinned versions in supported lockfiles against OSV; requires `--allow-network`. | Yes; package names, ecosystems, and versions only |
| `compare` | Compares two ScopeGuard JSON reports. | None |

The `inspect` checks are static heuristics, not a complete scanner. They do not test a live web service. API scenarios test only explicitly configured safe GET, HEAD, and OPTIONS operations and expected outcomes; they do not fuzz endpoints or infer the application's authorization policy.

## Install and run

Requires Python 3.11 or newer.

```powershell
git clone https://github.com/furkanersoy/ScopeGuard.git
cd ScopeGuard
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install .
```

On Linux or macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Developers can use `py -m pip install -e .` (or `python -m pip install -e .`) for an editable install.

### Startup menu

Run `scopeguard` with no arguments (or double-click `ScopeGuard.bat` on Windows) to open the bilingual menu:

1. **API Security** — opens an API submenu: create a starter scenario, validate the OpenAPI and scenario files, preview planned requests, inspect identity/endpoint coverage, or run configured checks. Scenario creation asks for an OpenAPI file, selected GET/HEAD/OPTIONS operations, sample path values, identities, and expected status codes. API runs save JSON, Markdown, SARIF, and HTML reports locally. Start the included demo in a second terminal before running its checks.
2. **Select Local Security Checks** — choose one or more categories separated by commas: `secrets`, `python`, `config`, `docker`, `kubernetes`, and `terraform`. The default is `python,config,docker,kubernetes,terraform`; secret scanning remains a separate main-menu shortcut. The selected local file or folder is scanned offline, without executing code, building images, or connecting to a Kubernetes cluster. The menu asks for JSON, Markdown, SARIF, and HTML report paths and can load an optional suppression YAML.
3. **Secret Detection** — scans a selected local file or folder for supported hard-coded secret patterns and saves local JSON, Markdown, SARIF, and HTML reports. It does not print matched secret values.
4. **Advanced command console** — accepts the normal CLI commands (`help`, `version`, `init`, `configure`, `quick-scan`, `inspect`, `dependencies`, `compare`, `validate`, `plan`, `coverage`, and `run`). Enter `menu` to return to the section menu or `exit` to close ScopeGuard. Choose `0` in a menu to go back or exit as indicated.
5. **Dependency Vulnerability Check** — selects a lockfile or folder and asks before sending exact package names and versions to OSV over HTTPS. It saves local JSON, Markdown, SARIF, and HTML reports.
6. **Create suppression from a report** — selects a finding from a local JSON report and creates a reasoned, expiring suppression YAML.
7. **Guided quick scan** — asks for a project path and scan profile, then saves JSON, Markdown, SARIF, and HTML reports without executing code or sending files over the network.
8. **Configure reusable project profile** — saves the project path, scan preset, report language/name, optional suppression file, and CI threshold in `.scopeguard-profile.yaml`. Reuse these settings from option 7 or with `scopeguard quick-scan --config .scopeguard-profile.yaml`.

The local inspection checks are heuristic and need human review. Use quoted paths containing spaces. The `--version` and `--help` options are also available from the normal command line.

### Run without a virtual environment

On Windows, you can install ScopeGuard into your Python user account and start it as a module:

```powershell
py -3 -m pip install --user .
py -3 -m scopeguard
```

This avoids a project `.venv` and a manual activation step. It installs dependencies into that Python account, so the automatic launcher above is preferred when you want ScopeGuard's dependencies isolated from other Python tools. Python 3.11 or newer is required.

## Offline local source inspection

ScopeGuard can inspect local source, configuration, Dockerfile, and Kubernetes manifest files independently of API checks. It reads supported text files without executing them or making network requests. The starter checks look for credential-like hard-coded values, selected risky Python calls (such as `eval`, unsafe deserialization, shell-enabled subprocess calls, and disabled TLS verification), and configuration patterns such as debug mode or wildcard CORS, plus Dockerfile checks for root execution, mutable base image references, and credential-like ARG/ENV assignments, Kubernetes checks for selected Pod/Workload security fields including privileged containers, privilege escalation, root execution, host namespaces, hostPath mounts, and added ALL capabilities. Terraform checks use textual heuristics for selected AWS security-group, S3, database, and storage settings; they do not evaluate modules, expressions, provider plans, or cloud state. Kubernetes inspection is a static text-based heuristic; it does not contact a cluster or validate complete Kubernetes semantics. These heuristic findings need human review; this is not a complete vulnerability scanner.

Run all local inspection checks and save JSON, Markdown, SARIF, and HTML reports on your computer:

```powershell
scopeguard inspect --path . --checks secrets python config docker kubernetes terraform --output inspect.json --markdown-output inspect.md --sarif-output inspect.sarif --html-output inspect.html --language en
```

Use `--checks` with one or more of `secrets`, `python`, `config`, `docker`, `kubernetes`, and `terraform` to choose categories. The `docker` check examines Dockerfiles offline for selected container hardening issues; it does not build images or contact registries. The `kubernetes` check applies static heuristics to YAML manifests for selected pod and container security settings; it does not connect to a cluster. ScopeGuard skips common virtual environment, dependency, and build folders, and ignores files larger than 1 MB. The reports contain file names and line numbers but omit source snippets and matched secret values. The optional SARIF 2.1.0 file maps finding severities to SARIF levels and includes descriptions and remediation. HTML output is self-contained and can be opened locally. All report formats stay on the selected local paths unless you opt into the workflow upload. The command returns exit status `1` when it finds findings; inspect the report and verify each result.

Try the safe, synthetic fixtures in [examples/local-scan](examples/local-scan/README.md). They demonstrate expected findings across all six categories and list the rule IDs and severities. The fixture README explains the report evidence fields and remediation guidance. Findings are expected, so this sample command exits with status `1`:

```powershell
scopeguard inspect --path examples/local-scan/insecure-patterns --checks secrets python config docker kubernetes terraform --output local-scan.json --markdown-output local-scan.md --sarif-output local-scan.sarif --language en
```

For the safe comparison set, scan `examples/local-scan/secure-patterns` with the same options and different output filenames. It is expected to produce zero findings and exit with status `0`.

### Suppressions

Use a suppression file only for a reviewed finding that needs a temporary exception. Each entry needs an exact or globbed rule ID, a relative file path pattern, a non-empty reason, and an ISO date expiry. Expired entries make the suppression file invalid. Suppressed findings remain listed in JSON, Markdown, HTML, and SARIF reports, including the reason and expiry.

```yaml
version: 1
suppressions:
  - rule_id: "terraform.public-ingress"
    path: "infra/network.tf"
    reason: "Temporary approved exception; access is restricted by the staging firewall."
    expires: "2026-12-31"
```

Pass it to either local or dependency scanning with `--suppressions scopeguard-ignore.yaml`. Suppressions affect only the matching rule and relative path.

### Dependency vulnerability checks

Dependency scanning is a separate, online opt-in command. It reads exact versions from `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock`, and `go.sum`, then queries OSV. It does not upload lockfiles or source code. The query sends package ecosystem, name, and version. Review your organization's data-sharing policy before using it on private projects.

```powershell
scopeguard dependencies --path . --allow-network --output dependencies.json --markdown-output dependencies.md --sarif-output dependencies.sarif --html-output dependencies.html --language en
```

Without `--allow-network`, ScopeGuard does not make OSV requests. The command has size and package-count limits and reports advisory IDs, detected versions, severity when available, and fixed versions when listed. Unknown advisory severity stays marked unknown rather than being guessed.

### HTML reports and comparison

The `run`, `inspect`, and `dependencies` commands can write a self-contained HTML report with `--html-output report.html`. It can be opened locally and does not load remote scripts or styles. Compare earlier and current JSON reports (API findings are matched by check and identity; local and dependency findings by rule and location/package):

```powershell
scopeguard compare --previous previous.json --current current.json --output diff.json --markdown-output diff.md --html-output diff.html
```

The comparison lists added, resolved, and unchanged findings. It exits with status `1` when active findings were added; reports that remove findings return `0`. It performs no network access.

### GitHub Actions and optional SARIF upload

The `.github/workflows/scopeguard-sarif.yml` workflow scans the repository on pushes and pull requests. To publish SARIF to GitHub Code Scanning, start the workflow manually in the Actions tab and set `upload_sarif` to `true`. Upload is off by default; local CLI scans never upload. GitHub repository settings and plan must support Code Scanning.

Create a starter scenario interactively from an OpenAPI document:

```powershell
scopeguard init --spec examples/api/openapi.yaml --output examples/scenarios/my-scenario.yaml
```

The wizard lets you select anonymous-access checks, BOLA/IDOR horizontal access checks, BFLA role checks, or custom safe-method status checks. The custom profile lists GET, HEAD, and OPTIONS operations from the OpenAPI document. It asks for sample path values and expected status codes and performs no API requests. Review the generated scenario before running it; the wizard cannot infer your authorization policy or prove that your expected responses are correct. Existing files are preserved unless you pass `--force`.

To start the included synthetic demo API, open a second terminal:

```powershell
py -m scopeguard_demo
```

The API listens on `http://127.0.0.1:8000`. Stop it with `Ctrl+C`.

In a second terminal, validate the example inputs:

```powershell
scopeguard validate --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml
```

Validation is offline and sends no network requests. The scenario file stores environment variable names, never token values. Before running authenticated checks, set the synthetic credentials in the same PowerShell session:

```powershell
$env:SG_USER_A_TOKEN = 'demo-user-a'
$env:SG_USER_B_TOKEN = 'demo-user-b'
```

Preview the exact requests before running them:

```powershell
scopeguard plan --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml
```

`plan` is offline: it does not read token environment variables or send requests. It shows the target, resolved paths, identities, expected status codes, and JSON assertion pointers/operators. For a remote scenario it also reminds you that execution requires `--allow-remote`.

See which identity/endpoint combinations have checks configured:

```powershell
scopeguard coverage --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml
```

The coverage matrix lists configured checks and marks empty identity/endpoint pairs as `not configured`. An empty cell is only a coverage gap in the scenario file; it is not evidence of a vulnerability. Declare required identity/endpoint pairs under `coverage.required` and exact check IDs under `coverage.required_checks` in the scenario YAML. `scopeguard coverage --strict` exits with status `1` if a required pair or check ID is missing, so CI can enforce both broad endpoint coverage and specific scenarios. This command is offline and does not read tokens.

### CI severity gates

`inspect` and `dependencies` accept `--fail-on any|critical|high|medium|low|none`. The default, `any`, keeps the existing behavior and exits with status `1` when any active finding remains. A threshold fails only when an active finding has that severity or higher; suppressed findings do not fail the gate. For example, `scopeguard inspect --path src --checks secrets python --fail-on high` gates a build on high or critical source findings. Use `--fail-on none` to produce reports without using findings as the command exit gate. To gate only on newly introduced findings, save the previous JSON report and use `scopeguard compare --previous baseline.json --current current.json`; it exits `1` when new findings are present.

With the demo API still running, execute the checks in a second terminal:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json
```

Add a shareable, redacted Markdown summary with `--markdown-output report.md`:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json --markdown-output report.md
```

Choose the finding and report language with `--language tr` or `--language en` (default: `en`). The localized report includes a finding title, severity, evidence, potential impact, and remediation guidance. For example:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json --markdown-output report.md --language tr
```

Optionally save findings in SARIF 2.1.0 format on your computer:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json --sarif-output report.sarif --language tr
```

SARIF is written only to the path you specify. ScopeGuard does not upload reports or findings to GitHub or any other service.

In the interactive `sg>` console, use the same options after `run`; do not prefix the command with `scopeguard` there.

The protected route checks cover anonymous denial (`401`), both users reading their own records (`200`), and each user being denied the other user's record (`404`). Those six checks should pass. The deliberately vulnerable route is expected to fail because it returns `200` where the scenario expects `404` and its JSON `/owner` assertion indicates cross-user access. The local demo therefore reports six passes and one intentional failure; `scopeguard run` exits with status `1` to make the detected issue visible. Reports include a localized explanation, severity, evidence, potential impact, and remediation advice. They omit response bodies, assertion values, and token values.

An assertion can be attached to a check like this:

```yaml
assert_json:
  - pointer: /owner
    not_equals: user-a
```

`equals` requires the JSON Pointer to exist and match; `not_equals` also passes when the pointer is absent, as it is in the protected route's `404` response.

## Run the automated tests

The unit tests validate malformed/out-of-scope configuration. Integration tests start the synthetic API on a temporary loopback port and verify access-control results and report redaction.

```powershell
py -m unittest discover -s tests -v
```

GitHub Actions runs the test suite and example validation on Python 3.11 and 3.13 for every push and pull request.

## Synthetic accounts and endpoints

User A owns `record-a`; User B owns `record-b`. These demo tokens are public fixtures and must never be reused anywhere else.

```powershell
Invoke-RestMethod -Headers @{ Authorization = 'Bearer demo-user-a' } -Uri 'http://127.0.0.1:8000/records/record-a'
Invoke-RestMethod -Headers @{ Authorization = 'Bearer demo-user-b' } -Uri 'http://127.0.0.1:8000/records/record-a'
Invoke-RestMethod -Headers @{ Authorization = 'Bearer demo-user-b' } -Uri 'http://127.0.0.1:8000/vulnerable/records/record-a'
```

Each user receives `200` for their own record and `404` for the other user's record from the protected route. Anonymous requests to records receive `401`. User B receives `200` for User A's record from the intentionally vulnerable route.

## Authorized staging targets

Loopback remains the default. To validate a staging scenario, set an exact hostname and port, opt in in the config, and keep HTTPS certificate verification enabled:

```yaml
target:
  base_url: https://staging.example.test
  allowed_hosts:
    - staging.example.test
  allowed_ports: [443]
  allow_remote: true
  max_requests: 10
  timeout_seconds: 5
  follow_redirects: false
```

`staging.example.test` is a reserved example name. Replace it only with a system you own or are explicitly authorized to test. A remote run also requires the explicit command-line flag:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/staging.yaml --output report.json --allow-remote
```

Remote targets must use HTTPS, the exact base hostname must be the only allowlisted hostname, and the configured port must be listed. Wildcards are rejected. `validate` remains offline; without `--allow-remote`, `run` refuses the remote target before sending a request.

## Safety

This is a deliberately vulnerable teaching fixture. Keep it bound to loopback and use only the synthetic data included here. Do not expose it to a network or use real credentials or data. The runner uses loopback by default; a remote target needs config and command-line opt-in, an exact hostname and port allowlist, HTTPS, and an authorized test scope. It sends only explicitly configured `GET`, `HEAD`, and `OPTIONS` requests, does not follow redirects, limits request count and rate, and does not save response bodies.

## Project plan

See [the architecture and roadmap](docs/architecture.md).

## License

No license has been selected yet. Until one is added, the source is not granted an open-source reuse license.


