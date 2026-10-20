# ScopeGuard

**Status: beta.** ScopeGuard is a local-first security checking tool. It checks API authorization behavior and selected local source/configuration patterns. It includes an offline request planner and coverage matrix, a read-only API scenario runner, bilingual findings, and local JSON, Markdown, and SARIF reports.

## Current milestone

- Local demo API binds to `127.0.0.1`; the runner defaults to loopback targets.
- All records and bearer tokens are synthetic.
- `GET /records/{id}` enforces record ownership.
- `GET /vulnerable/records/{id}` intentionally demonstrates a broken object-level authorization check.
- `scopeguard validate` checks the OpenAPI and YAML scenario structure without network access.
- `scopeguard run` executes only the configured, read-only `GET` checks and writes a redacted JSON report.
- `scopeguard inspect` scans selected local source/configuration patterns without executing code or using the network.
- API finding reports support Turkish and English; JSON and Markdown reports stay on the paths selected by the user. SARIF output is available for API runs.
- Remote targets require an exact HTTPS host/port allowlist in the config and an explicit `--allow-remote` flag at run time.

## Hızlı başlangıç (Windows)

1. Python 3.11 veya üzerini kur ve ScopeGuard deposunu indir.
2. `ScopeGuard.bat` dosyasına çift tıkla. İlk açılışta gerekli kurulumu otomatik yapar; sonraki açılışlarda aynı kurulumu kullanır.
3. `sg>` konsolunda komutları `scopeguard` öneki olmadan gir; örneğin `help` veya `inspect --path . --checks secrets python config --language tr`.
4. API örneğini çalıştırmak için ikinci PowerShell penceresinde `.\.venv\Scripts\python.exe -m scopeguard_demo` komutunu çalıştır. Sunucu `127.0.0.1:8000` adresinde açılır.
5. İlk pencerede `exit` ile konsoldan çık. PowerShell'den komut çalıştırırken `ScopeGuard.bat` önekini kullan; örneğin `.\ScopeGuard.bat validate --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml`.

Klasör açılmadan doğrudan komut çalıştırmak için PowerShell'de `.\ScopeGuard.bat inspect --path . --checks secrets python config --output inspect.json --markdown-output inspect.md --language tr` kullan. API kontrolleri için aşağıdaki adımları takip et. Gerçek servisleri yalnızca açıkça yetkilendirilmiş test kapsamlarında çalıştır.

ScopeGuard'u proje `.venv` klasörü oluşturmadan kullanmak için Windows'ta proje klasöründe `py -3 -m pip install --user .` ardından `py -3 -m scopeguard` komutlarını çalıştırabilirsin. Bu yöntem bağımlılıkları kullanıcı Python kurulumuna yükler; araçların bağımlılıklarını birbirinden ayrı tutmak için `ScopeGuard.bat` önerilir.

## Security checks and commands

| Command | What it checks or does | Network use |
| --- | --- | --- |
| `init` | Creates scenarios for anonymous access, BOLA/IDOR, BFLA, or custom GET status checks. | None |
| `inspect` | Selects local checks for hard-coded secrets, risky Python patterns, and configuration. | None; source code is not run |
| `validate` | Validates the OpenAPI document and scenario configuration. | None |
| `plan` | Shows the exact requests and identities in a scenario. | None; tokens are not read |
| `coverage` | Shows configured identity/endpoint pairs; `--strict` enforces required coverage. | None; tokens are not read |
| `run` | Sends configured read-only GET checks to the scoped target and writes local reports. | Yes, to the configured target only |

The `inspect` checks are static heuristics, not a complete scanner. They do not test a live web service. API scenarios test only explicitly configured GET operations and expected outcomes; they do not fuzz endpoints or infer the application's authorization policy.

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

Run `scopeguard` with no arguments to open the interactive console. It supports `help`, `version`, `init`, `inspect`, `validate`, `plan`, `coverage`, and `run`; enter `exit` to close it. Use quoted paths when a path contains spaces. The `--version` and `--help` options are available from the normal command line.

### Quick start on Windows

After cloning or downloading the project, double-click `ScopeGuard.bat`. On its first launch it creates a private `.venv` folder and installs ScopeGuard and its dependencies. Later launches reuse that setup. You do not need to activate the environment or type setup commands yourself. Python 3.11 or newer and an internet connection are needed for the first setup. You can pass normal ScopeGuard arguments to the launcher from PowerShell, too:

```powershell
.\ScopeGuard.bat inspect --path . --checks secrets python config --language tr
```

On Linux or macOS, make the launcher executable once with `chmod +x scopeguard.sh`, then run `./scopeguard.sh`. It performs the same first-run setup and opens the interactive console. Arguments can be passed after the script name.

### Run without a virtual environment

On Windows, you can install ScopeGuard into your Python user account and start it as a module:

```powershell
py -3 -m pip install --user .
py -3 -m scopeguard
```

This avoids a project `.venv` and a manual activation step. It installs dependencies into that Python account, so the automatic launcher above is preferred when you want ScopeGuard's dependencies isolated from other Python tools. Python 3.11 or newer is required.

## Offline local source inspection

ScopeGuard can inspect local source and configuration files independently of API checks. It reads supported text files without executing them or making network requests. The starter checks look for credential-like hard-coded values, selected risky Python calls (such as `eval`, unsafe deserialization, shell-enabled subprocess calls, and disabled TLS verification), and configuration patterns such as debug mode or wildcard CORS. These heuristic findings need human review; this is not a complete vulnerability scanner.

Run all local inspection checks and save reports on your computer:

```powershell
scopeguard inspect --path . --checks secrets python config --output inspect.json --markdown-output inspect.md --language tr
```

Use `--checks` with one or more of `secrets`, `python`, and `config` to choose categories. ScopeGuard skips common virtual environment, dependency, and build folders, and ignores files larger than 1 MB. The report contains file names and line numbers but omits source snippets and matched secret values. The command returns exit status `1` when it finds findings; inspect the report and verify each result.

Create a starter scenario interactively from an OpenAPI document:

```powershell
scopeguard init --spec examples/api/openapi.yaml --output examples/scenarios/my-scenario.yaml
```

The wizard lets you select anonymous-access checks, BOLA/IDOR horizontal access checks, BFLA role checks, or custom GET status checks. It asks you to select GET operations and collect sample path values, test identities, and expected status codes. It performs no API requests. Review the generated scenario before running it; the wizard cannot infer your authorization policy or prove that your expected responses are correct. Existing files are preserved unless you pass `--force`.

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

This is a deliberately vulnerable teaching fixture. Keep it bound to loopback and use only the synthetic data included here. Do not expose it to a network or use real credentials or data. The runner uses loopback by default; a remote target needs config and command-line opt-in, an exact hostname and port allowlist, HTTPS, and an authorized test scope. It sends only explicitly configured `GET` requests, does not follow redirects, limits request count and rate, and does not save response bodies.

## Project plan

See [the architecture and roadmap](docs/architecture.md).

## License

No license has been selected yet. Until one is added, the source is not granted an open-source reuse license.
