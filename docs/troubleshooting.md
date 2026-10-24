# Troubleshooting ScopeGuard

## Check the installation first

Run `scopeguard doctor` for an offline check of Python, PyYAML, and the packaged API demo files. It does not scan your project or make network requests.

## The `scopeguard` command is not found

- If you are using the downloaded repository on Windows, run `ScopeGuard.bat` from the repository folder. You can pass commands to it, for example `.\ScopeGuard.bat quick-scan`.
- If you installed from PyPI with pipx, open a new terminal after installation. If needed, run `pipx ensurepath` and restart the terminal.
- If you installed into an activated virtual environment, activate that same environment before running `scopeguard`.

## Python or first-launch setup fails

ScopeGuard requires Python 3.11 or newer. Check it with `py -3 --version` on Windows or `python3 --version` on Linux/macOS. The repository launcher creates a local `.venv` and installs dependencies the first time it runs. Installation needs access to the package index; a firewall, proxy, or offline connection can prevent setup.

For a source checkout, you can retry setup in PowerShell from the repository folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

The launchers refresh installation when package metadata changes. If installation still fails, keep the full error output and check that Python 3.11+ and pip are available.

## A scan exits with code 1

Exit code 1 means ScopeGuard completed the check and found a mismatch, finding, or missing required coverage. Read the generated report and review each result. In the included demo, the check named `vulnerable-route-should-deny-cross-user-read` is expected to fail because that endpoint is intentionally insecure.

## A command exits with code 2

Exit code 2 means the command could not complete, for example because a file is invalid or missing, a dependency is unavailable, a request failed, or a required test input is missing. Read the error printed immediately before the exit code and correct that issue before interpreting the report.

## Dependency scan says no supported lockfiles were found

The dependency checker reads pinned packages from `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock`, or `go.sum`. A `pyproject.toml` or `package.json` alone does not provide the exact resolved versions it needs. Create or commit a supported lockfile, then retry. The scan sends package name, ecosystem, and version to OSV only after you explicitly allow network access.

## API checks cannot reach the demo

Start the demo API in a second terminal before running API checks:

- PyPI installation: `scopeguard-demo`
- Source checkout: `py -m scopeguard_demo`
- Windows repository launcher: `& .\.venv\Scripts\python.exe -m scopeguard_demo`

The demo listens on `127.0.0.1:8000`. Keep it running while the check runs. If you changed the port or base URL, update the scenario file too.

## Authenticated API checks are skipped or fail

The scenario stores environment variable names, not token values. Set the synthetic demo values in the same terminal session that runs ScopeGuard:

```powershell
$env:SG_USER_A_TOKEN = 'demo-user-a'
$env:SG_USER_B_TOKEN = 'demo-user-b'
```

Use your own authorized test tokens only for systems you are allowed to test. Never paste token values into scenario files, reports, or public issues.

## A remote API target is refused

Remote runs require all of the following: an HTTPS base URL, an exact hostname and port in the scenario allowlist, `allow_remote: true` in the scenario, and the `--allow-remote` command-line option. `validate`, `plan`, and `coverage` are offline and do not send requests.

## A report filename already exists

The interactive menu chooses a numbered filename for its default reports. If you typed an existing filename, answer the overwrite prompt or enter a different name. Default report files are ignored by the repository's `.gitignore`; custom report names may need to be added to your own `.gitignore`.

## SARIF was not uploaded

Normal local scans only write SARIF to the path you selected. They never upload it automatically. GitHub upload is a separate, manually started Actions workflow option, when enabled in that workflow.

For the feature overview and setup, see the [README](../README.md).