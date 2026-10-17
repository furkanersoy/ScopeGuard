# ScopeGuard

**Status: early prototype.** ScopeGuard is a local-first API authorization regression tool. It currently includes a synthetic demo API and a configuration validator. The validator reads the OpenAPI and scenario files without sending network requests.

## Current milestone

- Local demo API only; it binds to `127.0.0.1`.
- All records and bearer tokens are synthetic.
- `GET /records/{id}` enforces record ownership.
- `GET /vulnerable/records/{id}` intentionally demonstrates a broken object-level authorization check.
- `scopeguard validate` checks the OpenAPI and YAML scenario structure without network access.
- `scopeguard run` executes only the configured, read-only `GET` checks and writes a redacted JSON report.

## Install and run

Requires Python 3.11 or newer.

```powershell
py -m pip install -e .
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

With the demo API still running, execute the checks in a second terminal:

```powershell
scopeguard run --spec examples/api/openapi.yaml --config examples/scenarios/local-demo.yaml --output report.json
```

The protected route checks should pass. The deliberately vulnerable route is expected to fail because it returns `200` where the scenario expects `404` and its JSON `/owner` value identifies another user. JSON assertions are evaluated in memory; the report records only the pointer, operator, and pass/fail result. Exit codes are `0` when all checks pass, `1` when a check fails, and `2` when a check is skipped or encounters an error. Reports omit response bodies, assertion values, and token values.

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

User B receives `404` for User A's record from the protected route and `200` from the intentionally vulnerable route.

## Safety

This is a deliberately vulnerable teaching fixture. Keep it bound to loopback and use only the synthetic data included here. Do not expose it to a network or use real credentials or data. The runner restricts targets to loopback, sends only explicitly configured `GET` requests, does not follow redirects, limits request count and rate, and does not save response bodies.

## Project plan

See [the architecture and roadmap](docs/architecture.md).

## License

No license has been selected yet. Until one is added, the source is not granted an open-source reuse license.
