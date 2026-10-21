# Offline local scan fixtures

These files are inert examples for checking ScopeGuard's local static scanner. They contain intentionally risky patterns and synthetic placeholder text. Do not execute the Python file, build the Dockerfile, apply the Kubernetes manifest, or use the sample string as a credential. ScopeGuard only reads the files as text/AST; it does not run code, build images, contact registries, or connect to a cluster.

From the repository root, scan the fixture directory with all local checks:

```powershell
scopeguard inspect --path examples/local-scan/insecure-patterns --checks secrets python config docker kubernetes --output local-scan.json --markdown-output local-scan.md --language en
```

On Windows before installing the console command, use `.\ScopeGuard.bat inspect ...` with the same arguments. In the interactive menu, choose **Select Local Security Checks**, enter the fixture directory, and keep or enter `secrets,python,config,docker,kubernetes`.

## Expected findings

The scanner should report the following rule IDs. The exact line number is shown in the generated report.

| Fixture | Expected rule IDs | Severity |
| --- | --- | --- |
| `sample.py` | `python.dynamic-eval`, `python.unsafe-pickle`, `python.unsafe-yaml`, `python.subprocess-shell`, `python.tempfile-mktemp` | High for the first four; Medium for `python.tempfile-mktemp` |
| `settings.yaml` | `config.debug-enabled`, `config.tls-verify-disabled`, `config.cors-wildcard` | Medium |
| `.env.example` | `secret.hardcoded` | High; the synthetic value is omitted from reports |
| `Dockerfile` | `docker.mutable-base-image`, `docker.build-arg-secret`, `docker.root-user` | Low, High, Medium respectively |
| `kubernetes-deployment.yaml` | `kubernetes.privileged`, `kubernetes.privilege-escalation`, `kubernetes.run-as-root`, `kubernetes.host-namespace`, `kubernetes.capabilities-all`, `kubernetes.host-path` | High except `kubernetes.privilege-escalation` (Medium) |

## Reading the report

Each finding includes its rule ID, severity, file and line, a localized explanation, and a remediation recommendation. File and line are the location evidence; source snippets and matched secret values are intentionally omitted. Severity is a prioritization hint, not proof of exploitability. These checks are static heuristics: review each result in its application context. A clean scan does not establish that a project is secure.
