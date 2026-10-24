# Publishing ScopeGuard to PyPI

The repository includes a release workflow at `.github/workflows/release.yml`. It builds and validates the wheel and source archive when a GitHub Release is published, then publishes them to PyPI using Trusted Publishing. It does not run for normal pushes or pull requests.

## One-time setup

1. Create and verify a PyPI account at [pypi.org](https://pypi.org/). Turn on account two-factor authentication.
2. In PyPI account settings, open **Publishing** and create a **pending publisher** with:
   - PyPI project name: `scopeguard`
   - Owner: `furkanersoy`
   - Repository: `ScopeGuard`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. In the GitHub repository, open **Settings → Environments** and create an environment named `pypi`. Add required reviewers if you want a manual approval gate before every upload.
4. Keep the project name in the pending publisher identical to `[project].name` in `pyproject.toml`. A pending publisher does not reserve the name until its first successful publication; check that the name is still available before creating the first release.

Trusted Publishing uses GitHub's OIDC identity and short-lived credentials. No PyPI API token or GitHub secret is stored in this repository. The build job has no PyPI publishing permission; only the isolated publishing job receives `id-token: write`.

## Publish a release

1. Set the version in `pyproject.toml` (for the first release, the current version is `0.2.0`).
2. Merge the version change into `master`.
3. Create a GitHub Release from the matching tag, for example `v0.2.0`. The workflow rejects a tag that does not exactly match the package version.
4. Wait for the release workflow. The build job runs `python -m build` and `twine check --strict`; the publish job starts only after these checks pass.
5. After PyPI finishes processing the first publication, users can install the command-line app with `pipx install scopeguard` or `py -m pip install --user scopeguard`. The interactive API menu uses the demo OpenAPI and scenario files bundled in the installed wheel; start the demo server in another terminal with `scopeguard-demo`.

Do not publish a version until its source, README, dependencies, and release notes have been reviewed. PyPI releases cannot be replaced with different files under the same version.