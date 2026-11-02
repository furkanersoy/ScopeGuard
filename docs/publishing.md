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
4. The first release has been published as `0.2.0`. The pending publisher is now bound to the project; future releases use the same Trusted Publishing workflow.

Trusted Publishing uses GitHub's OIDC identity and short-lived credentials. No PyPI API token or GitHub secret is stored in this repository. The build job has no PyPI publishing permission; only the isolated publishing job receives `id-token: write`.

## Publish a release

1. Choose a new version in `pyproject.toml` and update both changelog files and the English README.
2. Merge the reviewed changes into `master` and confirm CI passes.
3. Create a GitHub Release from the matching tag, for example `v0.2.2`. The workflow rejects a tag that does not exactly match the package version.
4. Wait for the release workflow. The build job runs `python -m build` and `twine check --strict`; the publish job starts only after these checks pass.
5. After PyPI finishes processing the release, users can install or update the command-line app with `pipx install scopeguard` or `pipx upgrade scopeguard`. The interactive API menu uses the demo OpenAPI and scenario files bundled in the wheel; start the demo server in another terminal with `scopeguard-demo`.

Do not publish a version until its source, README, dependencies, and release notes have been reviewed. PyPI releases cannot be replaced with different files under the same version.