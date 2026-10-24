"""Offline installation diagnostics for ScopeGuard."""

from __future__ import annotations

import sys

import yaml

from . import __version__
from .config import ValidationError, validate_inputs
from .example_paths import bundled_example_path


def run_doctor() -> int:
    """Check the runtime and validate demo assets without network access."""
    print(f"ScopeGuard diagnostics / ScopeGuard tanılama — v{__version__}")
    checks_ok = True

    python_ok = sys.version_info >= (3, 11)
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    python_status = "PASS" if python_ok else "FAIL"
    print(f"[{python_status}] Python {python_version}; requires >= 3.11 / Python {python_version}; gereken >= 3.11")
    checks_ok &= python_ok

    yaml_version = getattr(yaml, "__version__", "unknown")
    print(f"[PASS] PyYAML {yaml_version} / PyYAML {yaml_version}")

    spec_path = bundled_example_path("examples/api/openapi.yaml")
    scenario_path = bundled_example_path("examples/scenarios/local-demo.yaml")
    if spec_path is None or scenario_path is None:
        print("[FAIL] Packaged demo files are missing / Paketli demo dosyaları bulunamadı")
        checks_ok = False
    else:
        try:
            check_count = validate_inputs(spec_path, scenario_path)
        except (ValidationError, OSError) as exc:
            print(f"[FAIL] Packaged demo files are invalid: {exc} / Paketli demo dosyaları geçersiz: {exc}")
            checks_ok = False
        else:
            print(f"[PASS] Packaged demo inputs are valid ({check_count} checks) / Paketli demo girdileri geçerli ({check_count} kontrol)")

    print("Offline diagnostic only; no project files were scanned and no network requests were sent.")
    print("Yalnızca çevrimdışı tanılama yapıldı; proje dosyaları taranmadı ve ağa istek gönderilmedi.")
    if checks_ok:
        print("Installation looks ready / Kurulum kullanıma hazır görünüyor.")
        return 0
    print("Installation needs attention / Kurulumun düzeltilmesi gerekiyor.")
    return 1
