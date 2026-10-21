"""Offline source and configuration checks. Never executes scanned code or transmits findings."""

from __future__ import annotations

import ast
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import ValidationError

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 10_000
SKIP_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", "dist", "build", "site-packages"}
TEXT_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".php", ".rb", ".rs", ".cs",
    ".sh", ".ps1", ".bat", ".cmd", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".env", ".txt", ".md", ".tf", ".hcl", ".dockerfile",
}

_TEXT = {
    "en": {
        "secret.title": "Possible hard-coded secret",
        "secret.description": "A credential-like value appears to be assigned directly in a source or configuration file. The value itself is intentionally omitted from this report.",
        "secret.fix": "Move the credential to a secret manager or environment variable, revoke and rotate the exposed value, and review repository history for prior exposure.",
        "eval.title": "Dynamic code execution",
        "eval.description": "The code calls eval or exec, which can execute attacker-controlled input if data reaches this call.",
        "eval.fix": "Remove dynamic evaluation where possible. Use a constrained parser or explicit dispatch, and validate any unavoidable input.",
        "pickle.title": "Unsafe Python deserialization",
        "pickle.description": "pickle.load(s) can execute code while deserializing untrusted or tampered data.",
        "pickle.fix": "Do not deserialize untrusted pickle data. Prefer a data-only format such as JSON and validate its schema.",
        "yaml.title": "Potentially unsafe YAML loader",
        "yaml.description": "yaml.load is used without a safe loader; some loader choices can construct arbitrary Python objects from untrusted input.",
        "yaml.fix": "Use yaml.safe_load or explicitly select yaml.SafeLoader for untrusted YAML, then validate the resulting data structure.",
        "shell.title": "Shell command built through subprocess",
        "shell.description": "subprocess is invoked with shell=True, which can allow command injection when arguments contain untrusted data.",
        "shell.fix": "Use an argument list with shell=False and validate each argument. Avoid passing user-controlled strings to a shell.",
        "tls.title": "TLS certificate verification disabled",
        "tls.description": "TLS certificate verification is disabled. A network connection using this setting may be vulnerable to interception.",
        "tls.fix": "Keep certificate verification enabled and configure the correct trusted CA bundle when needed.",
        "mktemp.title": "Race-prone temporary file creation",
        "mktemp.description": "tempfile.mktemp returns a path without securely creating the file, leaving a race window.",
        "mktemp.fix": "Use tempfile.NamedTemporaryFile or another API that creates the file atomically with restrictive permissions.",
        "debug.title": "Debug mode enabled in configuration",
        "debug.description": "A configuration file enables debug mode, which may expose stack traces or sensitive diagnostics if used in production.",
        "debug.fix": "Disable debug mode in production and control it through an environment-specific setting.",
        "cors.title": "Wildcard CORS origin",
        "cors.description": "A CORS configuration allows every origin. This may expose browser-accessible responses to untrusted sites when credentials or sensitive data are involved.",
        "cors.fix": "Allow only the exact trusted origins required by the application and review credential handling.",
        "docker_root.title": "Container may run as root",
        "docker_root.description": "The final image stage has no explicit non-root USER, or selects root. The container may therefore start with elevated privileges.",
        "docker_root.fix": "Create or select a dedicated unprivileged user in the final image stage and set it with USER.",
        "docker_base.title": "Base image is not pinned by digest",
        "docker_base.description": "A Dockerfile base image uses a tag or an untagged reference rather than an immutable digest. Tags can resolve to different image contents over time.",
        "docker_base.fix": "Pin trusted base images with an @sha256 digest and update that digest through reviewed changes.",
        "docker_secret.title": "Possible secret in Docker build instruction",
        "docker_secret.description": "An ARG or ENV instruction assigns a credential-like value. Docker build arguments or environment values may be retained in image metadata or layers; the value is omitted from this report.",
        "docker_secret.fix": "Do not pass secrets through ARG or ENV. Use a build-secret mechanism and a secret manager, and rotate any value that was exposed.",
        "summary": "ScopeGuard local inspection",
        "findings": "Findings",
        "file": "File",
        "line": "Line",
        "severity": "Severity",
        "rule": "Rule",
        "no_findings": "No findings were reported by the selected local checks.",
        "redaction": "Source snippets and matched secret values are not included.",
    },
    "tr": {
        "secret.title": "Kaynak kodda olası sabit sır",
        "secret.description": "Kaynak veya yapılandırma dosyasında doğrudan atanmış, kimlik bilgisine benzeyen bir değer bulundu. Değerin kendisi güvenlik için rapora yazılmadı.",
        "secret.fix": "Kimlik bilgisini sır yöneticisine veya ortam değişkenine taşıyın; açığa çıkan değeri iptal edip yenileyin ve depo geçmişinde daha önce paylaşılmış olma ihtimalini inceleyin.",
        "eval.title": "Dinamik kod çalıştırma",
        "eval.description": "Kod eval veya exec çağırıyor. Bu çağrıya saldırgan denetimindeki veri ulaşırsa kod çalıştırılabilir.",
        "eval.fix": "Mümkünse dinamik değerlendirmeyi kaldırın. Kısıtlı bir ayrıştırıcı veya açık bir işlem eşlemesi kullanın; kaçınılmaz girdileri doğrulayın.",
        "pickle.title": "Güvensiz Python nesne serileştirmesini açma",
        "pickle.description": "pickle.load(s), güvenilmeyen veya değiştirilmiş veriyi açarken kod çalıştırabilir.",
        "pickle.fix": "Güvenilmeyen pickle verisini açmayın. JSON gibi yalnızca veri taşıyan bir biçim seçip şemasını doğrulayın.",
        "yaml.title": "Potansiyel olarak güvensiz YAML yükleyicisi",
        "yaml.description": "yaml.load güvenli olmayan bir yükleyiciyle kullanılıyor. Bazı yükleyiciler güvenilmeyen YAML içinden Python nesneleri oluşturabilir.",
        "yaml.fix": "Güvenilmeyen YAML için yaml.safe_load veya açıkça yaml.SafeLoader kullanın; ardından oluşan veri yapısını doğrulayın.",
        "shell.title": "subprocess ile kabuk komutu çalıştırma",
        "shell.description": "subprocess shell=True ile çağrılıyor. Argümanlarda güvenilmeyen veri varsa komut enjeksiyonu riski doğabilir.",
        "shell.fix": "shell=False ile argüman listesi kullanın ve her argümanı doğrulayın. Kullanıcı girdisini kabuk komutuna eklemeyin.",
        "tls.title": "TLS sertifika doğrulaması kapalı",
        "tls.description": "TLS sertifika doğrulaması devre dışı. Bu ayarla yapılan ağ bağlantısı araya girme saldırılarına açık olabilir.",
        "tls.fix": "Sertifika doğrulamasını açık tutun; gerekiyorsa doğru güvenilir CA paketini yapılandırın.",
        "mktemp.title": "Yarış durumuna açık geçici dosya oluşturma",
        "mktemp.description": "tempfile.mktemp dosyayı güvenli biçimde oluşturmadan yalnızca yol döndürür ve arada yarış durumu bırakır.",
        "mktemp.fix": "Dosyayı kısıtlı izinlerle atomik oluşturan tempfile.NamedTemporaryFile gibi bir API kullanın.",
        "debug.title": "Yapılandırmada hata ayıklama açık",
        "debug.description": "Bir yapılandırma dosyasında debug modu etkin. Üretimde kullanılırsa yığın izleri veya hassas tanılama bilgileri açığa çıkabilir.",
        "debug.fix": "Üretim ortamında debug modunu kapatın ve ortam bazlı bir ayarla yönetin.",
        "cors.title": "Tüm kaynaklara açık CORS kuralı",
        "cors.description": "CORS yapılandırması tüm kaynaklara izin veriyor. Kimlik bilgileri veya hassas veriler söz konusuysa güvenilmeyen siteler tarayıcı yanıtlarına erişebilir.",
        "cors.fix": "Yalnızca uygulamanın ihtiyaç duyduğu tam ve güvenilir kaynaklara izin verin; kimlik bilgisi kullanımını gözden geçirin.",
        "docker_root.title": "Konteyner root kullanıcısıyla çalışabilir",
        "docker_root.description": "Son imaj aşamasında root olmayan bir USER tanımlanmamış veya root seçilmiş. Bu nedenle konteyner yüksek yetkilerle başlayabilir.",
        "docker_root.fix": "Son imaj aşamasında ayrıcalıksız bir kullanıcı oluşturun veya seçin ve USER ile etkinleştirin.",
        "docker_base.title": "Taban imaj digest ile sabitlenmemiş",
        "docker_base.description": "Dockerfile taban imajı değişmez digest yerine etiketli veya etiketsiz bir başvuru kullanıyor. Etiketler zamanla farklı imaj içeriklerine işaret edebilir.",
        "docker_base.fix": "Güvenilir taban imajlarını @sha256 digest ile sabitleyin; digest güncellemelerini inceleyerek yapın.",
        "docker_secret.title": "Docker derleme komutunda olası sabit sır",
        "docker_secret.description": "Bir ARG veya ENV komutuna kimlik bilgisine benzeyen bir değer atanmış. Derleme argümanları veya ortam değerleri imaj metaverisinde ya da katmanlarında kalabilir; değer rapora eklenmez.",
        "docker_secret.fix": "Sırları ARG veya ENV ile aktarmayın. Derleme sırrı mekanizması ve sır yöneticisi kullanın; açığa çıkan değerleri yenileyin.",
        "summary": "ScopeGuard yerel inceleme",
        "findings": "Bulgular",
        "file": "Dosya",
        "line": "Satır",
        "severity": "Önem",
        "rule": "Kural",
        "no_findings": "Seçilen yerel kontroller bulgu üretmedi.",
        "redaction": "Kaynak kod parçaları ve eşleşen sır değerleri rapora eklenmez.",
    },
}

_RULES = {
    "secret.hardcoded": ("secret", "high"),
    "python.dynamic-eval": ("eval", "high"),
    "python.unsafe-pickle": ("pickle", "high"),
    "python.unsafe-yaml": ("yaml", "high"),
    "python.subprocess-shell": ("shell", "high"),
    "python.tls-verify-disabled": ("tls", "medium"),
    "python.tempfile-mktemp": ("mktemp", "medium"),
    "config.debug-enabled": ("debug", "medium"),
    "config.cors-wildcard": ("cors", "medium"),
    "config.tls-verify-disabled": ("tls", "medium"),
    "docker.root-user": ("docker_root", "medium"),
    "docker.mutable-base-image": ("docker_base", "low"),
    "docker.build-arg-secret": ("docker_secret", "high"),
}

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret(?:[_-]?key)?|password|passwd|client[_-]?secret)\b\s*[:=]\s*(['\"])([^'\"\r\n]{8,})\2"
)
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_PLACEHOLDER = re.compile(r"(?i)(example|dummy|changeme|change_me|your[_-]|replace[_-]?me|placeholder|xxxxx|<[^>]+>|demo[-_])")
_CONFIG_RULES = (
    ("config.tls-verify-disabled", re.compile(r"(?i)\b(?:verify_ssl|ssl_verify|tls_verify)\s*[:=]\s*(?:false|no|0)\b")),
    ("config.debug-enabled", re.compile(r"(?i)\bdebug\s*[:=]\s*(?:true|yes|1)\b")),
    ("config.cors-wildcard", re.compile(r"(?i)\b(?:allow_origins|cors_allow_all(?:_origins)?)\s*[:=]\s*(?:\[\s*['\"]\*['\"]\s*\]|true)")),
)



_DOCKER_SECRET_ASSIGNMENT = re.compile(
    r"(?i)^\s*(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|CREDENTIAL)[A-Za-z0-9_.-]*)\s*=\s*(.*?)\s*$"
)


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def _is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name == ".env" or path.name.startswith(".env.") or _is_dockerfile(path)


def _iter_files(root: Path) -> list[Path]:
    if root.is_symlink():
        raise ValidationError("scan root must not be a symbolic link")
    if root.is_file():
        return [root] if _is_text_candidate(root) else []
    if not root.is_dir():
        raise ValidationError(f"scan path is not a file or directory: {root}")
    files: list[Path] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRECTORIES and not (Path(current) / name).is_symlink()]
        for name in names:
            path = Path(current) / name
            if path.is_symlink() or not _is_text_candidate(path):
                continue
            files.append(path)
            if len(files) > MAX_FILES:
                raise ValidationError(f"scan includes more than {MAX_FILES} candidate files; narrow --path")
    return files


def _add_finding(findings: list[dict[str, Any]], seen: set[tuple[str, str, int]], rule_id: str, relative: str, line: int) -> None:
    key = (rule_id, relative, line)
    if key in seen:
        return
    seen.add(key)
    category, severity = _RULES[rule_id]
    findings.append({
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "file": relative.replace("\\", "/"),
        "line": line,
    })


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _python_findings(source: str, relative: str, findings: list[dict[str, Any]], seen: set[tuple[str, str, int]]) -> None:
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _qualified_name(node.func)
        rule_id = None
        if name in {"eval", "exec"}:
            rule_id = "python.dynamic-eval"
        elif name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"}:
            rule_id = "python.unsafe-pickle"
        elif name in {"yaml.load", "ruamel.yaml.load"}:
            loader = next((keyword.value for keyword in node.keywords if keyword.arg == "Loader"), None)
            loader_name = _qualified_name(loader) if loader is not None else ""
            if "SafeLoader" not in loader_name:
                rule_id = "python.unsafe-yaml"
        elif name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}:
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                rule_id = "python.subprocess-shell"
        elif name in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "httpx.get", "httpx.post", "httpx.request"}:
            if any(keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in node.keywords):
                rule_id = "python.tls-verify-disabled"
        elif name == "ssl._create_unverified_context":
            rule_id = "python.tls-verify-disabled"
        elif name == "tempfile.mktemp":
            rule_id = "python.tempfile-mktemp"
        if rule_id:
            _add_finding(findings, seen, rule_id, relative, getattr(node, "lineno", 1))


def _docker_findings(source: str, relative: str, findings: list[dict[str, Any]], seen: set[tuple[str, str, int]]) -> None:
    """Report selected Dockerfile hardening heuristics without building an image."""
    final_from_line: int | None = None
    final_user_line: int | None = None
    final_user: str | None = None
    stage_aliases: set[str] = set()

    for number, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        from_match = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", stripped)
        if from_match:
            image = from_match.group(1)
            final_from_line = number
            final_user_line = None
            final_user = None
            normalized_image = image.lower()
            is_variable = "$" in image
            is_previous_stage = normalized_image in stage_aliases
            if (
                normalized_image != "scratch"
                and not is_variable
                and not is_previous_stage
                and "@sha256:" not in normalized_image
            ):
                _add_finding(findings, seen, "docker.mutable-base-image", relative, number)
            if from_match.group(2):
                stage_aliases.add(from_match.group(2).lower())
            continue

        user_match = re.match(r"(?i)^USER\s+(\S+)", stripped)
        if user_match:
            final_user = user_match.group(1)
            final_user_line = number
            continue

        secret_match = _DOCKER_SECRET_ASSIGNMENT.match(stripped)
        if secret_match:
            value = secret_match.group(2).strip().strip("\"'")
            if value and "$" not in value and not _PLACEHOLDER.search(value):
                _add_finding(findings, seen, "docker.build-arg-secret", relative, number)

    if final_from_line is not None:
        user_id = final_user.lower().split(":", 1)[0] if final_user else None
        if final_user is None or (not final_user.startswith("$") and user_id in {"root", "0"}):
            _add_finding(findings, seen, "docker.root-user", relative, final_user_line or final_from_line)


def _scan_line_rules(line: str, relative: str, number: int, checks: set[str], findings: list[dict[str, Any]], seen: set[tuple[str, str, int]]) -> None:
    if "secrets" in checks:
        secret_match = _SECRET_ASSIGNMENT.search(line)
        has_secret = bool(secret_match and not _PLACEHOLDER.search(secret_match.group(3))) or bool(_AWS_KEY.search(line)) or bool(_GITHUB_TOKEN.search(line)) or bool(_PRIVATE_KEY.search(line))
        if has_secret:
            _add_finding(findings, seen, "secret.hardcoded", relative, number)
    if "config" in checks:
        for rule_id, pattern in _CONFIG_RULES:
            if pattern.search(line):
                _add_finding(findings, seen, rule_id, relative, number)


def _atomic_write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def render_local_markdown(report: dict[str, Any]) -> str:
    text = _TEXT[report["language"]]
    lines = [
        f"# {text['summary']}", "",
        f"- {text['file']}: {report['scanned_path']}",
        f"- Scanned files: {report['scanned_files']}",
        f"- {text['findings']}: {len(report['findings'])}", "",
        f"| {text['severity']} | {text['rule']} | {text['file']} | {text['line']} |", "| --- | --- | --- | ---: |",
    ]
    for finding in report["findings"]:
        category = _RULES[finding["rule_id"]][0]
        lines.append(f"| {finding['severity'].title()} | {text[f'{category}.title']} | {finding['file']} | {finding['line']} |")
        lines.extend(["", f"**{text[f'{category}.description']}**", "", f"**{text[f'{category}.fix']}**", ""])
    if not report["findings"]:
        lines.extend(["", text["no_findings"], ""])
    lines.extend(["", text["redaction"], ""])
    return "\n".join(lines)


def inspect_path(path: Path, checks: list[str], language: str = "en", *, output_paths: list[Path] | None = None) -> dict[str, Any]:
    """Scan local text files statically; no code execution and no network access."""
    if language not in _TEXT:
        raise ValidationError("language must be 'tr' or 'en'")
    allowed = {"secrets", "python", "config", "docker"}
    if not checks or len(set(checks)) != len(checks) or any(check not in allowed for check in checks):
        raise ValidationError("select one or more distinct checks: secrets, python, config, docker")
    if not path.exists():
        raise ValidationError(f"scan path does not exist: {path}")
    root = path.absolute()
    files = _iter_files(root)
    excludes = {item.resolve() for item in (output_paths or [])}
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    scanned = 0
    for file_path in files:
        if file_path.resolve() in excludes:
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        scanned += 1
        relative = file_path.name if root.is_file() else str(file_path.relative_to(root))
        if "python" in checks and file_path.suffix.lower() in {".py", ".pyi"}:
            _python_findings(source, relative, findings, seen)
        if "docker" in checks and _is_dockerfile(file_path):
            _docker_findings(source, relative, findings, seen)
        if "secrets" in checks or "config" in checks:
            for number, line in enumerate(source.splitlines(), 1):
                _scan_line_rules(line, relative, number, set(checks), findings, seen)
    findings.sort(key=lambda item: (item["file"].lower(), item["line"], item["rule_id"]))
    text = _TEXT[language]
    for finding in findings:
        category = _RULES[finding["rule_id"]][0]
        finding["title"] = text[f"{category}.title"]
        finding["description"] = text[f"{category}.description"]
        finding["remediation"] = text[f"{category}.fix"]
    return {
        "tool": "ScopeGuard",
        "mode": "offline-local-inspection",
        "language": language,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanned_path": str(root),
        "scanned_files": scanned,
        "checks": checks,
        "findings": findings,
    }


def write_local_reports(report: dict[str, Any], json_path: Path, markdown_path: Path | None = None) -> None:
    outputs = [json_path.resolve()]
    if markdown_path is not None:
        outputs.append(markdown_path.resolve())
    if len(set(outputs)) != len(outputs):
        raise ValidationError("JSON and Markdown outputs must use different paths")
    for output in outputs:
        if Path(report["scanned_path"]).resolve() == output:
            raise ValidationError("report output must not overwrite the scan target")
    report["findings_count"] = len(report["findings"])
    _atomic_write(json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    if markdown_path is not None:
        _atomic_write(markdown_path, render_local_markdown(report))
