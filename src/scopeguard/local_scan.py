"""Offline source and configuration checks. Never executes scanned code or transmits findings."""

from __future__ import annotations

import ast
import fnmatch
import html
import json
import os
import re
import tempfile

import yaml
from datetime import date, datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import quote

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
        "k8s_privileged.title": "Privileged Kubernetes container",
        "k8s_privileged.description": "A Kubernetes container explicitly enables privileged mode, which grants broad host-level capabilities.",
        "k8s_privileged.fix": "Remove privileged mode. Grant only the Linux capabilities the workload requires.",
        "k8s_escalation.title": "Privilege escalation is enabled",
        "k8s_escalation.description": "The container allows processes to gain additional privileges at runtime.",
        "k8s_escalation.fix": "Set allowPrivilegeEscalation to false unless a documented workload requirement needs it.",
        "k8s_root.title": "Container can run as root",
        "k8s_root.description": "The manifest sets the container user to UID 0 or explicitly permits running as root.",
        "k8s_root.fix": "Run as a dedicated non-root UID and set runAsNonRoot to true.",
        "k8s_host_namespace.title": "Pod shares a host namespace",
        "k8s_host_namespace.description": "The pod enables hostNetwork, hostPID, or hostIPC, reducing isolation from the node.",
        "k8s_host_namespace.fix": "Disable host namespace sharing unless the workload has a reviewed operational need.",
        "k8s_host_path.title": "Host filesystem path is mounted",
        "k8s_host_path.description": "A hostPath volume exposes a node filesystem path to the pod and can increase node compromise impact.",
        "k8s_host_path.fix": "Use a scoped PersistentVolume or another managed volume. If hostPath is required, restrict the path and mount it read-only.",
        "k8s_capabilities.title": "Container requests ALL Linux capabilities",
        "k8s_capabilities.description": "The container requests every Linux capability, granting far more privilege than most workloads need.",
        "k8s_capabilities.fix": "Drop all capabilities by default and add back only the specific capabilities required.",
        "tf_ingress.title": "Terraform ingress is open to the internet",
        "tf_ingress.description": "A Terraform security group ingress rule accepts traffic from all IPv4 or IPv6 addresses. The allowed ports and workload exposure need review.",
        "tf_ingress.fix": "Restrict ingress to the smallest required CIDR ranges and ports. Avoid 0.0.0.0/0 and ::/0 for administrative or sensitive services.",
        "tf_s3_acl.title": "Terraform S3 ACL grants public access",
        "tf_s3_acl.description": "An S3 bucket ACL grants public read or write access.",
        "tf_s3_acl.fix": "Remove public ACL grants and use a reviewed bucket policy with S3 Block Public Access enabled.",
        "tf_s3_block.title": "Terraform S3 public access block is disabled",
        "tf_s3_block.description": "An S3 public access block setting is explicitly disabled, which may allow public ACLs or policies.",
        "tf_s3_block.fix": "Enable all S3 Block Public Access settings unless a documented public bucket design requires otherwise.",
        "tf_database_public.title": "Terraform database service is publicly accessible",
        "tf_database_public.description": "A supported database resource explicitly enables public network accessibility.",
        "tf_database_public.fix": "Disable public accessibility and use private networking with narrowly scoped access rules.",
        "tf_storage.title": "Terraform storage encryption is disabled",
        "tf_storage.description": "A supported storage resource explicitly disables encryption at rest.",
        "tf_storage.fix": "Enable encryption at rest and use an approved key-management configuration.",
        "dependency.title": "Known vulnerable dependency version",
        "dependency.description": "The OSV vulnerability database reports this exact package version in an affected range. Review the advisory and whether the vulnerable code path is reachable.",
        "dependency.fix": "Upgrade to a fixed version listed in the advisory when available. If no fixed version is listed, evaluate the advisory's mitigation guidance.",

        "suppressed": "Suppressed findings",
        "suppression_reason": "Suppression reason",
        "expires": "Expires",
        "html.search": "Filter findings",
        "html.active": "Active findings",
        "html.total": "Total findings",
        "html.empty": "No active findings match this filter.",
        "html.status": "Status",
        "html.active_status": "Active",
        "html.suppressed_status": "Suppressed",
        "html.description": "Description",
        "html.remediation": "Remediation",
        "html.severity_filter": "Severity",


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
        "k8s_privileged.title": "Kubernetes konteyneri ayrıcalıklı çalışıyor",
        "k8s_privileged.description": "Kubernetes konteynerinde privileged modu açık. Bu ayar ana makine düzeyinde geniş yetkiler sağlayabilir.",
        "k8s_privileged.fix": "Privileged modunu kaldırın. Yalnızca iş yükünün gerektirdiği Linux yeteneklerini verin.",
        "k8s_escalation.title": "Yetki yükseltmeye izin veriliyor",
        "k8s_escalation.description": "Konteyner içindeki süreçlerin çalışma sırasında ek yetki kazanmasına izin veriliyor.",
        "k8s_escalation.fix": "Belgelenmiş bir gereksinim yoksa allowPrivilegeEscalation değerini false yapın.",
        "k8s_root.title": "Konteyner root kullanıcısıyla çalışabilir",
        "k8s_root.description": "Manifest, konteyner kullanıcısını UID 0 olarak ayarlıyor veya root ile çalışmaya açıkça izin veriyor.",
        "k8s_root.fix": "Ayrıcalıksız, özel bir UID kullanın ve runAsNonRoot değerini true yapın.",
        "k8s_host_namespace.title": "Pod ana makine ağ ad alanını paylaşıyor",
        "k8s_host_namespace.description": "Pod hostNetwork, hostPID veya hostIPC ayarını etkinleştiriyor; bu durum düğümden yalıtımı azaltır.",
        "k8s_host_namespace.fix": "İş yükü için incelenmiş bir operasyonel gereksinim yoksa ana makine ad alanı paylaşımını kapatın.",
        "k8s_host_path.title": "Ana makine dosya sistemi bağlanmış",
        "k8s_host_path.description": "hostPath birimi, düğümdeki bir dosya sistemi yolunu pod'a açar ve düğümün etkilenme riskini artırabilir.",
        "k8s_host_path.fix": "Kapsamı sınırlandırılmış PersistentVolume veya yönetilen başka bir birim kullanın. hostPath gerekiyorsa yolu kısıtlayın ve salt okunur bağlayın.",
        "k8s_capabilities.title": "Konteyner tüm Linux yeteneklerini istiyor",
        "k8s_capabilities.description": "Konteyner tüm Linux yeteneklerini istiyor. Çoğu iş yükünün ihtiyaç duyduğundan çok daha fazla yetki verir.",
        "k8s_capabilities.fix": "Varsayılan olarak tüm yetenekleri kaldırın ve yalnızca gerekenleri tek tek ekleyin.",
        "tf_ingress.title": "Terraform giriş kuralı internete açık",
        "tf_ingress.description": "Terraform güvenlik grubu giriş kuralı IPv4 veya IPv6 üzerindeki tüm adreslerden trafik kabul ediyor. İzin verilen portlar ve iş yükünün maruziyeti incelenmelidir.",
        "tf_ingress.fix": "Girişi gereken en dar CIDR aralıkları ve portlarla sınırlandırın. Yönetim veya hassas servislerde 0.0.0.0/0 ve ::/0 kullanmayın.",
        "tf_s3_acl.title": "Terraform S3 ACL herkese açık erişim veriyor",
        "tf_s3_acl.description": "S3 bucket ACL kuralı herkese açık okuma veya yazma izni veriyor.",
        "tf_s3_acl.fix": "Herkese açık ACL izinlerini kaldırın; incelenmiş bucket politikası ve S3 Block Public Access kullanın.",
        "tf_s3_block.title": "Terraform S3 herkese açık erişim engeli kapalı",
        "tf_s3_block.description": "S3 herkese açık erişim engeli ayarlarından biri açıkça kapatılmış; bu durum ACL veya politikalarla erişim açılmasına neden olabilir.",
        "tf_s3_block.fix": "Belgelenmiş herkese açık bucket gereksinimi yoksa tüm S3 Block Public Access ayarlarını açın.",
        "tf_database_public.title": "Terraform veritabanı servisi herkese açık",
        "tf_database_public.description": "Desteklenen bir veritabanı kaynağında internetten erişilebilirlik açıkça etkinleştirilmiş.",
        "tf_database_public.fix": "İnternetten erişilebilirliği kapatın; özel ağ ve dar kapsamlı erişim kuralları kullanın.",
        "tf_storage.title": "Terraform depolama şifrelemesi kapalı",
        "tf_storage.description": "Desteklenen bir depolama kaynağında bekleme anındaki şifreleme açıkça devre dışı bırakılmış.",
        "tf_storage.fix": "Bekleme anındaki şifrelemeyi açın ve onaylı bir anahtar yönetimi ayarı kullanın.",
        "dependency.title": "Bilinen zafiyet içeren bağımlılık sürümü",
        "dependency.description": "OSV zafiyet veritabanı bu paket sürümünü etkilenen aralıkta bildiriyor. Uyarıyı ve zafiyetli kod yolunun erişilebilir olup olmadığını inceleyin.",
        "dependency.fix": "Uyarıda belirtilen düzeltilmiş sürüme yükseltin. Düzeltilmiş sürüm yoksa uyarıdaki azaltma önerilerini değerlendirin.",

        "suppressed": "Bastırılan bulgular",
        "suppression_reason": "İstisna gerekçesi",
        "expires": "Bitiş tarihi",
        "html.search": "Bulgularda filtrele",
        "html.active": "Etkin bulgular",
        "html.total": "Toplam bulgu",
        "html.empty": "Bu filtreyle eşleşen etkin bulgu yok.",
        "html.status": "Durum",
        "html.active_status": "Etkin",
        "html.suppressed_status": "Bastırıldı",
        "html.description": "Açıklama",
        "html.remediation": "Düzeltme",
        "html.severity_filter": "Önem",


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
    "kubernetes.privileged": ("k8s_privileged", "high"),
    "kubernetes.privilege-escalation": ("k8s_escalation", "medium"),
    "kubernetes.run-as-root": ("k8s_root", "high"),
    "kubernetes.host-namespace": ("k8s_host_namespace", "high"),
    "kubernetes.host-path": ("k8s_host_path", "high"),
    "kubernetes.capabilities-all": ("k8s_capabilities", "high"),
    "terraform.public-ingress": ("tf_ingress", "high"),
    "terraform.public-s3-acl": ("tf_s3_acl", "high"),
    "terraform.s3-public-access-disabled": ("tf_s3_block", "high"),
    "terraform.database-publicly-accessible": ("tf_database_public", "high"),
    "terraform.storage-unencrypted": ("tf_storage", "medium"),
    "dependency.osv": ("dependency", "unknown"),
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


def _kubernetes_findings(source: str, relative: str, findings: list[dict[str, Any]], seen: set[tuple[str, str, int]]) -> None:
    """Inspect Kubernetes workload security fields using safe YAML node parsing."""
    def entries(node: yaml.Node | None) -> dict[str, yaml.Node]:
        if not isinstance(node, yaml.MappingNode):
            return {}
        return {
            key.value: value
            for key, value in node.value
            if isinstance(key, yaml.ScalarNode)
        }

    def value(node: yaml.Node | None) -> str | None:
        return node.value if isinstance(node, yaml.ScalarNode) else None

    def is_true(node: yaml.Node | None) -> bool:
        return isinstance(node, yaml.ScalarNode) and node.tag == "tag:yaml.org,2002:bool" and node.value.lower() in {"true", "yes", "on"}

    def is_false(node: yaml.Node | None) -> bool:
        return isinstance(node, yaml.ScalarNode) and node.tag == "tag:yaml.org,2002:bool" and node.value.lower() in {"false", "no", "off"}

    def report(rule_id: str, node: yaml.Node | None) -> None:
        if node is not None:
            _add_finding(findings, seen, rule_id, relative, node.start_mark.line + 1)

    def inspect_pod_spec(pod_spec: yaml.Node) -> None:
        pod_fields = entries(pod_spec)
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if is_true(pod_fields.get(field)):
                report("kubernetes.host-namespace", pod_fields[field])

        volumes = pod_fields.get("volumes")
        if isinstance(volumes, yaml.SequenceNode):
            for volume in volumes.value:
                host_path = entries(volume).get("hostPath")
                if host_path is not None:
                    report("kubernetes.host-path", host_path)

        contexts: list[yaml.Node] = []
        pod_context = pod_fields.get("securityContext")
        if pod_context is not None:
            contexts.append(pod_context)
        for field in ("containers", "initContainers", "ephemeralContainers"):
            containers = pod_fields.get(field)
            if isinstance(containers, yaml.SequenceNode):
                for container in containers.value:
                    context = entries(container).get("securityContext")
                    if context is not None:
                        contexts.append(context)

        for context in contexts:
            fields = entries(context)
            if is_true(fields.get("privileged")):
                report("kubernetes.privileged", fields["privileged"])
            if is_true(fields.get("allowPrivilegeEscalation")):
                report("kubernetes.privilege-escalation", fields["allowPrivilegeEscalation"])
            user_id = value(fields.get("runAsUser"))
            if user_id is not None and user_id.strip("'\"") == "0":
                report("kubernetes.run-as-root", fields["runAsUser"])
            elif is_false(fields.get("runAsNonRoot")):
                report("kubernetes.run-as-root", fields["runAsNonRoot"])

            capabilities = entries(fields.get("capabilities"))
            added = capabilities.get("add")
            if isinstance(added, yaml.SequenceNode):
                for capability in added.value:
                    if (value(capability) or "").upper() == "ALL":
                        report("kubernetes.capabilities-all", capability)
            elif (value(added) or "").strip("[]'\" ").upper() == "ALL":
                report("kubernetes.capabilities-all", added)

    def inspect_resource(resource: yaml.Node) -> None:
        fields = entries(resource)
        kind = value(fields.get("kind"))
        if kind == "List":
            items = fields.get("items")
            if isinstance(items, yaml.SequenceNode):
                for item in items.value:
                    inspect_resource(item)
            return

        spec = fields.get("spec")
        if kind == "Pod":
            if spec is not None:
                inspect_pod_spec(spec)
            return

        if kind == "CronJob":
            job_template = entries(spec).get("jobTemplate")
            job_spec = entries(job_template).get("spec")
            template = entries(job_spec).get("template")
        elif kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
            template = entries(spec).get("template")
        else:
            return
        pod_spec = entries(template).get("spec")
        if pod_spec is not None:
            inspect_pod_spec(pod_spec)

    try:
        documents = yaml.compose_all(source, Loader=yaml.SafeLoader)
        for document in documents:
            if document is None:
                continue
            fields = entries(document)
            if value(fields.get("apiVersion")) and value(fields.get("kind")):
                inspect_resource(document)
    except yaml.YAMLError:
        return

def _terraform_findings(source: str, relative: str, findings: list[dict[str, Any]], seen: set[tuple[str, str, int]]) -> None:
    """Find selected risky settings in Terraform resource blocks without evaluating HCL."""
    lines = source.splitlines()
    resource_type: str | None = None
    resource_depth = 0
    ingress_depth: int | None = None

    for number, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].split("//", 1)[0].strip()
        if not line:
            continue

        start = re.match(r'(?i)^resource\s+"([^"]+)"\s+"[^"]+"\s*\{', line)
        if start:
            resource_type = start.group(1).lower()
            resource_depth = line.count("{") - line.count("}")
            ingress_depth = None
            continue

        if resource_type is None:
            continue

        if re.match(r"(?i)^ingress\s*\{", line):
            ingress_depth = resource_depth + line.count("{") - line.count("}") - 1
        is_ingress_resource = resource_type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}
        is_ingress_block = resource_type == "aws_security_group" and ingress_depth is not None
        if is_ingress_resource or is_ingress_block:
            if re.search(r'(?i)(?:cidr_blocks|cidr_ipv4|ipv6_cidr_blocks)\s*=\s*(?:\[\s*)?["\'](?:0\.0\.0\.0/0|::/0)["\']', line):
                _add_finding(findings, seen, "terraform.public-ingress", relative, number)

        if resource_type in {"aws_s3_bucket", "aws_s3_bucket_acl"}:
            if re.search(r'(?i)\bacl\s*=\s*["\']public-(?:read|read-write)["\']', line):
                _add_finding(findings, seen, "terraform.public-s3-acl", relative, number)

        if resource_type == "aws_s3_bucket_public_access_block":
            if re.search(r"(?i)\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b", line):
                _add_finding(findings, seen, "terraform.s3-public-access-disabled", relative, number)

        if resource_type in {
            "aws_db_instance", "aws_rds_cluster", "aws_elasticache_cluster",
            "aws_elasticache_replication_group", "aws_redshift_cluster",
        } and re.search(r"(?i)\bpublicly_accessible\s*=\s*true\b", line):
            _add_finding(findings, seen, "terraform.database-publicly-accessible", relative, number)

        if resource_type in {
            "aws_ebs_volume", "aws_db_instance", "aws_rds_cluster",
            "aws_elasticache_cluster", "aws_elasticache_replication_group",
        } and re.search(r"(?i)\b(?:encrypted|storage_encrypted)\s*=\s*false\b", line):
            _add_finding(findings, seen, "terraform.storage-unencrypted", relative, number)

        opens = line.count("{")
        closes = line.count("}")
        resource_depth += opens - closes
        if ingress_depth is not None and resource_depth <= ingress_depth:
            ingress_depth = None
        if resource_depth <= 0:
            resource_type = None
            resource_depth = 0
            ingress_depth = None


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
    active = report["findings"]
    suppressed = report.get("suppressed_findings", [])
    lines = [
        f"# {text['summary']}", "",
        f"- {text['file']}: {report['scanned_path']}",
        f"- Scanned files: {report['scanned_files']}",
        f"- {text['findings']}: {len(active)}",
        f"- {text['suppressed']}: {len(suppressed)}", "",
        f"| {text['severity']} | {text['rule']} | {text['file']} | {text['line']} |", "| --- | --- | --- | ---: |",
    ]
    for finding in active:
        category = _RULES[finding["rule_id"]][0]
        title = finding.get("title", text[f"{category}.title"])
        lines.append(f"| {finding['severity'].title()} | {title} | {finding['file']} | {finding['line']} |")
        lines.extend(["", f"**{text[f'{category}.description']}**", "", f"**{text[f'{category}.fix']}**", ""])
    if not active:
        lines.extend(["", text["no_findings"], ""])
    if suppressed:
        lines.extend(["", f"## {text['suppressed']}", "", f"| {text['rule']} | {text['file']} | {text['line']} | {text['expires']} | {text['suppression_reason']} |", "| --- | --- | ---: | --- | --- |"])
        for finding in suppressed:
            lines.append(f"| {finding['rule_id']} | {finding['file']} | {finding['line']} | {finding['suppression_expires']} | {finding['suppression_reason']} |")
    lines.extend(["", text["redaction"], ""])
    return "\n".join(lines)




_CHECK_FOR_CATEGORY = {
    "secret": "secrets",
    "eval": "python",
    "pickle": "python",
    "yaml": "python",
    "shell": "python",
    "tls": "python",
    "mktemp": "python",
    "debug": "config",
    "cors": "config",
    "docker_root": "docker",
    "docker_base": "docker",
    "docker_secret": "docker",
    "k8s_privileged": "kubernetes",
    "k8s_escalation": "kubernetes",
    "k8s_root": "kubernetes",
    "k8s_host_namespace": "kubernetes",
    "k8s_host_path": "kubernetes",
    "k8s_capabilities": "kubernetes",
    "tf_ingress": "terraform",
    "tf_s3_acl": "terraform",
    "tf_s3_block": "terraform",
    "tf_database_public": "terraform",
    "tf_storage": "terraform",
    "dependency": "dependencies",
}


def render_local_html(report: dict[str, Any]) -> str:
    """Render a self-contained, escaped HTML report for local viewing."""
    text = _TEXT[report["language"]]
    active = report["findings"]
    suppressed = report.get("suppressed_findings", [])
    all_findings = [*active, *suppressed]
    rows: list[str] = []
    for finding in all_findings:
        category = _RULES[finding["rule_id"]][0]
        is_suppressed = "suppression_reason" in finding
        status = text["html.suppressed_status"] if is_suppressed else text["html.active_status"]
        reason = finding.get("suppression_reason", "")
        expires = finding.get("suppression_expires", "")
        cells = [
            finding["severity"].title(),
            finding["rule_id"],
            finding["file"],
            str(finding.get("line") or ""),
            finding.get("title", text[f"{category}.title"]),
            finding["description"],
            finding["remediation"],
            f"{status} — {reason} ({expires})" if is_suppressed else status,
        ]
        status_key = "suppressed" if is_suppressed else "active"
        escaped_severity = html.escape(finding["severity"], quote=True)
        rows.append(
            f'<tr data-severity="{escaped_severity}" data-status="{status_key}">'
            + "".join(f"<td>{html.escape(cell)}</td>" for cell in cells)
            + "</tr>"
        )
    body = "\n".join(rows) or f'<tr><td colspan="8">{html.escape(text["no_findings"])}</td></tr>'
    title = html.escape(text["summary"])
    source_name = html.escape(Path(report["scanned_path"]).name)
    empty = html.escape(text["html.empty"])
    language = report["language"]
    file_label = html.escape(text["file"])
    active_label = html.escape(text["html.active"])
    suppressed_label = html.escape(text["suppressed"])
    total_label = html.escape(text["html.total"])
    search_label = html.escape(text["html.search"])
    severity_filter_label = html.escape(text["html.severity_filter"])
    status_label = html.escape(text["html.status"])
    active_status_label = html.escape(text["html.active_status"])
    suppressed_status_label = html.escape(text["html.suppressed_status"])
    severity_label = html.escape(text["severity"])
    rule_label = html.escape(text["rule"])
    line_label = html.escape(text["line"])
    description_label = html.escape(text["html.description"])
    remediation_label = html.escape(text["html.remediation"])
    redaction_label = html.escape(text["redaction"])
    status_header_label = html.escape(text["html.status"])
    return f"""<!doctype html>
<html lang="{language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{color-scheme:light dark;font:14px system-ui,sans-serif}}
body{{margin:2rem;max-width:1500px}}h1{{margin-bottom:.25rem}}.meta{{opacity:.75;margin-bottom:1.5rem}}
.controls{{display:flex;gap:.75rem;margin:1rem 0}}input,select{{padding:.5rem;min-width:12rem}}
.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:1000px}}
th,td{{border:1px solid #7776;padding:.55rem;text-align:left;vertical-align:top}}
th{{position:sticky;top:0;background:#263342}}td{{max-width:28rem;overflow-wrap:anywhere}}
tr[data-status="suppressed"]{{opacity:.68}}.note{{margin-top:1rem;opacity:.8}}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">{file_label}: {source_name} · {active_label}: {len(active)} · {suppressed_label}: {len(suppressed)} · {total_label}: {len(all_findings)}</p>
<div class="controls">
<label>{search_label} <input id="search" type="search"></label>
<label>{severity_filter_label}
<select id="severity"><option value="">All</option><option>Critical</option><option>High</option><option>Medium</option><option>Moderate</option><option>Low</option><option>Unknown</option></select></label>
<label>{status_label}
<select id="status"><option value="">All</option><option value="active">{active_status_label}</option><option value="suppressed">{suppressed_status_label}</option></select></label>
</div>
<div class="table-wrap"><table>
<thead><tr><th>{severity_label}</th><th>{rule_label}</th><th>{file_label}</th><th>{line_label}</th><th>Finding</th><th>{description_label}</th><th>{remediation_label}</th><th>{status_header_label}</th></tr></thead>
<tbody id="findings">{body}</tbody></table></div>
<p id="empty" hidden>{empty}</p>
<p class="note">{redaction_label}</p>
<script>
const search=document.getElementById("search"),severity=document.getElementById("severity"),status=document.getElementById("status");
function filterRows(){{let visible=0;for(const row of document.querySelectorAll("#findings tr")){{const matchText=row.innerText.toLowerCase().includes(search.value.toLowerCase());const matchSeverity=!severity.value||row.dataset.severity===severity.value.toLowerCase();const matchStatus=!status.value||row.dataset.status===status.value;const show=matchText&&matchSeverity&&matchStatus;row.hidden=!show;if(show)visible++}}document.getElementById("empty").hidden=visible!==0}}
for(const control of [search,severity,status])control.addEventListener("input",filterRows);
</script>
</body>
</html>
"""


def render_local_sarif(report: dict[str, Any]) -> str:
    """Render findings as a local SARIF 2.1.0 document without source snippets."""
    text = _TEXT[report["language"]]
    selected_checks = set(report["checks"])
    rules: list[dict[str, Any]] = []
    rule_indexes: dict[str, int] = {}
    for rule_id, (category, severity) in sorted(_RULES.items()):
        if _CHECK_FOR_CATEGORY[category] not in selected_checks:
            continue
        level = {"high": "error", "medium": "warning", "low": "note", "unknown": "warning"}[severity]
        rule_indexes[rule_id] = len(rules)
        rules.append({
            "id": rule_id,
            "name": rule_id.replace(".", "_").replace("-", "_"),
            "shortDescription": {"text": text[f"{category}.title"]},
            "fullDescription": {"text": text[f"{category}.description"]},
            "help": {"text": text[f"{category}.fix"]},
            "helpUri": "https://github.com/furkanersoy/ScopeGuard#offline-local-source-inspection",
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": ["security", category],
                "scopeguard/severity": severity,
            },
        })

    root = Path(report["scanned_path"])
    scan_base = root.parent if root.is_file() else root
    try:
        path_prefix = scan_base.relative_to(Path.cwd().absolute())
    except ValueError:
        path_prefix = Path(".")

    results: list[dict[str, Any]] = []
    all_findings = [*report["findings"], *report.get("suppressed_findings", [])]
    for finding in all_findings:
        rule_id = finding["rule_id"]
        severity = finding["severity"]
        level = {"critical": "error", "high": "error", "medium": "warning", "moderate": "warning", "low": "note", "unknown": "warning"}[severity]
        relative_path = Path(finding["file"])
        artifact_path = relative_path if path_prefix == Path(".") else path_prefix / relative_path
        uri = quote(artifact_path.as_posix(), safe="/-._~")
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_indexes[rule_id],
            "level": level,
            "message": {"text": f"{finding.get('title', '')}: {finding['description']}".strip(": ")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": finding["line"]} if isinstance(finding.get("line"), int) and finding["line"] > 0 else {},
                },
            }],
            "properties": {
                "category": finding["category"],
                "severity": severity,
                "remediation": finding["remediation"],
                **({"vulnerabilityId": finding["vulnerability_id"]} if finding.get("vulnerability_id") else {}),
                **({"package": finding["package"], "version": finding["version"], "ecosystem": finding["ecosystem"]} if finding.get("package") else {}),
            },
        })
        if "suppression_reason" in finding:
            results[-1]["suppressions"] = [{
                "kind": "external",
                "justification": finding["suppression_reason"],
            }]

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ScopeGuard",
                    "informationUri": "https://github.com/furkanersoy/ScopeGuard",
                    "rules": rules,
                },
            },
            "results": results,
            "properties": {
                "mode": report["mode"],
                "language": report["language"],
                "checks": report["checks"],
                "scannedFiles": report["scanned_files"],
                "noNetworkAccess": True,
                "sourceSnippetsIncluded": False,
            },
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def inspect_path(path: Path, checks: list[str], language: str = "en", *, output_paths: list[Path] | None = None) -> dict[str, Any]:
    """Scan local text files statically; no code execution and no network access."""
    if language not in _TEXT:
        raise ValidationError("language must be 'tr' or 'en'")
    allowed = {"secrets", "python", "config", "docker", "kubernetes", "terraform"}
    if not checks or len(set(checks)) != len(checks) or any(check not in allowed for check in checks):
        raise ValidationError("select one or more distinct checks: secrets, python, config, docker, kubernetes, terraform")
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
        if "kubernetes" in checks and file_path.suffix.lower() in {".yaml", ".yml"}:
            _kubernetes_findings(source, relative, findings, seen)
        if "terraform" in checks and (file_path.suffix.lower() == ".tf" or file_path.name.lower().endswith(".tf.json")):
            _terraform_findings(source, relative, findings, seen)
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
        "suppressed_findings": [],
    }


def apply_suppressions(report: dict[str, Any], suppressions_path: Path | None) -> None:
    """Move active findings covered by dated, reasoned suppressions into a visible list."""
    report["suppressed_findings"] = []
    if suppressions_path is None:
        return
    try:
        data = yaml.safe_load(suppressions_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"cannot read suppressions file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValidationError("suppressions file is not valid YAML") from exc
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("suppressions"), list):
        raise ValidationError("suppressions file must contain version: 1 and a suppressions list")

    entries: list[dict[str, str]] = []
    today = datetime.now(timezone.utc).date()
    for index, item in enumerate(data["suppressions"], 1):
        if not isinstance(item, dict) or not {"rule_id", "path", "reason", "expires"} <= set(item):
            raise ValidationError(f"suppression {index} must set rule_id, path, reason, and expires")
        rule_pattern = str(item["rule_id"]).strip()
        path_pattern = str(item["path"]).replace("\\", "/").strip()
        reason = str(item["reason"]).strip()
        expires_text = str(item["expires"]).strip()
        if not any(fnmatch.fnmatchcase(rule_id, rule_pattern) for rule_id in _RULES):
            raise ValidationError(f"suppression {index} rule_id matches no known rule")
        if not path_pattern or path_pattern.startswith("/") or Path(path_pattern).is_absolute() or PureWindowsPath(path_pattern).is_absolute() or ".." in Path(path_pattern).parts or ".." in PureWindowsPath(path_pattern).parts:
            raise ValidationError(f"suppression {index} path must be a relative path pattern without '..'")
        if not reason:
            raise ValidationError(f"suppression {index} requires a non-empty reason")
        try:
            expires = date.fromisoformat(expires_text)
        except ValueError as exc:
            raise ValidationError(f"suppression {index} expires must use YYYY-MM-DD") from exc
        if expires.isoformat() != expires_text or expires < today:
            raise ValidationError(f"suppression {index} is expired or has an invalid date")
        entries.append({"rule_id": rule_pattern, "path": path_pattern, "reason": reason, "expires": expires_text})

    active: list[dict[str, Any]] = []
    for finding in report["findings"]:
        relative = finding["file"].replace("\\", "/")
        match = next((
            entry for entry in entries
            if fnmatch.fnmatchcase(finding["rule_id"], entry["rule_id"])
            and fnmatch.fnmatchcase(relative, entry["path"])
        ), None)
        if match is None:
            active.append(finding)
        else:
            suppressed = dict(finding)
            suppressed["suppression_reason"] = match["reason"]
            suppressed["suppression_expires"] = match["expires"]
            suppressed["suppression_path"] = match["path"]
            report["suppressed_findings"].append(suppressed)
    report["findings"] = active


def write_local_reports(
    report: dict[str, Any],
    json_path: Path,
    markdown_path: Path | None = None,
    sarif_path: Path | None = None,
    html_path: Path | None = None,
) -> None:
    outputs = [json_path.resolve()]
    if markdown_path is not None:
        outputs.append(markdown_path.resolve())
    if sarif_path is not None:
        outputs.append(sarif_path.resolve())
    if html_path is not None:
        outputs.append(html_path.resolve())
    if len(set(outputs)) != len(outputs):
        raise ValidationError("JSON, Markdown, SARIF, and HTML outputs must use different paths")
    for output in outputs:
        if Path(report["scanned_path"]).resolve() == output:
            raise ValidationError("report output must not overwrite the scan target")
    report["findings_count"] = len(report["findings"])
    report["suppressed_count"] = len(report.get("suppressed_findings", []))
    _atomic_write(json_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    if markdown_path is not None:
        _atomic_write(markdown_path, render_local_markdown(report))
    if sarif_path is not None:
        _atomic_write(sarif_path, render_local_sarif(report))
    if html_path is not None:
        _atomic_write(html_path, render_local_html(report))
