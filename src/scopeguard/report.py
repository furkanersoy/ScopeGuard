"""Render localized, redacted ScopeGuard findings and reports."""

from __future__ import annotations

from typing import Any

SUPPORTED_LANGUAGES = ("en", "tr")

_TEXT = {
    "en": {
        "report_title": "ScopeGuard report", "generated": "Generated", "version": "Version",
        "openapi": "OpenAPI", "scenario": "Scenario", "summary": "Summary", "checks": "Checks",
        "findings": "Findings", "status": "Status", "check": "Check", "identity": "Identity",
        "operation": "Operation", "expected": "Expected", "actual": "Actual", "assertions": "Assertions",
        "severity": "Severity", "evidence": "Evidence", "impact": "Impact", "remediation": "Recommended remediation",
        "high": "High", "pass": "PASS", "fail": "FAIL", "skipped": "SKIPPED", "error": "ERROR",
        "generic_title": "Authorization check failed",
        "generic_description": "The check did not match its expected result. Review the endpoint policy and scenario configuration.",
        "generic_impact": "The endpoint may not enforce the configured access-control expectation.",
        "generic_remediation": "Verify the intended authorization policy, then update the endpoint or the scenario and rerun the check.",
        "bola_title": "Broken Object Level Authorization (BOLA / IDOR)",
        "bola_description": "A request made as {identity} to {operation} returned a resource that the scenario expected to deny. The cross-user request should have been rejected, but the endpoint returned HTTP {actual}. This points to missing or incorrect object-level authorization.",
        "bola_impact": "A user may be able to read another user's record by changing its identifier. Depending on the data and available operations, this can expose private records across accounts.",
        "bola_remediation": "Enforce ownership on the server for every object access: derive the principal from the authenticated session, query by both object ID and owner ID, and return the same denial behavior for missing and unauthorized objects. Add regression checks for both users reading their own and each other's records.",
        "assertion_evidence": "JSON assertion {pointer} {operator} failed",
        "status_evidence": "Expected HTTP {expected}; received HTTP {actual}",
        "redaction_note": "Response bodies, assertion values, and credential values are not included in this report.",
    },
    "tr": {
        "report_title": "ScopeGuard raporu", "generated": "Oluşturulma zamanı", "version": "Sürüm",
        "openapi": "OpenAPI", "scenario": "Senaryo", "summary": "Özet", "checks": "Kontroller",
        "findings": "Güvenlik bulguları", "status": "Durum", "check": "Kontrol", "identity": "Kimlik",
        "operation": "İşlem", "expected": "Beklenen", "actual": "Alınan", "assertions": "JSON doğrulamaları",
        "severity": "Önem derecesi", "evidence": "Kanıt", "impact": "Olası etki", "remediation": "Önerilen düzeltme",
        "high": "Yüksek", "pass": "BAŞARILI", "fail": "BAŞARISIZ", "skipped": "ATLANDI", "error": "HATA",
        "generic_title": "Yetkilendirme kontrolü başarısız",
        "generic_description": "Kontrol, senaryoda beklenen sonuçla eşleşmedi. Uç nokta politikasını ve senaryo ayarlarını inceleyin.",
        "generic_impact": "Uç nokta, tanımlanan erişim kontrolü beklentisini uygulamıyor olabilir.",
        "generic_remediation": "Beklenen yetkilendirme politikasını doğrulayın; uç noktayı veya senaryoyu düzeltip kontrolü yeniden çalıştırın.",
        "bola_title": "Nesne Düzeyinde Yetkilendirme Hatası (BOLA / IDOR)",
        "bola_description": "{identity} kimliğiyle {operation} adresine yapılan istek, senaryonun erişimi reddetmesini beklediği hâlde kaynağı döndürdü. Başka kullanıcıya ait kayda yönelik isteğin reddedilmesi gerekiyordu; ancak uç nokta HTTP {actual} yanıtı verdi. Bu durum, nesne düzeyindeki yetkilendirmenin eksik veya hatalı olabileceğini gösterir.",
        "bola_impact": "Bir kullanıcı kayıt kimliğini değiştirerek başka bir kullanıcının verisini okuyabilir. Verinin ve uç noktaların kapsamına bağlı olarak hesaplar arası özel bilgiler açığa çıkabilir.",
        "bola_remediation": "Her nesne erişiminde sahipliği sunucu tarafında doğrulayın: kullanıcı kimliğini doğrulanmış oturumdan alın, veritabanı sorgusunda hem nesne kimliğini hem sahip kimliğini kullanın ve bulunamayan nesneyle yetkisiz nesne için aynı ret davranışını uygulayın. Her iki kullanıcının kendi ve diğer kullanıcı kayıtlarına erişimini kapsayan regresyon kontrolleri ekleyin.",
        "assertion_evidence": "JSON doğrulaması başarısız: {pointer} {operator}",
        "status_evidence": "Beklenen HTTP {expected}; alınan HTTP {actual}",
        "redaction_note": "Yanıt gövdeleri, doğrulama değerleri ve kimlik bilgileri bu rapora eklenmez.",
    },
}


def _cell(value: Any) -> str:
    """Escape untrusted/configured text for a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def build_findings(results: list[dict[str, Any]], language: str = "en") -> list[dict[str, str]]:
    """Turn failed checks into actionable, localized findings without response data."""
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported report language: {language}")
    text = _TEXT[language]
    findings: list[dict[str, str]] = []
    for result in results:
        if result.get("status") != "FAIL":
            continue
        expected = ", ".join(map(str, result.get("expected_status", []))) or "?"
        actual = str(result.get("actual_status", "?"))
        operation = str(result.get("operation", "the configured operation"))
        identity = str(result.get("identity", "the configured identity"))
        failed_assertions = [item for item in result.get("assertions", []) if item.get("status") == "FAIL"]
        is_bola = (
            ("vulnerable" in result.get("id", "").lower() or "record" in operation.lower())
            and any(item.get("pointer") == "/owner" and item.get("operator") == "not_equals" for item in failed_assertions)
        )
        if is_bola:
            finding = {
                "severity": text["high"], "title": text["bola_title"],
                "description": text["bola_description"].format(identity=identity, operation=operation, actual=actual),
                "impact": text["bola_impact"], "remediation": text["bola_remediation"],
            }
        else:
            finding = {
                "severity": text["high"], "title": text["generic_title"],
                "description": text["generic_description"], "impact": text["generic_impact"],
                "remediation": text["generic_remediation"],
            }
        evidence = [text["status_evidence"].format(expected=expected, actual=actual)]
        evidence.extend(
            text["assertion_evidence"].format(pointer=item.get("pointer", ""), operator=item.get("operator", ""))
            for item in failed_assertions
        )
        finding.update({
            "check_id": str(result.get("id", "")), "identity": identity,
            "operation": operation, "evidence": "; ".join(evidence),
        })
        findings.append(finding)
    return findings


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a localized, already-redacted report for human readers."""
    language = report.get("language", "en")
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported report language: {language}")
    text = _TEXT[language]
    summary = report["summary"]
    lines = [
        f"# {text['report_title']}", "",
        f"- {text['generated']}: {_cell(report['generated_at'])}",
        f"- {text['version']}: {_cell(report['version'])}",
        f"- {text['openapi']}: {_cell(report['spec_file'])}",
        f"- {text['scenario']}: {_cell(report['scenario_file'])}", "",
        f"## {text['summary']}", "",
        f"| {text['pass']} | {text['fail']} | {text['skipped']} | {text['error']} |",
        "| ---: | ---: | ---: | ---: |",
        f"| {summary['PASS']} | {summary['FAIL']} | {summary['SKIPPED']} | {summary['ERROR']} |", "",
        f"## {text['checks']}", "",
        f"| {text['status']} | {text['check']} | {text['identity']} | {text['operation']} | {text['expected']} | {text['actual']} | {text['assertions']} |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    status_names = {"PASS": "pass", "FAIL": "fail", "SKIPPED": "skipped", "ERROR": "error"}
    for result in report["results"]:
        actual = result.get("actual_status", result.get("reason", "-"))
        assertions = "; ".join(
            f"{item['pointer']} {item['operator']}: {item['status']}"
            for item in result.get("assertions", [])
        ) or "-"
        values = (
            text[status_names[result["status"]]], result["id"], result["identity"], result["operation"],
            ", ".join(map(str, result["expected_status"])), actual, assertions,
        )
        lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
    findings = report.get("findings", [])
    if findings:
        lines.extend(["", f"## {text['findings']}", ""])
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {index}. {finding['title']}", "",
                f"- {text['severity']}: {finding['severity']}",
                f"- {text['check']}: {finding['check_id']}",
                f"- {text['evidence']}: {_cell(finding['evidence'])}", "",
                finding["description"], "",
                f"**{text['impact']}:** {finding['impact']}", "",
                f"**{text['remediation']}:** {finding['remediation']}", "",
            ])
    lines.extend(["", text["redaction_note"], ""])
    return "\n".join(lines)
