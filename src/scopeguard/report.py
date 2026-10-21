"""Render localized, redacted ScopeGuard findings and reports."""

from __future__ import annotations

import html
import json
from typing import Any

SUPPORTED_LANGUAGES = ("en", "tr")

_TEXT = {
    "en": {
        "report_title": "ScopeGuard report", "generated": "Generated", "version": "Version",
        "openapi": "OpenAPI", "scenario": "Scenario", "summary": "Summary", "checks": "Checks",
        "findings": "Findings", "status": "Status", "check": "Check", "identity": "Identity",
        "operation": "Operation", "expected": "Expected", "actual": "Actual", "assertions": "Assertions",
        "severity": "Severity", "evidence": "Evidence", "description": "Description", "impact": "Impact", "remediation": "Recommended remediation",
        "high": "High", "pass": "PASS", "fail": "FAIL", "skipped": "SKIPPED", "error": "ERROR",
        "generic_title": "Authorization check failed",
        "generic_description": "The check did not match its expected result. Review the endpoint policy and scenario configuration.",
        "generic_impact": "The endpoint may not enforce the configured access-control expectation.",
        "generic_remediation": "Verify the intended authorization policy, then update the endpoint or the scenario and rerun the check.",
        "bola_title": "Broken Object Level Authorization (BOLA / IDOR)",
        "bola_description": "A request made as {identity} to {operation} returned a resource that the scenario expected to deny. The cross-user request should have been rejected, but the endpoint returned HTTP {actual}. This points to missing or incorrect object-level authorization.",
        "bola_impact": "A user may be able to read another user's record by changing its identifier. Depending on the data and available operations, this can expose private records across accounts.",
        "bola_remediation": "Enforce ownership on the server for every object access: derive the principal from the authenticated session, query by both object ID and owner ID, and return the same denial behavior for missing and unauthorized objects. Add regression checks for both users reading their own and each other's records.",
        "bfla_title": "Broken Function Level Authorization (BFLA)",
        "bfla_description": "A low-privilege identity ({identity}) received HTTP {actual} from privileged operation {operation}, although the scenario expected access to be denied. This suggests the server may not enforce role or permission checks for this function.",
        "bfla_impact": "A regular account may invoke administrative or otherwise restricted functionality, potentially changing or exposing data beyond its role.",
        "bfla_remediation": "Enforce authorization on the server for every privileged operation. Check permissions for the authenticated principal on each request, deny by default, and add role-based regression checks for both permitted and denied roles.",
        "authn_title": "Missing or Ineffective Authentication Control",
        "authn_description": "An unauthenticated request to {operation} received HTTP {actual}, although the scenario expected a denial. The endpoint may be accessible without the required login.",
        "authn_impact": "Unauthenticated users may access information or functionality intended only for signed-in users.",
        "authn_remediation": "Require authentication on this route and verify authorization on the server. Add anonymous and authenticated regression checks using the intended response policy.",
        "assertion_evidence": "JSON assertion {pointer} {operator} failed",
        "status_evidence": "Expected HTTP {expected}; received HTTP {actual}",
        "redaction_note": "Response bodies, assertion values, and credential values are not included in this report.",
    },
    "tr": {
        "report_title": "ScopeGuard raporu", "generated": "Oluşturulma zamanı", "version": "Sürüm",
        "openapi": "OpenAPI", "scenario": "Senaryo", "summary": "Özet", "checks": "Kontroller",
        "findings": "Güvenlik bulguları", "status": "Durum", "check": "Kontrol", "identity": "Kimlik",
        "operation": "İşlem", "expected": "Beklenen", "actual": "Alınan", "assertions": "JSON doğrulamaları",
        "severity": "Önem derecesi", "evidence": "Kanıt", "description": "Açıklama", "impact": "Olası etki", "remediation": "Önerilen düzeltme",
        "high": "Yüksek", "pass": "BAŞARILI", "fail": "BAŞARISIZ", "skipped": "ATLANDI", "error": "HATA",
        "generic_title": "Yetkilendirme kontrolü başarısız",
        "generic_description": "Kontrol, senaryoda beklenen sonuçla eşleşmedi. Uç nokta politikasını ve senaryo ayarlarını inceleyin.",
        "generic_impact": "Uç nokta, tanımlanan erişim kontrolü beklentisini uygulamıyor olabilir.",
        "generic_remediation": "Beklenen yetkilendirme politikasını doğrulayın; uç noktayı veya senaryoyu düzeltip kontrolü yeniden çalıştırın.",
        "bola_title": "Nesne Düzeyinde Yetkilendirme Hatası (BOLA / IDOR)",
        "bola_description": "{identity} kimliğiyle {operation} adresine yapılan istek, senaryonun erişimi reddetmesini beklediği hâlde kaynağı döndürdü. Başka kullanıcıya ait kayda yönelik isteğin reddedilmesi gerekiyordu; ancak uç nokta HTTP {actual} yanıtı verdi. Bu durum, nesne düzeyindeki yetkilendirmenin eksik veya hatalı olabileceğini gösterir.",
        "bola_impact": "Bir kullanıcı kayıt kimliğini değiştirerek başka bir kullanıcının verisini okuyabilir. Verinin ve uç noktaların kapsamına bağlı olarak hesaplar arası özel bilgiler açığa çıkabilir.",
        "bola_remediation": "Her nesne erişiminde sahipliği sunucu tarafında doğrulayın: kullanıcı kimliğini doğrulanmış oturumdan alın, veritabanı sorgusunda hem nesne kimliğini hem sahip kimliğini kullanın ve bulunamayan nesneyle yetkisiz nesne için aynı ret davranışını uygulayın. Her iki kullanıcının kendi ve diğer kullanıcı kayıtlarına erişimini kapsayan regresyon kontrolleri ekleyin.",
        "bfla_title": "Fonksiyon Düzeyinde Yetkilendirme Hatası (BFLA)",
        "bfla_description": "Düşük yetkili ({identity}) kimliği, senaryonun erişimi reddetmesini beklediği ayrıcalıklı {operation} işleminden HTTP {actual} yanıtı aldı. Bu, sunucunun bu işlev için rol veya izin kontrolü yapmadığını gösterebilir.",
        "bfla_impact": "Standart bir hesap, rolünün dışındaki yönetim işlevlerini çağırabilir; bu da yetkisiz veri erişimine veya değişikliğine yol açabilir.",
        "bfla_remediation": "Her ayrıcalıklı işlemde yetkiyi sunucu tarafında doğrulayın. Her istekte doğrulanmış kullanıcının izinlerini kontrol edin, varsayılan olarak erişimi reddedin ve izinli/izinsiz roller için regresyon kontrolleri ekleyin.",
        "authn_title": "Eksik veya Etkisiz Kimlik Doğrulama Kontrolü",
        "authn_description": "Kimlik doğrulaması olmadan {operation} adresine yapılan istek HTTP {actual} yanıtı aldı; senaryo erişimin reddedilmesini bekliyordu. Uç nokta oturum açmadan erişilebilir olabilir.",
        "authn_impact": "Oturum açmamış kullanıcılar yalnızca giriş yapmış kişilere açık olması gereken bilgi veya işlevlere erişebilir.",
        "authn_remediation": "Bu uç noktada kimlik doğrulamasını zorunlu tutun ve yetkiyi sunucuda doğrulayın. Tanımlanan yanıt politikasına göre anonim ve oturum açmış kullanıcılar için regresyon kontrolleri ekleyin.",
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
        check_id = str(result.get("id", "")).lower()
        is_bola = check_id.startswith("bola-") or (
            ("vulnerable" in check_id or "record" in operation.lower())
            and any(item.get("pointer") == "/owner" and item.get("operator") == "not_equals" for item in failed_assertions)
        )
        if is_bola:
            finding = {
                "rule_id": "scopeguard.bola",
                "severity": text["high"], "title": text["bola_title"],
                "description": text["bola_description"].format(identity=identity, operation=operation, actual=actual),
                "impact": text["bola_impact"], "remediation": text["bola_remediation"],
            }
        elif check_id.startswith("bfla-"):
            finding = {
                "rule_id": "scopeguard.bfla",
                "severity": text["high"], "title": text["bfla_title"],
                "description": text["bfla_description"].format(identity=identity, operation=operation, actual=actual),
                "impact": text["bfla_impact"], "remediation": text["bfla_remediation"],
            }
        elif check_id.startswith("anonymous-denied-"):
            finding = {
                "rule_id": "scopeguard.missing-authentication",
                "severity": text["high"], "title": text["authn_title"],
                "description": text["authn_description"].format(operation=operation, actual=actual),
                "impact": text["authn_impact"], "remediation": text["authn_remediation"],
            }
        else:
            finding = {
                "rule_id": "scopeguard.authorization-check-failed",
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


def render_sarif_report(report: dict[str, Any]) -> str:
    """Serialize localized findings as SARIF 2.1.0 without transmitting them."""
    findings = report.get("findings", [])
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding["rule_id"]
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id.rsplit(".", 1)[-1].replace("-", " ").title(),
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["description"]},
                "defaultConfiguration": {"level": "error"},
                "help": {
                    "text": finding["remediation"],
                    "markdown": f"**{finding['impact']}**\n\n{finding['remediation']}",
                },
                "properties": {"tags": ["security", "authorization", "access-control"]},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": f"{finding['title']}: {finding['description']} Evidence: {finding['evidence']}",
                    "markdown": f"### {finding['title']}\n\n{finding['description']}\n\n**{finding['evidence']}**",
                },
                "properties": {
                    "severity": finding["severity"],
                    "checkId": finding["check_id"],
                    "identity": finding["identity"],
                    "operation": finding["operation"],
                    "impact": finding["impact"],
                    "remediation": finding["remediation"],
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ScopeGuard",
                        "semanticVersion": report["version"],
                        "informationUri": "https://github.com/furkanersoy/ScopeGuard",
                        "rules": list(rules.values()),
                    }
                },
                "language": "tr-TR" if report.get("language") == "tr" else "en-US",
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


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


def render_html_report(report: dict[str, Any]) -> str:
    """Render a self-contained, localized HTML report with escaped report content."""
    language = report.get("language", "en")
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported report language: {language}")
    text = _TEXT[language]
    summary = report["summary"]
    status_names = {"PASS": "pass", "FAIL": "fail", "SKIPPED": "skipped", "ERROR": "error"}
    check_rows = []
    for result in report["results"]:
        actual = result.get("actual_status", result.get("reason", "-"))
        assertions = "; ".join(
            f"{item['pointer']} {item['operator']}: {item['status']}"
            for item in result.get("assertions", [])
        ) or "-"
        cells = (
            text[status_names[result["status"]]], result["id"], result["identity"],
            result["operation"], ", ".join(map(str, result["expected_status"])),
            actual, assertions,
        )
        check_rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in cells) + "</tr>")
    finding_rows = []
    for finding in report.get("findings", []):
        cells = (
            finding["severity"], finding["title"], finding["check_id"], finding["evidence"],
            finding["description"], finding["impact"], finding["remediation"],
        )
        finding_rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in cells) + "</tr>")
    checks_body = "\\n".join(check_rows) or '<tr><td colspan="7">—</td></tr>'
    findings_body = "\\n".join(finding_rows) or f'<tr><td colspan="7">{html.escape(text["findings"])}: 0</td></tr>'
    labels = {
        "title": text["report_title"], "generated": text["generated"], "version": text["version"],
        "openapi": text["openapi"], "scenario": text["scenario"], "summary": text["summary"],
        "checks": text["checks"], "findings": text["findings"], "status": text["status"],
        "check": text["check"], "identity": text["identity"], "operation": text["operation"],
        "expected": text["expected"], "actual": text["actual"], "assertions": text["assertions"],
        "severity": text["severity"], "evidence": text["evidence"], "description": text["description"], "impact": text["impact"],
        "remediation": text["remediation"], "redaction": text["redaction_note"],
    }
    labels = {key: html.escape(value) for key, value in labels.items()}
    return f"""<!doctype html>
<html lang="{language}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{labels["title"]}</title>
<style>
body{{font:14px system-ui,sans-serif;margin:2rem;max-width:1500px}}
h1{{margin-bottom:.25rem}}.meta{{opacity:.8}}.summary{{display:flex;gap:1rem;flex-wrap:wrap}}
.summary span{{padding:.6rem 1rem;border:1px solid #8888;border-radius:.5rem}}
.wrap{{overflow:auto;margin:1rem 0 2rem}}table{{border-collapse:collapse;width:100%;min-width:900px}}
th,td{{border:1px solid #8886;padding:.55rem;text-align:left;vertical-align:top}}
th{{position:sticky;top:0;background:#263342}}td{{overflow-wrap:anywhere}}.note{{opacity:.8}}
</style></head><body>
<h1>{labels["title"]}</h1>
<p class="meta">{labels["generated"]}: {html.escape(str(report["generated_at"]))} · {labels["version"]}: {html.escape(str(report["version"]))}<br>
{labels["openapi"]}: {html.escape(str(report["spec_file"]))} · {labels["scenario"]}: {html.escape(str(report["scenario_file"]))}</p>
<h2>{labels["summary"]}</h2>
<div class="summary"><span>{html.escape(text["pass"])}: {summary["PASS"]}</span><span>{html.escape(text["fail"])}: {summary["FAIL"]}</span>
<span>{html.escape(text["skipped"])}: {summary["SKIPPED"]}</span><span>{html.escape(text["error"])}: {summary["ERROR"]}</span></div>
<h2>{labels["checks"]}</h2><div class="wrap"><table><thead><tr>
<th>{labels["status"]}</th><th>{labels["check"]}</th><th>{labels["identity"]}</th><th>{labels["operation"]}</th>
<th>{labels["expected"]}</th><th>{labels["actual"]}</th><th>{labels["assertions"]}</th></tr></thead><tbody>{checks_body}</tbody></table></div>
<h2>{labels["findings"]}</h2><div class="wrap"><table><thead><tr>
<th>{labels["severity"]}</th><th>{labels["findings"]}</th><th>{labels["check"]}</th><th>{labels["evidence"]}</th>
<th>{labels["description"]}</th><th>{labels["impact"]}</th><th>{labels["remediation"]}</th></tr></thead><tbody>{findings_body}</tbody></table></div>
<p class="note">{labels["redaction"]}</p></body></html>
"""
