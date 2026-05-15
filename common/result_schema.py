import json
from datetime import datetime, timezone
from pathlib import Path


STATUS_VULNERABLE = "\ucde8\uc57d"
STATUS_GOOD = "\uc591\ud638"
STATUS_NA = "N/A"


def empty_summary():
    return {
        "total": 0,
        STATUS_VULNERABLE: 0,
        STATUS_GOOD: 0,
        STATUS_NA: 0,
    }


def summarize_findings(findings):
    summary = empty_summary()
    summary["total"] = len(findings)
    for finding in findings:
        status = finding.get("status", STATUS_NA)
        summary.setdefault(status, 0)
        summary[status] += 1
    return summary


def build_module_result(module_name, target, findings):
    return {
        "module": module_name,
        "target": target,
        "summary": summarize_findings(findings),
        "findings": findings,
    }


def build_combined_result(target, module_results):
    findings = []
    for result in module_results:
        findings.extend(result.get("findings", []))

    return {
        "scan_id": datetime.now(timezone.utc).strftime("SCAN-%Y%m%d%H%M%S"),
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize_findings(findings),
        "modules": module_results,
        "findings": findings,
    }


def write_json(result, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return path

