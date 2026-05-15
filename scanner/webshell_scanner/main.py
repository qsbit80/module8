import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.result_schema import (
    STATUS_GOOD,
    STATUS_NA,
    STATUS_VULNERABLE,
    build_module_result,
)

try:
    from scanner.webshell_scanner.modules.webshell import WebshellScanner
except ModuleNotFoundError:
    from modules.webshell import WebshellScanner


DEFAULT_OUTPUT = Path("data/scan_results/webshell_result.json")


def build_parser():
    parser = argparse.ArgumentParser(description="Upload/Webshell vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target base URL, for example http://127.0.0.1:5000")
    parser.add_argument("--module", default="webshell", choices=["webshell"], help="Scanner module to run")
    parser.add_argument("--username", default="user1", help="Login username")
    parser.add_argument("--password", default="user1pass", help="Login password")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="JSON result output path")
    return parser


def summarize(findings):
    summary = {STATUS_VULNERABLE: 0, STATUS_GOOD: 0, STATUS_NA: 0, "total": len(findings)}
    for finding in findings:
        summary.setdefault(finding["status"], 0)
        summary[finding["status"]] += 1
    return summary


def write_result(result, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def print_summary(result, output_path):
    summary = result["summary"]
    high_findings = [
        finding for finding in result["findings"]
        if finding["severity"] == "High" and finding["status"] == STATUS_VULNERABLE
    ]
    print("Upload/Webshell scan complete")
    print(f"- Target: {result['target']}")
    print(f"- Total checks: {summary['total']}")
    print(
        f"- {STATUS_VULNERABLE}: {summary.get(STATUS_VULNERABLE, 0)}, "
        f"{STATUS_GOOD}: {summary.get(STATUS_GOOD, 0)}, "
        f"{STATUS_NA}: {summary.get(STATUS_NA, 0)}"
    )
    if high_findings:
        print("- High findings:")
        for finding in high_findings:
            print(f"  - {finding['finding_id']}: {finding['title']}")
    else:
        print("- High findings: none")
    print(f"- JSON saved: {output_path}")


def run_scan_to_file(target, username="user1", password="user1pass", output_path=DEFAULT_OUTPUT):
    scanner = WebshellScanner(target, username, password)
    result = scanner.scan()
    result["summary"] = summarize(result["findings"])
    saved_path = write_result(result, output_path)
    print_summary(result, saved_path)
    return result, saved_path


def run_scan(config):
    scanner = WebshellScanner(config.TARGET_URL, config.USERNAME, config.PASSWORD)
    result = scanner.scan()
    return build_module_result(result["module"], result["target"], result["findings"])


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    run_scan_to_file(args.target, args.username, args.password, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
