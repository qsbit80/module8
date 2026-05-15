import importlib

import config
from common.result_schema import (
    STATUS_GOOD,
    STATUS_NA,
    STATUS_VULNERABLE,
    build_combined_result,
    write_json,
)


MODULE_ENTRYPOINTS = {
    "bac_scanner": "scanner.bac_scanner.scanner",
    "exposure_scanner": "scanner.exposure_scanner.scanner",
    "auth_session_scanner": "scanner.auth_session_scanner.scanner",
    "webshell_scanner": "scanner.webshell_scanner.main",
}


def run_pipeline():
    module_results = []
    for module_key in config.ENABLED_MODULES:
        module_path = MODULE_ENTRYPOINTS[module_key]
        module = importlib.import_module(module_path)
        module_results.append(module.run_scan(config))

    combined = build_combined_result(config.TARGET_URL, module_results)
    output_path = write_json(combined, config.OUTPUT_PATH)
    print_summary(combined, output_path)
    return combined


def print_summary(result, output_path):
    summary = result["summary"]
    print("Module8 vulnerability scan complete")
    print(f"- Target: {result['target']}")
    print(f"- Total checks: {summary['total']}")
    print(
        f"- {STATUS_VULNERABLE}: {summary.get(STATUS_VULNERABLE, 0)}, "
        f"{STATUS_GOOD}: {summary.get(STATUS_GOOD, 0)}, "
        f"{STATUS_NA}: {summary.get(STATUS_NA, 0)}"
    )
    print(f"- JSON saved: {output_path}")


if __name__ == "__main__":
    run_pipeline()
