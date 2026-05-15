from common.result_schema import build_module_result


MODULE_NAME = "Broken Access Control"


def run_scan(config):
    return build_module_result(MODULE_NAME, config.TARGET_URL, [])

