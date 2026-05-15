from common.result_schema import build_module_result


MODULE_NAME = "Auth/Session"


def run_scan(config):
    return build_module_result(MODULE_NAME, config.TARGET_URL, [])

