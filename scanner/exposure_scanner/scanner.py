from common.result_schema import build_module_result


MODULE_NAME = "Directory/File Exposure"


def run_scan(config):
    return build_module_result(MODULE_NAME, config.TARGET_URL, [])

