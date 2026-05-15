from pathlib import Path


TARGET_URL = "http://43.202.42.77"
USERNAME = "user1"
PASSWORD = "user1pass"

OUTPUT_PATH = Path("data/scan_results/combined_result.json")

ENABLED_MODULES = [
    "bac_scanner",
    "exposure_scanner",
    "auth_session_scanner",
    "webshell_scanner",
]

