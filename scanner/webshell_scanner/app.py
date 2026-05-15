from main import run_scan_to_file


# Put your AWS test site URL here.
# Example: TARGET_URL = "http://13.125.10.20"
# Example: TARGET_URL = "https://your-domain.com"
TARGET_URL = "http://43.202.42.77"

USERNAME = "user1"
PASSWORD = "user1pass"
OUTPUT_PATH = "data/scan_results/webshell_result.json"


def main():
    if "YOUR_AWS_PUBLIC_IP_OR_DOMAIN" in TARGET_URL:
        raise SystemExit(
            "Set TARGET_URL in webshell_scanner/app.py first. "
            'Example: TARGET_URL = "http://13.125.10.20"'
        )

    run_scan_to_file(
        target=TARGET_URL,
        username=USERNAME,
        password=PASSWORD,
        output_path=OUTPUT_PATH,
    )


if __name__ == "__main__":
    main()
