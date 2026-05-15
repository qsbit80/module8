from __future__ import annotations

from datetime import datetime, timezone
from html import unescape
from io import BytesIO
from typing import Iterable
from urllib.parse import urljoin
from uuid import uuid4

import requests


SUSPICIOUS_KEYWORDS = ("eval", "system", "exec", "cmd", "shell", "backdoor")
SHELL_MARKERS = ("SIMULATED_WEBSHELL_EXECUTION", "real_os_execution=false", "uid=33(www-data)")


class WebshellScanner:
    def __init__(self, target, username="user1", password="user1pass", session=None):
        self.target = target.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.session = session or requests.Session()
        self.probe_filename = f"webshell_probe_{uuid4().hex}.php"

    def scan(self):
        login_response = self._login()
        upload_get = self._request("GET", "upload")

        findings = []
        if upload_get is None or upload_get.status_code == 404:
            findings.extend(self._upload_not_available_findings())
        else:
            upload_post = self._upload_probe()
            upload_listing = self._request("GET", "uploads/")
            shell_probe = self._request("GET", "uploads/shell_demo.php?cmd=id")

            findings.append(self._risky_extension_finding(upload_post))
            findings.append(self._listing_finding(upload_listing))
            findings.append(self._webshell_marker_finding(shell_probe))
            findings.append(self._suspicious_keyword_finding([upload_get, upload_listing, shell_probe]))

        return {
            "scan_id": f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "target": self.target.rstrip("/"),
            "module": "Upload/Webshell",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": {"total": 0, "취약": 0, "양호": 0, "N/A": 0},
            "findings": findings,
            "login": {
                "status_code": getattr(login_response, "status_code", None),
                "authenticated": getattr(login_response, "status_code", None) in {200, 302},
            },
        }

    def _login(self):
        return self._request(
            "POST",
            "login",
            data={"username": self.username, "password": self.password},
            allow_redirects=False,
        )

    def _upload_probe(self):
        payload = b"demo marker only: eval system exec cmd shell"
        return self._request(
            "POST",
            "upload",
            files={"file": (self.probe_filename, BytesIO(payload), "application/x-php")},
            allow_redirects=False,
        )

    def _request(self, method, path, **kwargs):
        url = urljoin(self.target, path)
        try:
            return self.session.request(method, url, timeout=10, **kwargs)
        except requests.RequestException as exc:
            return FailedResponse(url=url, method=method, error=str(exc))

    def _upload_not_available_findings(self):
        request = {"method": "GET", "url": "/upload"}
        response = {"status_code": 404, "evidence": "업로드 기능을 찾을 수 없습니다."}
        return [
            finding(
                "UP-001",
                "위험 확장자 업로드 허용 여부",
                "N/A",
                "High",
                request,
                response,
                "파일 업로드 기능이 없어 위험 확장자 업로드 진단을 수행하지 않았습니다.",
                "업로드 기능이 존재하지 않아 해당 없음으로 판단했습니다.",
                "파일 업로드 기능을 추가할 경우 허용 목록 기반 확장자 검증을 적용합니다.",
            ),
            finding(
                "EXP-001",
                "업로드 디렉터리 목록 노출",
                "N/A",
                "Medium",
                request,
                response,
                "업로드 기능이 없어 업로드 목록 노출 진단을 수행하지 않았습니다.",
                "업로드 경로가 확인되지 않아 해당 없음으로 판단했습니다.",
                "업로드 경로를 웹 루트 밖에 두고 디렉터리 인덱싱을 비활성화합니다.",
            ),
            finding(
                "UP-002",
                "웹쉘 시뮬레이션 응답 노출",
                "N/A",
                "High",
                request,
                response,
                "업로드 기능이 없어 웹쉘 시뮬레이션 URL 진단을 수행하지 않았습니다.",
                "업로드 경로가 확인되지 않아 해당 없음으로 판단했습니다.",
                "업로드 파일은 실행되지 않도록 저장소와 웹 서버 실행 권한을 분리합니다.",
            ),
            finding(
                "UP-004",
                "업로드 응답 내 의심 패턴 노출",
                "N/A",
                "Medium",
                request,
                response,
                "업로드 기능이 없어 의심 패턴 진단을 수행하지 않았습니다.",
                "업로드 응답을 수집할 수 없어 해당 없음으로 판단했습니다.",
                "업로드 파일명과 본문을 검사하고 위험 문자열이 노출되지 않도록 관리합니다.",
            ),
        ]

    def _risky_extension_finding(self, response):
        status_code = getattr(response, "status_code", None)
        vulnerable = status_code in {200, 201, 302, 303}
        good = status_code in {400, 403, 415}
        status = "취약" if vulnerable else "양호" if good else "N/A"
        evidence = (
            f"{self.probe_filename} 업로드 요청에 HTTP {status_code} 응답이 반환되었습니다."
            if status_code else "업로드 요청 응답을 수집하지 못했습니다."
        )
        return finding(
            "UP-001",
            "위험 확장자 업로드 허용",
            status,
            "High",
            {"method": "POST", "url": "/upload", "filename": self.probe_filename},
            response_info(response, evidence),
            evidence,
            "위험 확장자 업로드가 성공 응답을 반환하면 웹쉘 업로드 위험이 있습니다."
            if status == "취약"
            else "서버가 위험 확장자 업로드를 차단했습니다." if status == "양호" else "업로드 응답을 판정할 수 없습니다.",
            "허용 목록 기반 확장자 검증과 파일 시그니처 검사를 적용합니다.",
        )

    def _listing_finding(self, response):
        body = response_text(response)
        status_code = getattr(response, "status_code", None)
        exposes_listing = status_code == 200 and ("shell_demo.php" in body or self.probe_filename in body)
        blocked = status_code in {401, 403, 404}
        status = "취약" if exposes_listing else "양호" if blocked else "N/A"
        evidence = (
            "업로드 목록에서 shell_demo.php 또는 업로드한 probe 파일명이 확인되었습니다."
            if exposes_listing
            else f"/uploads/ 접근 시 HTTP {status_code} 응답이 반환되었습니다."
        )
        return finding(
            "EXP-001",
            "업로드 디렉터리 목록 노출",
            status,
            "Medium",
            {"method": "GET", "url": "/uploads/"},
            response_info(response, evidence),
            evidence,
            "업로드 디렉터리 파일 목록이 웹 응답에 노출되었습니다."
            if status == "취약"
            else "업로드 디렉터리 직접 접근이 차단되었습니다." if status == "양호" else "업로드 목록 응답을 판정할 수 없습니다.",
            "디렉터리 인덱싱을 비활성화하고 업로드 저장소를 웹 루트 밖으로 분리합니다.",
        )

    def _webshell_marker_finding(self, response):
        body = response_text(response)
        status_code = getattr(response, "status_code", None)
        markers = [marker for marker in SHELL_MARKERS if marker in body]
        vulnerable = status_code == 200 and len(markers) >= 2
        blocked = status_code in {401, 403, 404}
        status = "취약" if vulnerable else "양호" if blocked else "N/A"
        evidence = (
            f"웹쉘 시뮬레이션 마커 확인: {', '.join(markers)}"
            if markers
            else f"웹쉘 시뮬레이션 URL 접근 시 HTTP {status_code} 응답이 반환되었습니다."
        )
        return finding(
            "UP-002",
            "웹쉘 시뮬레이션 응답 노출",
            status,
            "High",
            {"method": "GET", "url": "/uploads/shell_demo.php?cmd=id"},
            response_info(response, evidence),
            evidence,
            "업로드 경로에서 웹쉘 실행을 모사하는 고정 응답 마커가 노출되었습니다."
            if status == "취약"
            else "웹쉘 시뮬레이션 URL 직접 접근이 차단되었습니다." if status == "양호" else "웹쉘 시뮬레이션 응답을 판정할 수 없습니다.",
            "업로드 디렉터리의 스크립트 실행을 금지하고 업로드 파일 직접 접근을 제한합니다.",
        )

    def _suspicious_keyword_finding(self, responses: Iterable):
        detected = set()
        for response in responses:
            body = response_text(response).lower()
            detected.update(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in body)

        status = "취약" if detected else "양호"
        evidence = (
            "응답 본문에서 의심 키워드 확인: " + ", ".join(sorted(detected))
            if detected
            else "업로드 관련 응답 본문에서 의심 키워드가 확인되지 않았습니다."
        )
        return finding(
            "UP-004",
            "업로드 응답 내 의심 패턴 노출",
            status,
            "Medium",
            {"method": "GET", "url": "/upload, /uploads/, /uploads/shell_demo.php?cmd=id"},
            {"status_code": None, "evidence": evidence},
            evidence,
            "업로드 관련 응답에 웹쉘 탐지 키워드가 노출되었습니다."
            if status == "취약"
            else "수집된 응답에서 웹쉘 의심 키워드를 찾지 못했습니다.",
            "업로드된 파일을 악성 패턴 기준으로 검사하고 의심 파일은 격리합니다.",
        )


class FailedResponse:
    def __init__(self, url, method, error):
        self.url = url
        self.method = method
        self.error = error
        self.status_code = None
        self.text = ""


def finding(finding_id, title, status, severity, request, response, evidence_summary, reason, recommendation):
    return {
        "finding_id": finding_id,
        "title": title,
        "status": status,
        "severity": severity,
        "request": request,
        "response": response,
        "evidence_summary": evidence_summary,
        "reason": reason,
        "recommendation": recommendation,
    }


def response_info(response, evidence):
    return {
        "status_code": getattr(response, "status_code", None),
        "evidence": evidence,
    }


def response_text(response):
    if response is None:
        return ""
    return unescape(getattr(response, "text", "") or "")
