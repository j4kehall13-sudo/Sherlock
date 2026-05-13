import hashlib
import json
import re
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "ru",
    "cn",
    "tk",
    "gq",
    "work",
    "country",
    "stream",
    "download"
}


SUSPICIOUS_URL_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "billing",
    "wallet",
    "invoice",
    "download",
    "free",
    "gift",
    "prize",
    "reset",
    "confirm",
    "auth",
    "signin",
    "bank",
    "paypal",
    "microsoft",
    "office365",
    "onedrive"
]


def ps_quote(value: str) -> str:
    """
    Safely quote a string for use inside a single-quoted PowerShell argument.
    """
    return "'" + value.replace("'", "''") + "'"


def run_powershell(command: str, timeout: int | None = None) -> str:
    """
    Runs a predefined PowerShell command.

    This must not be used for arbitrary AI-generated commands.
    Keep all commands controlled and hard-coded in this file.
    """
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        return (
            "PowerShell command failed.\n\n"
            f"Return code: {result.returncode}\n\n"
            f"Error:\n{stderr if stderr else 'No error text returned.'}"
        )

    return stdout if stdout else "Command completed. No output was returned."


def format_json_output(raw_output: str) -> str:
    """
    Attempts to pretty-format PowerShell JSON output.
    Falls back to raw output if parsing fails.
    """
    if not raw_output or raw_output.strip() in ["null", ""]:
        return "No data returned."

    try:
        parsed = json.loads(raw_output)
        return json.dumps(parsed, indent=2)
    except Exception:
        return raw_output


def get_defender_status() -> str:
    command = "Get-MpComputerStatus | ConvertTo-Json -Depth 4"
    output = run_powershell(command, timeout=30)

    try:
        data = json.loads(output)

        useful_fields = {
            "AMServiceEnabled": data.get("AMServiceEnabled"),
            "AntivirusEnabled": data.get("AntivirusEnabled"),
            "RealTimeProtectionEnabled": data.get("RealTimeProtectionEnabled"),
            "BehaviorMonitorEnabled": data.get("BehaviorMonitorEnabled"),
            "IoavProtectionEnabled": data.get("IoavProtectionEnabled"),
            "NISEnabled": data.get("NISEnabled"),
            "AntispywareSignatureLastUpdated": data.get("AntispywareSignatureLastUpdated"),
            "AntivirusSignatureLastUpdated": data.get("AntivirusSignatureLastUpdated"),
            "NISSignatureLastUpdated": data.get("NISSignatureLastUpdated"),
            "FullScanAge": data.get("FullScanAge"),
            "QuickScanAge": data.get("QuickScanAge"),
            "FullScanEndTime": data.get("FullScanEndTime"),
            "QuickScanEndTime": data.get("QuickScanEndTime"),
        }

        report = "Microsoft Defender Status\n"
        report += "=========================\n\n"

        for key, value in useful_fields.items():
            report += f"{key}: {value}\n"

        report += "\nInterpretation:\n"

        if useful_fields["AntivirusEnabled"] is True:
            report += "- Antivirus appears to be enabled.\n"
        else:
            report += "- Antivirus does not appear to be enabled. Check Windows Security immediately.\n"

        if useful_fields["RealTimeProtectionEnabled"] is True:
            report += "- Real-time protection appears to be enabled.\n"
        else:
            report += "- Real-time protection appears disabled or unavailable. This is a significant issue.\n"

        if useful_fields["BehaviorMonitorEnabled"] is True:
            report += "- Behaviour monitoring appears to be enabled.\n"
        else:
            report += "- Behaviour monitoring appears disabled or unavailable.\n"

        return report

    except Exception:
        return (
            "Microsoft Defender Status\n"
            "=========================\n\n"
            "Could not parse Defender status cleanly. Raw output below:\n\n"
            + output
        )


def update_defender_signatures() -> str:
    command = "Update-MpSignature"
    output = run_powershell(command, timeout=180)

    return (
        "Microsoft Defender Signature Update\n"
        "===================================\n\n"
        f"{output}\n\n"
        "If no detailed output was returned, Windows may still have accepted the update command."
    )


def run_quick_scan() -> str:
    command = "Start-MpScan -ScanType QuickScan"
    output = run_powershell(command)

    return (
        "Microsoft Defender Quick Scan\n"
        "============================\n\n"
        f"{output}\n\n"
        "After completion, use the Threat History button to review detections."
    )


def run_full_scan() -> str:
    command = "Start-MpScan -ScanType FullScan"
    output = run_powershell(command)

    return (
        "Microsoft Defender Full Scan\n"
        "===========================\n\n"
        f"{output}\n\n"
        "Full scans can take a long time. Use Threat History afterwards to check detections."
    )


def scan_path_with_defender(scan_path: str) -> str:
    path = Path(scan_path)

    if not path.exists():
        return (
            "Defender Custom Scan\n"
            "====================\n\n"
            f"Path does not exist:\n{scan_path}"
        )

    quoted_path = ps_quote(str(path))
    command = f"Start-MpScan -ScanType CustomScan -ScanPath {quoted_path}"
    output = run_powershell(command)

    target_type = "folder" if path.is_dir() else "file"

    return (
        "Microsoft Defender Custom Scan\n"
        "==============================\n\n"
        f"Target type: {target_type}\n"
        f"Target path: {path}\n\n"
        f"{output}\n\n"
        "After completion, use the Threat History button to review detections."
    )


def get_threat_history() -> str:
    command = (
        "$detections = Get-MpThreatDetection; "
        "if ($null -eq $detections) { "
        "  'NO_DETECTIONS' "
        "} else { "
        "  $detections | Select-Object ThreatID,ThreatStatusID,"
        "InitialDetectionTime,LastThreatStatusChangeTime,"
        "Resources,ThreatStatusErrorCode | ConvertTo-Json -Depth 6 "
        "}"
    )

    output = run_powershell(command, timeout=60)

    if "NO_DETECTIONS" in output:
        return (
            "Microsoft Defender Threat History\n"
            "=================================\n\n"
            "No threat detections were returned by Microsoft Defender."
        )

    return (
        "Microsoft Defender Threat History\n"
        "=================================\n\n"
        + format_json_output(output)
    )


def hash_file(file_path: str) -> str:
    path = Path(file_path)

    if not path.exists():
        return f"File does not exist:\n{file_path}"

    if not path.is_file():
        return f"Selected path is not a file:\n{file_path}"

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    try:
        with open(path, "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break

                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

    except Exception as error:
        return f"Could not hash file:\n{error}"

    return (
        "File Hash Report\n"
        "================\n\n"
        f"File: {path}\n"
        f"Size: {path.stat().st_size} bytes\n\n"
        f"SHA256:\n{sha256.hexdigest()}\n\n"
        f"SHA1:\n{sha1.hexdigest()}\n\n"
        f"MD5:\n{md5.hexdigest()}\n\n"
        "Use SHA256 when checking the file against trusted malware-analysis services."
    )


def normalise_url(url: str) -> str:
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def is_ip_address(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return False


def check_url_basic(url: str) -> str:
    """
    Static local URL risk check.

    This does not visit the URL.
    It does not replace Malwarebytes, VirusTotal, Google Safe Browsing,
    Microsoft Defender SmartScreen, or a real browser isolation workflow.
    """
    original_url = url
    url = normalise_url(url)
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    warnings = []

    if not hostname:
        warnings.append("Could not identify a valid hostname.")

    if parsed.scheme != "https":
        warnings.append("URL does not use HTTPS.")

    if hostname and is_ip_address(hostname):
        warnings.append("URL uses a raw IP address instead of a normal domain.")

    if "@" in url:
        warnings.append("URL contains '@', which can be used to hide the true destination.")

    if len(url) > 120:
        warnings.append("URL is unusually long.")

    if hostname.count("-") >= 3:
        warnings.append("Domain contains several hyphens, which is sometimes used in phishing domains.")

    if hostname.count(".") >= 4:
        warnings.append("Domain has several subdomain levels. This can be legitimate, but is common in phishing infrastructure.")

    tld = hostname.split(".")[-1].lower() if "." in hostname else ""

    if tld in SUSPICIOUS_TLDS:
        warnings.append(f"Domain uses a commonly abused or higher-risk TLD: .{tld}")

    found_words = [
        word for word in SUSPICIOUS_URL_WORDS
        if word in url.lower()
    ]

    if found_words:
        warnings.append(
            "URL contains terms commonly seen in phishing or lure links: "
            + ", ".join(sorted(set(found_words)))
        )

    if re.search(r"%[0-9a-fA-F]{2}", url):
        warnings.append("URL contains encoded characters, which can be used to obscure the real destination.")

    if re.search(r"(.)\1{4,}", hostname):
        warnings.append("Hostname contains repeated characters, which can indicate suspicious domain generation.")

    if query and len(query) > 80:
        warnings.append("URL has a long query string. This can be used for tracking, redirects, or obfuscation.")

    risk_score = len(warnings)

    if risk_score == 0:
        risk_level = "LOW based on static checks only"
    elif risk_score <= 2:
        risk_level = "MEDIUM based on static checks"
    else:
        risk_level = "HIGH based on static checks"

    report = (
        "Static URL Check\n"
        "================\n\n"
        f"Original input: {original_url}\n"
        f"Normalised URL: {url}\n"
        f"Scheme: {parsed.scheme}\n"
        f"Hostname: {hostname}\n"
        f"Path: {path if path else '/'}\n"
        f"Query present: {'Yes' if query else 'No'}\n\n"
        f"Risk level: {risk_level}\n\n"
    )

    if warnings:
        report += "Potential red flags:\n"
        for warning in warnings:
            report += f"- {warning}\n"
    else:
        report += "No obvious local red flags were found.\n"

    report += (
        "\nImportant limitation:\n"
        "This check does not open the link and does not use a live reputation database. "
        "For stronger results, check the URL with a trusted reputation service or open it only in a controlled/sandboxed environment."
    )

    return report


def get_security_summary() -> str:
    status = get_defender_status()
    threats = get_threat_history()

    return (
        "Sherlock Local Security Summary\n"
        "===============================\n\n"
        "1. Defender Status\n"
        "------------------\n"
        f"{status}\n\n"
        "2. Threat History\n"
        "-----------------\n"
        f"{threats}\n\n"
        "Suggested next steps:\n"
        "- If signatures are old, run Update Signatures.\n"
        "- If QuickScanAge or FullScanAge is high, run a scan.\n"
        "- If real-time protection is disabled, open Windows Security and investigate.\n"
        "- If detections appear in threat history, review the affected file paths and remediation status."
    )