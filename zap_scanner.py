import json
import os
import subprocess


def run_zap_scan(url):
    """
    Runs OWASP ZAP Baseline passive scan using Docker.
    """

    os.makedirs("output", exist_ok=True)

    output_directory = os.path.abspath("output")

    zap_file = os.path.join(
        output_directory,
        "zap_results.json"
    )

    # Clean up any previous run's report so stale data is never reused
    if os.path.exists(zap_file):
        try:
            os.remove(zap_file)
        except Exception:
            pass

    import sys
    import shutil

    docker_bin = shutil.which("docker")
    if not docker_bin:
        print("[ZAP] Docker is not installed or not in PATH — skipping ZAP scan.")
        return []

    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{output_directory}:/zap/wrk/:rw",
        "-t",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t",
        url,
        "-J",
        "zap_results.json",
        "-I"
    ]

    # Prepend sudo on Linux/macOS if sudo is available and not running as root
    if sys.platform != "win32" and shutil.which("sudo") and os.geteuid() != 0:
        command = ["sudo"] + command

    print("\n[ZAP] Starting passive security scan...")
    print("[ZAP] This may take a minute...\n")

    try:
        proc = subprocess.run(
            command,
            check=False,
            timeout=300
        )
    except Exception as error:
        print(f"[ZAP] Failed to run: {error}")
        return []

    if not os.path.exists(zap_file):
        print("[ZAP] No JSON report was generated.")
        return []

    return parse_zap_results(zap_file)


def parse_zap_results(file_path):
    """
    Converts ZAP's JSON format into SiteSentinel findings.
    """

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        print(f"[ZAP] Could not read report: {error}")
        return []

    findings = []

    for site in data.get("site", []):

        alerts = site.get("alerts", [])

        for alert in alerts:

            severity = normalize_zap_severity(
                alert.get("riskdesc", "")
            )

            instances = alert.get("instances", [])

            affected_urls = []

            for instance in instances[:5]:
                uri = instance.get("uri")

                if uri and uri not in affected_urls:
                    affected_urls.append(uri)

            evidence_parts = []

            description = clean_text(
                alert.get("desc", "")
            )

            solution = clean_text(
                alert.get("solution", "")
            )

            if description:
                evidence_parts.append(description)

            if affected_urls:
                evidence_parts.append(
                    "Affected URLs: "
                    + ", ".join(affected_urls)
                )

            finding = {
                "title": alert.get(
                    "name",
                    "Unknown ZAP Finding"
                ),
                "severity": severity,
                "evidence": " ".join(evidence_parts),
                "source": "OWASP ZAP",
                "alert_id": alert.get("pluginid"),
                "confidence": alert.get("confidence"),
                "affected_count": len(instances),
                "affected_urls": affected_urls,
                "solution": solution
            }

            findings.append(finding)

    return findings


def normalize_zap_severity(risk_description):
    """
    Converts ZAP severity into our common format.
    """

    risk = risk_description.lower()

    if "high" in risk:
        return "high"

    if "medium" in risk:
        return "medium"

    if "low" in risk:
        return "low"

    return "info"


def clean_text(text):
    """
    Removes basic HTML tags commonly found in ZAP descriptions.
    """

    if not text:
        return ""

    replacements = {
        "<p>": " ",
        "</p>": " ",
        "<br>": " ",
        "<br/>": " ",
        "<br />": " "
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return " ".join(text.split())


def deduplicate_findings(findings):
    """
    Removes duplicate findings produced by manual checks and ZAP.
    """

    duplicate_groups = {
        "content security policy missing": "csp",
        "content security policy (csp) header not set": "csp",

        "mime sniffing protection missing": "mime",
        "x-content-type-options header missing": "mime",

        "clickjacking protection missing": "clickjacking",
        "missing anti-clickjacking header": "clickjacking",

        "hsts missing": "hsts",
        "strict-transport-security header": "hsts",

        "permissions policy missing": "permissions",
        "permissions policy header not set": "permissions",

        "cookie missing secure flag": "cookie-secure",
        "cookie without secure flag": "cookie-secure",

        "cookie missing httponly flag": "cookie-httponly",
        "cookie no httponly flag": "cookie-httponly",

        "cookie missing samesite attribute": "cookie-samesite",
        "cookie without samesite attribute": "cookie-samesite"
    }

    seen = set()
    unique_findings = []

    for finding in findings:

        title = finding.get(
            "title",
            ""
        ).strip().lower()

        key = duplicate_groups.get(
            title,
            title
        )

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    return unique_findings