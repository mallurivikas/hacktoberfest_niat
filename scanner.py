import json
import os
import time
import requests

from security_check import (
    check_security_headers,
    check_cookie_security
)

from zap_scanner import (
    run_zap_scan,
    deduplicate_findings
)


def scan_url(url):
    """
    Performs basic HTTP checks on the target URL.
    """

    # Add HTTPS automatically if protocol is missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        start = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "SiteSentinel/0.1"
            }
        )

        response_time = (
            time.perf_counter() - start
        ) * 1000

        # -----------------------------
        # Extract Cookies
        # -----------------------------

        cookies = []

        for cookie in response.cookies:
            cookies.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in cookie._rest,
                "samesite": cookie._rest.get("SameSite")
            })

        # -----------------------------
        # Build HTTP Result
        # -----------------------------

        result = {
            "target": url,
            "reachable": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "https": response.url.startswith("https://"),
            "response_time_ms": round(
                response_time,
                2
            ),

            "redirect_count": len(
                response.history
            ),

            "redirect_chain": [
                {
                    "status": redirect.status_code,
                    "url": redirect.url
                }
                for redirect in response.history
            ],

            "headers": dict(
                response.headers
            ),

            "cookies": cookies
        }

        return result

    except requests.RequestException as error:

        return {
            "target": url,
            "reachable": False,
            "error": str(error)
        }


def run_security_scan(url):
    """
    Runs the complete SiteSentinel security pipeline:

    1. HTTP checks
    2. Security header checks
    3. Cookie checks
    4. OWASP ZAP Baseline scan
    5. Merge findings
    6. Deduplicate findings
    """

    # =================================
    # STEP 1 - Basic HTTP Scan
    # =================================

    print("[SiteSentinel] Running HTTP checks...")

    result = scan_url(url)

    # Website could not be reached
    if not result.get("reachable"):

        result["security_findings"] = []

        result["scan_summary"] = {
            "manual_findings": 0,
            "zap_findings": 0,
            "total_findings": 0
        }

        return result

    print(
        f"[SiteSentinel] Target reachable: "
        f"{result['final_url']}"
    )

    # =================================
    # STEP 2 - Header Checks
    # =================================

    print(
        "[SiteSentinel] Checking "
        "security headers..."
    )

    header_findings = check_security_headers(
        result["headers"]
    )

    # =================================
    # STEP 3 - Cookie Checks
    # =================================

    print(
        "[SiteSentinel] Checking "
        "cookie security..."
    )

    cookie_findings = check_cookie_security(
        result["cookies"]
    )

    # Combine manual findings
    manual_findings = (
        header_findings +
        cookie_findings
    )

    print(
        f"[SiteSentinel] Manual findings: "
        f"{len(manual_findings)}"
    )

    # =================================
    # STEP 4 - OWASP ZAP
    # =================================

    print(
        "\n[SiteSentinel] Starting "
        "OWASP ZAP Baseline scan..."
    )

    zap_findings = run_zap_scan(
        result["final_url"]
    )

    print(
        f"\n[SiteSentinel] ZAP findings: "
        f"{len(zap_findings)}"
    )

    # =================================
    # STEP 5 - Merge Findings
    # =================================

    all_findings = (
        manual_findings +
        zap_findings
    )

    # =================================
    # STEP 6 - Deduplicate
    # =================================

    security_findings = deduplicate_findings(
        all_findings
    )

    result["security_findings"] = (
        security_findings
    )

    # =================================
    # Scan Summary
    # =================================

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in security_findings:

        severity = finding.get(
            "severity",
            "info"
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    result["scan_summary"] = {
        "manual_findings": len(
            manual_findings
        ),

        "zap_findings": len(
            zap_findings
        ),

        "total_findings": len(
            security_findings
        ),

        "severity_counts": (
            severity_counts
        )
    }

    return result


def save_results(result):
    """
    Saves final SiteSentinel security
    results to JSON.
    """

    os.makedirs(
        "output",
        exist_ok=True
    )

    output_path = (
        "output/security_results.json"
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=2
        )

    return output_path


if __name__ == "__main__":

    print(
        "\n"
        "====================================\n"
        "        SiteSentinel Scanner\n"
        "====================================\n"
    )

    target = input(
        "Enter target URL: "
    ).strip()

    print(
        "\n[SiteSentinel] Scan started...\n"
    )

    # Run complete security pipeline
    result = run_security_scan(
        target
    )

    # Save final results
    output_path = save_results(
        result
    )

    # =================================
    # Final Summary
    # =================================

    print(
        "\n"
        "====================================\n"
        "            Scan Complete\n"
        "===================================="
    )

    if result.get("reachable"):

        summary = result.get(
            "scan_summary",
            {}
        )

        severity = summary.get(
            "severity_counts",
            {}
        )

        print(
            f"\nTarget: "
            f"{result['final_url']}"
        )

        print(
            f"HTTP Status: "
            f"{result['status_code']}"
        )

        print(
            f"HTTPS: "
            f"{result['https']}"
        )

        print(
            f"Response Time: "
            f"{result['response_time_ms']} ms"
        )

        print(
            "\n--- Findings ---"
        )

        print(
            f"Manual Scanner: "
            f"{summary.get('manual_findings', 0)}"
        )

        print(
            f"OWASP ZAP: "
            f"{summary.get('zap_findings', 0)}"
        )

        print(
            f"Final Findings: "
            f"{summary.get('total_findings', 0)}"
        )

        print(
            "\n--- Severity ---"
        )

        print(
            f"High: "
            f"{severity.get('high', 0)}"
        )

        print(
            f"Medium: "
            f"{severity.get('medium', 0)}"
        )

        print(
            f"Low: "
            f"{severity.get('low', 0)}"
        )

        print(
            f"Info: "
            f"{severity.get('info', 0)}"
        )

    else:

        print(
            "\nTarget could not be reached."
        )

        print(
            f"Error: "
            f"{result.get('error')}"
        )

    print(
        f"\nFinal results saved to:\n"
        f"{output_path}"
    )

    print(
        "\n====================================\n"
    )