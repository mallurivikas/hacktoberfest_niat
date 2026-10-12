"""
scanner.py — Unified Web Security & Performance Auditor

Integrates:
  1. Collaborator's Security Checks (Headers, Cookies, SSL/TLS, OWASP ZAP Baseline)
  2. HTTP & Performance Metrics (Response Time, Status, TTFB)
  3. Google PageSpeed Insights & Lighthouse (LCP, FCP, Speed Index, TBT, CLS, Page Weight)
  4. k6 Load & Stress Testing (p50/p95 Latency, RPS, Error Rate)
  5. AI Intelligence (Gemma 27B / Gemini) for 0-100 Security & Performance Scoring
     and actionable improvement roadmaps.
"""

import datetime
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

import perf_basic
import perf_psi
import load_k6
import ai_gemini


# ── HTTP Probe (from Collaborator) ─────────────────────────────────────────────

def scan_url(url: str) -> dict:
    """
    Performs basic HTTP checks on the target URL.
    Extracts headers, cookies, redirects, and reachability.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        start = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "SiteSentinel/1.0 (Auditor; +https://github.com/)"
            }
        )

        response_time = (time.perf_counter() - start) * 1000

        # Extract Cookies
        cookies = []
        for cookie in response.cookies:
            cookies.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in getattr(cookie, "_rest", {}),
                "samesite": getattr(cookie, "_rest", {}).get("SameSite")
            })

        return {
            "target": url,
            "reachable": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "https": response.url.startswith("https://"),
            "response_time_ms": round(response_time, 2),
            "redirect_count": len(response.history),
            "redirect_chain": [
                {"status": r.status_code, "url": r.url}
                for r in response.history
            ],
            "headers": dict(response.headers),
            "cookies": cookies
        }

    except requests.RequestException as error:
        return {
            "target": url,
            "reachable": False,
            "error": str(error),
            "final_url": url,
            "https": url.startswith("https://"),
            "headers": {},
            "cookies": [],
            "redirect_count": 0,
            "redirect_chain": []
        }


# ── Security Scan Pipeline ─────────────────────────────────────────────────────

def run_security_scan(url: str, probe_result: dict = None) -> dict:
    """
    Runs the complete SiteSentinel security pipeline:
    1. HTTP checks & Headers
    2. Cookie security
    3. OWASP ZAP Baseline scan (via Docker if available)
    4. Deduplicate and summarize findings
    """
    if probe_result is None:
        probe_result = scan_url(url)

    if not probe_result.get("reachable"):
        probe_result["security_findings"] = []
        probe_result["scan_summary"] = {
            "manual_findings": 0,
            "zap_findings": 0,
            "total_findings": 0,
            "severity_counts": {"high": 0, "medium": 0, "low": 0, "info": 0}
        }
        return probe_result

    # 1. Header checks
    header_findings = check_security_headers(probe_result.get("headers", {}))

    # 2. Cookie checks
    cookie_findings = check_cookie_security(probe_result.get("cookies", []))

    manual_findings = header_findings + cookie_findings

    # 3. OWASP ZAP Baseline scan
    zap_findings = []
    try:
        zap_findings = run_zap_scan(probe_result.get("final_url", url))
    except Exception as exc:
        print(f"[SiteSentinel] ZAP scan skipped/failed: {exc}")

    # 4. Merge and deduplicate
    all_findings = manual_findings + (zap_findings or [])
    security_findings = deduplicate_findings(all_findings)

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for f in security_findings:
        sev = (f.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    probe_result["security_findings"] = security_findings
    probe_result["scan_summary"] = {
        "manual_findings": len(manual_findings),
        "zap_findings": len(zap_findings or []),
        "total_findings": len(security_findings),
        "severity_counts": severity_counts
    }

    return probe_result


# ── Unified Scan (Performance + Security + AI) ────────────────────────────────

def scan(url: str) -> dict:
    """
    Runs the entire unified audit:
      - Security checks & ZAP
      - HTTP performance & PSI/Lighthouse
      - k6 load test
      - Gemma 27B AI scoring & improvement analysis
    """
    wall_start = time.perf_counter()
    errors = []

    # Normalize protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # 1. Initial HTTP probe & Security Scan
    print(f"[Auditor] Starting unified scan for {url}...")
    security_res = run_security_scan(url)
    if security_res.get("error"):
        errors.append({"source": "security_probe", "message": security_res.get("error")})

    # 2. Performance: Basic HTTP
    print("[Auditor] Measuring HTTP response time and TTFB...")
    perf = perf_basic.measure(url)
    if perf.get("error"):
        errors.append({"source": "perf_basic", "message": perf.pop("error")})
    else:
        perf.pop("error", None)

    # 3. Performance: Google PageSpeed Insights / Lighthouse
    print("[Auditor] Fetching Lighthouse & Core Web Vitals...")
    psi = perf_psi.measure(url)
    if psi.get("error"):
        errors.append({"source": "perf_psi", "message": psi.pop("error")})
    else:
        psi.pop("error", None)
    perf.update({k: v for k, v in psi.items() if v is not None})

    # 4. Load & Stress Test (k6)
    print("[Auditor] Running load test...")
    load_test = load_k6.run(url)
    if load_test.get("error"):
        errors.append({"source": "load_k6", "message": load_test.pop("error")})
    else:
        load_test.pop("error", None)

    # 5. AI Synthesis & Scoring (Gemma 27B / Gemini)
    print("[Auditor] Running AI audit synthesis and scoring...")
    ai_analysis = ai_gemini.summarise(
        target=url,
        performance=perf,
        load_test=load_test,
        security_findings=security_res.get("security_findings", [])
    )
    if ai_analysis.get("error"):
        errors.append({"source": "ai_gemini", "message": ai_analysis.get("error")})

    wall_end = time.perf_counter()
    duration_ms = round((wall_end - wall_start) * 1000, 1)

    # Unified payload
    final_payload = {
        "target": url,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "scan_duration_ms": duration_ms,
        "scores": {
            "security_score": ai_analysis.get("security_score", 80),
            "performance_score": ai_analysis.get("performance_score", 75),
            "overall_score": ai_analysis.get("overall_score", 78),
            "overall_health": ai_analysis.get("overall_health", "warning")
        },
        "security": security_res,
        "performance": perf,
        "load_test": load_test,
        "ai_analysis": ai_analysis,
        # Backward compatibility aliases
        "ai_summary": {
            "overall_health": ai_analysis.get("overall_health"),
            "summary": ai_analysis.get("summary"),
            "top_issues": ai_analysis.get("top_issues", []),
            "generated_by": ai_analysis.get("generated_by")
        },
        "errors": errors
    }

    # Save to output files
    save_results(final_payload)

    print(f"[Auditor] Scan complete in {duration_ms/1000:.1f}s.")
    return final_payload


def save_results(result: dict) -> str:
    """
    Saves final audit results to output directory for caching and export.
    """
    os.makedirs("output", exist_ok=True)

    output_path = "output/scan_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # Also save collaborator's security_results.json for compatibility
    if "security" in result:
        with open("output/security_results.json", "w", encoding="utf-8") as f:
            json.dump(result["security"], f, indent=2)

    return output_path


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("      SiteSentinel & SiteAudit Unified Scanner")
    print("=" * 50 + "\n")

    target = input("Enter target URL: ").strip()
    if not target:
        target = "https://example.com"

    res = scan(target)
    scores = res.get("scores", {})
    print("\n--- RESULTS ---")
    print(f"Target:            {res['target']}")
    print(f"Security Score:    {scores.get('security_score')}/100")
    print(f"Performance Score: {scores.get('performance_score')}/100")
    print(f"Overall Score:     {scores.get('overall_score')}/100")
    print(f"Health:            {scores.get('overall_health')}")
    print(f"AI Summary:        {res.get('ai_analysis', {}).get('summary')}")
    print(f"Saved to:          output/scan_results.json\n")