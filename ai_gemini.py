"""
ai_gemini.py — AI synthesis using Google AI (Gemma 27B / Gemini)

Feeds both Security and Performance scan results to the AI model
and returns a structured, site-specific audit report with:
  - security_score (0-100)
  - performance_score (0-100)
  - overall_score (0-100)
  - overall_health ("good" | "warning" | "critical")
  - summary (site-specific executive overview)
  - security_improvements (actionable steps with exact headers and attributes)
  - performance_improvements (tailored to measured Core Web Vitals and TTFB)
  - top_issues (prioritised findings with exact fixes)
"""

import json
import re
import math
import time
from google import genai
from google.genai import types

from config import GEMINI_API_KEY, GEMINI_MODEL


# ── Deterministic Baseline Calculation (Robust Safety Net) ─────────────────────

def compute_baseline_scores(performance: dict, security_findings: list, load_test: dict) -> dict:
    """
    Computes deterministic 0-100 scores based on standard web security & performance rules.
    This guarantees accurate fallback scores if the AI service experiences temporary outages.
    """
    sec_score = 100
    high_count = 0
    med_count = 0
    low_count = 0

    for f in (security_findings or []):
        sev = (f.get("severity") or "info").lower()
        if sev == "high":
            high_count += 1
            sec_score -= 20
        elif sev == "medium":
            med_count += 1
            sec_score -= 10
        elif sev == "low":
            low_count += 1
            sec_score -= 4

    sec_score = max(5, min(100, round(sec_score)))

    lh_score = performance.get("lighthouse_score")
    if lh_score is not None:
        perf_score = float(lh_score)
    else:
        ttfb = performance.get("ttfb_ms") or 500
        rt = performance.get("response_time_ms") or 800
        perf_score = 100 - min(60, (ttfb / 50)) - min(30, (rt / 100))

    fail_rate = float(load_test.get("failure_rate_pct") or 0)
    if fail_rate > 0:
        perf_score -= min(30, fail_rate * 3)

    perf_score = max(5, min(100, round(perf_score)))
    overall_score = round((sec_score * 0.5) + (perf_score * 0.5))

    health = "good"
    if sec_score < 60 or perf_score < 50 or high_count > 0:
        health = "critical"
    elif sec_score < 85 or perf_score < 80 or med_count > 1:
        health = "warning"

    return {
        "security_score": sec_score,
        "performance_score": perf_score,
        "overall_score": overall_score,
        "overall_health": health
    }


def clean_json_text(raw: str) -> str:
    """
    Extracts and sanitises JSON from AI raw output,
    handling markdown blocks, preambles, and unescaped characters.
    """
    if not raw:
        return ""

    text = raw.strip()

    # Extract markdown code fence interior if present
    code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if code_block_match:
        text = code_block_match.group(1).strip()

    # Find outer { and }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        text = text[first_brace:last_brace + 1].strip()

    return text


def repair_json_string(json_str: str) -> dict:
    """
    Attempts multiple strategies to parse or repair JSON text.
    """
    if not json_str:
        return None

    try:
        return json.loads(json_str)
    except Exception:
        pass

    # Clean trailing commas
    cleaned = re.sub(r",\s*([\]}])", r"\1", json_str)
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Attempt closing quotes and braces if truncated
    truncated = cleaned.strip()
    if not truncated.endswith("}"):
        if truncated.count('"') % 2 != 0:
            truncated += '"'
        truncated += "\n}"
        try:
            return json.loads(truncated)
        except Exception:
            pass

    return None


# ── Site-Specific Prompt Builder ───────────────────────────────────────────────

def _build_prompt(target: str, performance: dict, load_test: dict, security_findings: list, baseline: dict) -> str:
    findings_list = []
    for f in (security_findings or []):
        t = f.get("title", "Issue")
        s = f.get("severity", "info").upper()
        findings_list.append(f"{t} ({s})")

    findings_text = ", ".join(findings_list) if findings_list else "None detected (all checked headers and cookies configured)"

    perf_summary = (
        f"Lighthouse: {performance.get('lighthouse_score', 'N/A')}/100, "
        f"TTFB: {performance.get('ttfb_ms', 'N/A')}ms, "
        f"Response Time: {performance.get('response_time_ms', 'N/A')}ms, "
        f"LCP: {performance.get('lcp_ms', 'N/A')}ms, "
        f"Page Weight: {performance.get('page_weight_kb', 'N/A')}KB"
    )

    lt_summary = (
        f"p50: {load_test.get('p50_latency_ms', 'N/A')}ms, "
        f"p95: {load_test.get('p95_latency_ms', 'N/A')}ms, "
        f"RPS: {load_test.get('requests_per_second', 'N/A')}, "
        f"Failure Rate: {load_test.get('failure_rate_pct', 'N/A')}%"
    )

    prompt = (
        f"You are a senior web reliability engineer. Analyze this website audit for {target}.\n"
        f"Metrics:\n"
        f"- Performance: {perf_summary}\n"
        f"- Load Stress: {lt_summary}\n"
        f"- Security Vulnerabilities: {findings_text}\n\n"
        f"Rules:\n"
        f"1. Provide specific, tailored recommendations referencing {target} and the exact metrics above.\n"
        f"2. If performance is already fast/high (e.g. Lighthouse >= 90), state that it is well-optimized and suggest maintenance or CDN edge caching instead of generic fixes.\n"
        f"3. If security headers or cookies are missing, name the exact missing header and exact recommended directive value.\n"
        f"4. Return ONLY valid JSON with keys: security_score (int), performance_score (int), overall_score (int), overall_health (good, warning, or critical), summary (string), security_improvements (list of strings), performance_improvements (list of strings), top_issues (list of objects with title, category, severity, recommendation)."
    )
    return prompt


# ── Public API ─────────────────────────────────────────────────────────────────

def summarise(
    target: str,
    performance: dict,
    load_test: dict,
    security_findings: list,
) -> dict:
    """
    Analyzes the complete audit result and generates:
      - security_score (0-100)
      - performance_score (0-100)
      - overall_score (0-100)
      - overall_health
      - summary (site-specific)
      - security_improvements (actionable)
      - performance_improvements (tailored)
      - top_issues
    """
    baseline = compute_baseline_scores(performance, security_findings, load_test)

    # Dynamic fallback based on the actual target and findings
    dynamic_sec_fixes = []
    for f in (security_findings or []):
        t = f.get("title", "")
        if "Content Security Policy" in t:
            dynamic_sec_fixes.append("Implement Content-Security-Policy: default-src 'self' to prevent XSS.")
        elif "HSTS" in t:
            dynamic_sec_fixes.append("Implement Strict-Transport-Security: max-age=31536000; includeSubDomains.")
        elif "Clickjacking" in t:
            dynamic_sec_fixes.append("Implement X-Frame-Options: DENY to mitigate clickjacking attacks.")
        elif "MIME" in t:
            dynamic_sec_fixes.append("Implement X-Content-Type-Options: nosniff.")
        elif "Cookie" in t:
            dynamic_sec_fixes.append("Add Secure, HttpOnly, and SameSite=Lax flags to cookies.")
        else:
            dynamic_sec_fixes.append(f"Remediate {t}: {f.get('evidence', '')[:100]}")

    if not dynamic_sec_fixes:
        dynamic_sec_fixes = ["All verified security headers are in place. Maintain CSP and HSTS rotation."]

    dynamic_perf_fixes = []
    lh = performance.get("lighthouse_score")
    if lh is not None and lh >= 90:
        dynamic_perf_fixes.append(f"Performance is optimal with Lighthouse {lh}/100. Maintain edge caching to sustain current throughput.")
        dynamic_perf_fixes.append("Configure automated performance regression alerts in CI/CD pipeline.")
    else:
        if performance.get("ttfb_ms") and performance["ttfb_ms"] > 600:
            dynamic_perf_fixes.append(f"Reduce Time to First Byte ({performance['ttfb_ms']}ms) via CDN edge caching and database query optimization.")
        if performance.get("lcp_ms") and performance["lcp_ms"] > 2500:
            dynamic_perf_fixes.append(f"Optimize Largest Contentful Paint ({performance['lcp_ms']}ms) by preloading hero assets and converting to WebP/AVIF.")
        if not dynamic_perf_fixes:
            dynamic_perf_fixes.append("Enable HTTP/2 or HTTP/3 and Brotli compression for static asset delivery.")

    result = {
        "security_score": baseline["security_score"],
        "performance_score": baseline["performance_score"],
        "overall_score": baseline["overall_score"],
        "overall_health": baseline["overall_health"],
        "summary": f"{target} audit completed. Security score is {baseline['security_score']}/100 and Performance score is {baseline['performance_score']}/100.",
        "security_improvements": dynamic_sec_fixes[:4],
        "performance_improvements": dynamic_perf_fixes[:3],
        "top_issues": [],
        "generated_by": GEMINI_MODEL,
        "error": None,
    }

    # Populate top issues from findings
    for f in (security_findings or [])[:4]:
        result["top_issues"].append({
            "title": f.get("title", "Security Notice"),
            "category": "Security",
            "severity": (f.get("severity") or "Medium").capitalize(),
            "recommendation": f.get("evidence") or f.get("solution") or "Configure security header appropriately."
        })

    if not GEMINI_API_KEY:
        result["error"] = "GEMINI_API_KEY not configured"
        return result

    # Query Gemma 27B, falling back to gemini-3.6-flash if high demand spikes occur
    prompt = _build_prompt(target, performance, load_test, security_findings, baseline)
    models_to_try = [GEMINI_MODEL, "gemini-3.6-flash", "gemini-flash-latest"]

    parsed = None
    last_err = None

    for model_name in models_to_try:
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=2500,
                ),
            )

            raw = None
            try:
                raw = response.text
            except Exception:
                pass

            if not raw and response.candidates:
                try:
                    raw = response.candidates[0].content.parts[0].text
                except Exception:
                    pass

            if raw:
                cleaned_json = clean_json_text(raw)
                parsed = repair_json_string(cleaned_json)
                if parsed and isinstance(parsed, dict):
                    result["generated_by"] = model_name
                    last_err = None
                    break
        except Exception as exc:
            last_err = exc
            time.sleep(1)

    if parsed and isinstance(parsed, dict):
        if "security_score" in parsed and isinstance(parsed["security_score"], (int, float)):
            result["security_score"] = max(0, min(100, round(parsed["security_score"])))

        if "performance_score" in parsed and isinstance(parsed["performance_score"], (int, float)):
            result["performance_score"] = max(0, min(100, round(parsed["performance_score"])))

        if "overall_score" in parsed and isinstance(parsed["overall_score"], (int, float)):
            result["overall_score"] = max(0, min(100, round(parsed["overall_score"])))
        else:
            result["overall_score"] = round((result["security_score"] + result["performance_score"]) / 2)

        if parsed.get("overall_health") in ("good", "warning", "critical"):
            result["overall_health"] = parsed["overall_health"].lower()

        if parsed.get("summary"):
            result["summary"] = parsed["summary"]

        if parsed.get("security_improvements") and isinstance(parsed["security_improvements"], list):
            result["security_improvements"] = [str(x) for x in parsed["security_improvements"]]

        if parsed.get("performance_improvements") and isinstance(parsed["performance_improvements"], list):
            result["performance_improvements"] = [str(x) for x in parsed["performance_improvements"]]

        if parsed.get("top_issues") and isinstance(parsed["top_issues"], list):
            formatted_issues = []
            for item in parsed["top_issues"]:
                if isinstance(item, dict):
                    formatted_issues.append({
                        "title": item.get("title", "Notice"),
                        "category": item.get("category", "General"),
                        "severity": item.get("severity", "Medium"),
                        "recommendation": item.get("recommendation", "")
                    })
                elif isinstance(item, str):
                    formatted_issues.append({
                        "title": item,
                        "category": "Audit",
                        "severity": "Medium",
                        "recommendation": item
                    })
            if formatted_issues:
                result["top_issues"] = formatted_issues

    elif last_err:
        result["error"] = f"AI notice: {last_err}. Used dynamic baseline."

    return result
