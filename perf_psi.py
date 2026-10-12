"""
perf_psi.py — Step 3: Google PageSpeed Insights (Lighthouse) integration

Fetches Lighthouse metrics from the PSI API v5 and returns them in the
shape expected by the 'performance' section of the shared JSON contract.

Metrics extracted:
  - lighthouse_score   : 0-100 overall performance score
  - lcp_ms             : Largest Contentful Paint (ms)
  - fcp_ms             : First Contentful Paint (ms)
  - cls                : Cumulative Layout Shift (unitless, e.g. 0.12)
  - speed_index_ms     : Speed Index (ms)
  - tbt_ms             : Total Blocking Time (ms)
  - page_weight_kb     : Total transfer size of all resources (KB)
"""

import requests
from config import PSI_API_KEY, PSI_STRATEGY

PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
TIMEOUT = 60   # PSI can take up to ~30 s for a cold analysis

# Lighthouse audit keys we care about
_AUDIT_KEYS = {
    "lcp_ms":          "largest-contentful-paint",
    "fcp_ms":          "first-contentful-paint",
    "speed_index_ms":  "speed-index",
    "tbt_ms":          "total-blocking-time",
    "cls":             "cumulative-layout-shift",
    "page_weight_kb":  "total-byte-weight",
}


def measure(url: str) -> dict:
    """
    Call the PSI API for `url` and return a dict of Lighthouse metrics.

    All values are None on failure; 'error' key contains a human-readable
    message that the caller should surface in the errors[] array.
    """
    result = {
        "lighthouse_score":  None,
        "lcp_ms":            None,
        "fcp_ms":            None,
        "cls":               None,
        "speed_index_ms":    None,
        "tbt_ms":            None,
        "page_weight_kb":    None,
        "error":             None,
    }

    # PSI requires a simple API key (starts with "AIza…"), not an OAuth2 token
    if not PSI_API_KEY or not PSI_API_KEY.startswith("AIza"):
        result["error"] = (
            "PSI API key missing or wrong type. "
            "Generate a simple API key at: "
            "console.cloud.google.com → APIs & Services → Credentials → "
            "Create Credentials → API key. "
            "Enable 'PageSpeed Insights API' in the API Library first."
        )
        return result

    params = {
        "url":      url,
        "strategy": PSI_STRATEGY,
        "category": "performance",
        "key":      PSI_API_KEY,
    }

    try:
        resp = requests.get(PSI_ENDPOINT, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        result["error"] = f"PSI API timed out after {TIMEOUT}s"
        return result
    except requests.exceptions.HTTPError as exc:
        # Surface the API's own error message when available
        try:
            api_msg = exc.response.json()["error"]["message"]
        except Exception:
            api_msg = str(exc)
        result["error"] = f"PSI API error — {api_msg}"
        return result
    except Exception as exc:
        result["error"] = f"PSI unexpected error — {exc}"
        return result

    try:
        lhr = data["lighthouseResult"]

        # Overall performance score (0.0–1.0 → 0–100)
        raw_score = (
            lhr.get("categories", {})
               .get("performance", {})
               .get("score")
        )
        if raw_score is not None:
            result["lighthouse_score"] = round(raw_score * 100)

        audits = lhr.get("audits", {})

        for field, audit_key in _AUDIT_KEYS.items():
            audit = audits.get(audit_key, {})
            val   = audit.get("numericValue")
            if val is None:
                continue

            if field == "cls":
                result["cls"] = round(val, 3)
            elif field == "page_weight_kb":
                result["page_weight_kb"] = round(val / 1024, 1)
            else:
                # All other fields are in ms — round to 1 decimal
                result[field] = round(val, 1)

    except (KeyError, TypeError) as exc:
        result["error"] = f"PSI response parse error — {exc}"

    return result
