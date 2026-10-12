"""
perf_basic.py — Step 2: Basic HTTP performance measurement
No external tools required; uses only the `requests` library.

Measures:
  - status_code       : HTTP response status
  - ttfb_ms           : Time to First Byte (headers received)
  - response_time_ms  : Full round-trip including body download
  - page_weight_kb    : Size of the downloaded HTML body
"""

import time
import requests

# Timeout for the initial connection and for reading the response (seconds)
CONNECT_TIMEOUT = 10
READ_TIMEOUT    = 20

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; SiteAudit/1.0; "
        "+https://github.com/siteaudit)"
    )
}


def measure(url: str) -> dict:
    """
    Perform a real HTTP GET and return timing metrics.

    Returns a dict with the same keys used in the 'performance' section
    of the shared JSON contract. Lighthouse/PSI fields are left as None
    (populated in Step 3).

    On failure, the 'error' key contains a human-readable message and
    all numeric fields remain None.
    """
    result = {
        "response_time_ms":  None,
        "status_code":       None,
        "ttfb_ms":           None,
        # ── Populated in Step 3 (PSI / Lighthouse) ──────────────
        "lighthouse_score":  None,
        "lcp_ms":            None,
        "fcp_ms":            None,
        "speed_index_ms":    None,
        "tbt_ms":            None,
        "cls":               None,
        # ── Re-populated here from actual body size ──────────────
        "page_weight_kb":    None,
        # ── Internal error flag (surfaced to errors[] in scanner) ─
        "error":             None,
    }

    try:
        wall_start = time.perf_counter()

        # stream=True so we can separate header arrival from body download
        response = requests.get(
            url,
            stream=True,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            headers=HEADERS,
            allow_redirects=True,
        )

        # requests sets response.elapsed as soon as headers are fully received —
        # this is the closest proxy for TTFB we can get without raw sockets.
        ttfb_ms = response.elapsed.total_seconds() * 1000

        # Consume the body so we can measure full download time + size
        body = b"".join(response.iter_content(chunk_size=16_384))

        wall_end = time.perf_counter()
        total_ms = (wall_end - wall_start) * 1000

        result["status_code"]      = response.status_code
        result["ttfb_ms"]          = round(ttfb_ms, 1)
        result["response_time_ms"] = round(total_ms, 1)
        result["page_weight_kb"]   = round(len(body) / 1024, 2)

    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Connection failed — {_clean(exc)}"
    except requests.exceptions.Timeout:
        result["error"] = (
            f"Request timed out "
            f"(connect={CONNECT_TIMEOUT}s / read={READ_TIMEOUT}s)"
        )
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects — possible redirect loop"
    except requests.exceptions.RequestException as exc:
        result["error"] = f"HTTP error — {_clean(exc)}"
    except Exception as exc:
        result["error"] = f"Unexpected error — {_clean(exc)}"

    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _clean(exc: Exception) -> str:
    """Return a short, readable version of an exception message."""
    msg = str(exc)
    # requests wraps errors in verbose context — grab only the root cause
    if ":" in msg:
        msg = msg.split(":")[-1].strip()
    return msg[:120]  # cap length for UI display
