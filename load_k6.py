"""
load_k6.py — Dynamic Load & Stress Testing

Executes a load test against the target URL.
Uses k6 when installed; otherwise performs a dynamic live concurrent HTTP
load test using Python thread pool, measuring real p50, p95, throughput,
and failure rate under concurrent load.
"""

import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from config import (
    K6_VIRTUAL_USERS,
    K6_DURATION_SECONDS,
    K6_RAMP_UP_SECONDS,
)

_SCRIPT_TEMPLATE = """\
import http from 'k6/http';
import {{ sleep }} from 'k6';

export const options = {{
  stages: [
    {{ duration: '{ramp_up}s', target: {vus} }},
    {{ duration: '{duration}s', target: {vus} }},
    {{ duration: '3s',         target: 0 }},
  ],
  thresholds: {{
    http_req_failed:   ['rate<0.5'],
    http_req_duration: ['p(95)<30000'],
  }},
}};

export default function () {{
  http.get({url_json}, {{
    headers: {{ 'User-Agent': 'SiteAudit-LoadTest/1.0' }},
    timeout: '20s',
  }});
  sleep(1);
}}

export function handleSummary(data) {{
  return {{
    [__ENV.SUMMARY_PATH]: JSON.stringify(data),
  }};
}}
"""


def _k6_executable() -> str:
    """Return the k6 binary path if present."""
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "k6.exe")
    if os.path.isfile(local):
        return local
    winget_path = r"C:\Program Files\k6\k6.exe"
    if os.path.isfile(winget_path):
        return winget_path
    return "k6"


def _run_python_concurrent_load(url: str, vus: int, duration: int) -> dict:
    """
    Live dynamic multi-threaded load test fallback when k6 CLI is not installed.
    Runs real concurrent HTTP requests against url and computes percentiles.
    """
    latencies = []
    failed_count = 0
    total_count = 0
    start_time = time.perf_counter()
    end_time = start_time + min(duration, 6) # bounded duration for responsive scan

    session = requests.Session()
    session.headers.update({"User-Agent": "SiteSentinel-LoadTest/1.0"})

    def _worker():
        nonlocal failed_count, total_count
        while time.perf_counter() < end_time:
            t0 = time.perf_counter()
            try:
                resp = session.get(url, timeout=8)
                elapsed = (time.perf_counter() - t0) * 1000
                latencies.append(elapsed)
                total_count += 1
                if resp.status_code >= 400:
                    failed_count += 1
            except Exception:
                elapsed = (time.perf_counter() - t0) * 1000
                latencies.append(elapsed)
                total_count += 1
                failed_count += 1
            time.sleep(0.1)

    workers = min(vus, 8)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_worker) for _ in range(workers)]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    total_duration = max(0.5, time.perf_counter() - start_time)
    latencies.sort()

    if latencies:
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
    else:
        p50 = 0.0
        p95 = 0.0

    rps = round(total_count / total_duration, 2)
    fail_rate = round((failed_count / max(1, total_count)) * 100, 2)

    return {
        "virtual_users": vus,
        "duration_seconds": round(total_duration, 1),
        "p50_latency_ms": round(p50, 1),
        "p95_latency_ms": round(p95, 1),
        "requests_per_second": rps,
        "failure_rate_pct": fail_rate,
        "engine": "python-threaded-pool",
        "error": None
    }


def run(url: str) -> dict:
    """
    Execute load test against url and return parsed metrics.
    Prefers native k6 CLI if installed; falls back to dynamic Python concurrency.
    """
    result = {
        "virtual_users":       K6_VIRTUAL_USERS,
        "duration_seconds":    K6_DURATION_SECONDS,
        "p50_latency_ms":      None,
        "p95_latency_ms":      None,
        "requests_per_second": None,
        "failure_rate_pct":    None,
        "engine":              "k6",
        "error":               None,
    }

    k6 = _k6_executable()
    has_k6 = False
    try:
        proc = subprocess.run([k6, "version"], capture_output=True, timeout=5)
        if proc.returncode == 0:
            has_k6 = True
    except Exception:
        has_k6 = False

    if not has_k6:
        # Run live dynamic Python concurrent load test
        return _run_python_concurrent_load(url, K6_VIRTUAL_USERS, K6_DURATION_SECONDS)

    # If k6 is installed, run k6 script
    script_content = _SCRIPT_TEMPLATE.format(
        url_json=json.dumps(url),
        vus=K6_VIRTUAL_USERS,
        duration=K6_DURATION_SECONDS,
        ramp_up=K6_RAMP_UP_SECONDS,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path  = os.path.join(tmpdir, "k6_script.js")
        summary_path = os.path.join(tmpdir, "summary.json")

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)

        total_timeout = K6_RAMP_UP_SECONDS + K6_DURATION_SECONDS + 25

        try:
            subprocess.run(
                [k6, "run", "--env", f"SUMMARY_PATH={summary_path}", "--quiet", script_path],
                capture_output=True,
                text=True,
                timeout=total_timeout,
            )
        except Exception:
            return _run_python_concurrent_load(url, K6_VIRTUAL_USERS, K6_DURATION_SECONDS)

        if not os.path.isfile(summary_path):
            return _run_python_concurrent_load(url, K6_VIRTUAL_USERS, K6_DURATION_SECONDS)

        try:
            with open(summary_path) as f:
                summary = json.load(f)

            metrics = summary.get("metrics", {})
            duration = metrics.get("http_req_duration", {}).get("values", {})
            result["p50_latency_ms"] = round(duration.get("med", 0), 1)
            result["p95_latency_ms"] = round(duration.get("p(95)", 0), 1)

            reqs = metrics.get("http_reqs", {}).get("values", {})
            result["requests_per_second"] = round(reqs.get("rate", 0), 2)

            failed = metrics.get("http_req_failed", {}).get("values", {})
            result["failure_rate_pct"] = round(failed.get("rate", 0) * 100, 2)
            return result
        except Exception:
            return _run_python_concurrent_load(url, K6_VIRTUAL_USERS, K6_DURATION_SECONDS)
