# SiteSentinel AI — Unified Web Security & Performance Auditor 🛡️⚡

A full-stack website auditor combining passive OWASP security scanning, Google Lighthouse Core Web Vitals, concurrent load testing, and **Gemma 27B AI** for dual 0–100 scoring and actionable improvement roadmaps.

---

## 🌟 Key Features

- **🛡️ Comprehensive Security Auditing**:
  - Validates critical HTTP headers: `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
  - Cookie security inspection: validates `Secure`, `HttpOnly`, and `SameSite` flags.
  - Integration with **OWASP ZAP Baseline Scanner** via Docker.

- **⚡ Core Web Vitals & HTTP Performance**:
  - Live HTTP round-trip timing, status codes, and Time to First Byte (TTFB).
  - Google PageSpeed Insights (PSI) API integration: Lighthouse score, Largest Contentful Paint (LCP), First Contentful Paint (FCP), Speed Index, Total Blocking Time (TBT), and Cumulative Layout Shift (CLS).

- **🚀 Concurrent Load & Stress Testing**:
  - Simulates concurrent virtual users (VUs) to test throughput (req/s), median latency (p50), peak latency (p95), and failure rate under stress.
  - Native **k6** execution when available, with an automatic multi-threaded Python concurrency fallback.

- **🤖 Gemma 27B AI Synthesis & Dual Scoring**:
  - Evaluates both security findings and performance metrics to generate:
    - **Security Score (0–100)**
    - **Performance Score (0–100)**
    - **Overall Combined Score (0–100)** and Health Status (`Good`, `Warning`, `Critical`).
  - Generates site-specific, non-generic step-by-step remediation plans to elevate both scores to 100.

- **📊 Modern Analytics Dashboard**:
  - Minimal dark executive UI built with vanilla CSS.
  - SVG animated radial progress score gauges.
  - 4 interactive Chart.js visualizations:
    - Core Web Vitals vs. Google Industry Benchmarks (Bar Chart)
    - Audit Balance Multi-Dimensional Radar Chart
    - Security Findings Distribution (Donut Chart)
    - Load Testing Stress Profile (Latency & Throughput)

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- (Optional) [Docker Desktop](https://www.docker.com/products/docker-desktop/) for OWASP ZAP container scans.
- (Optional) [k6](https://k6.io/) for native k6 load tests (`winget install k6`).

### 2. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/mallurivikas/hacktoberfest_niat.git
cd hacktoberfest_niat

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` or edit `config.py` with your API keys:
```bash
cp .env.example .env
```
Key variables:
- `GEMINI_API_KEY`: Google AI Studio API key (for Gemma 27B / Gemini).
- `GEMINI_MODEL`: Model ID (default: `gemma-4-26b-a4b-it`).
- `PSI_API_KEY`: Google PageSpeed Insights API key.

### 4. Running the Application
Start the Flask server:
```bash
python app.py
```
Open your browser and navigate to:
```text
http://localhost:5000
```
Enter any website URL (e.g. `https://example.com` or `https://github.com`) and click **Run Audit**.

---

## 📁 Project Architecture

```text
├── app.py               # Flask application & REST API routes (/api/scan)
├── config.py            # Central configuration & environment variables
├── scanner.py           # Master unified orchestrator (Security + Perf + AI)
├── scanner1.py          # Backward-compatibility alias
├── security_check.py    # Native security header & cookie inspection rules
├── zap_scanner.py       # OWASP ZAP passive baseline scanner (Docker)
├── perf_basic.py        # HTTP round-trip timing, status, and TTFB
├── perf_psi.py          # Google PageSpeed Insights & Lighthouse metrics
├── load_k6.py           # k6 / Python concurrent load stress tester
├── ai_gemini.py         # Google AI (Gemma 27B) scoring & improvement generator
├── requirements.txt     # Python package dependencies
├── frontend/
│   ├── index.html       # Auditor dashboard layout
│   ├── style.css        # Modern dark design system
│   └── main.js          # Interactive UI logic & Chart.js graph renderers
└── output/
    └── .gitkeep         # Directory for generated audit results (cached locally)
```

---

## 🛡️ License
Distributed under the MIT License. Built for Hacktoberfest & high-assurance web engineering.
