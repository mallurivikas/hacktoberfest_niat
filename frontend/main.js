// =============================================================================
// SiteSentinel AI — Frontend Client Logic & Interactive Visualizations
// =============================================================================

// Chart instances for cleanup
let vitalsChartInstance = null;
let radarChartInstance = null;
let securityChartInstance = null;
let loadChartInstance = null;

// DOM Elements
const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const statusBox = document.getElementById("scan-status-box");
const statusTitle = document.getElementById("scan-status");
const statusDetail = document.getElementById("scan-status-detail");
const resultsArea = document.getElementById("results");
const stepDots = document.querySelectorAll(".step-dot");

// Quick picks
document.querySelectorAll(".quick-pill").forEach(pill => {
  pill.addEventListener("click", () => {
    urlInput.value = pill.getAttribute("data-url");
    form.dispatchEvent(new Event("submit"));
  });
});

// Tab switching
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

    btn.classList.add("active");
    const targetId = btn.getAttribute("data-tab");
    const targetPane = document.getElementById(targetId);
    if (targetPane) targetPane.classList.add("active");
  });
});

// Copy JSON button
const copyJsonBtn = document.getElementById("copy-json-btn");
if (copyJsonBtn) {
  copyJsonBtn.addEventListener("click", () => {
    const rawText = document.getElementById("raw-json-viewer").textContent;
    navigator.clipboard.writeText(rawText).then(() => {
      const origText = copyJsonBtn.innerHTML;
      copyJsonBtn.innerHTML = "✅ Copied!";
      setTimeout(() => { copyJsonBtn.innerHTML = origText; }, 2000);
    });
  });
}

// ── Form Submission & Progress Ticker ─────────────────────────────────────────

let stepperInterval = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  let url = urlInput.value.trim();
  if (!url) return;

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
    urlInput.value = url;
  }

  setLoading(true);
  startProgressTicker();

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    if (!res.ok || data.error) {
      showErrorBanner(data.error || "Scan failed on the server.");
      return;
    }

    renderAuditDashboard(data);

  } catch (err) {
    console.error(err);
    showErrorBanner("Could not reach the auditor server. Ensure the backend is active on port 5000.");
  } finally {
    setLoading(false);
    clearInterval(stepperInterval);
    statusBox.hidden = true;
  }
});

function setLoading(isLoading) {
  scanBtn.disabled = isLoading;
  const btnSpinner = scanBtn.querySelector(".btn-spinner");
  const btnText = scanBtn.querySelector(".btn-text");

  if (isLoading) {
    btnSpinner.hidden = false;
    btnText.textContent = "Auditing...";
    statusBox.hidden = false;
    resultsArea.hidden = true;
  } else {
    btnSpinner.hidden = true;
    btnText.textContent = "Run Audit";
  }
}

function startProgressTicker() {
  const steps = [
    { title: "Inspecting Security Headers & SSL", detail: "Probing HSTS, CSP, Cookies, and OWASP baseline...", dot: 0 },
    { title: "Measuring Core Web Vitals", detail: "Fetching Google PageSpeed Insights & Lighthouse metrics...", dot: 1 },
    { title: "Running Load & Stress Simulation", detail: "Executing k6 concurrent virtual users probe...", dot: 2 },
    { title: "Consulting Gemma 27B AI", detail: "Synthesizing full telemetry and scoring out of 100...", dot: 3 }
  ];

  let current = 0;
  function updateStep(idx) {
    const s = steps[idx];
    statusTitle.textContent = s.title;
    statusDetail.textContent = s.detail;
    stepDots.forEach((d, i) => {
      d.classList.toggle("active", i <= s.dot);
    });
  }

  updateStep(0);
  let stepIdx = 0;
  stepperInterval = setInterval(() => {
    stepIdx = (stepIdx + 1) % steps.length;
    updateStep(stepIdx);
  }, 4500);
}

function showErrorBanner(msg) {
  const container = document.getElementById("scan-errors-container");
  container.innerHTML = `
    <div class="error-banner">
      <strong>⚠️ Scan Error:</strong> ${escapeHtml(msg)}
    </div>
  `;
  resultsArea.hidden = false;
}

// ── Main Render Orchestrator ──────────────────────────────────────────────────

function renderAuditDashboard(data) {
  resultsArea.hidden = false;

  // 1. Target metadata & overall health
  renderOverallHealth(data);

  // 2. Dual Radial Score Gauges
  renderDualScores(data);

  // 3. Meaningful Visual Charts (Chart.js)
  renderVisualCharts(data);

  // 4. AI Synthesis & Dual Improvement Playbooks
  renderAIAssessment(data);

  // 5. Deep-dive Metric Tables & Tabs
  renderMetricTabs(data);

  // 6. Partial Errors if any
  renderPartialErrors(data.errors);

  // 7. Raw JSON
  document.getElementById("raw-json-viewer").textContent = JSON.stringify(data, null, 2);

  // Smooth scroll down to results
  resultsArea.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── 1. Overall Health ─────────────────────────────────────────────────────────

function renderOverallHealth(data) {
  const sec = data.security || {};
  const scores = data.scores || {};
  const ai = data.ai_analysis || {};

  document.getElementById("target-display").textContent = data.target || "N/A";

  const overallVal = scores.overall_score ?? ai.overall_score ?? 75;
  document.getElementById("score-overall-val").textContent = overallVal;

  const health = (scores.overall_health || ai.overall_health || "warning").toLowerCase();
  const healthBadge = document.getElementById("overall-health-badge");
  healthBadge.className = `overall-health-badge ${health}`;
  healthBadge.textContent = health.toUpperCase();

  document.getElementById("scan-time-val").textContent = `${((data.scan_duration_ms || 0) / 1000).toFixed(1)}s`;
  document.getElementById("https-val").textContent = sec.https ? "Enforced ✅" : "No ❌";
  document.getElementById("http-status-val").textContent = sec.status_code ? `${sec.status_code} OK` : "N/A";
}

// ── 2. Dual Radial Score Meters ───────────────────────────────────────────────

function renderDualScores(data) {
  const scores = data.scores || {};
  const ai = data.ai_analysis || {};
  const secFindings = (data.security && data.security.security_findings) || [];
  const perf = data.performance || {};

  // Security Score
  const secScore = scores.security_score ?? ai.security_score ?? 80;
  document.getElementById("score-sec-val").textContent = secScore;
  const secProgress = document.getElementById("sec-progress");
  secProgress.setAttribute("stroke-dasharray", `${secScore}, 100`);

  // Color progress based on score
  if (secScore >= 85) {
    secProgress.setAttribute("class", "circle circle--emerald");
    document.getElementById("sec-badge").className = "badge badge--good";
    document.getElementById("sec-badge").textContent = "Grade A · Hardened";
  } else if (secScore >= 60) {
    secProgress.setAttribute("class", "circle circle--cyan");
    document.getElementById("sec-badge").className = "badge badge--warning";
    document.getElementById("sec-badge").textContent = "Grade B · Moderate";
  } else {
    secProgress.setAttribute("class", "circle circle--rose");
    document.getElementById("sec-badge").className = "badge badge--critical";
    document.getElementById("sec-badge").textContent = "Grade D · Vulnerable";
  }
  document.getElementById("sec-findings-summary").textContent = `${secFindings.length} issue(s) detected`;

  // Performance Score
  const perfScore = scores.performance_score ?? ai.performance_score ?? (perf.lighthouse_score || 70);
  document.getElementById("score-perf-val").textContent = perfScore;
  const perfProgress = document.getElementById("perf-progress");
  perfProgress.setAttribute("stroke-dasharray", `${perfScore}, 100`);

  if (perfScore >= 85) {
    perfProgress.setAttribute("class", "circle circle--emerald");
    document.getElementById("perf-badge").className = "badge badge--good";
    document.getElementById("perf-badge").textContent = "Fast & Optimized";
  } else if (perfScore >= 60) {
    perfProgress.setAttribute("class", "circle circle--amber");
    document.getElementById("perf-badge").className = "badge badge--warning";
    document.getElementById("perf-badge").textContent = "Degraded Speed";
  } else {
    perfProgress.setAttribute("class", "circle circle--rose");
    document.getElementById("perf-badge").className = "badge badge--critical";
    document.getElementById("perf-badge").textContent = "Severe Latency";
  }
  document.getElementById("perf-metrics-summary").textContent = `TTFB: ${perf.ttfb_ms || '—'}ms · LCP: ${perf.lcp_ms || '—'}ms`;
}

// ── 3. Visual Charts (Chart.js) ───────────────────────────────────────────────

function renderVisualCharts(data) {
  const perf = data.performance || {};
  const sec = data.security || {};
  const lt = data.load_test || {};
  const scores = data.scores || {};

  // Setup common dark theme styling for Chart.js
  Chart.defaults.color = '#94a3b8';
  Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
  Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";

  // ── Chart 1: Web Vitals vs. Benchmark (Bar Chart)
  if (vitalsChartInstance) vitalsChartInstance.destroy();
  const vitalsCtx = document.getElementById("vitalsChart").getContext("2d");

  const actualVitals = [
    perf.ttfb_ms || 0,
    perf.fcp_ms || 0,
    perf.lcp_ms || 0,
    perf.speed_index_ms || 0,
    perf.tbt_ms || 0
  ];
  const thresholdVitals = [600, 1800, 2500, 3400, 200]; // Google "Good" thresholds

  vitalsChartInstance = new Chart(vitalsCtx, {
    type: "bar",
    data: {
      labels: ["TTFB", "FCP", "LCP", "Speed Index", "Total Blocking"],
      datasets: [
        {
          label: "Site Measured (ms)",
          data: actualVitals,
          backgroundColor: "rgba(59, 130, 246, 0.8)",
          borderRadius: 6,
          borderWidth: 1,
          borderColor: "#3b82f6"
        },
        {
          label: "Google Good Baseline (ms)",
          data: thresholdVitals,
          backgroundColor: "rgba(16, 185, 129, 0.25)",
          borderColor: "#10b981",
          borderWidth: 1.5,
          borderRadius: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "top", labels: { boxWidth: 12, font: { size: 11 } } },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${ctx.raw} ms`
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { font: { size: 10 } }
        },
        x: {
          grid: { display: false },
          ticks: { font: { size: 11, weight: '600' } }
        }
      }
    }
  });

  // ── Chart 2: Audit Balance Radar Chart
  if (radarChartInstance) radarChartInstance.destroy();
  const radarCtx = document.getElementById("radarChart").getContext("2d");

  const secScore = scores.security_score || 80;
  const perfScore = scores.performance_score || 75;
  const ttfbScore = Math.max(10, Math.min(100, Math.round(100 - ((perf.ttfb_ms || 500) / 15))));
  const vitalsScore = perf.lighthouse_score || perfScore;
  const loadScore = Math.max(10, Math.min(100, Math.round(100 - (parseFloat(lt.failure_rate_pct || 0) * 4))));

  radarChartInstance = new Chart(radarCtx, {
    type: "radar",
    data: {
      labels: ["Security Posture", "Performance Score", "TTFB Speed", "Core Web Vitals", "Load Resilience"],
      datasets: [{
        label: "Site Balance",
        data: [secScore, perfScore, ttfbScore, vitalsScore, loadScore],
        backgroundColor: "rgba(6, 182, 212, 0.25)",
        borderColor: "#06b6d4",
        borderWidth: 2,
        pointBackgroundColor: "#06b6d4",
        pointBorderColor: "#fff",
        pointHoverRadius: 5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        r: {
          angleLines: { color: "rgba(255, 255, 255, 0.08)" },
          grid: { color: "rgba(255, 255, 255, 0.06)" },
          suggestedMin: 0,
          suggestedMax: 100,
          ticks: { display: false, stepSize: 20 },
          pointLabels: { font: { size: 11, weight: '600' }, color: '#cbd5e1' }
        }
      }
    }
  });

  // ── Chart 3: Security Findings Severity (Donut Chart)
  if (securityChartInstance) securityChartInstance.destroy();
  const secCtx = document.getElementById("securityChart").getContext("2d");

  const summary = (sec.scan_summary && sec.scan_summary.severity_counts) || { high: 0, medium: 0, low: 0, info: 0 };
  const counts = [summary.high || 0, summary.medium || 0, summary.low || 0, summary.info || 0];
  const allZero = counts.every(v => v === 0);

  securityChartInstance = new Chart(secCtx, {
    type: "doughnut",
    data: {
      labels: ["High", "Medium", "Low", "Informational"],
      datasets: [{
        data: allZero ? [0, 0, 0, 1] : counts,
        backgroundColor: allZero
          ? ["rgba(16, 185, 129, 0.6)"]
          : [
              "rgba(244, 63, 94, 0.85)",  // High
              "rgba(245, 158, 11, 0.85)", // Medium
              "rgba(59, 130, 246, 0.85)", // Low
              "rgba(148, 163, 184, 0.7)"  // Info
            ],
        borderColor: "#0f172a",
        borderWidth: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "68%",
      plugins: {
        legend: { position: "right", labels: { boxWidth: 10, font: { size: 11 } } },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.label}: ${allZero ? 'No critical vulnerabilities' : ctx.raw}`
          }
        }
      }
    }
  });

  // ── Chart 4: Load & Stress Profile (Bar Chart)
  if (loadChartInstance) loadChartInstance.destroy();
  const loadCtx = document.getElementById("loadChart").getContext("2d");

  loadChartInstance = new Chart(loadCtx, {
    type: "bar",
    data: {
      labels: ["p50 Latency (ms)", "p95 Latency (ms)", "Throughput (req/s)"],
      datasets: [{
        label: "Stress Metrics",
        data: [
          lt.p50_latency_ms || 0,
          lt.p95_latency_ms || 0,
          lt.requests_per_second || 0
        ],
        backgroundColor: [
          "rgba(16, 185, 129, 0.75)",
          "rgba(245, 158, 11, 0.75)",
          "rgba(139, 92, 246, 0.75)"
        ],
        borderColor: ["#10b981", "#f59e0b", "#8b5cf6"],
        borderWidth: 1.5,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: "rgba(255, 255, 255, 0.05)" }
        },
        x: {
          grid: { display: false },
          ticks: { font: { size: 11, weight: '600' } }
        }
      }
    }
  });
}

// ── 4. AI Assessment & Improvement Playbooks ──────────────────────────────────

function renderAIAssessment(data) {
  const ai = data.ai_analysis || {};

  document.getElementById("ai-model-tag").textContent = ai.generated_by || "gemma-4-26b-a4b-it";
  document.getElementById("ai-summary-text").textContent =
    ai.summary || "Website audit synthesized. Review specific roadmap recommendations below.";

  // Security Improvements
  const secList = document.getElementById("sec-improvement-list");
  secList.innerHTML = "";
  const secFixes = ai.security_improvements || [];
  if (secFixes.length === 0) {
    secList.innerHTML = "<li>All major security checks passed. Maintain current CSP & HSTS policies.</li>";
  } else {
    secFixes.forEach(item => {
      const li = document.createElement("li");
      li.textContent = item;
      secList.appendChild(li);
    });
  }

  // Performance Improvements
  const perfList = document.getElementById("perf-improvement-list");
  perfList.innerHTML = "";
  const perfFixes = ai.performance_improvements || [];
  if (perfFixes.length === 0) {
    perfList.innerHTML = "<li>Performance is running at optimal throughput with low TTFB.</li>";
  } else {
    perfFixes.forEach(item => {
      const li = document.createElement("li");
      li.textContent = item;
      perfList.appendChild(li);
    });
  }

  // Top Priority Issues
  const topIssuesGrid = document.getElementById("top-issues-grid");
  topIssuesGrid.innerHTML = "";
  const issues = ai.top_issues || [];

  if (issues.length === 0) {
    topIssuesGrid.innerHTML = `
      <div class="issue-card">
        <p style="color:#94a3b8; font-size:0.88rem;">No critical blockers identified. Excellent baseline configuration.</p>
      </div>`;
  } else {
    issues.forEach(iss => {
      const card = document.createElement("div");
      card.className = "issue-card";
      const sev = (iss.severity || "info").toLowerCase();
      const cat = (iss.category || "security").toUpperCase();

      card.innerHTML = `
        <div class="issue-card-top">
          <span class="issue-cat">${cat}</span>
          <span class="issue-sev ${sev}">${sev.toUpperCase()}</span>
        </div>
        <h5 class="issue-title">${escapeHtml(iss.title)}</h5>
        <p class="issue-fix">🔧 ${escapeHtml(iss.recommendation || "")}</p>
      `;
      topIssuesGrid.appendChild(card);
    });
  }
}

// ── 5. Metric Tabs & Node Inspector ───────────────────────────────────────────

function renderMetricTabs(data) {
  const sec = data.security || {};
  const perf = data.performance || {};
  const lt = data.load_test || {};
  const findings = sec.security_findings || [];

  // Tab 1: Security Findings List
  const findingsList = document.getElementById("security-findings-list");
  document.getElementById("findings-count-pill").textContent = `${findings.length} Issues`;
  findingsList.innerHTML = "";

  if (findings.length === 0) {
    findingsList.innerHTML = `
      <li class="check-item">
        <span class="check-item-icon">✅</span>
        <div class="check-item-body">
          <strong>No Security Vulnerabilities Detected</strong>
          <span>Headers and cookie protections are configured according to baseline best practices.</span>
        </div>
      </li>
    `;
  } else {
    findings.forEach(f => {
      const li = document.createElement("li");
      li.className = "check-item";
      const sev = (f.severity || "info").toLowerCase();
      const icon = sev === "high" ? "❌" : (sev === "medium" ? "⚠️" : "ℹ️");

      li.innerHTML = `
        <span class="check-item-icon">${icon}</span>
        <div class="check-item-body">
          <strong>${escapeHtml(f.title || "Check Failed")} <span class="issue-sev ${sev}" style="display:inline-block; margin-left:6px;">${sev.toUpperCase()}</span></strong>
          <span>${escapeHtml(f.evidence || f.detail || "")}</span>
          <div class="check-item-source">Source: ${escapeHtml(f.source || "SiteSentinel")}</div>
        </div>
      `;
      findingsList.appendChild(li);
    });
  }

  // Response Headers
  const headers = sec.headers || {};
  const headerRows = Object.keys(headers).map(k => [k, headers[k]]);
  renderTable("headers-table", headerRows.length ? headerRows : [["No headers captured", "—"]]);

  // Tab 2: Performance
  const perfRows = [
    ["Response Time", fmt(perf.response_time_ms, " ms")],
    ["Status Code", fmt(perf.status_code)],
    ["Time to First Byte (TTFB)", fmt(perf.ttfb_ms, " ms")],
    ["Lighthouse Score", fmt(perf.lighthouse_score, " / 100")],
    ["Largest Contentful Paint (LCP)", fmt(perf.lcp_ms, " ms")],
    ["First Contentful Paint (FCP)", fmt(perf.fcp_ms, " ms")],
    ["Speed Index", fmt(perf.speed_index_ms, " ms")],
    ["Total Blocking Time (TBT)", fmt(perf.tbt_ms, " ms")],
    ["Cumulative Layout Shift (CLS)", fmt(perf.cls)],
    ["Total Page Weight", fmt(perf.page_weight_kb, " KB")]
  ];
  renderTable("perf-table", perfRows);

  const netRows = [
    ["Target URL", sec.target || data.target || "—"],
    ["Final URL", sec.final_url || data.target || "—"],
    ["HTTPS Enforced", sec.https ? "True" : "False"],
    ["HTTP Redirect Count", fmt(sec.redirect_count)],
    ["Total Scan Duration", `${((data.scan_duration_ms || 0) / 1000).toFixed(1)} s`]
  ];
  renderTable("network-table", netRows);

  // Tab 3: Load Test
  const loadRows = [
    ["Concurrent Virtual Users", fmt(lt.virtual_users)],
    ["Test Duration", fmt(lt.duration_seconds, " s")],
    ["p50 Latency", fmt(lt.p50_latency_ms, " ms")],
    ["p95 Latency", fmt(lt.p95_latency_ms, " ms")],
    ["Throughput Rate", fmt(lt.requests_per_second, " req/s")],
    ["Failure Rate", fmt(lt.failure_rate_pct, "%")]
  ];
  renderTable("load-table", loadRows);
}

function renderPartialErrors(errors) {
  const container = document.getElementById("scan-errors-container");
  container.innerHTML = "";
  if (!errors || errors.length === 0) return;

  const banner = document.createElement("div");
  banner.className = "error-banner";
  banner.innerHTML = `
    <strong>⚠️ Notice: ${errors.length} scan component(s) encountered notices — partial results rendered:</strong>
    <ul>
      ${errors.map(e => `<li>[${escapeHtml(e.source || 'module')}]: ${escapeHtml(e.message || '')}</li>`).join('')}
    </ul>
  `;
  container.appendChild(banner);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderTable(tableId, rows) {
  const tbody = document.querySelector(`#${tableId} tbody`);
  if (!tbody) return;
  tbody.innerHTML = rows.map(([label, val]) =>
    `<tr><td>${escapeHtml(String(label))}</td><td>${escapeHtml(String(val))}</td></tr>`
  ).join("");
}

function fmt(val, unit = "") {
  if (val === null || val === undefined || val === "") return "—";
  return `${val}${unit}`;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
