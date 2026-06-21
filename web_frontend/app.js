const jobsBody = document.querySelector("#jobsBody");
const agentsBody = document.querySelector("#agentsBody");
const continuousBody = document.querySelector("#continuousBody");
const jobCount = document.querySelector("#jobCount");
const agentCount = document.querySelector("#agentCount");
const continuousCount = document.querySelector("#continuousCount");
const createStatus = document.querySelector("#createStatus");
const refreshButton = document.querySelector("#refreshButton");
const createJobForm = document.querySelector("#createJobForm");
const jobReportPanel = document.querySelector("#jobReportPanel");
const jobReportTitle = document.querySelector("#jobReportTitle");
const jobReportSubtitle = document.querySelector("#jobReportSubtitle");
const jobReportStatus = document.querySelector("#jobReportStatus");
const jobReportContent = document.querySelector("#jobReportContent");
const jobReportMeta = document.querySelector("#jobReportMeta");
const diagnosisSummary = document.querySelector("#diagnosisSummary");
const diagnosisBody = document.querySelector("#diagnosisBody");
const attributionSummary = document.querySelector("#attributionSummary");
const attributionBody = document.querySelector("#attributionBody");
const llmSummary = document.querySelector("#llmSummary");
const llmBody = document.querySelector("#llmBody");
const flamegraphOpenLink = document.querySelector("#flamegraphOpenLink");
const flamegraphFrame = document.querySelector("#flamegraphFrame");
const hotspotSummary = document.querySelector("#hotspotSummary");
const hotspotsBody = document.querySelector("#hotspotsBody");
const suggestionSummary = document.querySelector("#suggestionSummary");
const suggestionsBody = document.querySelector("#suggestionsBody");
const ebpfSummary = document.querySelector("#ebpfSummary");
const ebpfBody = document.querySelector("#ebpfBody");
const ebpfLatencySummary = document.querySelector("#ebpfLatencySummary");
const ebpfLatencyBody = document.querySelector("#ebpfLatencyBody");
const ebpfLatencyChart = document.querySelector("#ebpfLatencyChart");
const ebpfDiffSummary = document.querySelector("#ebpfDiffSummary");
const ebpfDiffBody = document.querySelector("#ebpfDiffBody");
const pyspySummary = document.querySelector("#pyspySummary");
const pyspyBody = document.querySelector("#pyspyBody");
let selectedJobId = null;

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${text}`);
  }
  return response.json();
}

function statusBadge(status) {
  const normalized = String(status || "UNKNOWN").toLowerCase();
  return `<span class="badge ${normalized}">${escapeHtml(status || "UNKNOWN")}</span>`;
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderAgents(agents) {
  agentCount.textContent = String(agents.length);
  if (agents.length === 0) {
    agentsBody.innerHTML = `<tr><td colspan="6" class="empty">No agents registered</td></tr>`;
    return;
  }

  agentsBody.innerHTML = agents.map((agent) => `
    <tr>
      <td class="mono">${escapeHtml(agent.agent_id)}</td>
      <td>${statusBadge(agent.status)}</td>
      <td>${escapeHtml(agent.hostname || "-")}</td>
      <td>${escapeHtml(agent.pid || "-")}</td>
      <td>${escapeHtml(formatTime(agent.last_heartbeat_at))}</td>
      <td>${escapeHtml(agent.seconds_since_last_heartbeat ?? "-")}s</td>
    </tr>
  `).join("");
}

function renderContinuousProfiles(sessions) {
  continuousCount.textContent = String(sessions.length);
  if (sessions.length === 0) {
    continuousBody.innerHTML = `<tr><td colspan="5" class="empty">No continuous profiles</td></tr>`;
    return;
  }

  continuousBody.innerHTML = sessions.slice(0, 8).map((session) => {
    const counts = session.status_counts || {};
    const target = session.target || {};
    const slices = [
      counts.DONE ? `${counts.DONE} done` : null,
      counts.RUNNING ? `${counts.RUNNING} running` : null,
      counts.PENDING ? `${counts.PENDING} pending` : null,
      counts.FAILED ? `${counts.FAILED} failed` : null,
    ].filter(Boolean).join(" / ") || `${session.slice_count || 0} scheduled`;
    return `
      <tr>
        <td class="mono">${escapeHtml(session.session_id || "-")}</td>
        <td>${statusBadge(session.status)}</td>
        <td>${escapeHtml(session.collector || "-")}</td>
        <td>${escapeHtml(slices)}</td>
        <td>${escapeHtml(target.comm || target.cmdline || session.pid || "-")}</td>
      </tr>
    `;
  }).join("");
}

function renderJobs(jobs) {
  jobCount.textContent = String(jobs.length);
  if (jobs.length === 0) {
    jobsBody.innerHTML = `<tr><td colspan="4" class="empty">No jobs created</td></tr>`;
    return;
  }

  jobsBody.innerHTML = jobs.map((job) => {
    const spec = job.spec || {};
    const hasReport = job.artifacts && (
      job.artifacts.hotspots
      || job.artifacts.suggestions
      || job.artifacts.flamegraph
      || job.artifacts.ebpf_syscalls
      || job.artifacts.ebpf_io_latency
      || job.artifacts.pyspy_profile
    );
    const continuous = spec.continuous || null;
    const prefix = continuous ? `slice ${continuous.slice_index}/${continuous.slice_count} · ` : "";
    const result = prefix + (hasReport ? "analysis ready" : (job.reason || "-"));
    const selectedClass = job.job_id === selectedJobId ? "selected-row" : "";
    return `
      <tr class="${selectedClass}">
        <td class="mono"><button type="button" class="link-button" data-report-job="${escapeHtml(job.job_id)}">${escapeHtml(job.job_id)}</button></td>
        <td>${statusBadge(job.status)}</td>
        <td>${escapeHtml(spec.pid || "-")}</td>
        <td><span class="job-result">${escapeHtml(result)}</span></td>
      </tr>
    `;
  }).join("");
}

function renderReportMeta(job) {
  const spec = job.spec || {};
  const target = spec.target || {};
  const items = [
    ["Status", statusBadge(job.status)],
    ["PID", escapeHtml(spec.pid || "-")],
    ["Collector", escapeHtml(spec.collector || "-")],
    ["Duration", `${escapeHtml(spec.duration_seconds || "-")}s`],
    ["Frequency", `${escapeHtml(spec.sample_frequency || "-")}Hz`],
    ["Reason", escapeHtml(job.reason || "-")],
    ["Target", escapeHtml(target.comm || target.cmdline || "-")],
  ];

  jobReportMeta.innerHTML = items.map(([label, value]) => `
    <div>
      <span>${label}</span>
      <strong>${value}</strong>
    </div>
  `).join("");
}

function renderHotspots(report) {
  const hotspots = report && Array.isArray(report.hotspots) ? report.hotspots : [];
  hotspotSummary.textContent = report ? `${report.total_samples || 0} samples` : "not available";
  if (hotspots.length === 0) {
    hotspotsBody.innerHTML = `<tr><td colspan="5" class="empty">No hotspot data</td></tr>`;
    return;
  }

  hotspotsBody.innerHTML = hotspots.slice(0, 10).map((hotspot) => `
    <tr>
      <td class="mono">${escapeHtml(hotspot.function || "-")}</td>
      <td>${escapeHtml(hotspot.self_samples ?? 0)}</td>
      <td>${escapeHtml(hotspot.inclusive_samples ?? 0)}</td>
      <td>${escapeHtml(hotspot.self_percent ?? 0)}%</td>
      <td>${escapeHtml(hotspot.inclusive_percent ?? 0)}%</td>
    </tr>
  `).join("");
}

function renderSuggestions(report) {
  const findings = report && Array.isArray(report.findings) ? report.findings : [];
  suggestionSummary.textContent = report ? `${report.finding_count || findings.length} finding(s)` : "not available";
  if (findings.length === 0) {
    suggestionsBody.innerHTML = `<p class="empty">No rule-based suggestions</p>`;
    return;
  }

  suggestionsBody.innerHTML = findings.map((finding) => {
    const evidence = finding.evidence || {};
    const actions = Array.isArray(finding.next_actions) ? finding.next_actions : [];
    const evidenceText = formatFindingEvidence(evidence);
    return `
      <article class="suggestion">
        <div class="suggestion-head">
          <span class="badge ${escapeHtml(String(finding.severity || "INFO").toLowerCase())}">${escapeHtml(finding.severity || "INFO")}</span>
          <strong>${escapeHtml(finding.title || finding.rule_id || "Suggestion")}</strong>
        </div>
        <p class="mono">${escapeHtml(finding.function || finding.target || "-")}</p>
        <p>${escapeHtml(finding.reason || finding.matched_condition || "")}</p>
        ${evidenceText ? `<p>${escapeHtml(evidenceText)}</p>` : ""}
        <p>${escapeHtml(finding.advice || "")}</p>
        ${actions.length ? `<ol>${actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ol>` : ""}
      </article>
    `;
  }).join("");
}

function renderDiagnosticReport(report) {
  if (!report) {
    diagnosisSummary.textContent = "not available";
    diagnosisBody.innerHTML = `<p class="empty">No diagnostic report</p>`;
    return;
  }

  const severity = report.severity || "INFO";
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const actions = Array.isArray(report.next_actions) ? report.next_actions : [];
  const dataQuality = Array.isArray(report.data_quality) ? report.data_quality : [];
  const sections = Array.isArray(report.sections) ? report.sections : [];
  diagnosisSummary.textContent = `${severity} / ${report.finding_count || findings.length} finding(s)`;

  const overviewSections = sections
    .filter((section) => ["cpu_hotspots", "ebpf_syscalls", "ebpf_io_latency", "python_profile", "baseline_diff"].includes(section.section_id))
    .slice(0, 4);

  diagnosisBody.innerHTML = `
    <div class="diagnosis-headline">
      <span class="badge ${escapeHtml(String(severity).toLowerCase())}">${escapeHtml(severity)}</span>
      <p>${escapeHtml(report.summary || "-")}</p>
    </div>
    ${findings.length ? `
      <div class="diagnosis-block">
        <h4>Key Findings</h4>
        <ul>
          ${findings.slice(0, 4).map((finding) => `
            <li>
              <strong>${escapeHtml(finding.title || finding.rule_id || "Finding")}</strong>
              <span>${escapeHtml(finding.reason || finding.matched_condition || finding.advice || "")}</span>
            </li>
          `).join("")}
        </ul>
      </div>
    ` : ""}
    ${actions.length ? `
      <div class="diagnosis-block">
        <h4>Next Actions</h4>
        <ol>
          ${actions.slice(0, 5).map((action) => `<li>${escapeHtml(action)}</li>`).join("")}
        </ol>
      </div>
    ` : ""}
    ${overviewSections.length ? `
      <div class="diagnosis-grid">
        ${overviewSections.map(renderDiagnosticSection).join("")}
      </div>
    ` : ""}
    ${dataQuality.length ? `
      <div class="diagnosis-block warning">
        <h4>Data Quality</h4>
        <ul>${dataQuality.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
      </div>
    ` : ""}
  `;
}

function renderDiagnosticSection(section) {
  const items = Array.isArray(section.items) ? section.items : [];
  return `
    <article class="diagnosis-section">
      <h4>${escapeHtml(section.title || section.section_id || "Section")}</h4>
      <dl>
        ${items.slice(0, 4).map((item) => `
          <div>
            <dt>${escapeHtml(item.label || "-")}</dt>
            <dd>${escapeHtml(item.value ?? "-")}</dd>
          </div>
        `).join("")}
      </dl>
    </article>
  `;
}

function renderAttribution(report) {
  if (!report) {
    attributionSummary.textContent = "not available";
    attributionBody.innerHTML = `<p class="empty">No attribution report</p>`;
    return;
  }

  const claims = Array.isArray(report.claims) ? report.claims : [];
  attributionSummary.textContent = `${report.severity || "INFO"} / ${report.claim_count || claims.length} claim(s)`;
  if (claims.length === 0) {
    attributionBody.innerHTML = `
      <div class="attribution-empty">
        <span class="badge ok">OK</span>
        <p>${escapeHtml(report.summary || "No clear root-cause hypothesis")}</p>
      </div>
    `;
    return;
  }

  attributionBody.innerHTML = `
    <p class="attribution-summary">${escapeHtml(report.summary || "")}</p>
    ${claims.slice(0, 4).map((claim) => {
      const evidence = Array.isArray(claim.evidence) ? claim.evidence : [];
      const actions = Array.isArray(claim.next_actions) ? claim.next_actions : [];
      const missingEvidence = Array.isArray(claim.missing_evidence) ? claim.missing_evidence : [];
      const evidenceSources = Array.isArray(claim.evidence_sources) ? claim.evidence_sources : [];
      const evidenceLimit = claim.claim_type === "fusion" ? 6 : 2;
      return `
        <article class="attribution-card">
          <div class="attribution-head">
            <div>
              <strong>${escapeHtml(claim.title || claim.claim_id || "Root cause claim")}</strong>
              <p>${escapeHtml(claim.root_cause || "-")}</p>
              <p class="attribution-meta">
                ${escapeHtml(claim.claim_type || "single")} ·
                ${escapeHtml(claim.triage_priority || "P4")} · score ${escapeHtml(claim.confidence_score ?? "-")} ·
                ${escapeHtml(claim.evidence_count ?? evidence.length)} evidence ·
                ${escapeHtml(evidenceSources.join(", ") || "no source")}
              </p>
            </div>
            <div class="attribution-badges">
              <span class="badge priority">${escapeHtml(claim.triage_priority || "P4")}</span>
              <span class="badge ${escapeHtml(String(claim.severity || "INFO").toLowerCase())}">${escapeHtml(claim.severity || "INFO")}</span>
              <span class="badge confidence">${escapeHtml(claim.confidence || "LOW")}</span>
            </div>
          </div>
          ${evidence.length ? `
            <div class="attribution-evidence">
              <h4>Evidence</h4>
              <ul>
                ${evidence.slice(0, evidenceLimit).map((item) => `
                  <li>
                    <span>${escapeHtml(item.source || "-")}</span>
                    ${escapeHtml(item.summary || item.evidence_id || "-")}
                  </li>
                `).join("")}
              </ul>
            </div>
          ` : ""}
          ${missingEvidence.length ? `
            <div class="attribution-missing">
              <h4>Missing Evidence</h4>
              <ul>${missingEvidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
            </div>
          ` : ""}
          ${actions.length ? `
            <div class="attribution-actions">
              <h4>Next Actions</h4>
              <ol>${actions.slice(0, 3).map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ol>
            </div>
          ` : ""}
        </article>
      `;
    }).join("")}
  `;
}

function renderLlmReport(report) {
  if (!report) {
    llmSummary.textContent = "not available";
    llmBody.innerHTML = `<p class="empty">No LLM report</p>`;
    return;
  }

  const mode = report.mode || "template";
  const provider = report.provider || "template";
  const keyPoints = Array.isArray(report.key_points) ? report.key_points : [];
  const recommendations = Array.isArray(report.recommendations) ? report.recommendations : [];
  const evidence = Array.isArray(report.evidence_used) ? report.evidence_used : [];
  llmSummary.textContent = `${mode} / ${provider}`;
  llmBody.innerHTML = `
    <article class="llm-card">
      <div class="llm-headline">
        <span class="badge ${escapeHtml(String(report.severity || "INFO").toLowerCase())}">${escapeHtml(report.severity || "INFO")}</span>
        <p>${escapeHtml(report.summary || "-")}</p>
      </div>
      ${keyPoints.length ? `
        <div class="llm-block">
          <h4>Key Points</h4>
          <ul>${keyPoints.map((point) => `<li>${escapeHtml(point)}</li>`).join("")}</ul>
        </div>
      ` : ""}
      ${recommendations.length ? `
        <div class="llm-block">
          <h4>Recommendations</h4>
          <ol>${recommendations.slice(0, 5).map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ol>
        </div>
      ` : ""}
      ${evidence.length ? `
        <div class="llm-block">
          <h4>Evidence Used</h4>
          <ul>
            ${evidence.slice(0, 6).map((item) => `
              <li class="mono">${escapeHtml(item.type || "-")}: ${escapeHtml(item.id || item.job_id || item.collector || "-")}</li>
            `).join("")}
          </ul>
        </div>
      ` : ""}
      ${report.llm_error ? `<p class="llm-warning">LLM fallback: ${escapeHtml(report.llm_error)}</p>` : ""}
      <details class="llm-markdown">
        <summary>Markdown</summary>
        <pre>${escapeHtml(report.markdown || "")}</pre>
      </details>
    </article>
  `;
}

function formatFindingEvidence(evidence) {
  if (evidence.self_percent !== undefined || evidence.inclusive_percent !== undefined) {
    return `Self ${evidence.self_percent ?? 0}%, inclusive ${evidence.inclusive_percent ?? 0}%.`;
  }
  const parts = [];
  if (evidence.count !== undefined) parts.push(`count ${evidence.count}`);
  if (evidence.rate_per_second !== undefined) parts.push(`rate ${evidence.rate_per_second}/s`);
  if (evidence.read_per_second !== undefined) parts.push(`read ${evidence.read_per_second}/s`);
  if (evidence.write_per_second !== undefined) parts.push(`write ${evidence.write_per_second}/s`);
  if (evidence.p50_bucket !== undefined) parts.push(`p50 ${evidence.p50_bucket}`);
  if (evidence.p99_bucket !== undefined) parts.push(`p99 ${evidence.p99_bucket}`);
  if (evidence.tail_1ms_percent !== undefined) parts.push(`tail >=1ms ${evidence.tail_1ms_percent}%`);
  return parts.join(", ");
}

function renderEbpfSyscalls(report) {
  const events = report && Array.isArray(report.events) ? report.events : [];
  ebpfSummary.textContent = report
    ? `${report.total_events || 0} event(s) / ${report.duration_seconds || "-"}s`
    : "not available";
  if (events.length === 0) {
    ebpfBody.innerHTML = `<tr><td colspan="3" class="empty">No eBPF syscall data</td></tr>`;
    return;
  }

  ebpfBody.innerHTML = events.map((event) => `
    <tr>
      <td class="mono">${escapeHtml(event.event || "-")}</td>
      <td>${escapeHtml(event.count ?? 0)}</td>
      <td>${escapeHtml(event.rate_per_second ?? 0)}</td>
    </tr>
  `).join("");
}

function renderEbpfLatency(report) {
  const events = report && Array.isArray(report.events) ? report.events : [];
  ebpfLatencySummary.textContent = report
    ? `${report.total_events || 0} event(s) / ${report.duration_seconds || "-"}s`
    : "not available";
  if (events.length === 0) {
    ebpfLatencyChart.innerHTML = `<p class="empty">No eBPF IO latency data</p>`;
    ebpfLatencyBody.innerHTML = `<tr><td colspan="4" class="empty">No eBPF IO latency data</td></tr>`;
    return;
  }

  ebpfLatencyChart.innerHTML = renderLatencyChart(events);
  const rows = [];
  for (const event of events) {
    const histogram = Array.isArray(event.histogram) ? event.histogram : [];
    for (const bucket of histogram) {
      rows.push(`
        <tr>
          <td class="mono">${escapeHtml(event.event || "-")}</td>
          <td>${escapeHtml(bucket.bucket || "-")}</td>
          <td>${escapeHtml(bucket.count ?? 0)}</td>
          <td>${escapeHtml(bucket.percent ?? 0)}%</td>
        </tr>
      `);
    }
  }
  ebpfLatencyBody.innerHTML = rows.join("");
}

function renderLatencyChart(events) {
  const maxCount = Math.max(
    1,
    ...events.flatMap((event) => {
      const histogram = Array.isArray(event.histogram) ? event.histogram : [];
      return histogram.map((bucket) => Number(bucket.count || 0));
    }),
  );

  return events.map((event) => {
    const histogram = Array.isArray(event.histogram) ? event.histogram : [];
    const eventName = String(event.event || "unknown").toLowerCase();
    return `
      <div class="latency-group">
        <div class="latency-group-title">
          <strong>${escapeHtml(event.event || "-")}</strong>
          <span>p50 ${escapeHtml(event.p50_bucket || "-")} / p99 ${escapeHtml(event.p99_bucket || "-")}</span>
        </div>
        <div class="latency-bars">
          ${histogram.map((bucket) => renderLatencyBar(bucket, maxCount, eventName)).join("")}
        </div>
      </div>
    `;
  }).join("");
}

function renderLatencyBar(bucket, maxCount, eventName) {
  const count = Number(bucket.count || 0);
  const width = Math.max(0, Math.min(100, (count / maxCount) * 100));
  const widthText = width.toFixed(2);
  return `
    <div class="latency-row">
      <span class="latency-label">${escapeHtml(bucket.bucket || "-")}</span>
      <div class="latency-track" aria-label="${escapeHtml(bucket.bucket || "-")} ${escapeHtml(count)} samples">
        <span class="latency-fill ${escapeHtml(eventName)}" style="width: ${widthText}%"></span>
      </div>
      <span class="latency-value">${escapeHtml(bucket.percent ?? 0)}%</span>
    </div>
  `;
}

function renderLatencyDiff(report) {
  if (!report || report.comparison_available === false) {
    ebpfDiffSummary.textContent = report ? "no baseline" : "not available";
    ebpfDiffBody.innerHTML = `<p class="empty">${escapeHtml(report?.reason || "No eBPF latency diff data")}</p>`;
    return;
  }

  const events = Array.isArray(report.events) ? report.events : [];
  ebpfDiffSummary.textContent = `baseline ${report.baseline_job_id || "-"} / ${report.finding_count || 0} finding(s)`;
  if (events.length === 0) {
    ebpfDiffBody.innerHTML = `<p class="empty">No comparable latency events</p>`;
    return;
  }

  ebpfDiffBody.innerHTML = events.map((event) => {
    const verdict = event.verdict || "similar";
    const tailDelta = Number(event.tail_1ms_percent_delta || 0);
    return `
      <article class="diff-card ${escapeHtml(verdict)}">
        <div class="diff-card-head">
          <strong>${escapeHtml(event.event || "-")}</strong>
          <span class="badge ${escapeHtml(verdict)}">${escapeHtml(verdict)}</span>
        </div>
        <dl>
          <div>
            <dt>tail >=1ms</dt>
            <dd>${escapeHtml(event.baseline_tail_1ms_percent ?? 0)}% -> ${escapeHtml(event.current_tail_1ms_percent ?? 0)}% (${formatSigned(tailDelta)} pts)</dd>
          </div>
          <div>
            <dt>p99</dt>
            <dd>${escapeHtml(event.baseline_p99_bucket || "-")} -> ${escapeHtml(event.current_p99_bucket || "-")}</dd>
          </div>
          <div>
            <dt>samples</dt>
            <dd>${escapeHtml(event.baseline_total_count ?? 0)} -> ${escapeHtml(event.current_total_count ?? 0)}</dd>
          </div>
        </dl>
      </article>
    `;
  }).join("");
}

function renderPyspyProfile(report) {
  const hotspots = report && Array.isArray(report.hotspots) ? report.hotspots : [];
  pyspySummary.textContent = report ? `${report.total_samples || 0} samples` : "not available";
  if (hotspots.length === 0) {
    pyspyBody.innerHTML = `<tr><td colspan="4" class="empty">No Python profile data</td></tr>`;
    return;
  }

  pyspyBody.innerHTML = hotspots.slice(0, 10).map((hotspot) => {
    const location = hotspot.file ? `${hotspot.file}:${hotspot.line || "-"}` : "-";
    return `
      <tr>
        <td class="mono">${escapeHtml(hotspot.function || "-")}</td>
        <td>${escapeHtml(hotspot.self_percent ?? 0)}%</td>
        <td>${escapeHtml(hotspot.inclusive_percent ?? 0)}%</td>
        <td class="mono">${escapeHtml(location)}</td>
      </tr>
    `;
  }).join("");
}

function formatSigned(value) {
  if (value > 0) return `+${value}`;
  return String(value);
}

async function loadJobReport(jobId, options = {}) {
  selectedJobId = jobId;
  document.querySelectorAll("#jobsBody tr").forEach((row) => row.classList.remove("selected-row"));
  const selectedButton = Array.from(document.querySelectorAll("[data-report-job]"))
    .find((button) => button.dataset.reportJob === jobId);
  if (selectedButton) selectedButton.closest("tr").classList.add("selected-row");

  jobReportTitle.textContent = jobId;
  jobReportSubtitle.textContent = "Loading analysis artifacts";
  jobReportStatus.textContent = "Loading...";
  flamegraphFrame.removeAttribute("src");
  flamegraphOpenLink.classList.add("hidden");
  hotspotsBody.innerHTML = `<tr><td colspan="5" class="empty">Loading...</td></tr>`;
  ebpfBody.innerHTML = `<tr><td colspan="3" class="empty">Loading...</td></tr>`;
  ebpfLatencyChart.innerHTML = `<p class="empty">Loading...</p>`;
  ebpfLatencyBody.innerHTML = `<tr><td colspan="4" class="empty">Loading...</td></tr>`;
  ebpfDiffSummary.textContent = "";
  ebpfDiffBody.innerHTML = `<p class="empty">Loading...</p>`;
  pyspySummary.textContent = "";
  pyspyBody.innerHTML = `<tr><td colspan="4" class="empty">Loading...</td></tr>`;
  diagnosisSummary.textContent = "";
  diagnosisBody.innerHTML = `<p class="empty">Loading...</p>`;
  attributionSummary.textContent = "";
  attributionBody.innerHTML = `<p class="empty">Loading...</p>`;
  llmSummary.textContent = "";
  llmBody.innerHTML = `<p class="empty">Loading...</p>`;
  suggestionsBody.innerHTML = `<p class="empty">Loading...</p>`;

  try {
    const job = await fetchJson(`/api/jobs/${encodeURIComponent(jobId)}`);
    const artifacts = job.artifacts || {};
    const [diagnosticReport, attributionReport, llmReport, hotspots, suggestions, ebpfSyscalls, ebpfLatency, ebpfLatencyDiff, pyspyProfile] = await Promise.all([
      fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/report`),
      fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/attribution`),
      fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/llm-report`),
      artifacts.hotspots ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/hotspots`) : Promise.resolve(null),
      artifacts.suggestions ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/suggestions`) : Promise.resolve(null),
      artifacts.ebpf_syscalls ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/ebpf_syscalls`) : Promise.resolve(null),
      artifacts.ebpf_io_latency ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/ebpf_io_latency`) : Promise.resolve(null),
      artifacts.ebpf_io_latency ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/compare/ebpf-io-latency`) : Promise.resolve(null),
      artifacts.pyspy_profile ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/pyspy_profile`) : Promise.resolve(null),
    ]);

    renderReportMeta(job);
    jobReportSubtitle.textContent = `${job.status || "UNKNOWN"} / PID ${(job.spec || {}).pid || "-"}`;
    if (artifacts.flamegraph) {
      const flamegraphUrl = `/api/jobs/${encodeURIComponent(jobId)}/artifacts/flamegraph`;
      flamegraphFrame.src = flamegraphUrl;
      flamegraphOpenLink.href = flamegraphUrl;
      flamegraphOpenLink.classList.remove("hidden");
    }
    renderDiagnosticReport(diagnosticReport);
    renderAttribution(attributionReport);
    renderLlmReport(llmReport);
    renderHotspots(hotspots);
    renderEbpfSyscalls(ebpfSyscalls);
    renderEbpfLatency(ebpfLatency);
    renderLatencyDiff(ebpfLatencyDiff);
    renderPyspyProfile(pyspyProfile);
    renderSuggestions(suggestions);
    jobReportStatus.textContent = job.status === "DONE" ? "Analysis ready" : "Artifacts may be incomplete";
    if (options.scroll && window.matchMedia("(max-width: 1180px)").matches) {
      jobReportPanel.scrollIntoView({ block: "start", behavior: "smooth" });
    }
  } catch (error) {
    jobReportStatus.textContent = error.message;
  }
}

async function refreshDashboard() {
  refreshButton.disabled = true;
  try {
    const [jobs, agents, sessions] = await Promise.all([
      fetchJson("/api/jobs"),
      fetchJson("/api/agents"),
      fetchJson("/api/continuous-profiles"),
    ]);
    renderJobs(jobs);
    renderAgents(agents);
    renderContinuousProfiles(sessions);
    if (!selectedJobId) {
      const latestReportJob = jobs.find((job) => job.artifacts && (
        job.artifacts.hotspots
        || job.artifacts.suggestions
        || job.artifacts.flamegraph
        || job.artifacts.ebpf_syscalls
        || job.artifacts.ebpf_io_latency
        || job.artifacts.pyspy_profile
      ));
      if (latestReportJob) {
        loadJobReport(latestReportJob.job_id);
      }
    }
  } catch (error) {
    createStatus.textContent = error.message;
  } finally {
    refreshButton.disabled = false;
  }
}

createJobForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  createStatus.textContent = "Creating...";
  const continuous = document.querySelector("#continuousInput").checked;
  const payload = {
    pid: Number(document.querySelector("#pidInput").value),
    duration_seconds: Number(document.querySelector("#durationInput").value),
    sample_frequency: Number(document.querySelector("#frequencyInput").value),
    collector: document.querySelector("#collectorInput").value,
  };

  try {
    const url = continuous ? "/api/continuous-profiles" : "/api/jobs";
    const body = continuous
      ? {
          pid: payload.pid,
          slice_duration_seconds: payload.duration_seconds,
          sample_frequency: payload.sample_frequency,
          collector: payload.collector,
          slice_count: Number(document.querySelector("#sliceCountInput").value),
          interval_seconds: Number(document.querySelector("#intervalInput").value),
        }
      : payload;
    const created = await fetchJson(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    createStatus.textContent = continuous
      ? `Created ${created.session_id}`
      : `Created ${created.job_id}`;
    await refreshDashboard();
  } catch (error) {
    createStatus.textContent = error.message;
  }
});

refreshButton.addEventListener("click", refreshDashboard);
jobsBody.addEventListener("click", (event) => {
  const button = event.target.closest("[data-report-job]");
  if (!button) return;
  loadJobReport(button.dataset.reportJob, { scroll: true });
});
refreshDashboard();
setInterval(refreshDashboard, 5000);
