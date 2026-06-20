const jobsBody = document.querySelector("#jobsBody");
const agentsBody = document.querySelector("#agentsBody");
const jobCount = document.querySelector("#jobCount");
const agentCount = document.querySelector("#agentCount");
const createStatus = document.querySelector("#createStatus");
const refreshButton = document.querySelector("#refreshButton");
const createJobForm = document.querySelector("#createJobForm");
const jobReportPanel = document.querySelector("#jobReportPanel");
const jobReportTitle = document.querySelector("#jobReportTitle");
const jobReportSubtitle = document.querySelector("#jobReportSubtitle");
const jobReportStatus = document.querySelector("#jobReportStatus");
const jobReportContent = document.querySelector("#jobReportContent");
const jobReportMeta = document.querySelector("#jobReportMeta");
const flamegraphOpenLink = document.querySelector("#flamegraphOpenLink");
const flamegraphFrame = document.querySelector("#flamegraphFrame");
const hotspotSummary = document.querySelector("#hotspotSummary");
const hotspotsBody = document.querySelector("#hotspotsBody");
const suggestionSummary = document.querySelector("#suggestionSummary");
const suggestionsBody = document.querySelector("#suggestionsBody");
const ebpfSummary = document.querySelector("#ebpfSummary");
const ebpfBody = document.querySelector("#ebpfBody");
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
    );
    const result = hasReport ? "analysis ready" : (job.reason || "-");
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
    return `
      <article class="suggestion">
        <div class="suggestion-head">
          <span class="badge ${escapeHtml(String(finding.severity || "INFO").toLowerCase())}">${escapeHtml(finding.severity || "INFO")}</span>
          <strong>${escapeHtml(finding.title || finding.rule_id || "Suggestion")}</strong>
        </div>
        <p class="mono">${escapeHtml(finding.function || "-")}</p>
        <p>${escapeHtml(finding.reason || finding.matched_condition || "")}</p>
        <p>Self ${escapeHtml(evidence.self_percent ?? 0)}%, inclusive ${escapeHtml(evidence.inclusive_percent ?? 0)}%.</p>
        <p>${escapeHtml(finding.advice || "")}</p>
        ${actions.length ? `<ol>${actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ol>` : ""}
      </article>
    `;
  }).join("");
}

function renderEbpfSyscalls(report) {
  const events = report && Array.isArray(report.events) ? report.events : [];
  ebpfSummary.textContent = report ? `${report.total_events || 0} event(s)` : "not available";
  if (events.length === 0) {
    ebpfBody.innerHTML = `<tr><td colspan="2" class="empty">No eBPF syscall data</td></tr>`;
    return;
  }

  ebpfBody.innerHTML = events.map((event) => `
    <tr>
      <td class="mono">${escapeHtml(event.event || "-")}</td>
      <td>${escapeHtml(event.count ?? 0)}</td>
    </tr>
  `).join("");
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
  ebpfBody.innerHTML = `<tr><td colspan="2" class="empty">Loading...</td></tr>`;
  suggestionsBody.innerHTML = `<p class="empty">Loading...</p>`;

  try {
    const job = await fetchJson(`/api/jobs/${encodeURIComponent(jobId)}`);
    const artifacts = job.artifacts || {};
    const [hotspots, suggestions, ebpfSyscalls] = await Promise.all([
      artifacts.hotspots ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/hotspots`) : Promise.resolve(null),
      artifacts.suggestions ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/suggestions`) : Promise.resolve(null),
      artifacts.ebpf_syscalls ? fetchJson(`/api/jobs/${encodeURIComponent(jobId)}/artifacts/ebpf_syscalls`) : Promise.resolve(null),
    ]);

    renderReportMeta(job);
    jobReportSubtitle.textContent = `${job.status || "UNKNOWN"} · PID ${(job.spec || {}).pid || "-"}`;
    if (artifacts.flamegraph) {
      const flamegraphUrl = `/api/jobs/${encodeURIComponent(jobId)}/artifacts/flamegraph`;
      flamegraphFrame.src = flamegraphUrl;
      flamegraphOpenLink.href = flamegraphUrl;
      flamegraphOpenLink.classList.remove("hidden");
    }
    renderHotspots(hotspots);
    renderEbpfSyscalls(ebpfSyscalls);
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
    const [jobs, agents] = await Promise.all([
      fetchJson("/api/jobs"),
      fetchJson("/api/agents"),
    ]);
    renderJobs(jobs);
    renderAgents(agents);
    if (!selectedJobId) {
      const latestReportJob = jobs.find((job) => job.artifacts && (
        job.artifacts.hotspots
        || job.artifacts.suggestions
        || job.artifacts.flamegraph
        || job.artifacts.ebpf_syscalls
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
  const payload = {
    pid: Number(document.querySelector("#pidInput").value),
    duration_seconds: Number(document.querySelector("#durationInput").value),
    sample_frequency: Number(document.querySelector("#frequencyInput").value),
    collector: document.querySelector("#collectorInput").value,
  };

  try {
    const job = await fetchJson("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    createStatus.textContent = `Created ${job.job_id}`;
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
