const jobsBody = document.querySelector("#jobsBody");
const agentsBody = document.querySelector("#agentsBody");
const jobCount = document.querySelector("#jobCount");
const agentCount = document.querySelector("#agentCount");
const createStatus = document.querySelector("#createStatus");
const refreshButton = document.querySelector("#refreshButton");
const createJobForm = document.querySelector("#createJobForm");

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
    jobsBody.innerHTML = `<tr><td colspan="7" class="empty">No jobs created</td></tr>`;
    return;
  }

  jobsBody.innerHTML = jobs.map((job) => {
    const spec = job.spec || {};
    const artifactLinks = [];
    if (job.artifacts && job.artifacts.flamegraph) {
      artifactLinks.push(`<a href="/api/jobs/${encodeURIComponent(job.job_id)}/artifacts/flamegraph" target="_blank">flamegraph</a>`);
    }
    if (job.artifacts && job.artifacts.hotspots) {
      artifactLinks.push(`<a href="/api/jobs/${encodeURIComponent(job.job_id)}/artifacts/hotspots" target="_blank">hotspots</a>`);
    }
    if (job.artifacts && job.artifacts.summary) {
      artifactLinks.push(`<a href="/api/jobs/${encodeURIComponent(job.job_id)}/artifacts/summary" target="_blank">summary</a>`);
    }
    const artifacts = artifactLinks.length ? artifactLinks.join(" ") : "-";
    return `
      <tr>
        <td class="mono">${escapeHtml(job.job_id)}</td>
        <td>${statusBadge(job.status)}</td>
        <td>${escapeHtml(spec.pid || "-")}</td>
        <td>${escapeHtml(spec.duration_seconds || "-")}s</td>
        <td>${escapeHtml(spec.sample_frequency || "-")}Hz</td>
        <td>${escapeHtml(job.reason || "-")}</td>
        <td>${artifacts}</td>
      </tr>
    `;
  }).join("");
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
refreshDashboard();
setInterval(refreshDashboard, 5000);
