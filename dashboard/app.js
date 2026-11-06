const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
let dashboardData = null;

const byId = (id) => document.getElementById(id);
const formatName = (name) => name.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
const formatTime = (value) => value ? new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium", timeStyle: "short"
}).format(new Date(value)) : "—";

function calculateScore(findings) {
  const deductions = { Critical: 30, High: 18, Medium: 8, Low: 3 };
  return Math.max(0, 100 - findings.reduce((total, item) => total + (deductions[item.severity] || 0), 0));
}

function renderFindings(filter = "all") {
  const container = byId("findings");
  const findings = dashboardData.latest_scan.findings
    .filter((item) => filter === "all" || item.severity === filter)
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
  container.replaceChildren();

  if (!findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    const title = document.createElement("strong");
    title.textContent = filter === "all" ? "No open findings" : `No ${filter} findings`;
    const detail = document.createElement("span");
    detail.textContent = "The latest completed scan did not detect an issue in this category.";
    empty.append(title, detail);
    container.append(empty);
    return;
  }

  findings.forEach((item) => {
    const row = document.createElement("article");
    row.className = "finding";
    const severity = document.createElement("span");
    severity.className = `severity ${item.severity}`;
    severity.textContent = item.severity;
    const body = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = item.rule_id;
    const resource = document.createElement("p");
    resource.className = "resource";
    resource.textContent = item.resource_id;
    const description = document.createElement("p");
    description.textContent = item.description;
    const recommendation = document.createElement("p");
    recommendation.textContent = `Recommended: ${item.recommendation}`;
    body.append(title, resource, description, recommendation);
    row.append(severity, body);
    container.append(row);
  });
}

function renderSeverityBreakdown(counts, total) {
  const container = byId("severityBreakdown");
  const levels = ["Critical", "High", "Medium", "Low"];
  const peak = Math.max(1, ...levels.map((level) => counts[level] || 0));
  byId("findingTotal").textContent = `${total} finding${total === 1 ? "" : "s"}`;
  container.replaceChildren();

  levels.forEach((level) => {
    const count = counts[level] || 0;
    const row = document.createElement("button");
    row.type = "button";
    row.className = "severity-row";
    row.setAttribute("aria-label", `Filter ${level} findings, ${count}`);
    row.title = `Show ${level.toLowerCase()} findings`;
    const label = document.createElement("span");
    label.className = `severity-label ${level}`;
    label.textContent = level;
    const track = document.createElement("span");
    track.className = "severity-track";
    const fill = document.createElement("span");
    fill.className = `severity-fill ${level}`;
    fill.style.width = `${(count / peak) * 100}%`;
    track.append(fill);
    const value = document.createElement("strong");
    value.textContent = count;
    row.append(label, track, value);
    container.append(row);
  });

  const insight = byId("riskInsight");
  const priority = levels.find((level) => counts[level] > 0);
  insight.className = `risk-insight${priority ? ` has-${priority.toLowerCase()}` : ""}`;
  insight.replaceChildren();
  const icon = document.createElement("span");
  icon.className = "insight-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "";
  icon.classList.toggle("has-priority", Boolean(priority));
  const copy = document.createElement("div");
  const title = document.createElement("strong");
  const detail = document.createElement("p");
  if (priority) {
    title.textContent = `${priority} findings need attention`;
    detail.textContent = `Start with ${counts[priority]} ${priority.toLowerCase()} item${counts[priority] === 1 ? "" : "s"}. Select this severity to jump straight to the matching findings.`;
  } else {
    title.textContent = "All clear";
    detail.textContent = "No open findings in the latest scan. Keep your scheduled scans running to catch new changes.";
  }
  copy.append(title, detail);
  insight.append(icon, copy);
}

function render(data) {
  dashboardData = data;
  const scan = data.latest_scan;
  const findings = scan.findings || [];
  const counts = findings.reduce((result, item) => {
    result[item.severity] = (result[item.severity] || 0) + 1;
    return result;
  }, {});
  const resources = Object.values(scan.resources_scanned || {}).reduce((a, b) => a + b, 0);
  const score = calculateScore(findings);

  const badge = byId("scanBadge");
  badge.textContent = scan.demo_mode ? "Demo data · synthetic" : scan.scan_status === "complete" ? "Scan complete" : "Scan incomplete";
  badge.className = `status-badge ${scan.scan_status}`;
  if (scan.scan_status === "incomplete") {
    const errorDetails = (scan.errors || []).map((e) => e.message || e.check).join("; ");
    badge.title = errorDetails ? `Errors: ${errorDetails}` : "Scan incomplete";
  } else {
    badge.title = "All checks completed successfully";
  }
  byId("securityScore").textContent = score;
  byId("scoreCaption").textContent = score === 100 ? "No issues detected" : `${findings.length} open finding${findings.length === 1 ? "" : "s"}`;
  byId("criticalCount").textContent = counts.Critical || 0;
  byId("highCount").textContent = counts.High || 0;
  byId("resourceCount").textContent = resources;
  byId("scanTime").textContent = formatTime(scan.scan_time);
  byId("scanRegion").textContent = scan.demo_mode ? "DEMO · SYNTHETIC" : `AWS · ${scan.region || "region unavailable"}`;
  byId("demoNotice").textContent = scan.demo_mode
    ? findings.length
      ? "Showing five sample findings. This data is illustrative and is not from an AWS scan."
      : "Showing a synthetic sample scan. This data is not from AWS."
    : "Current view uses the dashboard scan data.";

  // Update sticky HUD bar
  const hudScore = byId("hudScore");
  const hudCard = byId("hudScoreCard");
  const hudFindings = byId("hudFindings");
  if (hudScore) {
    hudScore.textContent = score;
    const tone = score >= 80 ? "good" : score >= 50 ? "warn" : "bad";
    hudScore.className = `hud-score ${tone}`;
    if (hudCard) hudCard.className = `hud-score-card ${tone}`;
  }
  if (hudFindings) {
    hudFindings.textContent = score === 100 ? "0 findings" : `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  }

  // Update quick metrics on the live testing page
  if (byId("demoCriticalCount")) byId("demoCriticalCount").textContent = counts.Critical || 0;
  if (byId("demoHighCount")) byId("demoHighCount").textContent = counts.High || 0;
  if (byId("demoResourceCount")) byId("demoResourceCount").textContent = resources;
  if (byId("demoScanTime")) byId("demoScanTime").textContent = formatTime(scan.scan_time);
  if (byId("demoRegionTag")) byId("demoRegionTag").textContent = scan.demo_mode ? "DEMO" : (scan.region || "eu-north-1");

  renderSeverityBreakdown(counts, findings.length);

  const coverage = byId("coverage");
  coverage.replaceChildren();
  Object.entries(scan.resources_scanned || {}).forEach(([name, value]) => {
    const item = document.createElement("div");
    item.className = "coverage-item";
    const label = document.createElement("span");
    label.textContent = formatName(name);
    const count = document.createElement("strong");
    count.textContent = value;
    const track = document.createElement("span");
    track.className = "coverage-track";
    track.setAttribute("aria-label", `${value} checked`);
    const fill = document.createElement("span");
    fill.style.width = `${resources ? (value / resources) * 100 : 0}%`;
    track.append(fill);
    item.append(label, count, track);
    coverage.append(item);
  });

  const history = byId("history");
  history.replaceChildren();
  (data.scan_history || []).slice(0, 5).forEach((entry) => {
    const row = document.createElement("div");
    row.className = "history-row";
    const detail = document.createElement("div");
    const title = document.createElement("p");
    title.textContent = entry.scan_status === "complete" ? "Completed scan" : "Incomplete scan";
    const time = document.createElement("span");
    time.textContent = formatTime(entry.scan_time);
    detail.append(title, time);
    const count = document.createElement("strong");
    count.className = "history-count";
    count.textContent = `${entry.finding_count || 0} findings`;
    row.append(detail, count);
    history.append(row);
  });
  if (!history.children.length) history.textContent = "No historical scans available.";

  renderFindings();
}

byId("severityFilter").addEventListener("change", (event) => renderFindings(event.target.value));
byId("severityBreakdown").addEventListener("click", (event) => {
  const row = event.target.closest(".severity-row");
  if (!row) return;
  const level = row.querySelector(".severity-label").textContent;
  byId("severityFilter").value = level;
  renderFindings(level);
  byId("findings").scrollIntoView({ behavior: "smooth", block: "start" });
});

const startCommands = byId("startCommands").textContent;
byId("copyStart").addEventListener("click", async () => {
  const button = byId("copyStart");
  try {
    await navigator.clipboard.writeText(startCommands);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Select to copy";
  }
  setTimeout(() => button.textContent = "Copy", 1600);
});

const demoTimestamp = new Date().toISOString();
const demoFindings = [
  ["SG_UNRESTRICTED_SSH", "EC2", "sg-demo-ssh", "SSH is allowed from any IPv4 address.", "Restrict SSH access to approved IP ranges."],
  ["SG_UNRESTRICTED_RDP", "EC2", "sg-demo-rdp", "RDP is allowed from any IPv4 address.", "Restrict RDP access to approved IP ranges."],
  ["EBS_VOLUME_UNENCRYPTED", "EBS", "vol-demo-01", "The sample EBS volume is not encrypted at rest.", "Use an encrypted volume and snapshot."],
  ["RDS_PUBLICLY_ACCESSIBLE", "RDS", "db-demo-01", "The sample database has a public endpoint enabled.", "Disable public access and use private networking."],
  ["RDS_STORAGE_UNENCRYPTED", "RDS", "db-demo-01", "The sample database storage is not encrypted at rest.", "Migrate to an encrypted database instance."],
];
const demoData = {
  latest_scan: {
    scan_time: demoTimestamp,
    region: "demo",
    scan_status: "complete",
    demo_mode: true,
    resources_scanned: { security_groups: 2, ebs_volumes: 1, rds_instances: 1, s3_buckets: 0 },
    findings: demoFindings.map(([rule_id, service, resource_id, description, recommendation], index) => ({
      finding_id: `DEMO-${String(index + 1).padStart(2, "0")}`,
      rule_id,
      service,
      resource_id,
      severity: "High",
      description,
      recommendation,
    })),
    errors: [],
  },
  scan_history: [{ scan_time: demoTimestamp, scan_status: "complete", finding_count: 5 }],
};
byId("loadDemo").addEventListener("click", () => render(demoData));
byId("loadLive").addEventListener("click", () => loadDashboard().catch(error => {
  byId("demoNotice").textContent = `Could not load current dashboard data: ${error.message}`;
}));
byId("scanButton").addEventListener("click", async () => {
  const button = byId("scanButton"); button.disabled = true; button.textContent = "Scanning…";
  try {
    const response = await fetch("/api/scan", { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Scan failed");
    byId("scanCommand").textContent = `${result.command}: ${result.result.scan_status}, ${result.result.resources_scanned} resources checked, ${result.result.findings} finding(s)`;
    await loadDashboard();
  } catch (error) {
    byId("scanCommand").textContent = `Scan failed: ${error.message}`;
  } finally { button.disabled = false; button.textContent = "Run scan"; }
});
byId("themeToggle").addEventListener("click", () => {
  const light = document.documentElement.dataset.theme === "dark";
  document.documentElement.dataset.theme = light ? "light" : "dark";
  byId("themeToggle").textContent = light ? "Use dark mode" : "Use light mode";
  localStorage.setItem("scanner-theme", light ? "light" : "dark");
});
const savedTheme = localStorage.getItem("scanner-theme");
document.documentElement.dataset.theme = savedTheme || "light";
byId("themeToggle").textContent = document.documentElement.dataset.theme === "light" ? "Use dark mode" : "Use light mode";
const loadDashboard = () => fetch(`dashboard-data.json?_t=${Date.now()}`, { cache: "no-store" })
  .then((response) => response.ok ? response.json() : fetch(`dashboard-data.example.json?_t=${Date.now()}`).then((sample) => sample.json()))
  .then(render);
loadDashboard().catch(error => {
  byId("scanBadge").textContent = "Dashboard data unavailable";
  byId("scanBadge").className = "status-badge incomplete";
  const message = document.createElement("div"); message.className = "empty error"; message.textContent = error.message; byId("findings").replaceChildren(message);
});

document.addEventListener("click", async (event) => {
  const copyBtn = event.target.closest(".copy-cli-btn");
  if (copyBtn) {
    const targetId = copyBtn.getAttribute("data-target");
    const targetEl = document.getElementById(targetId);
    if (!targetEl) return;
    try {
      await navigator.clipboard.writeText(targetEl.textContent.trim());
      const original = copyBtn.textContent;
      copyBtn.textContent = "Copied!";
      setTimeout(() => { copyBtn.textContent = original; }, 1600);
    } catch {
      copyBtn.textContent = "Select to copy";
      setTimeout(() => { copyBtn.textContent = "Copy"; }, 1600);
    }
    return;
  }

  const tabBtn = event.target.closest(".cli-tab-btn");
  if (tabBtn) {
    const card = tabBtn.closest(".cli-card");
    if (!card) return;
    const mode = tabBtn.getAttribute("data-mode");
    card.querySelectorAll(".cli-tab-btn").forEach((btn) => {
      btn.classList.toggle("active", btn === tabBtn);
    });
    card.querySelectorAll(".cli-pane").forEach((pane) => {
      pane.classList.toggle("active", pane.getAttribute("data-mode") === mode);
    });
  }

});
