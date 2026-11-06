const byId = (id) => document.getElementById(id);

function scoreFor(findings) {
  const deductions = { Critical: 30, High: 18, Medium: 8, Low: 3 };
  return Math.max(0, 100 - findings.reduce((total, item) => total + (deductions[item.severity] || 0), 0));
}

function updateHeader(data) {
  const scan = data.latest_scan || {};
  const findings = scan.findings || [];
  const score = scoreFor(findings);
  const tone = score >= 80 ? "good" : score >= 50 ? "warn" : "bad";
  const card = byId("hudScoreCard");
  const value = byId("hudScore");
  const count = byId("hudFindings");
  const badge = byId("scanBadge");

  value.textContent = score;
  value.className = `hud-score ${tone}`;
  card.className = `hud-score-card ${tone}`;
  count.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  badge.textContent = scan.demo_mode
    ? "Demo data · synthetic"
    : scan.scan_status === "complete" ? "Scan complete" : "Scan incomplete";
  badge.className = `status-badge ${scan.scan_status || ""}`;
  badge.title = scan.scan_status === "incomplete"
    ? (scan.errors || []).map((error) => error.message || error.check).join("; ") || "Scan incomplete"
    : "All checks completed successfully";
}

async function loadHeaderData() {
  const response = await fetch(`dashboard-data.json?_t=${Date.now()}`, { cache: "no-store" });
  const data = response.ok
    ? await response.json()
    : await fetch(`dashboard-data.example.json?_t=${Date.now()}`).then((sample) => sample.json());
  updateHeader(data);
}

const savedTheme = localStorage.getItem("scanner-theme") || "light";
document.documentElement.dataset.theme = savedTheme;
byId("themeToggle").textContent = savedTheme === "light" ? "Use dark mode" : "Use light mode";

byId("themeToggle").addEventListener("click", () => {
  const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  byId("themeToggle").textContent = theme === "light" ? "Use dark mode" : "Use light mode";
  localStorage.setItem("scanner-theme", theme);
});

byId("scanButton").addEventListener("click", async () => {
  const button = byId("scanButton");
  const badge = byId("scanBadge");
  button.disabled = true;
  button.textContent = "Scanning…";
  try {
    const response = await fetch("/api/scan", { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Scan failed");
    await loadHeaderData();
  } catch (error) {
    badge.textContent = `Scan failed: ${error.message}`;
    badge.className = "status-badge incomplete";
  } finally {
    button.disabled = false;
    button.textContent = "Run scan";
  }
});

document.addEventListener("click", async (event) => {
  const copyButton = event.target.closest(".copy-cli-btn");
  if (copyButton) {
    const target = document.getElementById(copyButton.dataset.target);
    if (!target) return;
    const original = copyButton.textContent;
    try {
      await navigator.clipboard.writeText(target.textContent.trim());
      copyButton.textContent = "Copied";
    } catch {
      copyButton.textContent = "Select to copy";
    }
    setTimeout(() => { copyButton.textContent = original; }, 1600);
    return;
  }

  const tabButton = event.target.closest(".cli-tab-btn");
  if (!tabButton) return;
  const card = tabButton.closest(".cli-card");
  const mode = tabButton.dataset.mode;
  card.querySelectorAll(".cli-tab-btn").forEach((button) => button.classList.toggle("active", button === tabButton));
  card.querySelectorAll(".cli-pane").forEach((pane) => pane.classList.toggle("active", pane.dataset.mode === mode));
});

loadHeaderData().catch((error) => {
  const badge = byId("scanBadge");
  badge.textContent = "Dashboard data unavailable";
  badge.className = "status-badge incomplete";
  badge.title = error.message;
});
