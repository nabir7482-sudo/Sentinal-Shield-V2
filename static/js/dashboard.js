/* Charts are rendered solely from statistics returned by the SQLite-backed dashboard. */
(() => {
  const data = window.dashboardData;
  if (!data || !window.Chart) return;
  Chart.defaults.color = "#91a0b3";
  Chart.defaults.borderColor = "#26354a";
  const colors = { LOW: "#8da1b9", MEDIUM: "#f7d774", HIGH: "#ffad4d", CRITICAL: "#ff5e72" };
  new Chart(document.getElementById("attacksHourChart"), {
    type: "line",
    data: { labels: data.hourly.labels, datasets: [{ label: "Attacks", data: data.hourly.values, borderColor: "#2ee6a6", backgroundColor: "rgba(46,230,166,.12)", fill: true, tension: .35, pointRadius: 3 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
  });
  const doughnut = (id, values, palette) => new Chart(document.getElementById(id), { type: "doughnut", data: { labels: Object.keys(values), datasets: [{ data: Object.values(values), backgroundColor: palette, borderColor: "#111a28", borderWidth: 3 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 14 } } } } });
  doughnut("verdictChart", { "True Positive": data.verdicts["True Positive"] || 0, "False Positive": data.verdicts["False Positive"] || 0 }, ["#2ee6a6", "#ff5e72"]);
  const form = document.getElementById("aiChatForm");
  form.addEventListener("submit", async (event) => { event.preventDefault(); const response = await fetch("/ai-chat", { method: "POST", body: new FormData(form) }); const result = await response.json(); document.getElementById("aiAnswer").textContent = result.answer || "No answer available."; });
  window.setTimeout(() => window.location.reload(), 10000);
})();
