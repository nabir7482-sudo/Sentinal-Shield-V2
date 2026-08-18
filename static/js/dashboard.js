/* Charts are rendered solely from statistics returned by the SQLite-backed dashboard. */
(() => {
  const data = window.dashboardData;
  if (!data || !window.Chart) return;
  Chart.defaults.color = "#91a0b3";
  Chart.defaults.borderColor = "#26354a";
  const colors = { LOW: "#8da1b9", MEDIUM: "#f7d774", HIGH: "#ffad4d", CRITICAL: "#ff5e72" };
  new Chart(document.getElementById("timelineChart"), {
    type: "line",
    data: { labels: data.timeline.labels, datasets: [{ label: "Events", data: data.timeline.values, borderColor: "#2ee6a6", backgroundColor: "rgba(46,230,166,.12)", fill: true, tension: .35, pointRadius: 3 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
  });
  const doughnut = (id, values, palette) => new Chart(document.getElementById(id), { type: "doughnut", data: { labels: Object.keys(values), datasets: [{ data: Object.values(values), backgroundColor: palette, borderColor: "#111a28", borderWidth: 3 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 14 } } } } });
  doughnut("severityChart", data.severity, Object.keys(data.severity).map(key => colors[key] || "#51a9ff"));
  doughnut("categoryChart", data.categories, ["#51a9ff", "#2ee6a6", "#f7d774", "#ffad4d", "#ff5e72", "#9e8cff"]);
})();
