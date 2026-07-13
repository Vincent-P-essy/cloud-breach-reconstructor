const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
}[character]));

function render(report) {
  const risk = Math.max(0, ...report.incidents.map((incident) => incident.risk_score));
  const cards = [
    [report.events.length, "evidence events"],
    [report.edges.length, "typed links"],
    [report.findings.length, "findings"],
    [`${risk.toFixed(1)}/100`, "maximum risk"]
  ];
  byId("metrics").innerHTML = cards.map(([value, label]) =>
    `<div><strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span></div>`).join("");
  byId("timeline").innerHTML = report.events.map((event) => {
    const techniques = (report.attack_mapping[event.event_id] || []).join(" · ");
    return `<div class="event"><time>${escapeHtml(event.timestamp.slice(11, 19))}</time>` +
      `<div><b>${escapeHtml(event.action)}</b><small>${escapeHtml(event.provider)} · ` +
      `${escapeHtml(event.actor)}<br>${escapeHtml(event.resource)} ${escapeHtml(techniques)}</small></div></div>`;
  }).join("");
  byId("edges").innerHTML = report.edges.map((edge) =>
    `<div><code>${escapeHtml(edge.source)}</code><span>→</span><code>${escapeHtml(edge.target)}</code>` +
    `<b>${escapeHtml(edge.kind)}</b><meter min="0" max="1" value="${edge.confidence}"></meter>` +
    `<em>${edge.confidence.toFixed(2)}</em></div>`).join("");
  byId("blast").innerHTML = Object.entries(report.blast_radius).map(([kind, values]) =>
    `<h3>${escapeHtml(kind)}</h3><p>${values.map(escapeHtml).join(" · ") || "none"}</p>`).join("");
  byId("containment").innerHTML = report.containment_actions.map((action) =>
    `<p><b>${escapeHtml(action.priority)}</b> ${escapeHtml(action.action)}<small>${escapeHtml(action.scope)}</small></p>`
  ).join("") || "<p>No deterministic action triggered.</p>";
  byId("status").textContent = `${report.diagnostics.causality_engine} · input ${report.input_sha256.slice(0, 12)}…`;
}

async function load() {
  byId("status").textContent = "Reconstructing reference evidence…";
  try {
    const response = await fetch("/api/v1/demo", {headers: {Accept: "application/json"}});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    byId("status").textContent = `Reference reconstruction unavailable: ${error.message}`;
  }
}

byId("refresh").addEventListener("click", load);
load();
