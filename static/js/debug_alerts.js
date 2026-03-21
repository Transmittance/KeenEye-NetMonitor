(() => {
  const byId = (id) => document.getElementById(id);

  const ui = {
    baseUrl: byId("baseUrl"),
    pollMs: byId("pollMs"),
    applyBtn: byId("applyBtn"),
    connPill: byId("connPill"),
    lastUpdate: byId("lastUpdate"),
    statusBody: byId("statusBody"),
    cntAll: byId("cntAll"),
    cntAlerts: byId("cntAlerts"),
    cntSys: byId("cntSys"),
    alertsBox: byId("alertsBox"),
    logBox: byId("logBox")
  };

  if (!ui.baseUrl || !ui.pollMs || !ui.applyBtn) {
    return;
  }

  let timer = null;

  const escapeHtml = (value) =>
    (value ?? "")
      .toString()
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

  const format = (value) => {
    if (value === null || value === undefined) return "-";
    if (typeof value === "number") {
      return Number.isFinite(value) ? value.toFixed(4).replace(/\.?0+$/, "") : String(value);
    }
    if (typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  };

  const setConnection = (connected) => {
    ui.connPill.textContent = connected ? "Connected" : "Disconnected";
    ui.connPill.className = `pill ${connected ? "ok" : "bad"}`;
  };

  const fetchJson = async (url) => {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return response.json();
  };

  const renderStatus = (status) => {
    const entries = Object.entries(status || {});
    ui.statusBody.innerHTML =
      entries
        .map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(format(value))}</td></tr>`)
        .join("") || '<tr><td colspan="2" class="empty-cell">No data available.</td></tr>';
  };

  const renderAlertsAndLogs = (events) => {
    const all = Array.isArray(events) ? events : [];
    const alerts = all.filter((event) => event.type === "alert");
    const logs = all.filter((event) => event.type !== "alert");

    ui.cntAll.textContent = `Events: ${all.length}`;
    ui.cntAlerts.textContent = `Alerts: ${alerts.length}`;
    ui.cntSys.textContent = `System: ${logs.length}`;

    const alertsHtml = alerts
      .slice()
      .reverse()
      .map((event) => {
        const topTargets = Array.isArray(event.top_targets) ? event.top_targets : [];

        const targetRows = topTargets
          .map(
            (target) => `
              <tr>
                <td>${escapeHtml(format(target.dst))}</td>
                <td>${escapeHtml(format(target.flows_total))}</td>
                <td>${escapeHtml(format(target.unique_dst_ports))}</td>
                <td>${escapeHtml(format(target.syn_count))}</td>
                <td>${escapeHtml(format(target.rst_count))}</td>
              </tr>
            `
          )
          .join("");

        const topTable = topTargets.length
          ? `
              <div class="table-wrap">
                <table>
                  <thead><tr><th>dst</th><th>flows</th><th>ports</th><th>SYN</th><th>RST</th></tr></thead>
                  <tbody>${targetRows}</tbody>
                </table>
              </div>
            `
          : "";

        return `
          <div class="event alert">
            <div><b>${escapeHtml(format(event.ts))}</b> <span class="pill bad">ALERT</span></div>
            <div>${escapeHtml(format(event.message))}</div>
            <div class="muted mono">src=${escapeHtml(format(event.src))} p=${escapeHtml(format(event.proba))} pcap=${escapeHtml(format(event.pcap))}</div>
            ${topTable}
          </div>
        `;
      })
      .join("");

    const logsHtml = logs
      .slice()
      .reverse()
      .map(
        (event) => `
          <div class="event system">
            <div><b>${escapeHtml(format(event.ts))}</b> <span class="pill">LOG</span></div>
            <div>${escapeHtml(format(event.message || event.type || event))}</div>
          </div>
        `
      )
      .join("");

    ui.alertsBox.innerHTML = alertsHtml || '<div class="empty-cell">No alerts yet.</div>';
    ui.logBox.innerHTML = logsHtml || '<div class="empty-cell">No log events yet.</div>';
    ui.lastUpdate.textContent = `Last update: ${new Date().toLocaleTimeString()}`;
  };

  const tick = async () => {
    const base = ui.baseUrl.value.trim().replace(/\/+$/, "");

    try {
      const [status, events] = await Promise.all([
        fetchJson(`${base}/api/status`),
        fetchJson(`${base}/api/alerts`)
      ]);
      setConnection(true);
      renderStatus(status);
      renderAlertsAndLogs(events);
    } catch {
      setConnection(false);
    }
  };

  const startPolling = () => {
    if (timer) {
      clearInterval(timer);
    }

    const intervalMs = Math.max(250, Number.parseInt(ui.pollMs.value || "1000", 10));
    timer = setInterval(tick, intervalMs);
    tick();
  };

  ui.applyBtn.addEventListener("click", startPolling);
  startPolling();
})();
