(() => {
  const byId = (id) => document.getElementById(id);

  const ui = {
    limit: byId("limit"),
    startCapture: byId("startCapture"),
    captureState: byId("captureState"),
    captureLine: byId("captureLine"),
    refreshStatus: byId("refreshStatus"),
    statusPill: byId("statusPill"),
    statusBody: byId("statusBody"),
    refreshDevices: byId("refreshDevices"),
    seeAllDevices: byId("seeAllDevices"),
    autoDevices: byId("autoDevices"),
    devicesInfo: byId("devicesInfo"),
    devicesBody: byId("devicesBody"),
    refreshAlerts: byId("refreshAlerts"),
    alertsBox: byId("alertsBox")
  };

  if (!ui.limit || !ui.startCapture || !ui.captureState || !ui.captureLine) {
    return;
  }

  const escapeHtml = (value) =>
    (value ?? "")
      .toString()
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

  const setPill = (element, text, kind) => {
    element.textContent = text;
    element.className = `pill ${kind || ""}`.trim();
  };

  const getLimit = () => {
    const value = Number.parseInt(ui.limit.value, 10);
    if (Number.isNaN(value) || value < 1) return 1;
    return value;
  };

  const devicesState = {
    all: []
  };
  let captureBusy = false;

  const syncCaptureButtonsDisabled = () => {
    document.querySelectorAll(".device-capture-btn").forEach((button) => {
      button.disabled = captureBusy;
    });
  };

  const setCaptureBusy = (busy) => {
    captureBusy = Boolean(busy);
    ui.startCapture.disabled = captureBusy;
    syncCaptureButtonsDisabled();
  };

  const loadStatus = async () => {
    try {
      const response = await fetch("/api/status", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      const keys = [
        "running",
        "router",
        "iface",
        "remote_dir",
        "chunk_sec",
        "threshold",
        "K",
        "window_sec",
        "model",
        "local_spool"
      ];

      const rows = keys
        .map((key) => `<tr><th>${key}</th><td class="mono">${escapeHtml(payload[key])}</td></tr>`)
        .join("");

      ui.statusBody.innerHTML = rows || '<tr><td colspan="2" class="empty-cell">No data available.</td></tr>';
      setPill(ui.statusPill, payload.running ? "running" : "stopped", payload.running ? "ok" : "bad");
    } catch (error) {
      setPill(ui.statusPill, "error", "bad");
      ui.statusBody.innerHTML = `<tr><td colspan="2" class="empty-cell">${escapeHtml(error.message)}</td></tr>`;
    }
  };

  const renderDevices = () => {
    const allDevices = devicesState.all;
    const offlineCount = allDevices.filter((device) => !device.online).length;
    const onlineCount = allDevices.length - offlineCount;
    const visibleDevices = allDevices.filter((device) => device.online);

    ui.devicesBody.innerHTML =
      visibleDevices
        .map(
          (device) => `
            <tr>
              <td>${device.online ? "yes" : ""}</td>
              <td class="mono">${escapeHtml(device.online ? device.ip : "")}</td>
              <td class="mono">${escapeHtml(device.mac)}</td>
              <td>${escapeHtml(device.name || device.hostname || "")}</td>
              <td>${escapeHtml(device.vendor || "")}</td>
              <td>
                ${device.online && device.ip
                  ? `<button type="button" class="device-capture-btn" data-mac="${escapeHtml(device.mac)}">Capture</button>`
                  : '<span class="muted">-</span>'}
              </td>
            </tr>
          `
        )
        .join("") ||
      (allDevices.length
        ? '<tr><td colspan="6" class="empty-cell">No online devices. Click "See all".</td></tr>'
        : '<tr><td colspan="6" class="empty-cell">No devices found.</td></tr>');

    setPill(ui.devicesInfo, `online: ${onlineCount} / total: ${allDevices.length}`, "ok");

    syncCaptureButtonsDisabled();
  };

  const loadDevices = async () => {
    try {
      const response = await fetch("/api/devices", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      const devices = Array.isArray(payload.devices) ? payload.devices : [];
      devicesState.all = devices;
      renderDevices();
    } catch (error) {
      setPill(ui.devicesInfo, "error", "bad");
      ui.devicesBody.innerHTML = `<tr><td colspan="6" class="empty-cell">${escapeHtml(error.message)}</td></tr>`;
    }
  };

  const loadAlerts = async () => {
    try {
      const response = await fetch("/api/alerts", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      const alertsOnly = Array.isArray(payload)
        ? payload.filter((event) => event.type === "alert").slice().reverse().slice(0, 10)
        : [];

      ui.alertsBox.innerHTML =
        alertsOnly
          .map(
            (event) => `
              <div class="event alert">
                <div><b>${escapeHtml(event.ts || "")}</b> <span class="pill bad">ALERT</span></div>
                <div>${escapeHtml(event.message || "")}</div>
                ${event.src ? `<div class="muted mono">src=${escapeHtml(event.src)} p=${escapeHtml(event.proba)}</div>` : ""}
              </div>
            `
          )
          .join("") || '<div class="empty-cell">No alerts yet.</div>';
    } catch (error) {
      ui.alertsBox.innerHTML = `<div class="empty-cell">${escapeHtml(error.message)}</div>`;
    }
  };

  const startCaptureRequest = async (url, body, startText) => {
    if (captureBusy) {
      return;
    }

    setCaptureBusy(true);
    setPill(ui.captureState, "starting", "warn");
    ui.captureLine.textContent = startText;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      if (!payload.job_id) {
        throw new Error("job_id is missing");
      }

      const stream = new EventSource(`/capture/stream/${payload.job_id}`);
      stream.onmessage = (event) => {
        const data = JSON.parse(event.data);
        ui.captureLine.textContent = data.line || "";
        setPill(ui.captureState, data.status || "running");

        if (data.status === "done") {
          stream.close();
          setCaptureBusy(false);
          setPill(ui.captureState, "done", "ok");
          const sourceLabel = data.capture_source_label ? ` (${data.capture_source_label})` : "";
          ui.captureLine.textContent = `Done${sourceLabel}: ${data.pcap_name || "No file name"}`;
          if (data.pcap_name) {
            window.location.href = `/pcap/${encodeURIComponent(data.pcap_name)}`;
          }
        }

        if (data.status === "failed") {
          stream.close();
          setCaptureBusy(false);
          setPill(ui.captureState, "failed", "bad");
          ui.captureLine.textContent = `Failed: ${data.error || "Unknown error"}`;
        }
      };

      stream.onerror = () => {
        stream.close();
        setCaptureBusy(false);
        setPill(ui.captureState, "stream error", "bad");
        ui.captureLine.textContent = "Stream connection was interrupted.";
      };
    } catch (error) {
      setCaptureBusy(false);
      setPill(ui.captureState, "failed", "bad");
      ui.captureLine.textContent = `Failed to start capture: ${error.message}`;
    }
  };

  const startCapture = async () =>
    startCaptureRequest(
      "/capture/start",
      { limit: getLimit() },
      "Starting general capture..."
    );

  const startDeviceCapture = async (device) => {
    const label = device.name || device.hostname || device.ip || device.mac || "selected device";
    return startCaptureRequest(
      "/capture/start_device",
      {
        limit: getLimit(),
        ip: device.ip,
        mac: device.mac,
        name: device.name || "",
        hostname: device.hostname || ""
      },
      `Starting capture for ${label}...`
    );
  };

  ui.refreshStatus.addEventListener("click", loadStatus);
  ui.refreshDevices.addEventListener("click", loadDevices);
  ui.refreshAlerts.addEventListener("click", loadAlerts);
  ui.startCapture.addEventListener("click", startCapture);
  if (ui.seeAllDevices) {
    ui.seeAllDevices.addEventListener("click", () => {
      window.location.href = "/devices";
    });
  }
  ui.devicesBody.addEventListener("click", (event) => {
    const button = event.target.closest(".device-capture-btn");
    if (!button) return;

    const mac = (button.dataset.mac || "").toLowerCase();
    const device = devicesState.all.find((item) => (item.mac || "").toLowerCase() === mac);
    if (!device || !device.online || !device.ip) {
      return;
    }

    startDeviceCapture(device);
  });
  loadStatus();
  loadDevices();
  loadAlerts();

  setInterval(() => {
    if (ui.autoDevices.checked) {
      loadDevices();
    }
    loadStatus();
    loadAlerts();
  }, 5000);
})();
