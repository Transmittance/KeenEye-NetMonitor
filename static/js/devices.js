(() => {
  const body = document.getElementById("tbody");
  const status = document.getElementById("status");
  const auto = document.getElementById("auto");
  const refresh = document.getElementById("refresh");

  if (!body || !status || !auto || !refresh) {
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

  const setStatus = (text, kind) => {
    status.textContent = text;
    status.className = `pill ${kind || ""}`.trim();
  };

  let devicesCache = [];
  let captureBusy = false;

  const syncCaptureButtons = () => {
    document.querySelectorAll(".device-capture-btn").forEach((button) => {
      button.disabled = captureBusy;
    });
  };

  const render = (devices) => {
    devicesCache = devices;
    const rows = devices
      .map(
        (device) => `
          <tr>
            <td>${device.online ? "yes" : ""}</td>
            <td class="mono">${escapeHtml(device.online ? device.ip : "")}</td>
            <td class="mono">${escapeHtml(device.mac)}</td>
            <td>${escapeHtml(device.name || "")}</td>
            <td>${escapeHtml(device.hostname || "")}</td>
            <td>${escapeHtml(device.vendor || "")}</td>
            <td>${escapeHtml(device.type || "")}</td>
            <td>${escapeHtml(device.expires ?? "")}</td>
            <td>
              ${device.online && device.ip
                ? `<button type="button" class="device-capture-btn" data-mac="${escapeHtml(device.mac)}">Capture</button>`
                : '<span class="muted">-</span>'}
            </td>
          </tr>
        `
      )
      .join("");

    body.innerHTML = rows || '<tr><td colspan="9" class="empty-cell">No devices found.</td></tr>';
    syncCaptureButtons();
  };

  const load = async () => {
    setStatus("loading", "warn");

    try {
      const response = await fetch("/api/devices", { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      if (!payload.ok) {
        throw new Error("API returned ok=false");
      }

      const devices = Array.isArray(payload.devices) ? payload.devices : [];
      render(devices);
      setStatus(`ok: ${devices.length}`, "ok");
    } catch (error) {
      setStatus("error", "bad");
      body.innerHTML = `<tr><td colspan="9" class="empty-cell">${escapeHtml(error.message)}</td></tr>`;
      devicesCache = [];
    }
  };

  const startDeviceCapture = async (device) => {
    if (captureBusy) return;

    captureBusy = true;
    refresh.disabled = true;
    syncCaptureButtons();
    setStatus("capturing", "warn");

    try {
      const response = await fetch("/capture/start_device", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          limit: 500,
          ip: device.ip,
          mac: device.mac,
          name: device.name || "",
          hostname: device.hostname || ""
        })
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
        if (data.status === "done") {
          stream.close();
          captureBusy = false;
          refresh.disabled = false;
          syncCaptureButtons();
          setStatus("done", "ok");
          if (data.pcap_name) {
            window.location.href = `/pcap/${encodeURIComponent(data.pcap_name)}`;
          }
          return;
        }
        if (data.status === "failed") {
          stream.close();
          captureBusy = false;
          refresh.disabled = false;
          syncCaptureButtons();
          setStatus("failed", "bad");
        }
      };

      stream.onerror = () => {
        stream.close();
        captureBusy = false;
        refresh.disabled = false;
        syncCaptureButtons();
        setStatus("stream error", "bad");
      };
    } catch (error) {
      captureBusy = false;
      refresh.disabled = false;
      syncCaptureButtons();
      setStatus(`error: ${error.message}`, "bad");
    }
  };

  refresh.addEventListener("click", load);
  body.addEventListener("click", (event) => {
    const button = event.target.closest(".device-capture-btn");
    if (!button) return;

    const mac = (button.dataset.mac || "").toLowerCase();
    const device = devicesCache.find((item) => (item.mac || "").toLowerCase() === mac);
    if (!device || !device.online || !device.ip) {
      return;
    }

    startDeviceCapture(device);
  });

  load();

  setInterval(() => {
    if (auto.checked && !captureBusy) {
      load();
    }
  }, 5000);
})();
