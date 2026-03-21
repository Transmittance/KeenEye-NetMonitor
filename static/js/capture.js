(() => {
  const line = document.getElementById("line");
  const button = document.getElementById("btn");
  const limitInput = document.getElementById("limit");
  const statePill = document.getElementById("statePill");

  if (!line || !button || !limitInput || !statePill) {
    return;
  }

  const getLimit = () => {
    const value = Number.parseInt(limitInput.value, 10);
    if (Number.isNaN(value) || value < 1) return 1;
    return value;
  };

  const setState = (text, type) => {
    statePill.textContent = text;
    statePill.className = `pill ${type || ""}`.trim();
  };

  button.addEventListener("click", async () => {
    button.disabled = true;
    limitInput.disabled = true;
    setState("starting", "warn");
    line.textContent = "Starting capture...";

    try {
      const response = await fetch("/capture/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: getLimit() })
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
        line.textContent = data.line || "";
        setState(data.status || "running");

        if (data.status === "done") {
          stream.close();
          button.disabled = false;
          limitInput.disabled = false;
          setState("done", "ok");
          line.textContent = `Done: ${data.pcap_name || "No file name"}`;
          if (data.pcap_name) {
            window.location.href = `/pcap/${encodeURIComponent(data.pcap_name)}`;
          }
        }

        if (data.status === "failed") {
          stream.close();
          button.disabled = false;
          limitInput.disabled = false;
          setState("failed", "bad");
          line.textContent = `Failed: ${data.error || "Unknown error"}`;
        }
      };

      stream.onerror = () => {
        stream.close();
        button.disabled = false;
        limitInput.disabled = false;
        setState("stream error", "bad");
        line.textContent = "Stream connection was interrupted.";
      };
    } catch (error) {
      button.disabled = false;
      limitInput.disabled = false;
      setState("failed", "bad");
      line.textContent = `Failed to start capture: ${error.message}`;
    }
  });
})();
