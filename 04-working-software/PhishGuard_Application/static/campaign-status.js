(() => {
  const root = document.getElementById("campaign-live-status");
  if (!root) return;

  const titleCase = (value) => String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());

  const updateText = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };

  async function refresh() {
    if (document.hidden) return;
    try {
      const response = await fetch(root.dataset.statusUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) return;
      const payload = await response.json();
      updateText("campaign-status-label", titleCase(payload.campaign_status));
      for (const key of ["recipients", "delivered", "clicked", "completed"]) {
        updateText(`metric-${key}`, payload.metrics[key]);
      }

      const panel = document.getElementById("dispatch-progress-panel");
      const job = payload.dispatch_job;
      if (panel && job) {
        panel.hidden = false;
        updateText("dispatch-status-label", titleCase(job.status));
        updateText(
          "dispatch-progress-copy",
          `${job.processed_recipients} of ${job.total_recipients} processed`,
        );
        updateText(
          "dispatch-result-copy",
          `${job.sent_recipients} sent · ${job.failed_recipients} failed`,
        );
        const progress = document.getElementById("dispatch-progress");
        if (progress) {
          progress.max = Math.max(job.total_recipients, 1);
          progress.value = job.processed_recipients;
        }
      }
    } catch (_error) {
      // A later poll retries transient network or restart conditions.
    }
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refresh();
  });
  refresh();
  window.setInterval(refresh, 2500);
})();
