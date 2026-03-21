(() => {
  const searchInput = document.getElementById("flowFilter");
  const protoSelect = document.getElementById("protoFilter");
  const rows = Array.from(document.querySelectorAll("#flowsTable tbody tr"));

  if (!searchInput || !protoSelect || !rows.length) {
    return;
  }

  const applyFilters = () => {
    const query = searchInput.value.trim().toLowerCase();
    const protocol = protoSelect.value;

    for (const row of rows) {
      const rowProtocol = row.getAttribute("data-proto") || "";
      const haystack = row.getAttribute("data-search") || "";
      const byProtocol = !protocol || rowProtocol === protocol;
      const bySearch = !query || haystack.includes(query);
      row.style.display = byProtocol && bySearch ? "" : "none";
    }
  };

  searchInput.addEventListener("input", applyFilters);
  protoSelect.addEventListener("change", applyFilters);
})();
