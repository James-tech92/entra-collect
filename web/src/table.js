export function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Small, non-virtualized table — fine for the row counts a single Graph
 * area (e.g. CA policies) produces. Revisit with report.js's chunked
 * IntersectionObserver approach if a later area needs it. */
export function renderTable(container, headers, rows) {
  if (!rows || !rows.length) {
    container.innerHTML = '<p class="muted">No data.</p>';
    return;
  }
  container.innerHTML =
    '<div style="overflow:auto"><table><thead><tr>' +
    headers.map((h) => "<th>" + escapeHtml(h) + "</th>").join("") +
    "</tr></thead><tbody>" +
    rows
      .map(
        (r) =>
          "<tr>" +
          headers.map((h) => "<td>" + escapeHtml(r[h]) + "</td>").join("") +
          "</tr>"
      )
      .join("") +
    "</tbody></table></div>";
}
