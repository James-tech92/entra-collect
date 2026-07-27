/**
 * CSV reading/writing shared by the collector, analyzer and report.
 *
 * The parser is a character-level state machine over the whole document rather
 * than a per-line split, because quoted fields legitimately contain newlines
 * and delimiters. Microsoft's Secure Score `Remediation` column, for instance,
 * is multi-line HTML: splitting on "\n" first shifts every later column of the
 * record onto the wrong header, which silently corrupts the data instead of
 * failing loudly.
 */

const DEFAULT_DELIM = ";";

/** Delimiter used by the header row (files are written with ";" for Excel-FR). */
function detectDelimiter(text) {
  const firstLine = String(text).replace(/^\uFEFF/, "").split(/\r?\n/, 1)[0] || "";
  let inQ = false;
  for (const ch of firstLine) {
    if (ch === '"') inQ = !inQ;
    else if (!inQ && ch === ";") return ";";
    else if (!inQ && ch === ",") return ",";
  }
  return DEFAULT_DELIM;
}

/**
 * Parse CSV text into an array of row objects keyed by header.
 * Handles quoted fields containing the delimiter, quotes ("") and newlines.
 *
 * @returns {Array<Record<string,string>>}
 */
function parseCsv(text) {
  if (!text || !String(text).trim()) return [];
  const src = String(text).replace(/^\uFEFF/, "");
  const delim = detectDelimiter(src);

  /** @type {string[][]} */
  const records = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  let sawAny = false;

  const endField = () => {
    row.push(field);
    field = "";
    sawAny = true;
  };
  const endRecord = () => {
    endField();
    // Ignore blank lines rather than emitting phantom records.
    if (row.length > 1 || row[0] !== "") records.push(row);
    row = [];
    sawAny = false;
  };

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += ch;
      continue;
    }
    if (ch === '"') inQuotes = true;
    else if (ch === delim) endField();
    else if (ch === "\r") {
      if (src[i + 1] === "\n") i++;
      endRecord();
    } else if (ch === "\n") endRecord();
    else field += ch;
  }
  if (field !== "" || sawAny || row.length) endRecord();

  if (!records.length) return [];
  const headers = records[0].map((h) => h.trim());
  return records.slice(1).map((cells) => {
    const o = {};
    headers.forEach((h, i) => {
      o[h] = cells[i] !== undefined ? cells[i] : "";
    });
    return o;
  });
}

/** Quote a value when it contains the delimiter, a quote or a newline. */
function escapeCsv(v, delim = DEFAULT_DELIM) {
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (s.includes(delim) || /["\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/** Serialize row objects, using the union of all keys as the header. */
function toCsv(rows, delim = DEFAULT_DELIM) {
  if (!rows || !rows.length) return "";
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  return [
    cols.join(delim),
    ...rows.map((r) => cols.map((c) => escapeCsv(r[c], delim)).join(delim)),
  ].join("\n");
}

module.exports = { parseCsv, toCsv, escapeCsv, detectDelimiter, DEFAULT_DELIM };
