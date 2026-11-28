// CSV -> NDJSON for the user import (C-M10). The server has one import format, the NDJSON record of
// docs/IMPORT-EXPORT.md; the console converts a CSV file into it in the browser and posts it to
// the same endpoint, so there is no second parser on the server.
//
// The header row names record fields. Nested fields use dots:
//
//   email, email_verified, id
//   claims.<standard claim>          (claims.name, claims.locale, claims.address.locality, ...)
//   attributes.<attribute name>      (values are strings; other types need NDJSON)
//   password.<field>                 (password.scheme, password.hash, password.iterations, ...)
//   password.salt.hex / password.salt.base64 / password.hash.hex / password.hash.base64 (byte fields)
//
// Parsing follows RFC 4180: comma separators, double-quoted fields may hold commas, quotes ("")
// and line breaks; CRLF or LF line ends; a UTF-8 byte order mark is ignored. Empty cells are left
// out of the record. Errors carry the 1-based line number of the CSV file.

export interface CsvError {
  line: number;
  message: string;
}

export type CsvConversion =
  | { ndjson: string; records: number; /** CSV line of each NDJSON record (index 0 = record line 1). */ sourceLines: number[] }
  | { errors: CsvError[] };

/** Standard claims of `StandardClaims` (admin API schema). */
const CLAIMS = new Set([
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "phone_number",
  "phone_number_verified",
]);
const ADDRESS_FIELDS = new Set(["formatted", "street_address", "locality", "region", "postal_code", "country"]);
const PASSWORD_FIELDS = new Set(["scheme", "hash", "salt", "log_n", "r", "p", "prf", "iterations", "profile", "alg", "position"]);
const BYTE_FIELDS = new Set(["hash", "salt"]);
const BYTE_ENCODINGS = new Set(["hex", "base64"]);
const INTEGER_COLUMNS = new Set(["password.log_n", "password.r", "password.p", "password.iterations"]);
const BOOLEAN_COLUMNS = new Set(["email_verified", "claims.phone_number_verified"]);
const ATTRIBUTE_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

/** At most this many errors are reported (a wrong file would otherwise list every line). */
const MAX_ERRORS = 50;

interface Row {
  line: number;
  fields: string[];
}

/** RFC 4180 rows with the line each starts on. */
function parseRows(text: string): { rows: Row[]; errors: CsvError[] } {
  const rows: Row[] = [];
  const errors: CsvError[] = [];
  let fields: string[] = [];
  let field = "";
  let line = 1;
  let rowLine = 1;
  let quoted = false;
  let quoteLine = 1;
  let afterQuote = false;
  let i = 0;

  const endField = () => {
    fields.push(field);
    field = "";
    afterQuote = false;
  };
  const endRow = () => {
    endField();
    rows.push({ line: rowLine, fields });
    fields = [];
  };

  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
        afterQuote = true;
        i += 1;
        continue;
      }
      if (c === "\n") line += 1;
      field += c;
      i += 1;
      continue;
    }
    if (c === ",") {
      endField();
      i += 1;
      continue;
    }
    if (c === "\r" || c === "\n") {
      endRow();
      i += c === "\r" && text[i + 1] === "\n" ? 2 : 1;
      line += 1;
      rowLine = line;
      continue;
    }
    if (c === '"') {
      if (field === "" && !afterQuote) {
        quoted = true;
        quoteLine = line;
        i += 1;
        continue;
      }
      errors.push({ line, message: 'A quote (") inside an unquoted field: put the whole field in quotes and double the quote ("").' });
      // Skip to the next line to keep reporting other problems.
      while (i < text.length && text[i] !== "\n") i += 1;
      fields = [];
      field = "";
      afterQuote = false;
      continue;
    }
    if (afterQuote) {
      errors.push({ line, message: "Text after a closing quote: a quoted field must end at a comma or the end of the line." });
      while (i < text.length && text[i] !== "\n") i += 1;
      fields = [];
      field = "";
      afterQuote = false;
      continue;
    }
    field += c;
    i += 1;
  }
  if (quoted) {
    errors.push({ line: quoteLine, message: "A quoted field is never closed (missing closing quote)." });
  } else if (field !== "" || fields.length > 0 || afterQuote) {
    endRow();
  }
  return { rows, errors };
}

/** Why a header name is not a record field, or null when it is one. */
function headerProblem(name: string): string | null {
  if (name === "email" || name === "email_verified" || name === "id") return null;
  const parts = name.split(".");
  const [head, second, third, ...rest] = parts;
  if (head === "claims") {
    if (second === "address" && third && rest.length === 0 && ADDRESS_FIELDS.has(third)) return null;
    if (second && !third && CLAIMS.has(second)) return null;
    return `"${name}" is not a standard claim (for example claims.name, claims.locale or claims.address.locality).`;
  }
  if (head === "attributes") {
    if (second && parts.length === 2 && ATTRIBUTE_NAME.test(second)) return null;
    return `"${name}": name one custom attribute, for example attributes.department.`;
  }
  if (head === "password") {
    if (second && PASSWORD_FIELDS.has(second)) {
      if (!third) return null;
      if (BYTE_FIELDS.has(second) && BYTE_ENCODINGS.has(third) && rest.length === 0) return null;
    }
    return `"${name}" is not a password field (scheme, hash, salt, log_n, r, p, prf, iterations, profile, alg, position; byte fields also as password.hash.hex or password.salt.base64).`;
  }
  return `Unknown column "${name}". Columns: email, email_verified, id, claims.<claim>, attributes.<name>, password.<field>.`;
}

function parseBoolean(value: string): boolean | null {
  const v = value.trim().toLowerCase();
  if (["true", "yes", "1"].includes(v)) return true;
  if (["false", "no", "0"].includes(v)) return false;
  return null;
}

function setPath(target: Record<string, unknown>, path: string[], value: unknown) {
  let node = target;
  for (const key of path.slice(0, -1)) {
    const next = node[key];
    if (typeof next === "object" && next !== null) node = next as Record<string, unknown>;
    else {
      const created: Record<string, unknown> = {};
      node[key] = created;
      node = created;
    }
  }
  const last = path[path.length - 1];
  if (last !== undefined) node[last] = value;
}

/** Converts CSV text into NDJSON user records, or returns every problem with its line number. */
export function csvToNdjson(text: string): CsvConversion {
  const source = text.startsWith("﻿") ? text.slice(1) : text;
  const { rows, errors } = parseRows(source);
  const report = (): CsvConversion => ({ errors: [...errors].sort((a, b) => a.line - b.line).slice(0, MAX_ERRORS) });

  const isBlank = (row: Row) => row.fields.every((f) => f.trim() === "");
  const header = rows.find((r) => !isBlank(r));
  if (!header) {
    if (errors.length === 0) errors.push({ line: 1, message: "The file is empty: the first line must name the columns (at least email)." });
    return report();
  }

  const columns = header.fields.map((f) => f.trim());
  const parseErrors = errors.length;
  const seen = new Set<string>();
  columns.forEach((name) => {
    if (name === "") {
      errors.push({ line: header.line, message: "A column has no name in the header row." });
      return;
    }
    const problem = headerProblem(name);
    if (problem) errors.push({ line: header.line, message: problem });
    if (seen.has(name)) errors.push({ line: header.line, message: `The column "${name}" appears twice.` });
    seen.add(name);
  });
  for (const a of columns) {
    for (const b of columns) {
      if (a !== b && a !== "" && b.startsWith(`${a}.`)) {
        errors.push({ line: header.line, message: `The columns "${a}" and "${b}" both set ${a}: keep one of them.` });
      }
    }
  }
  if (!columns.includes("email")) {
    errors.push({ line: header.line, message: "The header row has no email column; every record needs an email address." });
  }
  // A broken header makes every row meaningless: report the header (and parse) problems only.
  if (errors.length > parseErrors) return report();

  const lines: string[] = [];
  const sourceLines: number[] = [];
  for (const row of rows) {
    if (row === header || row.line < header.line || isBlank(row)) continue;
    if (row.fields.length !== columns.length) {
      errors.push({
        line: row.line,
        message: `Expected ${columns.length} ${columns.length === 1 ? "field" : "fields"} (as in the header row), found ${row.fields.length}.`,
      });
      continue;
    }
    const record: Record<string, unknown> = {};
    let ok = true;
    columns.forEach((name, index) => {
      const raw = row.fields[index] ?? "";
      const value = name === "email" || INTEGER_COLUMNS.has(name) || BOOLEAN_COLUMNS.has(name) ? raw.trim() : raw;
      if (value === "") return;
      let parsed: unknown = value;
      if (BOOLEAN_COLUMNS.has(name)) {
        parsed = parseBoolean(value);
        if (parsed === null) {
          errors.push({ line: row.line, message: `${name}: "${value}" is not true or false.` });
          ok = false;
          return;
        }
      } else if (INTEGER_COLUMNS.has(name)) {
        if (!/^\d+$/.test(value)) {
          errors.push({ line: row.line, message: `${name}: "${value}" is not a whole number.` });
          ok = false;
          return;
        }
        parsed = Number(value);
      }
      setPath(record, name.split("."), parsed);
    });
    if (record.email === undefined) {
      errors.push({ line: row.line, message: "The email field is empty." });
      ok = false;
    }
    if (errors.length >= MAX_ERRORS) break;
    if (!ok || errors.length > 0) continue;
    lines.push(JSON.stringify(record));
    sourceLines.push(row.line);
  }
  if (errors.length > 0) return report();
  return { ndjson: lines.length ? `${lines.join("\n")}\n` : "", records: lines.length, sourceLines };
}

/** Whether a file looks like CSV rather than NDJSON: by extension, else by its first non-blank line. */
export function looksLikeCsv(name: string, text: string): boolean {
  const lower = name.toLowerCase();
  if (lower.endsWith(".csv")) return true;
  if (lower.endsWith(".ndjson") || lower.endsWith(".jsonl")) return false;
  const first = text.replace(/^﻿/, "").split(/\r?\n/).find((l) => l.trim() !== "");
  return first !== undefined && !first.trimStart().startsWith("{");
}

/**
 * The example file offered on the import page: two users without passwords (they set one through
 * "Forgot password" or an admin's reset email). Hash columns are described in IMPORT-EXPORT.md.
 */
export const EXAMPLE_CSV = [
  "email,email_verified,claims.name,claims.locale,attributes.department",
  "ada@example.com,true,Ada Lovelace,en,",
  'grace@example.com,false,"Hopper, Grace",en,',
  "",
].join("\r\n");
