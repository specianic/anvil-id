// Post-build: write precompressed .br and .gz sidecars next to every compressible asset in dist/.
// anvilid serves them by negotiating Accept-Encoding (rust-embed's own compression does not emit
// sidecars). Files of 1 KiB or less are left alone: the framing overhead outweighs the saving.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist");
const COMPRESSIBLE = new Set([".js", ".mjs", ".css", ".html", ".svg", ".json", ".txt", ".map"]);
const MIN_BYTES = 1024;

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else if (entry.isFile()) yield full;
  }
}

let count = 0;
for (const file of walk(dist)) {
  if (!COMPRESSIBLE.has(path.extname(file))) continue;
  if (statSync(file).size <= MIN_BYTES) continue;
  const data = readFileSync(file);
  writeFileSync(
    `${file}.br`,
    brotliCompressSync(data, {
      params: {
        [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
        [constants.BROTLI_PARAM_SIZE_HINT]: data.length,
      },
    }),
  );
  writeFileSync(`${file}.gz`, gzipSync(data, { level: 9 }));
  count += 1;
}
console.log(`compress: wrote .br and .gz sidecars for ${count} file(s) in ${path.relative(process.cwd(), dist) || "."}`);
