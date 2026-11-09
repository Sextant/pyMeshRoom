// node build.mjs -> ../meshroom/data/meshcore-web.html: the whole app in one file. pyMeshRoom serves it at
// /meshcore-web/; it also opens from disk or from any web server. It is committed, and rebuilt by
// .github/workflows/web.yml when the source changes on main.
// Each module keeps its own scope; the Content-Security-Policy allows only this file's own script and style.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const IMPORT_RE = /^import\s*\{([^}]*)\}\s*from\s*"(\.[^"]+)";?\s*$/gm;
const EXPORT_RE = /^export\s+(?:async\s+)?(?:const|let|class|function\*?)\s+([A-Za-z_$][\w$]*)/gm;

const order = [];
const seen = new Set();

function visit(file) {
  if (seen.has(file)) return;
  seen.add(file);
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(IMPORT_RE)) visit(resolve(dirname(file), m[2]));
  if (/^\s*(import|export)\b(?!\s+(async\s+)?(const|let|class|function))/m.test(src.replace(IMPORT_RE, "")))
    throw new Error(relative(root, file) + ": use `import { a } from \"./x.js\"` and `export const|function|class` only");
  order.push({ file, src });
}

const id = (file) => "__" + relative(root, file).replace(/\W/g, "_");

function bundle(entry) {
  visit(resolve(root, entry));
  return order.map(({ file, src }) => {
    const exports = new Set();
    const body = src
      .replace(IMPORT_RE, (_, names, from) => {
        const binds = names.split(",").map((s) => s.trim()).filter(Boolean)
          .map((s) => s.replace(/^(\S+)\s+as\s+(\S+)$/, "$1: $2"));
        return `const { ${binds.join(", ")} } = ${id(resolve(dirname(file), from))};`;
      })
      .replace(EXPORT_RE, (m, name) => { exports.add(name); return m.replace(/^export\s+/, ""); });
    return `// ${relative(root, file)}\nconst ${id(file)} = (() => {\n${body}\nreturn { ${[...exports].join(", ")} };\n})();\n`;
  }).join("\n");
}

const sha = (s) => "'sha256-" + createHash("sha256").update(s).digest("base64") + "'";
const script = bundle("src/app.js");
const style = readFileSync(join(root, "src/style.css"), "utf8");
let html = readFileSync(join(root, "index.html"), "utf8");
// The map's Leaflet comes from the serving pyMeshRoom's /static/ ('self') or unpkg, pinned by hash in map.js.
const LEAFLET = "https://unpkg.com/leaflet@1.9.4/dist/";
const csp = `default-src 'none'; script-src ${sha(script)} 'self' ${LEAFLET}leaflet.js; style-src ${sha(style)} 'self' ${LEAFLET}leaflet.css; ` +
  `img-src 'self' data: https://media.giphy.com https://i.giphy.com https://tile.openstreetmap.org https://*.tile.openstreetmap.org ${LEAFLET}images/; ` +
  "connect-src https: wss: http: ws:; base-uri 'none'; form-action 'none'";
const swap = (pattern, text) => {
  if (!pattern.test(html)) throw new Error("index.html: no match for " + pattern);
  html = html.replace(pattern, () => text);
};
swap(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/, `<meta http-equiv="Content-Security-Policy" content="${csp}">`);
swap(/<link rel="stylesheet" href="src\/style.css">/, `<style>${style}</style>`);
swap(/<script type="module" src="src\/app.js"><\/script>/, `<script type="module">${script}</script>`);
const out = join(root, "..", "meshroom", "data", "meshcore-web.html");
writeFileSync(out, html);
console.log("wrote " + relative(process.cwd(), out) + " (" + Math.round(html.length / 1024) + " KB)");
