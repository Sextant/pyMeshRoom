// The map: nodes that advertise a position (repeaters, rooms, people), on OpenStreetMap through Leaflet. Leaflet is
// loaded only when the map is first opened: from the pyMeshRoom serving this page, else from unpkg, pinned by hash.
const LEAFLET = {
  js: ["static/leaflet.js", "sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="],
  css: ["static/leaflet.css", "sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="],
};
const UNPKG = "https://unpkg.com/leaflet@1.9.4/dist/";
const COLORS = { repeater: "#5cb3ff", room: "#c38bff", chat: "#4caf7a", sensor: "#e0a83e" };

let loading = null;

// A name as text (Leaflet puts a string tooltip in as HTML, and names come from adverts and servers).
function textNode(text) {
  const e = document.createElement("span");
  e.textContent = text;
  return e;
}

function load(tag, attrs) {
  return new Promise((resolve, reject) => {
    const e = document.createElement(tag);
    Object.assign(e, attrs, { crossOrigin: "anonymous", onload: resolve, onerror: () => reject(new Error("couldn't load the map library")) });
    document.head.append(e);
  });
}

// serverBase: the pyMeshRoom serving this page (its /static/ has Leaflet, or sends us on to unpkg), or null.
function leaflet(serverBase) {
  if (window.L) return Promise.resolve(window.L);
  const base = serverBase ? serverBase.replace(/\/$/, "") + "/" : UNPKG;
  const url = (f) => (serverBase ? base + f : UNPKG + f.replace("static/", ""));
  loading ||= Promise.all([
    load("link", { rel: "stylesheet", href: url(LEAFLET.css[0]), integrity: LEAFLET.css[1] }),
    load("script", { src: url(LEAFLET.js[0]), integrity: LEAFLET.js[1] }),
  ]).then(() => window.L).catch((e) => { loading = null; throw e; });
  return loading;
}

let map = null, layer = null;

// Shows the nodes with positions in `box`. popup(node) builds each marker's popup (a DOM element: names are untrusted).
export async function showMap(box, nodes, { serverBase, center, popup }) {
  const L = await leaflet(serverBase);
  if (!map) {
    map = L.map(box, { worldCopyJump: true });
    // OSM's tile servers refuse requests without a Referer (their tile usage policy), and this page sends none: the
    // tiles carry the page's origin (only that), as the dashboard's map does
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18, attribution: "&copy; OpenStreetMap contributors", referrerPolicy: "strict-origin-when-cross-origin",
    }).addTo(map);
    layer = L.layerGroup().addTo(map);
  }
  layer.clearLayers();
  const placed = nodes.filter((n) => n.lat != null && n.lon != null && (n.lat || n.lon));
  for (const n of placed) {
    L.circleMarker([n.lat, n.lon], {
      radius: n.type === "repeater" ? 7 : 6, color: "#0b1420", weight: 1, fillColor: COLORS[n.type] || COLORS.chat, fillOpacity: 0.9,
    }).bindPopup(() => popup(n)).bindTooltip(textNode(n.name || n.pubHex.slice(0, 8))).addTo(layer);
  }
  map.invalidateSize();
  if (center) map.setView([center.lat, center.lon], 12);
  else if (placed.length) map.fitBounds(placed.map((n) => [n.lat, n.lon]), { padding: [30, 30], maxZoom: 12 });
  else map.setView([20, 0], 2);
  return placed.length;
}
